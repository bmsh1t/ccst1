"""Explicit offline sentence-transformers models for derived recall only.

Each local directory requires recall-model.json: schema_version=1, role
(encoder/reranker), version, sentence_transformers_version, dimension,
max_seq_length, and files (relative filename -> SHA256). All model files must
be listed. No dependency installation, model discovery or remote loading occurs.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import struct


class LocalModelError(ValueError):
    """Local model missing, incompatible or not completely bound."""


def _file_hash(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def model_manifest(directory, role):
    if directory is None:
        raise LocalModelError(f"explicit local {role} directory not configured")
    root = Path(directory).absolute()
    if not root.is_dir() or any(path.is_symlink() for path in (root, *root.parents)):
        raise LocalModelError("model requires an existing non-symlink local directory")
    manifest_path = root / "recall-model.json"
    if manifest_path.is_symlink():
        raise LocalModelError("symlink model manifest refused")
    raw = manifest_path.read_bytes()
    spec = json.loads(raw)
    if (not isinstance(spec, dict) or spec.get("schema_version") != 1 or spec.get("role") != role
            or not isinstance(spec.get("version"), str) or not spec["version"]
            or not isinstance(spec.get("sentence_transformers_version"), str)
            or type(spec.get("dimension")) is not int or spec["dimension"] < 1
            or type(spec.get("max_seq_length")) is not int or spec["max_seq_length"] < 32
            or not isinstance(spec.get("files"), dict) or not spec["files"]):
        raise LocalModelError("invalid recall-model.json identity/dimension/files")
    found = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise LocalModelError("symlink model file refused")
        if path.is_file() and path != manifest_path:
            found[path.relative_to(root).as_posix()] = _file_hash(path)
    if found != spec["files"]:
        raise LocalModelError("model files differ from manifest; no load attempted")
    if not any(name.endswith(".safetensors") for name in found):
        raise LocalModelError("local model requires safetensors weights")
    modules = root / "modules.json"
    if modules.exists():
        module_specs = json.loads(modules.read_text())
        if not isinstance(module_specs, list):
            raise LocalModelError("invalid modules.json")
        for module in module_specs:
            if not isinstance(module, dict):
                raise LocalModelError("invalid model module")
            relative = module.get("path", "")
            if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise LocalModelError("model module escapes bound directory")
            if not str(module.get("type", "")).startswith("sentence_transformers.models."):
                raise LocalModelError("custom model modules refused")
    return root, {**spec, "manifest_sha256": hashlib.sha256(raw).hexdigest()}


class LocalModel:
    """Two concrete sentence-transformers APIs, never remote providers."""

    def __init__(self, directory, role):
        self.root, self.identity = model_manifest(directory, role)
        self.role = role
        try:
            version = importlib.metadata.version("sentence-transformers")
        except importlib.metadata.PackageNotFoundError as exc:
            raise LocalModelError("sentence-transformers dependency unavailable; install only by explicit approval") from exc
        if version != self.identity["sentence_transformers_version"]:
            raise LocalModelError("sentence-transformers version differs from manifest")
        try:
            from sentence_transformers import CrossEncoder, SentenceTransformer
            kwargs = dict(device="cpu", local_files_only=True, trust_remote_code=False)
            if role == "encoder":
                self.model = SentenceTransformer(str(self.root), **kwargs,
                                                model_kwargs={"use_safetensors": True})
                if self.model.get_sentence_embedding_dimension() != self.identity["dimension"]:
                    raise LocalModelError("encoder dimension differs from manifest")
                if self.identity["max_seq_length"] > self.model.max_seq_length:
                    raise LocalModelError("manifest exceeds encoder token capacity")
                self.model.max_seq_length = self.identity["max_seq_length"]
            else:
                if self.identity["dimension"] != 1:
                    raise LocalModelError("reranker requires a single output score")
                self.model = CrossEncoder(str(self.root), **kwargs,
                                          max_length=self.identity["max_seq_length"],
                                          model_kwargs={"use_safetensors": True})
            self.tokenizer = self.model.tokenizer
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise LocalModelError(f"offline {role} load failed: {exc}") from exc
        if model_manifest(self.root, role)[1] != self.identity:
            raise LocalModelError("model files changed while loading")

    def chunks(self, text, *, query=None):
        """Cover every token, including long-method tails; keep parent refs outside."""
        pair = query is not None
        reserved = self.tokenizer.num_special_tokens_to_add(pair=pair)
        if pair:
            reserved += len(self.tokenizer.encode(query, add_special_tokens=False, truncation=False))
        width = self.identity["max_seq_length"] - reserved
        if width < 8:
            raise LocalModelError("query exceeds local model token budget; original query not truncated")
        tokens = self.tokenizer.encode(text, add_special_tokens=False, truncation=False)
        result = []
        for start in range(0, len(tokens), width):
            part = self.tokenizer.decode(tokens[start:start + width], skip_special_tokens=False,
                                         clean_up_tokenization_spaces=False)
            if len(self.tokenizer.encode(part, add_special_tokens=False, truncation=False)) > width:
                raise LocalModelError("tokenizer roundtrip exceeds chunk budget; no silent truncation")
            result.append(part)
        return result or [""]

    def encode(self, texts):
        try:
            rows = self.model.encode(texts, batch_size=32, convert_to_numpy=True,
                                     normalize_embeddings=True, show_progress_bar=False, prompt="",
                                     precision="float32").tolist()
            return [float32_vector(row, self.identity["dimension"]) for row in rows]
        except (AttributeError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
            raise LocalModelError(f"local encoder failed: {exc}") from exc

    def score(self, query, texts):
        try:
            scores = self.model.predict([(query, text) for text in texts], batch_size=32,
                                        show_progress_bar=False, convert_to_numpy=True).tolist()
            if len(scores) != len(texts) or any(not isinstance(score, (int, float)) or not math.isfinite(score) for score in scores):
                raise LocalModelError("reranker returned non-finite or non-scalar scores")
            return scores
        except (AttributeError, RuntimeError, TypeError, ValueError, OverflowError) as exc:
            raise LocalModelError(f"local reranker failed: {exc}") from exc


def float32_vector(values, dimension):
    if type(dimension) is not int or dimension < 1:
        raise LocalModelError("invalid embedding dimension or non-finite value")
    try:
        if len(values) != dimension or not all(math.isfinite(value) for value in values):
            raise LocalModelError("invalid embedding dimension or non-finite value")
        packed = struct.pack(f"<{dimension}f", *values)
    except LocalModelError:
        raise
    except (TypeError, ValueError, OverflowError, struct.error) as exc:
        raise LocalModelError("invalid embedding dimension or non-finite value") from exc
    result = list(struct.unpack(f"<{dimension}f", packed))
    if not all(math.isfinite(value) for value in result) or not any(result):
        raise LocalModelError("invalid float32 embedding")
    return result


def unavailable(exc):
    return {"status": "unavailable", "reason": str(exc)[:240]}
