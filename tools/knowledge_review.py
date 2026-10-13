"""Byte-bound knowledge review contracts; no registry or lifecycle mutations."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def knowledge_path(repo_root: Path, ref: str) -> Path:
    """Resolve a canonical knowledge reference without following symlink paths."""
    root = Path(repo_root).absolute()
    if not isinstance(ref, str) or not ref.startswith("knowledge/"):
        raise ValueError("review reference must be inside knowledge/")
    relative = Path(ref)
    if ref != relative.as_posix() or ".." in relative.parts:
        raise ValueError("noncanonical knowledge reference")
    path = root / relative
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink knowledge reference refused")
    if not path.resolve().is_relative_to(root.resolve() / "knowledge"):
        raise ValueError("knowledge reference escapes root")
    return path


def validate_review(review: dict, card_id: str, candidate_sha256: str, review_path: Path,
                    *, read_bytes: Callable[[Path], bytes] = Path.read_bytes) -> None:
    """Check explicit judgments and artifact bindings, never infer content truth."""
    if not isinstance(review, dict):
        raise ValueError("review must be a JSON object")
    if type(review.get("schema_version")) is not int or review["schema_version"] != 1 or review.get("decision") != "accept":
        raise ValueError("review requires schema_version=1 and decision=accept")
    if (not isinstance(candidate_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", candidate_sha256)
            or review.get("card_id") != card_id or review.get("candidate_sha256") != candidate_sha256):
        raise ValueError("review does not bind current candidate bytes; review the changed method again")
    for field in ("reviewer", "reviewed_at", "rationale", "transferability"):
        if not isinstance(review.get(field), str) or not review[field].strip():
            raise ValueError(f"review requires nonempty {field}")
    kind = review.get("intake_kind")
    if kind not in ("new-method", "existing-contract-migration", "existing-knowledge-review"):
        raise ValueError("review has invalid intake_kind")
    if kind != "new-method":
        if not isinstance(review.get("existing_source"), str) or not review["existing_source"].strip():
            raise ValueError("existing knowledge review requires existing_source")
        return
    questions = review.get("three_questions")
    if not isinstance(questions, dict) or any(
        not isinstance(questions.get(key), str) or not questions[key].strip()
        for key in ("model_seen", "inferable_from_evidence", "real_cost_delta")
    ):
        raise ValueError("new method requires three whole-unit increment judgments")
    blind = review.get("blind_answer")
    if not isinstance(blind, dict) or blind.get("verdict") != "incremental":
        raise ValueError("new method requires a completed whole-unit blind answer; unstable alone is not admission")
    for field in ("model", "configuration", "criteria", "increment"):
        if not isinstance(blind.get(field), str) or not blind[field].strip():
            raise ValueError(f"blind answer requires {field}")
    root = review_path.parent
    candidate = review_path.with_name(f"{card_id}.md")
    for field in ("question", "allowed_material", "response"):
        artifact = blind.get(field)
        if not isinstance(artifact, dict) or not isinstance(artifact.get("file"), str):
            raise ValueError(f"blind answer requires bound {field} artifact")
        relative = Path(artifact["file"])
        path = root / relative
        if (relative.is_absolute() or ".." in relative.parts
                or artifact["file"] != relative.as_posix()
                or path.resolve() in {candidate.resolve(), review_path.resolve()}
                or not path.resolve().is_relative_to(root.resolve())
                or any(part.is_symlink() for part in (path, *path.parents))):
            raise ValueError(f"blind answer {field} must be a separate artifact inside candidates")
        if sha256(read_bytes(path)) != artifact.get("sha256"):
            raise ValueError(f"blind answer {field} artifact changed; review again")


def load_review(repo_root: Path, review_ref: str, card_id: str, candidate: bytes) -> tuple[dict, bytes]:
    if not isinstance(review_ref, str) or not review_ref.startswith("knowledge/candidates/") or not review_ref.endswith(".review.json"):
        raise ValueError("review must be a .review.json file inside knowledge/candidates/")
    path = knowledge_path(repo_root, review_ref)
    raw = path.read_bytes()
    review = json.loads(raw)
    validate_review(review, card_id, sha256(candidate), path)
    if path.read_bytes() != raw:
        raise ValueError("review changed during acquisition; retry")
    return review, raw


def publication_ref(card_id: str, published_sha256: str, review_sha256: str) -> str:
    if not isinstance(card_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", card_id):
        raise ValueError("invalid knowledge review card id")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
           for value in (published_sha256, review_sha256)):
        raise ValueError("invalid knowledge publication hash")
    return f"knowledge/reviews/{card_id}/{published_sha256}-{review_sha256}.json"


def publication_receipt(*, card_id: str, file: str, candidate: bytes, published: bytes,
                        review_ref: str, review_bytes: bytes, replaced_refs: dict) -> dict:
    return {"schema_version": 1, "card_id": card_id, "file": file,
            "candidate_sha256": sha256(candidate), "published_sha256": sha256(published),
            "review_ref": review_ref, "review_sha256": sha256(review_bytes),
            "review": json.loads(review_bytes), "replaced_refs": replaced_refs}


def read_published_review(repo_root: Path, entry: dict, published: bytes,
                          *, read_bytes: Callable[[Path], bytes] = Path.read_bytes) -> dict:
    """Return a current review binding or a visible non-admission diagnostic."""
    result = {"status": "review-unverified"}
    try:
        card_id, file = entry.get("id"), entry.get("file")
        ref = entry.get("review_receipt")
        if not isinstance(ref, str):
            raise ValueError("no published-byte review receipt; explicitly review current knowledge")
        result["ref"] = ref
        path = knowledge_path(repo_root, ref)
        raw = read_bytes(path)
        result["sha256"] = sha256(raw)
        receipt = json.loads(raw)
        if not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1:
            raise ValueError("invalid knowledge publication receipt schema")
        if receipt.get("card_id") != card_id or receipt.get("file") != file or receipt.get("published_sha256") != sha256(published):
            raise ValueError("publication receipt does not bind current knowledge bytes")
        if ref != publication_ref(card_id, sha256(published), receipt.get("review_sha256")):
            raise ValueError("publication receipt identity mismatch")
        review_ref = receipt.get("review_ref")
        if not isinstance(review_ref, str) or not review_ref.startswith("knowledge/candidates/") or not review_ref.endswith(".review.json"):
            raise ValueError("invalid publication review reference")
        review_path = knowledge_path(repo_root, review_ref)
        review_bytes = read_bytes(review_path)
        if sha256(review_bytes) != receipt.get("review_sha256") or json.loads(review_bytes) != receipt.get("review"):
            raise ValueError("publication review changed or was withdrawn; review current bytes again")
        validate_review(receipt["review"], card_id, receipt.get("candidate_sha256"), review_path, read_bytes=read_bytes)
        replacements = receipt.get("replaced_refs")
        if not isinstance(replacements, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in replacements.items()):
            raise ValueError("invalid publication reference mapping")
        if entry.get("status", "active") != "active":
            raise ValueError("knowledge registry entry is not active")
        if read_bytes(path) != raw or read_bytes(review_path) != review_bytes:
            raise ValueError("publication review changed during acquisition; retry")
        result.update(status="ready", card_id=card_id, file=file,
                      published_sha256=receipt["published_sha256"],
                      candidate_sha256=receipt["candidate_sha256"],
                      review_ref=review_ref, review_sha256=receipt["review_sha256"],
                      intake_kind=receipt["review"]["intake_kind"],
                      reviewer=receipt["review"]["reviewer"], reviewed_at=receipt["review"]["reviewed_at"])
    except (OSError, UnicodeError, ValueError) as exc:
        result["reason"] = f"{type(exc).__name__}: {exc}"[:240]
    return result
