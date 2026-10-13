"""Explicit post-commit index updates; canonical owners never depend on this module."""
from __future__ import annotations

import json
import shlex
import sqlite3
from pathlib import Path

from tools.recall_index import build_text_index
from tools.relation_recall import build_relations


def add_index_options(parser, *, default=None):
    parser.add_argument("--update-index", choices=("text", "relations", "all"), default=default,
                        help="explicitly update derived indexes after a successful save")
    parser.add_argument("--index-encoder", default=default, metavar="PATH",
                        help="local encoder for --update-index text/all; never downloaded")


def validate_index_options(update_index, encoder_path):
    """Validate without opening an owner, index or model."""
    if update_index not in (None, "text", "relations", "all"):
        raise ValueError("--update-index must be text, relations or all")
    if encoder_path is not None:
        if update_index not in ("text", "all"):
            raise ValueError("--index-encoder requires --update-index text or all")
        if not isinstance(encoder_path, str) or not encoder_path.strip():
            raise ValueError("--index-encoder requires a nonempty local path")


def _rebuild_command(root, target, namespace, *, shared, encoder_path):
    command = ["python3", "tools/experience_recall.py",
               "index-build" if namespace == "text" else "relation-build",
               "--repo-root", str(Path(root).absolute()), "--full-rebuild"]
    command += ["--shared"] if shared else ["--target", target]
    if namespace == "text":
        if not shared:
            command.append("--no-knowledge")
        if encoder_path is not None:
            command += ["--encoder-path", str(Path(encoder_path).absolute())]
    return shlex.join(command)


def update_saved_result(result, root, *, update_index, encoder_path=None, target=None, shared=False):
    """Append independent index outcomes only after the owner has returned its receipt."""
    validate_index_options(update_index, encoder_path)
    if update_index is None:
        return result
    if (shared and target is not None) or (not shared and not target):
        raise ValueError("post-save index update requires exactly one target or shared partition")
    indexes = {}
    for namespace in (("text", "relations") if update_index == "all" else (update_index,)):
        try:
            if namespace == "text":
                outcome = build_text_index(root, target, encoder_path=encoder_path,
                                           include_knowledge=False, shared=shared)
            else:
                outcome = build_relations(root, target, shared=shared)
        except (OSError, ValueError, sqlite3.Error) as exc:
            outcome = {"health": {"status": "unavailable", "reason": str(exc),
                                  "error_type": type(exc).__name__}}
        indexes[namespace] = {"result": outcome}
        if outcome["health"]["status"] != "ready":
            indexes[namespace]["recovery_command"] = _rebuild_command(
                root, target, namespace, shared=shared, encoder_path=encoder_path)
    partial = any(row["result"]["health"]["status"] != "ready" for row in indexes.values())
    update = {"requested": update_index, "partition": "shared" if shared else "target",
              "status": "partial" if partial else "ready", "indexes": indexes}
    if partial:
        update["reason"] = "Save committed; index update incomplete. Rebuild only the index; do not repeat the save."
    return {**result, "save_status": "saved", "index_update": update, "partial": partial}


def format_saved_result(result):
    """Text output retains the full owner receipt and all partial index diagnostics."""
    receipt = {key: value for key, value in result.items() if key not in {"index_update", "partial", "save_status"}}
    lines = ["Save: committed", "Receipt: " + json.dumps(receipt, ensure_ascii=False, sort_keys=True),
             "Index update: " + json.dumps(result["index_update"], ensure_ascii=False, sort_keys=True)]
    if result["partial"]:
        lines.append("Partial: committed save retained; see diagnostics and index recovery commands above.")
    return "\n".join(lines)
