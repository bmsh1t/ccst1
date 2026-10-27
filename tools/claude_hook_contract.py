"""Claude transport/configuration only; no target owner or model execution."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shlex
import stat

try:
    from tools.skill_reference_contract import CORE_SKILL_PATH
except ImportError:
    from skill_reference_contract import CORE_SKILL_PATH


HOOK_OWNER = "settings.json#ccst-autopilot"
HOOK_MARKER = "--ccst-autopilot-host"
RECOVERY_PARTS = 8
CONTEXT_UNITS = 7000


def json_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _source(root: Path, relative: str) -> tuple[str, str]:
    path = root / relative
    if (path.is_symlink() or not path.resolve().is_relative_to(root)
            or any(p.is_symlink() for p in path.parents if p.is_relative_to(root))):
        raise ValueError(f"unsafe host source: {relative}")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"host source is not a regular file: {relative}")
    raw = path.read_bytes()
    after = path.stat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if signature(before) != signature(after):
        raise ValueError(f"host source changed during capture: {relative}")
    text = raw.decode("utf-8")
    if not text.strip():
        raise ValueError(f"empty host source: {relative}")
    return text, hashlib.sha256(raw).hexdigest()


def _body(text: str) -> str:
    lines = text.splitlines(keepends=True)
    if lines[0].lstrip("\ufeff").strip() == "---":
        end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
        if end is None:
            raise ValueError("unterminated host source frontmatter")
        return "".join(lines[end + 1:])
    return text


def capture_context(repo_root: Path | str, *, round_mode: bool = False) -> dict:
    """Capture original bodies; source hashes prevent mixed-version recovery."""
    root = Path(repo_root).resolve()
    sources = ((CORE_SKILL_PATH, None), ("skills/runtime-protocol.md", None),
               ("commands/autopilot.md", "## Shared Automation"))
    if round_mode:
        sources += (("commands/autopilot-round.md", "## Prepare And Terminal Precheck"),)
    sections, bindings = [], {}
    for relative, heading in sources:
        text, digest = _source(root, relative)
        body = _body(text)
        if heading:
            lines = body.splitlines(keepends=True)
            offset = next((i for i, line in enumerate(lines) if line.rstrip("\r\n") == heading), None)
            if offset is None:
                raise ValueError(f"required host section missing: {relative} {heading}")
            body = "".join(lines[offset:])
        if not body.strip():
            raise ValueError(f"empty host body: {relative}")
        bindings[relative] = digest
        sections.append(f"CCST_SOURCE {root / relative}\nPACKAGE_ROOT {root / Path(relative).parent}\n"
                        f"SHA256 {digest}\nBODY_BEGIN\n{body}\nBODY_END")
    text = "\n\n".join(sections)
    return {"text": text, "sha256": json_digest(bindings), "sources": bindings,
            "sections": sections,
            "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "chunks": context_chunks(text)}


def dynamic_output(text: str) -> str:
    if len(text.encode("utf-8")) >= 24000:
        raise ValueError("Autopilot dynamic output exceeds the verified host limit; split transport before continuing")
    return text


def context_chunks(text: str) -> list[str]:
    """Bound escaped UTF-16 units, including astral Unicode and control escapes."""
    chunks, part, units = [], [], 0
    for char in text:
        width = len(json.dumps(char, ensure_ascii=False)[1:-1].encode("utf-16-le")) // 2
        if units + width > CONTEXT_UNITS:
            chunks.append("".join(part))
            part, units = [], 0
        part.append(char)
        units += width
    if part:
        chunks.append("".join(part))
    if len(chunks) > RECOVERY_PARTS:
        raise ValueError("complete host context exceeds installed recovery slots; update transport before installation")
    return chunks


def hook_context(event: str, text: str) -> dict:
    result = {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}
    if len(json.dumps(result, ensure_ascii=False).encode("utf-16-le")) // 2 >= 10000:
        raise ValueError("host context exceeds Claude hook output limit; no preview fallback")
    return result


def host_source_digest(repo_root: Path | str, *, context: dict | None = None) -> str:
    root = Path(repo_root).resolve()
    # Validate the largest supported body during installation, not during a hunt.
    if context is None:
        context = capture_context(root, round_mode=True)
    binding = dict(context["sources"])
    for relative in ("commands/autopilot-round.md", "tools/autopilot_host.py", "tools/claude_hook_contract.py"):
        if relative not in binding:
            _, binding[relative] = _source(root, relative)
    return json_digest(binding)


def host_hooks(repo_root: Path | str, runtime_root: Path | str) -> dict:
    root, runtime = Path(repo_root).resolve(), Path(runtime_root).resolve()
    command = shlex.join(["python3", str(root / "tools/autopilot_host.py"),
                          "--runtime-root", str(runtime), "--contract-sha256", host_source_digest(root),
                          HOOK_MARKER, "hook"])
    hooks = {event: [{"hooks": [{"type": "command", "command": command, "timeout": 30}]}]
             for event in ("SessionStart", "UserPromptSubmit", "Stop", "StopFailure", "SessionEnd")}
    hooks["SessionStart"][0]["hooks"] += [
        {"type": "command", "command": command + " --part " + str(part), "timeout": 30}
        for part in range(RECOVERY_PARTS)
    ]
    return hooks


def managed_hook_groups(settings: dict) -> dict:
    if not isinstance(settings, dict):
        raise ValueError("Claude settings must be an object")
    hooks = settings.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("Claude settings hooks must be an object")
    found = {}
    for event, groups in hooks.items():
        if not isinstance(groups, list) or any(not isinstance(g, dict) for g in groups):
            raise ValueError(f"invalid Claude hook groups: {event}")
        for group in groups:
            entries = group.get("hooks", [])
            if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
                raise ValueError(f"invalid Claude hook entries: {event}")
            if any(HOOK_MARKER in str(e.get("command", "")) or "autopilot_host.py" in str(e.get("command", ""))
                   for e in entries):
                found.setdefault(event, []).append(group)
    return found


def replace_managed_hooks(settings: dict, groups: dict) -> dict:
    """Preserve unrelated values and hook order; caller owns ownership/CAS checks."""
    previous = managed_hook_groups(settings)
    hooks = {event: [g for g in entries if g not in previous.get(event, [])]
             for event, entries in settings.get("hooks", {}).items()}
    for event, entries in groups.items():
        hooks.setdefault(event, []).extend(entries)
    return {**settings, "hooks": hooks}
