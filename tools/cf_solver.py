#!/usr/bin/env python3
"""Cloudflare bypass solver — obtain cf_clearance via 2Captcha + Playwright.

Covers two CF challenge tiers:
  Tier 1 — site-embedded Turnstile widget: solver.turnstile()
  Tier 2 — Managed Challenge interstitial: stealth Chrome + hook
           turnstile.render + feed the solved token to CF's callback.

Pure JS Challenges (no Turnstile token) are NOT solvable by token services —
the tool exits with code 2 and tells the operator to use a manual cf_clearance.

Usage:
  python3 tools/cf_solver.py --target https://example.com/
  python3 tools/cf_solver.py --target URL --tier 1|2
  python3 tools/cf_solver.py --target URL --export-env    # prints a source command for private auth.env
  python3 tools/cf_solver.py --target URL --dry-run       # detect tier + check balance, no solve

Output:
  Default: writes `.private/cf/<target>/` and a public reference marker under recon/.
  --export-env: prints `export BBHUNT_AUTH_HEADERS='...'` for shell sourcing.

Exit codes:
  0  success, cf_clearance obtained
  1  challenge present but solve failed
  2  JS challenge (no Turnstile) — unsolvable, use manual cookie
  3  2Captcha balance insufficient or API key invalid
  4  Playwright/dependency missing
  5  config error (no api_key)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = BASE_DIR / "config.json"

try:
    from tools.private_artifacts import private_artifact_dir, write_private_text
except ImportError:  # pragma: no cover - direct tools/ execution
    from private_artifacts import private_artifact_dir, write_private_text  # type: ignore

# cf_clearance is UA-bound — the exact UA used to solve MUST be sent with every
# subsequent request carrying that cookie, or CF re-challenges. Pin it as a
# constant so write_output can pair it with the cookie for downstream tools.
CF_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Hook turnstile.render to capture sitekey/cData/chlPageData/action and stash
# the CF callback so the solved token can be fed back into CF's own submission
# path. Also sets window.__tsParams so detect_challenge can confirm render was
# actually called (vs just loaded).
INJECT_JS = r"""
console.clear = () => console.log('Console was cleared');
window.__tsParams = null;
window.__tsRendered = false;
const i = setInterval(() => {
  if (window.turnstile) {
    clearInterval(i);
    const origRender = window.turnstile.render;
    window.turnstile.render = (a, b) => {
      window.__tsParams = {
        sitekey: b && b.sitekey,
        pageurl: window.location.href,
        data: b && b.cData,
        pagedata: b && b.chlPageData,
        action: b && b.action,
        userAgent: navigator.userAgent,
        json: 1,
      };
      window.__tsRendered = true;
      window.cfCallback = b && b.callback;
      console.log('intercepted-params:' + JSON.stringify(window.__tsParams));
      return origRender ? origRender(a, b) : undefined;
    };
  }
}, 50);
"""


def load_config() -> dict:
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"[!] config.json parse error: {exc}", file=sys.stderr)
    section = cfg.get("cf_solver", {}) or {}
    api_key = os.environ.get("TWOCAPTCHA_API_KEY") or section.get("api_key", "")
    return {
        "service": section.get("service", "2captcha"),
        "api_key": api_key,
        "headful": bool(section.get("headful", False)),
        "balance_check": section.get("balance_check", True),
    }


def check_balance(api_key: str) -> float | None:
    import requests

    try:
        r = requests.get(
            "https://2captcha.com/res.php",
            params={"key": api_key, "action": "getbalance", "json": 1},
            timeout=20,
        ).json()
    except Exception as exc:
        print(f"[!] 2Captcha balance check failed: {exc}", file=sys.stderr)
        return None
    if r.get("status") != 1:
        print(f"[!] 2Captcha API error: {r.get('request')}", file=sys.stderr)
        return None
    return float(r["request"])


def target_storage_key(target: str) -> str:
    """Match target_paths.target_storage_key for the recon dir name."""
    sys.path.insert(0, str(BASE_DIR))
    try:
        from tools.target_paths import target_storage_key as _t
        return _t(target)
    except Exception:
        return re.sub(r"[^A-Za-z0-9._:-]+", "_", target).strip("._-") or "target"


def detect_challenge(page, timeout_s: int = 12) -> str:
    """Classify the challenge on a page that has INJECT_JS installed and loaded."""
    import time

    title = (page.title() or "").lower()
    challenged = "just a moment" in title or "checking your browser" in title

    # Wait for turnstile.render to actually fire (managed/embedded) or time out.
    # Pure JS challenges load turnstile API but never call render.
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        info = page.evaluate(
            """() => ({
                ts: typeof window.turnstile !== 'undefined',
                rendered: window.__tsRendered === true,
                dom_widget: !!(document.querySelector('[data-sitekey]') ||
                               document.querySelector('iframe[src*="challenges.cloudflare"]')),
            })"""
        )
        if info.get("rendered") or info.get("dom_widget"):
            return "tier1_widget" if not challenged else "tier2_managed"
        if not info.get("ts"):
            # turnstile API never loaded within window → either no challenge
            # or pure JS challenge (no turnstile at all)
            if not challenged:
                return "none"
            time.sleep(0.3)
            continue
        time.sleep(0.4)

    # Window expired: challenged but render never fired
    if challenged:
        return "js_challenge"
    return "none"


def launch_browser(headful: bool):
    try:
        from playwright.sync_api import sync_playwright
        from playwright_stealth import Stealth
    except ImportError:
        print(
            "[!] Playwright not installed. Run:\n"
            "    pip install playwright playwright-stealth && playwright install chrome",
            file=sys.stderr,
        )
        sys.exit(4)

    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(channel="chrome", headless=not headful)
    except Exception as exc:
        print(f"[!] Chrome launch failed ({exc}). Falling back to bundled chromium.", file=sys.stderr)
        browser = pw.chromium.launch(headless=not headful)
    context = browser.new_context(
        user_agent=CF_UA,
        viewport={"width": 1366, "height": 768},
        locale="en-US",
    )
    page = context.new_page()
    try:
        Stealth().apply_stealth_sync(page)
    except Exception as exc:
        print(f"[!] stealth apply warning: {exc}", file=sys.stderr)
    return pw, browser, context, page


def solve_tier1(solver, url: str, sitekey: str) -> str | None:
    """Pure Turnstile API solve; browser is only needed to extract sitekey."""
    print(f"[*] Tier 1: solver.turnstile(sitekey={sitekey[:20]}..., url=...)")
    result = solver.turnstile(sitekey=sitekey, url=url)
    if isinstance(result, dict):
        return result.get("code")
    return str(result) if result else None


def solve_tier2(solver, url: str, headful: bool) -> dict | None:
    """Managed Challenge — stealth Chrome + inject hook + cfCallback injection."""
    pw, browser, context, page = launch_browser(headful)
    try:
        page.add_init_script(INJECT_JS)
        print(f"[*] Tier 2: navigating to {url}")
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
        except Exception as exc:
            print(f"[!] navigation error: {exc}", file=sys.stderr)

        # Poll window.__tsParams directly (set by INJECT_JS when render fires).
        # Console listener is unreliable across Playwright/CF timing; the window
        # flag is the source of truth and matches what detect_challenge reads.
        import time

        params = None
        deadline = time.time() + 40
        while time.time() < deadline:
            params = page.evaluate("() => window.__tsParams || null")
            if params:
                break
            time.sleep(0.5)
        if not params:
            print("[!] no turnstile.render captured in 40s — likely JS challenge", file=sys.stderr)
            return None

        print(f"[+] captured sitekey: {params.get('sitekey', '?')[:24]}...")
        print("[*] solving via 2captcha turnstile (managed params)...")
        # Build kwargs, dropping empty values (SDK rejects None for optional params).
        solve_kwargs = {"sitekey": params.get("sitekey"), "url": params.get("pageurl") or url}
        for src_key, sdk_key in (("userAgent", "useragent"), ("action", "action"), ("data", "data"), ("pagedata", "pagedata")):
            val = params.get(src_key)
            if val:
                solve_kwargs[sdk_key] = val
        try:
            res = solver.turnstile(**solve_kwargs)
        except Exception as exc:
            print(f"[!] 2captcha solve failed: {exc}", file=sys.stderr)
            return None
        token = res.get("code") if isinstance(res, dict) else None
        if not token:
            print("[!] unexpected solver response: missing token", file=sys.stderr)
            return None
        print("[+] token obtained (value redacted)")

        # Feed token back via CF's own callback
        try:
            page.evaluate("(token) => { if (window.cfCallback) window.cfCallback(token); }", token)
        except Exception as exc:
            print(f"[!] cfCallback inject warning: {exc}", file=sys.stderr)

        # Wait for challenge to clear
        try:
            page.wait_for_function(
                "document.title && !/just a moment|checking your browser/i.test(document.title)",
                timeout=20000,
            )
            print(f"[+] challenge cleared. Title: {page.title()}")
        except Exception:
            print(f"[!] title still challenged after token: {page.title()}", file=sys.stderr)

        cookies = context.cookies()
        cf = [c for c in cookies if c["name"] in ("cf_clearance", "__cf_bm")]
        return {"cookies": cf, "page_size": len(page.content())} if cf else None
    finally:
        browser.close()
        pw.stop()


def solve_tier1_with_browser(solver, url: str, headful: bool) -> dict | None:
    """Tier 1 widget present — extract sitekey from DOM, solve, inject, grab cookie."""
    pw, browser, context, page = launch_browser(headful)
    try:
        page.add_init_script(INJECT_JS)
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        import time

        # Prefer window.__tsParams (set by INJECT_JS render hook); fall back to DOM scrape.
        params = None
        deadline = time.time() + 15
        while time.time() < deadline:
            params = page.evaluate("() => window.__tsParams || null")
            if params and params.get("sitekey"):
                break
            time.sleep(0.5)
        if not params or not params.get("sitekey"):
            sitekey = page.evaluate(
                "() => { const e = document.querySelector('[data-sitekey]'); return e ? e.getAttribute('data-sitekey') : null; }"
            )
            if not sitekey:
                print("[!] no sitekey found on page", file=sys.stderr)
                return None
            params = {"sitekey": sitekey, "pageurl": url}

        token = solve_tier1(solver, url, params["sitekey"])
        if not token:
            return None
        page.evaluate("(token) => { if (window.cfCallback) window.cfCallback(token); }", token)
        try:
            page.wait_for_function(
                "document.title && !/just a moment|checking your browser/i.test(document.title)",
                timeout=15000,
            )
        except Exception:
            pass
        cf = [c for c in context.cookies() if c["name"] in ("cf_clearance", "__cf_bm")]
        return {"cookies": cf} if cf else None
    finally:
        browser.close()
        pw.stop()


def check_cookie(target: str) -> bool | None:
    """Probe target with the stored cf_cookies.txt + cf_ua.txt pair.

    Returns True if the cookie still passes CF (HTTP 200), False if CF
    re-challenged (403/just-a-moment), None if no stored cookie exists.
    cf_clearance is short-lived (~30min observed) so this lets the operator
    or a recon wrapper decide whether to re-solve before a long run.

    Uses curl (not requests) because CF validates TLS/JA3 fingerprints and
    python-requests' TLS profile re-triggers challenges even with a valid
    cf_clearance — curl matches the recon toolchain and is more reliable.
    """
    import subprocess

    recon_dir = BASE_DIR / "recon" / target_storage_key(target)
    private_dir = private_artifact_dir(BASE_DIR, "cf", target_storage_key(target))
    cookie_path = private_dir / "cf_cookies.txt"
    ua_path = private_dir / "cf_ua.txt"
    if not cookie_path.exists():
        # 兼容迁移前的本地文件；新写入永远进入 `.private`。
        cookie_path = recon_dir / "cf_cookies.txt"
        ua_path = recon_dir / "cf_ua.txt"
    if not cookie_path.exists():
        return None
    cookie = cookie_path.read_text(encoding="utf-8").strip()
    ua = ua_path.read_text(encoding="utf-8").strip() if ua_path.exists() else CF_UA
    try:
        result = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null",
                "-w", "%{http_code}|%{size_download}",
                "--max-time", "15",
                "-A", ua,
                "-H", f"Cookie: {cookie}",
                target,
            ],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except Exception as exc:
        print(f"[!] cookie check request failed: {exc}", file=sys.stderr)
        return False
    out = (result.stdout or "").strip()
    parts = out.split("|", 1)
    code = int(parts[0]) if parts and parts[0].isdigit() else 0
    # CF challenge responses are 403 with the "just a moment" interstitial.
    # 200 = cookie still valid; anything else (incl. 403) = re-challenged.
    return code == 200


def write_output(cookies: list[dict], target: str, export_env: bool) -> str:
    pairs = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    # Pair the UA with the cookie — cf_clearance is UA-bound, so downstream
    # tools MUST send the exact UA the solver used or CF re-challenges.
    auth_headers = f"Cookie: {pairs}\nUser-Agent: {CF_UA}"
    target_key = target_storage_key(target)
    private_dir = private_artifact_dir(BASE_DIR, "cf", target_key)
    cookie_path = write_private_text(private_dir / "cf_cookies.txt", pairs + "\n")
    ua_path = write_private_text(private_dir / "cf_ua.txt", CF_UA + "\n")
    env_path = write_private_text(
        private_dir / "auth.env",
        f"export BBHUNT_AUTH_HEADERS={shlex.quote(auth_headers)}\n",
    )
    out_dir = BASE_DIR / "recon" / target_storage_key(target)
    out_dir.mkdir(parents=True, exist_ok=True)
    marker_path = out_dir / "cf_cookies.txt"
    marker_path.write_text(f"private_ref={cookie_path.relative_to(BASE_DIR)}\n", encoding="utf-8")
    (out_dir / "cf_ua.txt").write_text(
        f"private_ref={ua_path.relative_to(BASE_DIR)}\n",
        encoding="utf-8",
    )
    print(f"[+] Cloudflare auth material written to {private_dir}")
    print(f"[*] enable in recon: source {shlex.quote(str(env_path))}")
    if export_env:
        print(f"source {shlex.quote(str(env_path))}")
    return auth_headers


def main() -> int:
    ap = argparse.ArgumentParser(description="Cloudflare bypass solver (2Captcha + Playwright)")
    ap.add_argument("--target", required=True, help="target URL (https://...)")
    ap.add_argument("--tier", type=int, choices=[1, 2], help="force tier 1 (widget) or 2 (managed)")
    ap.add_argument("--export-env", action="store_true", help="print a source command for private auth.env")
    ap.add_argument("--dry-run", action="store_true", help="detect tier + check balance, no solve")
    ap.add_argument(
        "--check",
        action="store_true",
        help="probe target with stored cf_cookies.txt; exit 0 valid, 1 expired, 6 no cookie",
    )
    ap.add_argument(
        "--auto-resolve",
        action="store_true",
        help="with --check: re-solve automatically if the stored cookie is expired",
    )
    args = ap.parse_args()

    if args.check:
        valid = check_cookie(args.target)
        if valid is None:
            print("[*] no stored cf_cookies.txt — run without --check to solve first")
            return 6
        if valid:
            print("[+] stored cf_cookies.txt still valid (CF passes)")
            return 0
        print("[!] stored cf_cookies.txt expired (CF re-challenged)")
        if not args.auto_resolve:
            print("[*] re-run with --auto-resolve to refresh, or solve fresh without --check", file=sys.stderr)
            return 1
        print("[*] --auto-resolve: proceeding to re-solve")
        # fall through to normal detect+solve flow below

    cfg = load_config()
    if not cfg["api_key"]:
        print(
            "[!] no 2captcha api_key. Set cf_solver.api_key in config.json "
            "or TWOCAPTCHA_API_KEY env var.",
            file=sys.stderr,
        )
        return 5

    try:
        from twocaptcha import TwoCaptcha
    except ImportError:
        print("[!] 2captcha-python missing. Run: pip install 2captcha-python", file=sys.stderr)
        return 4
    solver = TwoCaptcha(cfg["api_key"])
    if not hasattr(solver, "turnstile"):
        print("[!] installed twocaptcha package lacks turnstile support.", file=sys.stderr)
        return 4

    if cfg["balance_check"]:
        bal = check_balance(cfg["api_key"])
        if bal is None:
            return 3
        print(f"[*] 2captcha balance: ${bal:.4f}")

    # Detect tier (unless forced) — run even in dry-run so the operator learns the tier
    tier = args.tier
    if tier is None:
        print("[*] detecting challenge tier...")
        pw, browser, context, page = launch_browser(cfg["headful"])
        try:
            page.add_init_script(INJECT_JS)
            try:
                page.goto(args.target, wait_until="domcontentloaded", timeout=30000)
            except Exception as exc:
                print(f"[!] probe navigation error: {exc}", file=sys.stderr)
            kind = detect_challenge(page)
            print(f"[*] detected: {kind}")
        finally:
            browser.close()
            pw.stop()
        if kind == "none":
            print("[+] no challenge present, nothing to solve")
            return 0
        if kind == "js_challenge":
            print(
                "[!] JS challenge (no Turnstile) — 2captcha cannot solve. "
                "Use a manual cf_clearance cookie from your browser.",
                file=sys.stderr,
            )
            return 2
        tier = 1 if kind == "tier1_widget" else 2

    if args.dry_run:
        print(f"[*] dry-run: would solve with tier {tier}")
        return 0

    print(f"[*] solving with tier {tier}")
    if tier == 1:
        result = solve_tier1_with_browser(solver, args.target, cfg["headful"])
    else:
        result = solve_tier2(solver, args.target, cfg["headful"])

    if not result or not result.get("cookies"):
        print("[!] solve failed — no cf_clearance obtained", file=sys.stderr)
        return 1

    write_output(result["cookies"], args.target, args.export_env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
