"""HTTP 发送语义能力声明与低层 raw HTTP/1 发送器。

这个模块不替代 `request_guard.py`。request_guard 负责遥测和节流建议；
这里负责回答一个更底层的问题：某个发送方式会不会保留字节级请求语义。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import socket
import ssl
import time


CAP_AUTO_HOST = "auto_host_header"
CAP_AUTO_CONTENT_LENGTH = "auto_content_length"
CAP_BYTE_EXACT = "byte_exact_payload"
CAP_CONFLICTING_LENGTH = "preserve_conflicting_length"
CAP_MALFORMED_HEADERS = "malformed_header_bytes"
CAP_CONNECTION_REUSE = "connection_reuse_control"
CAP_PARTIAL_BODY = "partial_body_control"
CAP_BROWSER_STATE = "browser_state"
CAP_HTTP2 = "http2_frames"


@dataclass(frozen=True)
class SenderProfile:
    """描述一个发送后端的保真能力，而不是描述漏洞类别。"""

    name: str
    description: str
    capabilities: frozenset[str]
    limitations: tuple[str, ...] = ()
    local: bool = True

    def supports(self, required: set[str] | frozenset[str]) -> bool:
        return set(required).issubset(self.capabilities)


@dataclass(frozen=True)
class SenderRequirement:
    """专项执行器向发送层提出的能力需求。"""

    name: str
    required_capabilities: frozenset[str]
    reason: str


@dataclass
class RawHttpResult:
    """raw HTTP/1 发送结果，保留字节和耗时，便于后续证据模型判断。"""

    ok: bool
    response: bytes = b""
    elapsed_ms: float = 0.0
    error: str = ""
    peer_closed: bool = False

    @property
    def text(self) -> str:
        return self.response.decode("utf-8", errors="replace")


SENDER_PROFILES: tuple[SenderProfile, ...] = (
    SenderProfile(
        name="raw-http1",
        description="本地 socket/TLS 原始 HTTP/1 发送器，尽量保留调用方给出的请求字节。",
        capabilities=frozenset(
            {
                CAP_BYTE_EXACT,
                CAP_CONFLICTING_LENGTH,
                CAP_MALFORMED_HEADERS,
                CAP_CONNECTION_REUSE,
                CAP_PARTIAL_BODY,
            }
        ),
        limitations=(
            "不自动补 Host 或 Content-Length。",
            "不实现 HTTP/2 帧层语义。",
            "默认单连接低频发送，连接编排由上层专项执行器控制。",
        ),
    ),
    SenderProfile(
        name="urllib-fetch",
        description="项目现有普通 HTTP 请求路径，适合常规探测和内容抓取。",
        capabilities=frozenset({CAP_AUTO_HOST, CAP_AUTO_CONTENT_LENGTH}),
        limitations=(
            "会规范化请求，不适合畸形 header、冲突长度或 request smuggling。",
            "连接复用和请求边界不可精确控制。",
        ),
    ),
    SenderProfile(
        name="browser-playwright",
        description="浏览器态请求和 XHR/API 观察，适合认证态和前端行为证据。",
        capabilities=frozenset({CAP_AUTO_HOST, CAP_AUTO_CONTENT_LENGTH, CAP_BROWSER_STATE}),
        limitations=(
            "浏览器会强制协议合法性，不能保留大多数畸形 HTTP 请求。",
            "适合作为影响验证或隐藏 API 发现，不适合作为字节级发送器。",
        ),
    ),
    SenderProfile(
        name="h2-lowlevel",
        description="概念性 HTTP/2 低层发送器，当前项目未内置实现。",
        capabilities=frozenset({CAP_HTTP2, CAP_BYTE_EXACT}),
        limitations=("需要后续接入 hyper-h2、Burp/自研 H2 客户端或外部工具。",),
        local=False,
    ),
    SenderProfile(
        name="burp-compatible",
        description="外部 Burp/Turbo Intruder 兼容语义，作为能力参照而非项目内置依赖。",
        capabilities=frozenset(
            {
                CAP_BYTE_EXACT,
                CAP_CONFLICTING_LENGTH,
                CAP_MALFORMED_HEADERS,
                CAP_CONNECTION_REUSE,
                CAP_PARTIAL_BODY,
                CAP_HTTP2,
            }
        ),
        limitations=("不是内置依赖；只用于规划、提示和外部复现路线选择。",),
        local=False,
    ),
)


def get_sender_profile(name: str) -> SenderProfile:
    normalized = (name or "").strip().lower()
    for profile in SENDER_PROFILES:
        if profile.name == normalized:
            return profile
    raise KeyError(f"unknown sender profile: {name}")


def select_sender(
    required_capabilities: set[str] | frozenset[str],
    *,
    local_only: bool = True,
) -> SenderProfile | None:
    """按能力选择发送器；默认只返回项目可直接使用的本地 sender。"""

    required = frozenset(required_capabilities)
    for profile in SENDER_PROFILES:
        if local_only and not profile.local:
            continue
        if profile.supports(required):
            return profile
    return None


def describe_sender_capabilities() -> list[dict]:
    return [
        {
            "name": profile.name,
            "description": profile.description,
            "capabilities": sorted(profile.capabilities),
            "limitations": list(profile.limitations),
            "local": profile.local,
        }
        for profile in SENDER_PROFILES
    ]


class RawHttp1Sender:
    """最小 raw HTTP/1 sender，用于需要字节保真的低频验证。

    调用方必须传入完整 HTTP 请求字节，本类不会修正 Host、Content-Length、
    Transfer-Encoding 或换行，避免破坏上层专项执行器的语义。
    """

    def __init__(self, *, timeout: float = 10.0, read_limit: int = 1024 * 1024):
        self.timeout = timeout
        self.read_limit = read_limit

    def send(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        tls: bool = False,
        server_hostname: str | None = None,
        recv_until_close: bool = True,
    ) -> RawHttpResult:
        started = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=self.timeout) as raw_sock:
                raw_sock.settimeout(self.timeout)
                sock = self._wrap_tls(raw_sock, host, server_hostname) if tls else raw_sock
                with sock:
                    sock.sendall(payload)
                    response, peer_closed = self._read_response(sock, recv_until_close=recv_until_close)
                    return RawHttpResult(
                        ok=True,
                        response=response,
                        elapsed_ms=(time.monotonic() - started) * 1000,
                        peer_closed=peer_closed,
                    )
        except Exception as exc:
            return RawHttpResult(
                ok=False,
                elapsed_ms=(time.monotonic() - started) * 1000,
                error=str(exc),
            )

    def _wrap_tls(self, raw_sock: socket.socket, host: str, server_hostname: str | None) -> ssl.SSLSocket:
        context = ssl.create_default_context()
        return context.wrap_socket(raw_sock, server_hostname=server_hostname or host)

    def _read_response(self, sock: socket.socket, *, recv_until_close: bool) -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        peer_closed = False
        while total < self.read_limit:
            try:
                chunk = sock.recv(min(65536, self.read_limit - total))
            except socket.timeout:
                break
            if not chunk:
                peer_closed = True
                break
            chunks.append(chunk)
            total += len(chunk)
            if not recv_until_close:
                break
        return b"".join(chunks), peer_closed


def send_raw_http1(
    host: str,
    port: int,
    payload: bytes,
    *,
    tls: bool = False,
    timeout: float = 10.0,
    server_hostname: str | None = None,
    recv_until_close: bool = True,
) -> RawHttpResult:
    return RawHttp1Sender(timeout=timeout).send(
        host,
        port,
        payload,
        tls=tls,
        server_hostname=server_hostname,
        recv_until_close=recv_until_close,
    )


def _parse_capabilities(value: str) -> frozenset[str]:
    return frozenset(item.strip() for item in (value or "").split(",") if item.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Describe HTTP sender semantics and choose a sender by capability.")
    parser.add_argument("--list", action="store_true", help="List known sender profiles.")
    parser.add_argument("--require", default="", help="Comma-separated required capabilities.")
    parser.add_argument("--include-external", action="store_true", help="Allow non-local/external sender profiles.")
    args = parser.parse_args(argv)

    if args.require:
        required = _parse_capabilities(args.require)
        selected = select_sender(required, local_only=not args.include_external)
        payload = {
            "required_capabilities": sorted(required),
            "selected_sender": selected.name if selected else "",
            "selected_profile": describe_sender_capabilities()
            if args.list
            else ([item for item in describe_sender_capabilities() if item["name"] == selected.name] if selected else []),
        }
    else:
        payload = {"senders": describe_sender_capabilities()}

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
