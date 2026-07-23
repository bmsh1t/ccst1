"""OpenAPI/Swagger 语义 Recon 回归。"""

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tools import openapi_semantics


REPO_ROOT = Path(__file__).resolve().parent.parent


def _fetcher(responses):
    def fetch(url, _timeout, _max_bytes):
        response = responses.get(url)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise openapi_semantics.FetchError(f"HTTP 404 for {url}", status=404)
        if isinstance(response, str):
            response = response.encode()
        return response, "application/json"

    return fetch


def _read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_openapi3_run_writes_semantics_and_merges_endpoints_idempotently(tmp_path):
    recon = tmp_path / "recon" / "target.test"
    (recon / "exposure").mkdir(parents=True)
    (recon / "live").mkdir(parents=True)
    (recon / "urls").mkdir(parents=True)
    spec_url = "https://docs.target.test/openapi.json"
    (recon / "exposure" / "api_doc_candidates.txt.validated").write_text(
        f"[urls] {spec_url}\n",
        encoding="utf-8",
    )
    (recon / "exposure" / "api_doc_candidates.txt").write_text(
        f"[urls] {spec_url}\n",
        encoding="utf-8",
    )
    (recon / "live" / "urls.txt").write_text(
        "https://api.target.test/base\nhttps://second.target.test\n",
        encoding="utf-8",
    )
    original_live = (recon / "live" / "urls.txt").read_bytes()
    (recon / "urls" / "api_endpoints.txt").write_text(
        "https://api.target.test/existing\n",
        encoding="utf-8",
    )
    spec = {
        "openapi": "3.1.0",
        "info": {"title": "Accounts"},
        "servers": [{"url": "https://external.example/{version}", "variables": {"version": {"default": "v1"}}}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users/{id}": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "tenant", "in": "header", "schema": {"type": "string"}},
                ],
                "get": {
                    "operationId": "getUser",
                    "parameters": [
                        {"name": "include", "in": "query", "schema": {"type": "string"}},
                    ],
                },
            },
            "/health": {"get": {"security": []}},
            "/optional": {"get": {"security": [{}, {"bearerAuth": []}]}},
        },
    }
    firebase_url = "https://api.target.test/__/firebase/init.json"
    responses = {
        spec_url: json.dumps(spec),
        firebase_url: json.dumps({"projectId": "target", "storageBucket": "target.appspot.com"}),
    }

    first = openapi_semantics.run(
        tmp_path,
        "target.test",
        max_platform_hosts=1,
        fetcher=_fetcher(responses),
    )
    second = openapi_semantics.run(
        tmp_path,
        "target.test",
        max_platform_hosts=1,
        fetcher=_fetcher(responses),
    )

    api_specs = recon / "api_specs"
    operations = _read_jsonl(api_specs / "operations.jsonl")
    by_path = {item["path"]: item for item in operations}
    assert first == second
    assert first["status"] == "ok"
    assert first["counts"] == {
        "candidate_urls": 1,
        "specs_parsed": 1,
        "operations": 3,
        "public_operations": 2,
        "auth_boundary_candidates": 3,
        "platform_metadata": 1,
        "errors": 0,
    }
    assert first["metadata_hosts"] == {"total": 2, "attempted": 1, "overflow": 1}
    assert by_path["/users/{id}"]["url"] == "https://external.example/v1/users/{id}?include=FUZZ"
    assert by_path["/users/{id}"]["security_status"] == "declared_required"
    assert by_path["/users/{id}"]["security_schemes"] == ["bearerAuth"]
    assert [(item["in"], item["name"]) for item in by_path["/users/{id}"]["parameters"]] == [
        ("header", "tenant"),
        ("path", "id"),
        ("query", "include"),
    ]
    assert by_path["/health"]["security_status"] == "explicit_public"
    assert by_path["/optional"]["security_status"] == "anonymous_optional"
    assert (api_specs / "unauth_api_findings.txt").read_text(encoding="utf-8") == ""
    assert len(_read_jsonl(api_specs / "auth_boundary_candidates.jsonl")) == 3
    assert _read_jsonl(api_specs / "platform_metadata.jsonl")[0]["fields"]["projectId"] == "target"
    assert (recon / "live" / "urls.txt").read_bytes() == original_live
    assert (recon / "urls" / "api_endpoints.txt").read_text(encoding="utf-8").splitlines() == [
        "https://api.target.test/existing",
        "https://external.example/v1/health",
        "https://external.example/v1/optional",
        "https://external.example/v1/users/{id}?include=FUZZ",
    ]


def test_yaml_and_swagger2_resolution_and_security_states():
    yaml_spec = openapi_semantics.parse_document(
        b"""
openapi: 3.0.3
info:
  title: YAML API
servers:
  - url: /api/v2
paths:
  /status:
    get:
      operationId: status
"""
    )
    yaml_operations = openapi_semantics.extract_operations(
        yaml_spec,
        "https://target.test/docs/openapi.yaml",
    )
    assert yaml_operations[0]["url"] == "https://target.test/api/v2/status"
    assert yaml_operations[0]["security_status"] == "unspecified"

    swagger = openapi_semantics.parse_document(json.dumps({
        "swagger": "2.0",
        "info": {"title": "Legacy"},
        "schemes": ["https", "http"],
        "host": "legacy.target.test",
        "basePath": "/v1",
        "security": [],
        "parameters": {
            "Page": {"name": "page", "in": "query", "type": "integer"},
        },
        "paths": {
            "/items": {
                "get": {"parameters": [{"$ref": "#/parameters/Page"}]},
            },
        },
    }).encode())
    operations = openapi_semantics.extract_operations(swagger, "https://docs.target.test/swagger.json")
    assert [item["url"] for item in operations] == [
        "https://legacy.target.test/v1/items?page=FUZZ",
        "http://legacy.target.test/v1/items?page=FUZZ",
    ]
    assert all(item["security_status"] == "explicit_public" for item in operations)
    assert operations[0]["parameters"][0]["type"] == "integer"


def test_duplicate_operations_merge_sources_and_preserve_security_conflict():
    required = {
        "schema_version": 1,
        "record_type": "openapi_operation",
        "method": "GET",
        "url": "https://api.target.test/users",
        "path": "/users",
        "operation_id": "listUsers",
        "operation_ids": ["listUsers"],
        "summary": "",
        "api_title": "API",
        "parameters": [],
        "security_status": "declared_required",
        "security_schemes": ["bearerAuth"],
        "security_declarations": [{
            "source": "https://a.test/openapi.json",
            "status": "declared_required",
            "schemes": ["bearerAuth"],
            "origin": "global",
        }],
        "sources": ["https://a.test/openapi.json"],
        "spec_versions": ["3.0.0"],
    }
    public = json.loads(json.dumps(required))
    public.update({
        "operation_id": "users",
        "operation_ids": ["users"],
        "security_status": "explicit_public",
        "security_schemes": [],
        "security_declarations": [{
            "source": "https://b.test/openapi.json",
            "status": "explicit_public",
            "schemes": [],
            "origin": "operation",
        }],
        "sources": ["https://b.test/openapi.json"],
        "spec_versions": ["3.1.0"],
    })

    merged = openapi_semantics.merge_operations([required, public])[0]

    assert merged["security_status"] == "conflicting_declarations"
    assert merged["security_schemes"] == ["bearerAuth"]
    assert merged["operation_ids"] == ["listUsers", "users"]
    assert merged["sources"] == ["https://a.test/openapi.json", "https://b.test/openapi.json"]


def test_partial_run_records_fetch_parse_and_yaml_errors_and_clears_old_outputs(tmp_path, monkeypatch):
    recon = tmp_path / "recon" / "target.test"
    (recon / "exposure").mkdir(parents=True)
    (recon / "api_specs").mkdir(parents=True)
    (recon / "urls").mkdir(parents=True)
    failed_url = "https://target.test/openapi.json"
    yaml_url = "https://target.test/swagger.yaml"
    invalid_url = "https://target.test/schema.json"
    (recon / "exposure" / "api_doc_candidates.txt").write_text(
        f"{failed_url}\n{yaml_url}\n{invalid_url}\n",
        encoding="utf-8",
    )
    for name in openapi_semantics.OWNED_ARTIFACTS.values():
        (recon / "api_specs" / name).write_text("stale\n", encoding="utf-8")
    responses = {
        failed_url: openapi_semantics.FetchError("network down"),
        yaml_url: b"openapi: 3.0.0\npaths: {}\n",
        invalid_url: b'{"name":"not a schema"}',
    }
    original_yaml_loader = openapi_semantics._load_yaml

    def missing_yaml(text):
        if text.startswith("openapi:"):
            raise ValueError("YAML parser unavailable (PyYAML not installed)")
        return original_yaml_loader(text)

    monkeypatch.setattr(openapi_semantics, "_load_yaml", missing_yaml)

    summary = openapi_semantics.run(tmp_path, "target.test", fetcher=_fetcher(responses))

    api_specs = recon / "api_specs"
    errors = _read_jsonl(api_specs / "errors.jsonl")
    assert summary["status"] == "partial"
    assert summary["counts"]["errors"] == 3
    assert {item["stage"] for item in errors} == {"spec_fetch", "spec_parse"}
    assert any("YAML parser unavailable" in item["error"] for item in errors)
    assert (api_specs / "operations.jsonl").read_text(encoding="utf-8") == ""
    assert (api_specs / "public_operations.txt").read_text(encoding="utf-8") == ""
    assert (api_specs / "unauth_api_findings.txt").read_text(encoding="utf-8") == ""


def test_invalid_run_arguments_fail_before_writing(tmp_path):
    with pytest.raises(ValueError, match="max_platform_hosts"):
        openapi_semantics.run(tmp_path, "target.test", max_platform_hosts=-1)
    assert not (tmp_path / "recon" / "target.test" / "api_specs").exists()


def test_fetch_rejects_declared_or_streamed_oversize_response(monkeypatch):
    class Response:
        def __init__(self, *, declared="", body=b""):
            self.headers = {"Content-Length": declared, "Content-Type": "application/json"}
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            return self.body[:size]

    monkeypatch.setattr(
        openapi_semantics.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(declared="100"),
    )
    with pytest.raises(openapi_semantics.FetchError, match="exceeds 10 bytes"):
        openapi_semantics._fetch_url("https://target.test/openapi.json", 1, 10)

    monkeypatch.setattr(
        openapi_semantics.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(body=b"x" * 11),
    )
    with pytest.raises(openapi_semantics.FetchError, match="exceeds 10 bytes"):
        openapi_semantics._fetch_url("https://target.test/openapi.json", 1, 10)


def test_atomic_writer_preserves_old_file_on_replace_failure(tmp_path, monkeypatch):
    path = tmp_path / "summary.json"
    path.write_text("old\n", encoding="utf-8")
    original_replace = type(path).replace

    def fail_replace(self, target):
        if self.name.startswith(".summary.json."):
            raise OSError("simulated replace failure")
        return original_replace(self, target)

    monkeypatch.setattr(type(path), "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        openapi_semantics._atomic_write_text(path, "new\n")
    assert path.read_text(encoding="utf-8") == "old\n"
    assert not list(tmp_path.glob(".summary.json.*.tmp"))


def test_summary_json_is_published_last(tmp_path, monkeypatch):
    calls = []
    real_writer = openapi_semantics._atomic_write_text

    def record_write(path, content):
        calls.append(path.name)
        real_writer(path, content)

    monkeypatch.setattr(openapi_semantics, "_atomic_write_text", record_write)

    summary = openapi_semantics.run(tmp_path, "target.test", fetcher=_fetcher({}))

    assert summary["status"] == "empty"
    assert calls[-1] == "summary.json"


def test_cli_localhost_wiring_fetches_spec_and_metadata(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/openapi.json":
                payload = {
                    "openapi": "3.0.3",
                    "info": {"title": "Local fixture"},
                    "servers": [{"url": "/api"}],
                    "security": [{"bearerAuth": []}],
                    "paths": {
                        "/users": {
                            "get": {
                                "parameters": [
                                    {"name": "id", "in": "query", "schema": {"type": "string"}},
                                ],
                            },
                        },
                    },
                }
                body = json.dumps(payload).encode()
            elif self.path == "/.well-known/oauth-authorization-server":
                body = json.dumps({
                    "issuer": origin,
                    "authorization_endpoint": origin + "/authorize",
                }).encode()
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    origin = f"http://127.0.0.1:{server.server_port}"
    target = f"127.0.0.1:{server.server_port}"
    recon = tmp_path / "recon" / target
    (recon / "exposure").mkdir(parents=True)
    (recon / "live").mkdir(parents=True)
    (recon / "exposure" / "api_doc_candidates.txt").write_text(
        origin + "/openapi.json\n",
        encoding="utf-8",
    )
    (recon / "live" / "urls.txt").write_text(origin + "\n", encoding="utf-8")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "openapi_semantics.py"),
                "--repo-root",
                str(tmp_path),
                "--target",
                target,
                "--max-platform-hosts",
                "1",
                "--json",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["counts"]["operations"] == 1
    assert summary["counts"]["platform_metadata"] == 1
    assert (recon / "urls" / "api_endpoints.txt").read_text(encoding="utf-8").strip() == (
        origin + "/api/users?id=FUZZ"
    )
    assert (recon / "api_specs" / "summary.json").is_file()
