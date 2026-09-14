"""distill digest 契约：脱敏、sha 绑定、git 可达性与 promote 迁移闭环。

可复现契约（2026-09-14）：git-tracked 卡的 target-evidence refs 必须指向
clone 后可达的文件。digest 是从 raw 确定性派生的脱敏事实摘要——
不含 headers/body（真实目标响应可能含 PII，scrubbed copy 进 git 就是泄露）。
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from distill_digest import (
    DIGEST_DIR,
    build_digest,
    digest_path_for,
    migrate_card_refs,
    write_digest,
)


def _probe_body(token_id: int) -> dict:
    # 真实 probe 的 Authorization 是 JWT；测试里伪造一个 payload 可解的
    # 三段 token（不追求签名，digest 只解 payload 取 id/role）。
    import base64

    payload = json.dumps({"data": {"id": token_id, "role": "customer"}})
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    fake_token = f"header.{payload_b64}.sig"
    return {
        "kind": "probe",
        "schema_version": 1,
        "ts": "2026-09-14T00:00:00Z",
        "target": "t.test",
        "request": {
            "method": "GET",
            "url": "http://t.test/rest/basket/1",
            "headers": {"Authorization": f"Bearer {fake_token}"},
            "body": "",
        },
        "response": {
            "status": 200,
            "body_sha256": "a" * 64,
            "body_retained_bytes": 1310,
            "body": '{"secret":"PII-VALUE"}',
        },
    }


def _seed_raw_probe(repo: Path, name: str = "p1.json", token_id: int = 24) -> str:
    raw_dir = repo / "evidence" / "t.test" / "probe"
    raw_dir.mkdir(parents=True)
    (raw_dir / name).write_text(json.dumps(_probe_body(token_id)), encoding="utf-8")
    return f"evidence/t.test/probe/{name}"


def _seed_candidate_card(repo: Path, card_id: str, raw_ref: str) -> Path:
    candidates = repo / "knowledge" / "candidates"
    candidates.mkdir(parents=True, exist_ok=True)
    card = candidates / f"{card_id}.md"
    card.write_text(
        f"""---
id: {card_id}
type: technique-card
related_skills:
  - web2-vuln-classes
trigger_tags:
  - {card_id}
risk: low
maturity: draft
load_priority: low
deep_refs: []
source_refs:
  - type: target-evidence
    target: t.test
    refs: ["{raw_ref}"]
updated: 2026-09-14
---

# 卡

## Quick Recall

- 触发：x
- 判定条件：y
- 停止：z

## 触发信号

- signal

## 思路分支 / 最小验证

- step

## 证据

- 来源目标：t.test（脱敏后写入）
- 原始证据：
- `{raw_ref}`

## 常见误判 / 死路

- misjudge

## 下一步或晋升

- next
""",
        encoding="utf-8",
    )
    return card


def test_digest_contains_facts_not_credentials_or_bodies(tmp_path: Path) -> None:
    raw_ref = _seed_raw_probe(tmp_path)

    payload = build_digest(tmp_path, "t.test", raw_ref)

    facts = payload["facts"]
    assert facts["method"] == "GET"
    assert facts["path"] == "/rest/basket/1"
    assert facts["status"] == 200
    assert facts["body_sha256"] == "a" * 64
    assert facts["body_bytes"] == 1310
    # 脱敏红线：digest 文本里不得出现 headers、body 或 raw token 片段
    text = json.dumps(payload, ensure_ascii=False)
    assert "Authorization" not in text
    assert "Bearer" not in text
    assert "PII-VALUE" not in text
    # raw_sha256 绑定本机原件（存在时双向可校验）
    import hashlib

    assert payload["raw_sha256"] == hashlib.sha256((tmp_path / raw_ref).read_bytes()).hexdigest()
    assert payload["raw_path"] == raw_ref


def test_write_digest_is_idempotent_and_reports_creation(tmp_path: Path) -> None:
    raw_ref = _seed_raw_probe(tmp_path)

    first_path, first_created = write_digest(tmp_path, "t.test", raw_ref)
    assert first_created is True
    second_path, second_created = write_digest(tmp_path, "t.test", raw_ref)
    assert second_created is False
    assert first_path == second_path
    assert first_path.is_file()


def test_digest_path_is_filesystem_safe(tmp_path: Path) -> None:
    path = digest_path_for(tmp_path, "127.0.0.1:3001", "evidence/x/probe/p.json")
    assert ":" not in str(path.relative_to(tmp_path))
    assert path.name == "p.json"
    assert path.parent.name == "127.0.0.1_3001"


def test_migrate_card_refs_rewrites_frontmatter_and_body(tmp_path: Path) -> None:
    raw_ref = _seed_raw_probe(tmp_path)
    card = _seed_candidate_card(tmp_path, "t-card", raw_ref)

    result = migrate_card_refs(tmp_path, "t-card")

    assert result["changed"] is True
    digest_rel = result["replaced"][raw_ref]
    assert digest_rel.startswith("knowledge/distill-digests/")
    text = card.read_text(encoding="utf-8")
    assert f'refs: ["{digest_rel}"]' in text
    # 正文"原始证据"行同步迁移，不留 frontmatter/body 分裂
    assert f"- `{digest_rel}`" in text
    assert raw_ref not in text
    assert (tmp_path / digest_rel).is_file()


def test_migrate_is_noop_without_target_evidence_refs(tmp_path: Path) -> None:
    candidates = tmp_path / "knowledge" / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "plain.md").write_text(
        "---\nid: plain\nsource_refs: []\nupdated: 2026-09-14\n---\n\n# plain\n",
        encoding="utf-8",
    )
    result = migrate_card_refs(tmp_path, "plain")
    assert result["changed"] is False
    assert result["created"] == []


# ---- audit 可达性规则 ----

def _make_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    (path / ".gitignore").write_text("evidence/*\n!knowledge/distill-digests/\n", encoding="utf-8")


def test_audit_flags_gitignored_ref_in_git_repo(tmp_path: Path) -> None:
    _make_git_repo(tmp_path)
    raw_ref = _seed_raw_probe(tmp_path)

    from knowledge_audit import AuditReport, _audit_target_evidence_refs

    class _Ref:
        id = f"t.test|{raw_ref}"

    report = AuditReport()
    _audit_target_evidence_refs(report, tmp_path, "knowledge/cards/x.md", _Ref())
    codes = [issue.code for issue in report.issues]
    assert "target-evidence-ref-ignored" in codes


def test_audit_accepts_digest_ref_in_git_repo(tmp_path: Path) -> None:
    _make_git_repo(tmp_path)
    raw_ref = _seed_raw_probe(tmp_path)
    _, _ = write_digest(tmp_path, "t.test", raw_ref)
    digest_rel = f"knowledge/distill-digests/t.test/p1.json"

    from knowledge_audit import AuditReport, _audit_target_evidence_refs

    class _Ref:
        id = f"t.test|{digest_rel}"

    report = AuditReport()
    _audit_target_evidence_refs(report, tmp_path, "knowledge/cards/x.md", _Ref())
    assert report.errors == 0
    assert report.issues == []


def test_audit_skips_git_check_outside_git_repo(tmp_path: Path) -> None:
    # 非 git 目录（tmp_path 测试夹具/裸部署）：回退磁盘存在性判定，
    # 不因 check-ignore 128 报错——既有夹具行为保持。
    raw_ref = _seed_raw_probe(tmp_path)

    from knowledge_audit import AuditReport, _audit_target_evidence_refs

    class _Ref:
        id = f"t.test|{raw_ref}"

    report = AuditReport()
    _audit_target_evidence_refs(report, tmp_path, "knowledge/cards/x.md", _Ref())
    assert report.errors == 0


# ---- promote 迁移闭环（非 git 夹具：走磁盘回退分支） ----

def test_promote_migrates_refs_and_rolls_back_digests(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    from knowledge_promote import promote

    raw_ref = _seed_raw_probe(tmp_path)
    card_id = "t-cross-actor"
    _seed_candidate_card(tmp_path, card_id, raw_ref)
    # registry + skill fixture（与 test_knowledge_promote 同构）
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir(parents=True, exist_ok=True)
    (knowledge / "capabilities.yaml").write_text(
        "schema_version: 1\ncontracts:\n"
        "  max_core_cards: 20\n  default_cards_max: 8\n"
        "  card_layers:\n    - core\n    - reference\n    - case-router\n    - payload-pack\n    - playbook\n"
        "  load_modes:\n    - default\n    - signal-or-default\n    - signal-only\n    - on-demand\n    - gated\n"
        "capabilities: []\n",
        encoding="utf-8",
    )
    cards = knowledge / "cards"
    cards.mkdir(exist_ok=True)
    skill = tmp_path / "skills" / "web2-vuln-classes"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: web2-vuln-classes\n---\n", encoding="utf-8")

    promote(tmp_path, card_id=card_id)

    # 卡已迁移：frontmatter + body 指向 digest，digest 存在
    promoted = cards / f"{card_id}.md"
    text = promoted.read_text(encoding="utf-8")
    assert "knowledge/distill-digests/" in text
    assert raw_ref not in text
    assert (tmp_path / "knowledge" / "distill-digests" / "t.test" / "p1.json").is_file()


# ─── 脱敏回归（2026-09-14 审计：字符串身份与路径令牌原样进知识目录）──────────

def test_actor_fingerprint_hashes_string_identity(tmp_path):
    """JWT payload 的 id 是 email/用户名时，digest 只留短哈希（可对比、无原文）。"""
    import base64
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import _actor_fingerprint

    payload = base64.urlsafe_b64encode(
        _json.dumps({"data": {"id": "admin@company.com", "role": "admin"}}).encode()
    ).decode().rstrip("=")
    fp = _actor_fingerprint(
        {"request": {"headers": {"Authorization": f"Bearer abc.{payload}.def"}}}
    )
    assert "company.com" not in fp
    assert fp.startswith("id=hash:")
    # role 是权限名不是身份，保留对比度
    assert fp.endswith("role=admin")


def test_actor_fingerprint_keeps_numeric_identity():
    """数字 id 原样保留——对象身份对比的事实本体。"""
    import base64
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import _actor_fingerprint

    payload = base64.urlsafe_b64encode(
        _json.dumps({"data": {"id": 25, "role": "customer"}}).encode()
    ).decode().rstrip("=")
    fp = _actor_fingerprint(
        {"request": {"headers": {"Authorization": f"Bearer abc.{payload}.def"}}}
    )
    assert fp == "id=25 role=customer"


def test_probe_facts_redacts_token_path_segments(tmp_path):
    """路径里的 token/secret 形态段替换为占位符；对象 ID 与常规路径不受影响。"""
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import _probe_facts

    def _facts(url):
        p = tmp_path / f"probe-{abs(hash(url))}.json"
        p.write_text(_json.dumps({
            "request": {"method": "GET", "url": url},
            "response": {"status": 200}, "ts": "t",
        }))
        return _probe_facts(p, tmp_path)["path"]

    assert "SECRET" not in _facts("https://t.com/api/verify/SECRET-TOKEN-XYZ123456")
    assert _facts("https://t.com/api/verify/SECRET-TOKEN-XYZ123456").endswith("<secret-redacted>")
    assert _facts("https://t.com/rest/basket/1") == "/rest/basket/1"
    assert _facts("https://t.com/api/v2/admin/users/export") == "/api/v2/admin/users/export"


def test_pull_log_cli_records_after_native_read(tmp_path, capsys):
    """薄 CLI：record 记录一条 kb-card-read；卡不存在时拒绝。"""
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from knowledge_pull_log import main as pull_main, pull_stats

    cards = tmp_path / "knowledge" / "cards"
    cards.mkdir(parents=True)
    (cards / "demo-card.md").write_text("body", encoding="utf-8")

    rc = pull_main(["record", "--card", "demo-card", "--target", "t.local",
                    "--repo-root", str(tmp_path)])
    assert rc == 0
    stats = pull_stats(tmp_path)
    assert stats["demo-card"]["pulls"] == 1
    assert stats["demo-card"]["last_pull"]

    with pytest.raises(SystemExit):
        pull_main(["record", "--card", "missing-card", "--repo-root", str(tmp_path)])
