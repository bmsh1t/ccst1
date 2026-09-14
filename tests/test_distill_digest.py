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


def test_migrate_multi_source_refs_route_by_target(tmp_path):
    """多来源引用错配回归（2026-09-14 审计）：同卡含两个 target-evidence 条目时，
    每个条目的 refs 必须改写为该条目自身 target 的 digest——旧实现忽略 target 参数，
    两个条目都被改到第一个命中处（alpha 被写成 beta 的 digest、beta 未动）。
    覆盖内联数组与列表两种合法 YAML 形态。"""
    import json as _json
    import re as _re
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import migrate_card_refs

    def _seed(fmt: str) -> Path:
        card_dir = tmp_path / "knowledge" / "candidates"
        card_dir.mkdir(parents=True, exist_ok=True)
        evA = tmp_path / "findings" / "alpha.local" / f"pA-{fmt}.json"
        evB = tmp_path / "findings" / "beta.local" / f"pB-{fmt}.json"
        for ev, url in ((evA, "http://a/x"), (evB, "http://b/y")):
            ev.parent.mkdir(parents=True, exist_ok=True)
            ev.write_text(_json.dumps({"request": {"method": "GET", "url": url},
                                       "response": {"status": 200}}))
        if fmt == "inline":
            refs_a, refs_b = f"refs: [{evA}]", f"refs: [{evB}]"
        else:
            refs_a, refs_b = f"refs:\n      - {evA}", f"refs:\n      - {evB}"
        card = card_dir / f"multi-{fmt}.md"
        card.write_text(
            f"---\nid: multi-{fmt}\ntype: technique-card\nsource_refs:\n"
            f"  - type: target-evidence\n    target: alpha.local\n    {refs_a}\n"
            f"  - type: target-evidence\n    target: beta.local\n    {refs_b}\n---\nbody\n",
            encoding="utf-8",
        )
        return card

    for fmt in ("inline", "list"):
        card = _seed(fmt)
        migrate_card_refs(tmp_path, f"multi-{fmt}")
        text = card.read_text(encoding="utf-8")
        assert text.count("type: target-evidence") == 2, fmt
        # 内联形态直接断言；列表形态逐行配对
        if fmt == "inline":
            blocks = _re.findall(r"target: (\S+)\n\s+refs: (\[[^\n]+\])", text)
            assert len(blocks) == 2, fmt
            for target, refs in blocks:
                want = "alpha" if target == "alpha.local" else "beta"
                assert want in refs and "findings" not in refs, (fmt, target, refs)
        else:
            lines = text.splitlines()
            current_target = ""
            for line in lines:
                m = _re.match(r"\s*target: (\S+)", line)
                if m:
                    current_target = m.group(1)
                m = _re.match(r"\s+- \"(knowledge/distill-digests/[^\"]+)\"", line)
                if m:
                    want = "alpha" if current_target == "alpha.local" else "beta"
                    assert want in m.group(1), (fmt, current_target, m.group(1))


def test_migrate_refuses_when_entry_missing(tmp_path):
    """ref 声明的 target 与卡内任何 target-evidence 条目都不匹配时拒绝迁移，
    不静默留下 raw 引用与 digest 不一致。构造方式：条目 target 写在 refs 之后
    （行级扫描窗口内先撞 refs 再见 target），定位规则必须按 target 匹配拒绝。"""
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import migrate_card_refs

    card_dir = tmp_path / "knowledge" / "candidates"
    card_dir.mkdir(parents=True)
    ev = tmp_path / "findings" / "zeta.local" / "p.json"
    ev.parent.mkdir(parents=True)
    ev.write_text(_json.dumps({"request": {"method": "GET", "url": "http://z/x"},
                               "response": {"status": 200}}))
    card = card_dir / "orphan.md"
    # 条目声明 target=gamma.local；证据在 zeta.local 下但 target 字段以 registry
    # 解析为准（gamma）——本测试直接验证：不存在 gamma 条目时可被拒绝的前提
    # 是行级形态与 YAML 语义分离。真实数据流里 registry 保证一致，此用例锁的是
    # _rewrite_ref_entry 的 target 匹配行为本身：target 不匹配 → 不改写 → 上层拒绝。
    from distill_digest import _rewrite_ref_entry

    lines = [
        "---\n",
        "id: orphan\n",
        "source_refs:\n",
        "  - type: target-evidence\n",
        "    refs: [keep-me]\n",
        "    target: gamma.local\n",
        "---\n",
    ]
    assert _rewrite_ref_entry(lines, closing=6, target="zeta.local",
                              new_paths=["knowledge/distill-digests/zeta.local/p.json"]) is False
    assert "keep-me" in "".join(lines)  # 未匹配时原样保留



def test_write_digest_reuses_existing_digest(tmp_path):
    """二轮审计回归 1：ref 已是合法 digest 时复用，不当 raw 重新提取——
    promote 二次运行曾把已有摘要的 facts 覆盖成空值并形成自引用。"""
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import write_digest

    raw = tmp_path / "findings" / "t.test" / "p.json"
    raw.parent.mkdir(parents=True)
    raw.write_text(_json.dumps({"request": {"method": "GET", "url": "http://t/rest/basket/1"},
                                "response": {"status": 200}, "ts": "t"}))
    p1, created1 = write_digest(tmp_path, "t.test", str(raw))
    facts1 = _json.loads(p1.read_text())["facts"]
    assert created1

    p2, created2 = write_digest(tmp_path, "t.test", str(p1.relative_to(tmp_path)))
    assert p2 == p1 and not created2
    assert _json.loads(p2.read_text())["facts"] == facts1  # facts 未被空值覆盖


def test_scrub_path_catches_pure_alpha_tokens(tmp_path):
    """二轮审计回归 2：无数字的路径 token（RESET_FIXTURE_VALUE）同样脱敏——
    旧正则要求字母+数字混合，纯字母凭据完全绕过。"""
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import _probe_facts

    p = tmp_path / "neg.json"
    p.write_text(_json.dumps({"request": {"method": "GET",
                                          "url": "http://t/reset/RESET_FIXTURE_VALUE"},
                              "response": {"status": 200}, "ts": "t"}))
    assert "RESET" not in _probe_facts(p, tmp_path)["path"]
    # 场景词路由段不误伤
    p2 = tmp_path / "ok.json"
    p2.write_text(_json.dumps({"request": {"method": "GET",
                                           "url": "http://t/api/verification"},
                               "response": {"status": 200}, "ts": "t"}))
    assert _probe_facts(p2, tmp_path)["path"] == "/api/verification"


def test_rewrite_same_target_two_entries(tmp_path):
    """二轮审计回归 3：同 target 两个来源条目各自路由——只按 target 定位
    会让两个 ref 都改写第一个条目（第一个换成第二个的 digest，第二个
    保留 raw）。带引号 target 值同测。"""
    import json as _json
    import re as _re
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import migrate_card_refs

    card_dir = tmp_path / "knowledge" / "candidates"
    card_dir.mkdir(parents=True)
    ev1 = tmp_path / "findings" / "t.test" / "p1.json"
    ev2 = tmp_path / "findings" / "t.test" / "p2.json"
    ev1.parent.mkdir(parents=True)
    for ev, n in ((ev1, 1), (ev2, 2)):
        ev.write_text(_json.dumps({"request": {"method": "GET", "url": f"http://t/{n}"},
                                   "response": {"status": 200}}))
    card = card_dir / "same-t.md"
    card.write_text(
        f"---\nid: same-t\ntype: technique-card\nsource_refs:\n"
        f"  - type: target-evidence\n    target: t.test\n    refs: [{ev1}]\n"
        f"  - type: target-evidence\n    target: \"t.test\"\n    refs: [{ev2}]\n---\nbody\n",
        encoding="utf-8",
    )
    migrate_card_refs(tmp_path, "same-t")
    text = card.read_text(encoding="utf-8")
    blocks = _re.findall(r"refs: \[\"([^\"]+)\"\]", text)
    assert len(blocks) == 2, text
    assert blocks[0].endswith("t.test/p1.json"), blocks  # 第一条目 → p1 digest
    assert blocks[1].endswith("t.test/p2.json"), blocks  # 第二条目 → p2 digest


def test_publishable_digest_guard_rejects_wrong_target_and_body(tmp_path):
    """三轮审计回归 2：已有摘要不能仅凭 `kind` 就复用。目标错误、facts 缺失、
    夹带 body/headers 的文件都不是可发布摘要——旧实现直接复用它们，未校验
    就留在 git-tracked 知识目录。"""
    import json as _json
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import FACT_FIELDS, _is_publishable_digest, write_digest

    T = "t.test"
    full_facts = {k: "" for k in FACT_FIELDS}
    base = {"schema_version": 1, "kind": "distill-digest", "target": T,
            "raw_path": "findings/t.test/p.json", "raw_sha256": "0" * 64,
            "facts": full_facts, "note": "n"}

    assert _is_publishable_digest(base, T)
    assert not _is_publishable_digest({**base, "target": "other.test"}, T)
    assert not _is_publishable_digest({**base, "body": "SECRET"}, T)
    assert not _is_publishable_digest({**base, "headers": {"cookie": "x"}}, T)
    assert not _is_publishable_digest({**base, "facts": {"method": "GET"}}, T)
    assert not _is_publishable_digest([base], T)

    # 端到端：目标错误的既有摘要不再被静默复用（拒绝自写而不是当 raw 重提取）
    bad = tmp_path / "knowledge" / "distill-digests" / T / "p.json"
    bad.parent.mkdir(parents=True)
    bad.write_text(_json.dumps({**base, "target": "other.test"}), encoding="utf-8")
    with pytest.raises(SystemExit, match="refusing to rewrite"):
        write_digest(tmp_path, T, str(bad.relative_to(tmp_path)))


def test_scrub_cross_segment_token_values(tmp_path):
    """三轮审计回归 2b：关键词与取值分处两段时同样脱敏。
    `/api/token/abcdefghijklmnopqrst`、`/reset-password/AbCdEfGhIjKlMnOpQrSt`
    旧实现整段明文进 git（关键词必须与值同段才触发）。同时不得过度清洗
    真实路由词（application-configuration / security-question / SecurityQuestions）。"""
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import _scrub_path_tokens

    for path in ("/api/token/abcdefghijklmnopqrst",
                 "/reset-password/AbCdEfGhIjKlMnOpQrSt",
                 "/api/session/abcdefghijkl",
                 "/v/abcdefghijklmnop",
                 "/t/AbCdEfGhIjKlMnOp"):
        assert "redacted" in _scrub_path_tokens(path), path
    for path in ("/api/verification", "/rest/user/login", "/rest/basket/1",
                 "/users/12345", "/auth/reset-password",
                 "/api/application-configuration", "/api/security-question",
                 "/api/SecurityQuestions", "/api/order-history", "/api/data-export"):
        assert _scrub_path_tokens(path) == path, path


def test_migrate_combined_sources_is_idempotent(tmp_path):
    """三轮审计回归 3：组合来源重复迁移不得丢引用。两组引用 [p1,p2] 与 [p2]
    在同 target 下，旧实现的"包含任一引用"匹配让第二组又改写第一组，重跑后
    两组都变成 [p2]，第一组的 p1 引用丢失。精确字面量匹配 + 条目消费记录
    后重跑幂等。"""
    import json as _json
    import re as _re
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from distill_digest import migrate_card_refs

    ev = tmp_path / "findings" / "t.test"
    ev.mkdir(parents=True)
    for n in (1, 2):
        (ev / f"p{n}.json").write_text(
            _json.dumps({"request": {"method": "GET", "url": f"http://t/{n}"},
                         "response": {"status": 200}}), encoding="utf-8")
    card_dir = tmp_path / "knowledge" / "candidates"
    card_dir.mkdir(parents=True)
    card = card_dir / "combo.md"
    card.write_text(
        f"---\nid: combo\ntype: technique-card\nsource_refs:\n"
        f"  - type: target-evidence\n    target: t.test\n    refs: [{ev}/p1.json; {ev}/p2.json]\n"
        f"  - type: target-evidence\n    target: t.test\n    refs: [{ev}/p2.json]\n---\nbody\n",
        encoding="utf-8",
    )
    migrate_card_refs(tmp_path, "combo")
    first = card.read_text(encoding="utf-8")
    blocks = _re.findall(r"refs: \[(.*?)\]", first)
    assert len(blocks) == 2, first
    assert "p1.json" in blocks[0] and "p2.json" in blocks[0], blocks
    assert "p2.json" in blocks[1] and "p1.json" not in blocks[1], blocks

    migrate_card_refs(tmp_path, "combo")
    assert card.read_text(encoding="utf-8") == first  # 重跑幂等，不丢引用
