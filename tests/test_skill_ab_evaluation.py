"""Skill-creator 风格的 Skill A/B 回归验证。"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import subprocess

from context_pack import build_context_pack


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_VALIDATOR = Path("/root/.codex/skills/.system/skill-creator/scripts/quick_validate.py")
CARD = "knowledge/cards/{}"


@dataclass(frozen=True)
class SkillEvalTask:
    """单个 A/B 任务：期望卡片、禁止噪音卡片和关键 seed 证据。"""

    name: str
    focus: str
    expected_cards: tuple[str, ...]
    forbidden_cards: tuple[str, ...]
    seed_groups: tuple[tuple[str, ...], ...]
    expected_skill: str = "web2-vuln-classes"
    expected_checks: tuple[str, ...] = ("rules/red-lines.md", "rules/coverage-gate.md")


EVAL_TASKS = [
    SkillEvalTask(
        name="jwt_key_source_single_variable",
        focus="JWT authentication bypass unverified signature session token payload sub role admin JWK JKU KID alg confusion",
        expected_cards=(CARD.format("auth-sso-token-edge-cases.md"),),
        forbidden_cards=(),
        seed_groups=(("claim-only tamper", "无效签名"), ("key-source", "JWK"), ("服务端身份", "权限")),
    ),
    SkillEvalTask(
        name="graphql_node_global_id_without_node_runtime_noise",
        focus="GraphQL private posts node global ID introspection query fields",
        expected_cards=(CARD.format("graphql.md"),),
        forbidden_cards=(CARD.format("node-prototype-pollution.md"),),
        seed_groups=(("GraphQL", "global ID"),),
    ),
    SkillEvalTask(
        name="api_hpp_mass_assignment_matrix",
        focus="API server-side parameter pollution HPP duplicate query parameter mass assignment over-posting PATCH user profile role isAdmin plan status",
        expected_cards=(
            CARD.format("api-testing-workflow.md"),
            CARD.format("business-logic-state-machines.md"),
        ),
        forbidden_cards=(),
        seed_groups=(("HPP",), ("mass assignment",), ("状态机",)),
    ),
    SkillEvalTask(
        name="cache_poisoning_deception_without_host_smuggling_dependency",
        focus="web-cache-poisoning cache-deception unkeyed header cache key victim request shape",
        expected_cards=(CARD.format("proxy-cache-boundaries.md"),),
        forbidden_cards=(CARD.format("auth-access.md"), CARD.format("browser-client-boundaries.md")),
        seed_groups=(("cache-buster",), ("victim request shape",), ("cache key",)),
    ),
    SkillEvalTask(
        name="smuggling_capture_noise_control",
        focus="request smuggling account request capture CSRF Cookie storage poll readback victim session",
        expected_cards=(CARD.format("proxy-cache-boundaries.md"),),
        forbidden_cards=(
            CARD.format("browser-client-boundaries.md"),
            CARD.format("web-llm-tool-chains.md"),
            CARD.format("auth-access.md"),
        ),
        seed_groups=(("capture-other-users",), ("Content-Length",), ("Cookie line",), ("poll", "重试")),
    ),
    SkillEvalTask(
        name="xxe_svg_conversion_readback",
        focus="SVG upload XXE image conversion read-back rendered text XML external entity XInclude",
        expected_cards=(CARD.format("xxe-xml-parser.md"), CARD.format("upload-parser.md")),
        forbidden_cards=(),
        seed_groups=(("SVG/Office/XML",), ("read-back",), ("上传请求", "转换")),
    ),
    SkillEvalTask(
        name="cors_origin_without_auth_idor_noise",
        focus="CORS trusted origin null origin credentialed read Access-Control-Allow-Credentials",
        expected_cards=(CARD.format("browser-client-boundaries.md"),),
        forbidden_cards=(CARD.format("auth-access.md"), CARD.format("api-idor.md")),
        seed_groups=(("Origin",), ("凭据", "敏感响应")),
    ),
    SkillEvalTask(
        name="websocket_cswsh_without_authz_noise",
        focus="WebSockets cross-site websocket hijacking CSWSH origin message schema authz",
        expected_cards=(CARD.format("websocket-realtime-api.md"),),
        forbidden_cards=(
            CARD.format("auth-access.md"),
            CARD.format("api-idor.md"),
            CARD.format("browser-client-boundaries.md"),
        ),
        seed_groups=(("WebSocket", "Origin"), ("CSWSH",), ("消息 schema",)),
    ),
    SkillEvalTask(
        name="info_disclosure_stack_trace_without_race_noise",
        focus="Information disclosure source map backup file debug stack trace config leak",
        expected_cards=(CARD.format("information-disclosure-source-config.md"),),
        forbidden_cards=(CARD.format("race-conditions.md"),),
        seed_groups=(("source map",), ("配置",)),
    ),
    SkillEvalTask(
        name="race_payment_otp_redline_guidance",
        focus="race payment otp coupon checkout parallel replay state transition",
        expected_cards=(CARD.format("race-conditions.md"), CARD.format("auth-credential-recovery-flows.md")),
        forbidden_cards=(),
        seed_groups=(("低频状态模型",), ("HTTP/2 multiplex",), ("锁定/限速", "停止条件")),
    ),
]


def _naive_no_skill_cards(focus: str) -> list[str]:
    """无技能关键词基线：模拟没有四层路由/去噪/知识卡 seed 时的朴素选择。"""
    blob = focus.lower()
    cards: list[str] = []

    def add(card: str) -> None:
        if card not in cards:
            cards.append(card)

    if any(token in blob for token in ("jwt", "oauth", "oidc", "saml", "sso", "jwk", "jku", "kid")):
        add(CARD.format("auth-sso-token-edge-cases.md"))
    if any(token in blob for token in ("auth", "authz", "role", "admin", "credentialed", "cookie", "csrf")):
        add(CARD.format("auth-access.md"))
        add(CARD.format("api-idor.md"))
    if "graphql" in blob:
        add(CARD.format("graphql.md"))
    if "node" in blob or "__proto__" in blob or "prototype" in blob:
        add(CARD.format("node-prototype-pollution.md"))
    if any(token in blob for token in ("api", "hpp", "parameter pollution", "duplicate query", "parser")):
        add(CARD.format("api-testing-workflow.md"))
    if any(token in blob for token in ("mass assignment", "over-post", "price", "payment", "coupon", "checkout", "isadmin", "plan", "status")):
        add(CARD.format("business-logic-state-machines.md"))
    if any(token in blob for token in ("cache", "smuggling", "host-header", "host header", "proxy")):
        add(CARD.format("proxy-cache-boundaries.md"))
    if any(token in blob for token in ("cors", "csrf", "origin", "dom", "clickjacking", "cookie")):
        add(CARD.format("browser-client-boundaries.md"))
    if "rag" in blob or "llm" in blob:
        add(CARD.format("web-llm-tool-chains.md"))
    if any(token in blob for token in ("xxe", "xml", "xinclude", "external entity")):
        add(CARD.format("xxe-xml-parser.md"))
    if any(token in blob for token in ("upload", "svg", "office", "image conversion")):
        add(CARD.format("upload-parser.md"))
    if any(token in blob for token in ("websocket", "cswsh")):
        add(CARD.format("websocket-realtime-api.md"))
    if any(token in blob for token in ("information disclosure", "source map", "backup", "debug", "config", "leak")):
        add(CARD.format("information-disclosure-source-config.md"))
    if "race" in blob:
        add(CARD.format("race-conditions.md"))
    if any(token in blob for token in ("otp", "password reset", "account recovery")):
        add(CARD.format("auth-credential-recovery-flows.md"))
    return cards


def _contains_group(lines: list[str], group: tuple[str, ...]) -> bool:
    joined = "\n".join(lines).lower()
    return all(fragment.lower() in joined for fragment in group)


def _score(task: SkillEvalTask, *, cards: list[str], seeds: list[str], checks: list[str], skill: str) -> tuple[int, int]:
    score = 0
    max_score = 1 + len(task.expected_cards) + len(task.forbidden_cards) + len(task.seed_groups) + len(task.expected_checks)
    score += int(skill == task.expected_skill)
    score += sum(card in cards for card in task.expected_cards)
    score += sum(card not in cards for card in task.forbidden_cards)
    score += sum(_contains_group(seeds, group) for group in task.seed_groups)
    score += sum(check in checks for check in task.expected_checks)
    return score, max_score


def _run_with_skills(task: SkillEvalTask) -> tuple[str, int, int]:
    pack = build_context_pack(REPO_ROOT, target="eval.test", focus=task.focus)
    cards = list(pack["knowledge_cards"])
    seeds = list(pack["hypothesis_seeds"])
    checks = list(pack["required_checks"])
    score, max_score = _score(
        task,
        cards=cards,
        seeds=seeds,
        checks=checks,
        skill=str(pack["selected_skill_id"]),
    )
    assert task.expected_skill == pack["selected_skill_id"]
    assert not [card for card in task.expected_cards if card not in cards]
    assert not [card for card in task.forbidden_cards if card in cards]
    assert not [group for group in task.seed_groups if not _contains_group(seeds, group)]
    assert not [check for check in task.expected_checks if check not in checks]
    return task.name, score, max_score


def _run_without_skills_baseline(task: SkillEvalTask) -> tuple[str, int, int]:
    cards = _naive_no_skill_cards(task.focus)
    score, max_score = _score(
        task,
        cards=cards,
        seeds=["Generic baseline: send one baseline request and compare one changed input."],
        checks=[],
        skill="none",
    )
    return task.name, score, max_score


def test_project_skills_pass_skill_creator_quick_validate():
    failures = []
    for skill_md in sorted((REPO_ROOT / "skills").glob("*/SKILL.md")):
        result = subprocess.run(
            ["python3", str(SKILL_VALIDATOR), str(skill_md.parent)],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            failures.append(f"{skill_md.parent.relative_to(REPO_ROOT)}: {result.stdout or result.stderr}")
    assert not failures


def test_context_pack_skills_outperform_no_skill_keyword_baseline():
    """并发执行多个任务，证明技能层带来路由、去噪和证据门槛提升。"""
    with_results: dict[str, tuple[int, int]] = {}
    baseline_results: dict[str, tuple[int, int]] = {}

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(_run_with_skills, task) for task in EVAL_TASKS]
        for future in as_completed(futures):
            name, score, max_score = future.result()
            with_results[name] = (score, max_score)

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(_run_without_skills_baseline, task) for task in EVAL_TASKS]
        for future in as_completed(futures):
            name, score, max_score = future.result()
            baseline_results[name] = (score, max_score)

    with_score = sum(score for score, _ in with_results.values())
    with_max = sum(max_score for _, max_score in with_results.values())
    baseline_score = sum(score for score, _ in baseline_results.values())
    baseline_max = sum(max_score for _, max_score in baseline_results.values())

    assert with_max == baseline_max
    assert with_score == with_max
    assert baseline_score < with_score * 0.5
