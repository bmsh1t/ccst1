#!/usr/bin/env python3
"""Marker-replay lane (archived 2026-09-12: zero routing in practice).

RCE/SSTI inert-marker 证明从未被任何目标路由到（evidence/ 零 marker run）。
marker 是否出现是单请求可观察的事实——Claude 用 probe + ledger 落账即可走完，
不需要 pair 原语。validation_runner 只保留 request-diff 一个 lane；需要时从
此处恢复函数体 + CLI 子命令 + main 分发三块即可。
"""

from __future__ import annotations


def run_marker_replay(
    *,
    repo_root: Path,
    target: str,
    url: str,
    expect_marker: str,
    baseline_url: str = "",
    baseline_body: str | None = None,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: int = 10,
    finding_id: str = "",
    repeat: int = 1,
    vuln_class: str = "RCE",
    no_ledger: bool = False,
    browser_observed: bool = False,
    state_changing: bool | None = None,
    redline_checked: bool = False,
    identity_v2: dict[str, Any] | None = None,
    session: AuthSession | None = None,
) -> dict[str, Any]:
    """Replay an exact request and require an inert marker in every response.

    This lane deliberately does not generate payloads. Claude/operator chooses
    the hypothesis and exact safe marker request; an optional neutral baseline
    proves the marker is not naturally present. The runner handles stable replay,
    evidence artifacts, rubric, and ledger output.
    """
    marker = str(expect_marker or "")
    if not marker:
        raise ValueError("expect_marker is required")
    baseline_url = str(baseline_url or "").strip()
    if baseline_url and not url_belongs_to_target(baseline_url, target):
        raise ValueError("marker baseline URL is off-target")
    marker_bytes = marker.encode("utf-8", errors="replace")
    marker_quality = {
        "byte_length": len(marker_bytes),
        "distinct_characters": len(set(marker)),
        "sufficient": len(marker_bytes) >= 8 and len(set(marker)) >= 4,
    }
    state_changing = _validate_request_facts(state_changing, redline_checked)
    finding_id = finding_id or _default_finding_id("marker-replay", url)
    bundle = _bundle_dir(repo_root, target, finding_id)
    private_bundle = _private_bundle_dir(repo_root, target, bundle)
    write_private_json(private_bundle / "inputs.json", {"url": url, "expect_marker": marker})
    repeat = max(1, int(repeat or 1))
    method_u = method.upper()
    runs: list[dict[str, Any]] = []

    for idx in range(1, repeat + 1):
        baseline_response = None
        baseline_artifacts = None
        if baseline_url:
            baseline_response = request_once(
                target=target,
                url=baseline_url,
                method=method_u,
                headers=headers,
                body=body if baseline_body is None else baseline_body,
                timeout=timeout,
                session=session,
            )
            prefix = "" if repeat == 1 else f"{idx}."
            baseline_artifacts = _write_raw_http(
                private_bundle,
                f"{prefix}baseline.",
                baseline_response,
                repo_root,
            )
        response = request_once(
            target=target,
            url=url,
            method=method_u,
            headers=headers,
            body=body,
            timeout=timeout,
            session=session,
        )
        prefix = "" if repeat == 1 else f"{idx}."
        raw_artifacts = _write_raw_http(
            private_bundle,
            f"{prefix}variant." if baseline_url else prefix,
            response,
            repo_root,
        )
        # The target-response body is the only marker oracle; transport diagnostics
        # such as stderr are never evidence of target behavior.
        marker_found = marker in response["body"]
        run = {
            "iteration": idx,
            "url": public_url_shape(url),
            "method": method_u,
            "status": response["status"],
            "marker_found": marker_found,
            "marker_occurrences": response["body"].count(marker),
            "artifacts": {
                "request": raw_artifacts["request"],
                "response": raw_artifacts["response"],
                "identity": raw_artifacts["identity"],
            },
            "snapshot": _response_snapshot(response),
        }
        if baseline_response is not None and baseline_artifacts is not None:
            run["baseline_marker_found"] = marker in baseline_response["body"]
            run["baseline_marker_occurrences"] = baseline_response["body"].count(marker)
            run["baseline_status"] = baseline_response["status"]
            run["baseline_body_truncated"] = bool(baseline_response.get("body_truncated"))
            run["baseline_artifacts"] = {
                "request": baseline_artifacts["request"],
                "response": baseline_artifacts["response"],
                "identity": baseline_artifacts["identity"],
            }
            run["baseline_snapshot"] = _response_snapshot(baseline_response)
        runs.append(run)

    marker_present = all(bool(run["marker_found"]) for run in runs)
    baseline_valid = (
        all(
            200 <= int(run.get("baseline_status", 0) or 0) < 400
            and not bool(run.get("baseline_body_truncated"))
            for run in runs
        )
        if baseline_url
        else None
    )
    baseline_absent = (
        all(not bool(run.get("baseline_marker_found")) for run in runs)
        if baseline_url and baseline_valid
        else None
    )
    marker_oracle_passed = bool(
        baseline_url
        and baseline_valid
        and baseline_absent
        and marker_quality["sufficient"]
        and marker_present
    ) if baseline_url else None
    oracle_status = (
        "passed" if marker_oracle_passed
        else "not_requested" if not baseline_url
        else "invalid_control" if not baseline_valid
        else "rejected"
    )
    candidate_ready = marker_present if not baseline_url else marker_oracle_passed
    result = (
        "tested_finding"
        if candidate_ready
        else "candidate"
        if baseline_url and (baseline_valid is False or marker_present)
        else "tested_clean"
    )
    finding = {
        "type": vuln_class,
        "url": public_url_shape(url),
        "summary": (
            f"exact marker replay for {vuln_class}; marker_present={candidate_ready}; "
            f"repeat={repeat}; method={method_u}"
        ),
        "raw": (
            "rce-poc controlled marker exact request safe proof repeated"
            if candidate_ready
        else "baseline control was invalid"
            if baseline_url and baseline_valid is False
        else "marker observed but baseline/marker oracle was not proven"
            if baseline_url and marker_present
            else "exact marker replay did not show expected inert marker"
        ),
        "confidence": "high" if candidate_ready else "medium",
    }
    rubric = compact_evidence_rubric(evaluate_candidate_evidence(finding, vuln_type=vuln_class))
    # The oracle (baseline_valid + baseline_absent + marker quality + repeats) is
    # the single promotion authority; the rubric stays advisory-only here so the
    # ledger row can never disagree with the runner result the witness compares.
    ledger_result = result
    summary_path = bundle / "summary.json"
    # Keep the ledger evidence_ref bound to an artifact inside the bundle's own
    # bindings, mirroring request-diff/idor lanes: the witness requires the
    # ledger row's evidence_ref to appear in the runner artifact_bindings, and a
    # self-referencing summary.json can never satisfy that.
    # The ledger evidence_ref must resolve into the bundle's own artifact
    # bindings (the witness requires it); the first replayed response is
    # already bound as the "response" artifact, so point at it directly
    # instead of adding a duplicate kind that desyncs the operation id.
    first_response = runs[0].get("artifacts", {}).get("response", "") if runs else ""
    marker_replay_evidence = {"runs": runs}
    evidence_ref = str(first_response or _rel(summary_path, repo_root))
    notes = (
        f"Validation runner marker-replay for {vuln_class}: "
        f"marker_present={marker_present}, oracle={oracle_status}, "
        f"repeat={repeat}, method={method_u}."
    )
    ledger = _record_ledger_if_needed(
        repo_root=repo_root,
        no_ledger=no_ledger,
        target=target,
        endpoint=url,
        method=method_u,
        vuln_class=vuln_class,
        actor="anonymous",
        object_scope="none",
        variant="replay",
        result=ledger_result,
        source="validation-runner:marker-replay",
        evidence_ref=evidence_ref,
        notes=notes,
        browser_observed=browser_observed,
        redline_checked=redline_checked,
        state_changing=state_changing,
        identity_v2=identity_v2,
        artifact_bindings=_artifact_bindings(marker_replay_evidence, repo_root),
        operation_material={
            "target": canonical_target_value(target),
            "lane": "marker_replay",
            "finding_id": finding_id,
            "url": public_url_shape(url),
            "method": method_u,
            "vuln_class": vuln_class,
            "expect_marker_sha256": hashlib.sha256(marker.encode("utf-8", errors="replace")).hexdigest(),
            "baseline_url": public_url_shape(baseline_url) if baseline_url else "",
            "repeat": repeat,
            "evidence_shape": "marker_replay",
        },
        finding_id=finding_id,
    )
    xss_marker = str(vuln_class or "").strip().lower() in {
        "xss",
        "cross-site-scripting",
    }
    ai_next = {
        "hypothesis": "exact request causes server-side evaluation/execution observable through an inert marker",
        "next_action": "If marker is stable, use /validate to assess execution context and bounded impact; if absent, refine the hypothesis or downgrade.",
        "stop_condition": "Expected inert marker is absent, unstable across repeats, or only appears in client-side/static reflection without execution context.",
    }
    if xss_marker:
        ai_next = {
            "hypothesis": "the supplied input is reflected in a target-owned HTML response",
            "next_action": "Capture the exact browser execution context and encoding boundary; keep plain or safely encoded reflection as a signal, not an XSS finding.",
            "stop_condition": "The marker is absent, unstable, safely encoded, or has no executable browser context.",
        }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "lane": "marker_replay",
        "target": canonical_target_value(target),
        "finding_id": finding_id,
        "url": public_url_shape(url),
        "method": method_u,
        "vuln_class": vuln_class,
        "generated_at": now_utc(),
        "result": result,
        "candidate_ready": candidate_ready,
        "marker_oracle": {
            "status": oracle_status,
            "baseline_url": public_url_shape(baseline_url) if baseline_url else "",
            "baseline_valid": baseline_valid,
            "baseline_absent": baseline_absent,
            "marker_quality": marker_quality,
        },
        "expect_marker_length": len(marker.encode("utf-8", errors="replace")),
        "expect_marker_sha256": hashlib.sha256(marker.encode("utf-8", errors="replace")).hexdigest(),
        "state_changing": state_changing,
        "redline_checked": redline_checked,
        "repeat": repeat,
        "runs": runs,
        "evidence_rubric": rubric,
        "ledger_record": ledger,
        "ai_next": ai_next,
    }
    return _finalize_runner_summary(summary, summary_path, repo_root)
