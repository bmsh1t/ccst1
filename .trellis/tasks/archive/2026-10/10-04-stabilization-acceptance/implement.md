# 集中验收执行计划

## 门禁与顺序

- [x] 恢复到 `a31535d`，F06–F11 前置修复已收尾；主线程已完整阅读父任务与 F01/F02 原始规划。
- [x] 补齐 F01–F05 研究，保留 F06–F11 / 历史任务研究；不新增测试或产品代码。
- [x] PRD/design/implement、context、命令静态检查和独立计划复核完成。
- [x] 最终计划获用户后续明确批准（2026-10-08 回复“继续”）；已激活现有任务。
- [x] 激活现有任务；六组首次执行通过，421 个唯一 testcase，无失败/错误/跳过。
- [x] 写入 `acceptance.md`，主线程核对原始结果及 F01/F02 原始 AC；收尾批次获用户“继续”确认。
- [ ] 获确认后提交记录、归档核实任务、记录 journal；不推送。

## 已批准后使用的唯一命令清单

从原仓库根目录用 Bash 执行下面整块。执行前只允许任务规划记录变更；若 HEAD 或 tracked
产品/测试变更，停止重新核对。它只创建临时副本/测试数据，不安装依赖或同步 runtime。

```bash
set -euo pipefail
umask 077
SOURCE="$PWD"
BASE="$(git -c safe.directory="$SOURCE" rev-parse 'a31535d^{commit}')"
test "$(git -c safe.directory="$SOURCE" rev-parse HEAD)" = "$BASE"
git -c safe.directory="$SOURCE" diff --quiet HEAD
RUN="$(mktemp -d /tmp/ccst-acceptance.XXXXXX)"
printf 'RUN=%s\nBASE=%s\n' "$RUN" "$BASE"
git -c safe.directory="$SOURCE" archive --format=tar --output="$RUN/source.tar" "$BASE"
sha256sum "$RUN/source.tar" > "$RUN/source.sha256"
mkdir "$RUN/repo"
tar -xf "$RUN/source.tar" -C "$RUN/repo"
cd "$RUN/repo"
env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -c \
  'import sys, importlib.metadata as m; print(sys.version); print({k: m.version(k) for k in ("pytest", "requests", "PyYAML", "certifi")})' \
  > "$RUN/environment.txt"

run_group() {
  local name="$1" limit="$2"
  shift 2
  local dir="$RUN/$name" rc
  mkdir -p "$dir/home" "$dir/temp" "$dir/memory"
  local -a command=(env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8
    HOME="$dir/home" TMPDIR="$dir/temp" HUNT_MEMORY_DIR="$dir/memory"
    NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
    PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
    /usr/bin/timeout --signal=TERM --kill-after=10s "${limit}s"
    /usr/bin/python3 -m pytest -q -ra --durations=10
    -o faulthandler_timeout=45 -p no:cacheprovider
    --basetemp="$dir/pytest-tmp" --junitxml="$dir/junit.xml" "$@")
  printf '%q ' "${command[@]}" > "$dir/command.txt"
  printf '\n' >> "$dir/command.txt"
  date -u +%FT%TZ > "$dir/started.txt"
  if "${command[@]}" > "$dir/pytest.log" 2>&1; then rc=0; else rc=$?; fi
  printf '%s\n' "$rc" > "$dir/exit-code.txt"
  date -u +%FT%TZ > "$dir/finished.txt"
  cat "$dir/pytest.log"
  if (( rc != 0 )); then return "$rc"; fi
  env -i PATH=/usr/bin:/bin /usr/bin/python3 -I - "$dir/junit.xml" > "$dir/result.json" <<'PY'
import json
import sys
import xml.etree.ElementTree as ET
suites = list(ET.parse(sys.argv[1]).getroot().iter("testsuite"))
counts = {key: sum(int(s.get(key, "0")) for s in suites)
          for key in ("tests", "failures", "errors", "skipped")}
counts["seconds"] = sum(float(s.get("time", "0")) for s in suites)
print(json.dumps(counts, sort_keys=True))
assert counts["tests"] > 0 and not any(counts[k] for k in ("failures", "errors", "skipped")), counts
PY
  cat "$dir/result.json"
}

# A: F01, including self-owned loopback redirect compatibility.
run_group A-auth 60 \
  tests/test_auth_session.py \
  tests/test_validation_runner.py::test_cli_auth_file_builds_session_and_raw_header_keeps_precedence \
  tests/test_validation_runner.py::test_redirect_handler_rejects_off_target_redirect \
  tests/test_validation_runner.py::test_cross_origin_redirect_replays_only_explicitly_authorized_session_headers

# B: F02, retaining time for the process/reaper cleanup matrix.
run_group B-locks 120 \
  tests/test_runtime_phase_execution.py \
  tests/test_runtime_state.py::test_runtime_phase_lock_remains_held_by_inheriting_child \
  tests/test_runtime_state.py::test_direct_phase_runner_marks_child_lock_ownership \
  tests/test_runtime_state.py::test_direct_phase_runner_finalizes_interrupted_runner

# C: F03-F05 and their existing compatibility boundaries.
run_group C-store-evidence 60 \
  tests/test_validation_runner.py::test_partial_variant_subject_registration_recovers_claim \
  tests/test_validation_runner.py::test_primary_request_claim_survives_partial_registration_and_retry \
  tests/test_validation_runner.py::test_primary_runner_rejects_invalid_claim_before_side_effects \
  tests/test_validation_runner.py::test_declared_variant_subject_anchors_finding_and_action_to_tested_side \
  tests/test_validation_runner.py::test_declared_variant_subject_refuses_action_bound_to_baseline_side \
  tests/test_validation_runner.py::test_runner_registration_refuses_changed_material_before_any_operation \
  tests/test_validation_runner.py::test_record_evidence_claim_stays_open_until_explicit_completion \
  tests/test_target_store.py::test_bound_execution_observation_admission \
  tests/test_target_store.py::test_partial_recovery_requires_all_attempts_registered \
  tests/test_target_store.py::test_unknown_external_effect_can_be_supplemented_without_reexecution \
  tests/test_target_store.py::test_partial_and_foreign_evidence_never_confirms \
  tests/test_target_store.py::test_execution_completion_rejects_unbound_stale_and_damaged_evidence \
  tests/test_target_store.py::test_execution_completion_rechecks_artifact_authorization \
  tests/test_target_store.py::test_execution_completion_verifies_operation_before_write_transaction \
  tests/test_target_store.py::test_execution_completion_ignores_unrelated_store_writes \
  tests/test_target_store.py::test_completion_proof_and_audit_roll_back_together \
  tests/test_target_store.py::test_claims_are_compare_and_swap_and_concurrent_registration_is_idempotent \
  tests/test_target_store.py::test_non_execution_work_records_artifact_without_fabricating_http_evidence \
  tests/test_target_store.py::test_operation_verification_checks_all_material_in_one_snapshot \
  tests/test_target_store.py::test_artifact_invalidations_are_append_only_and_authorization_is_derived \
  tests/test_evidence_ledger.py::test_actor_matrix_uses_current_authorization_without_reviving_history \
  tests/test_evidence_ledger.py::test_actor_matrix_honors_registration_succession \
  tests/test_evidence_ledger.py::test_actor_matrix_preserves_healthy_historical_identity_results \
  tests/test_evidence_ledger.py::test_actor_matrix_requires_matching_method_and_actor \
  tests/test_current_truth.py::test_truncated_store_read_is_damage_too \
  tests/test_current_truth.py::test_current_truth_checks_every_operation_on_one_snapshot_and_rechecks_next_read \
  tests/test_current_truth.py::test_ledger_summary_reuses_the_seam_result_instead_of_reading_again \
  tests/test_context_pack.py::test_context_pack_surfaces_actor_matrix_gaps \
  tests/test_checkpoint.py::test_checkpoint_surfaces_actor_matrix_gaps_without_creating_actions

# D: F06-F08, including validate-to-report publication and recovery.
run_group D-reports 60 \
  tests/test_finding_index.py tests/test_hunt_initialization.py \
  tests/test_target_store.py tests/test_validate_target_mode.py \
  -k 'report or attachment or screenshot or attach_images or delivery_event or finding_authorization or non_report'

# E: F09 receipt reader and bootstrap consumer.
run_group E-runtime 60 \
  tests/test_runtime_doctor.py tests/test_autopilot_bootstrap.py \
  -k 'receipt or runtime_read_error or compare_runtime_reports_diff_missing_and_extra or compare_runtime_ignores_unrelated_external_skills'

# F: F10 final whole-file cache coverage and F11 real documented CLI.
run_group F-cache-guidance 60 \
  tests/test_disclosed_pattern_dedup.py tests/test_target_memory_cli.py

printf 'All six groups passed without skips. Evidence: %s\n' "$RUN"
```

## 失败处理与完成证据

1. 首次失败立即保留 RUN、退出码、日志和已有 JUnit；124/137 分别记录超时/强杀，不冒充断言失败。B 异常后核对本次临时路径关联的进程并完成清理后才继续工作。
2. 先确定环境、已存在故障或本批回归；无代码/配置/环境新变化不重跑失败命令。需要产品修复则报告归属和最小范围，回到规划；不改测试迁就结果。
3. 六组成功后写 `acceptance.md`：逐 F 编号映射、命令/基线/archive hash、环境版本、每组结果/时间、日志/JUnit 摘要、已测与未测、F01/F02 原始 AC 核对、其他历史任务保留清单引用。
4. 当前依赖版本不同于 CI 锁，记录偏差但不安装；无真实部署、真实模型、长期调查或全仓能力结论。收尾前复核本轮所有 diff，检查无隐式副作用、空跑、第二套真源或范围外文件。
5. 更新 PRD/父任务已核实的 checklist；规范复核默认记录“行为契约未改，无需新规范”，只有发现必要澄清才原位更新并检查。不自动修 F04/F06 归档元数据。
6. 精确提交/归档候选：本验收记录；`10-02-auth-env-roundtrip-isolation`、`10-02-direct-phase-lock-inheritance`、`10-04-stabilization-acceptance`、`10-04-stabilization-closeout`；其他 32 项保持原样。必须在通过后获得批次确认，按工作记录→归档→journal 分开提交。
7. 归档使用现有 `task.py archive ... --skip-branch-validation --no-commit`（原任务实际在 main），先 F01/F02、再验收子任务、最后父任务。归档绑定真实工作提交、修正 task-local context 路径并 validate；仅 force-add 精确归档目录。journal 绑定本次工作记录提交，用 `add_session.py --no-commit`；不 amend/push。

## 当前状态

集中验收已通过；记录提交 `fde6342`，四项归档已执行，journal 待最后登记。

2026-10-08 规划检查：`task.py validate` 通过（implement 5 项、check 4 项）；从本文提取的
Bash 经 `bash -n` 通过；AST 检查确认六组静态选择非空、显式函数存在、无静态函数交集，
任务文本无行尾空白。未执行 pytest 或 collect-only，参数化后的实际数量以验收输出为准。
独立只读复核 `/root/acceptance_plan_review` 检查 D/E 全部静态命中路径、隔离、错误门禁和
归档顺序，无阻塞项。
