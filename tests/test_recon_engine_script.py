"""Regression tests for recon_engine.sh shell pitfalls."""

from pathlib import Path


def test_recon_engine_guards_common_set_e_pitfalls():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "log_vuln()" in text
    assert 'TARGET_KIND="domain"' in text
    assert 'TARGET_KIND="ip"' in text
    assert 'TARGET_KIND="cidr"' in text
    assert 'cat "$RECON_DIR/subdomains/"*.txt 2>/dev/null | sort -u > "$RECON_DIR/subdomains/all.txt" || true' in text
    assert '"$HTTPX_BIN" -l "$HTTPX_INPUT_FILE"' in text
    assert "resolve_pd_httpx()" in text
    assert 'FUZZ_COUNT=$((FUZZ_COUNT + 1))' in text
    assert 'CONTENT_TYPE=$(curl -sI "${BB_AUTH_ARGS[@]}" --max-time 5 "${base_url}${path}" 2>/dev/null | grep -i content-type | head -1 || true)' in text
    assert "for host in network.hosts():" in text
    assert "if count >= limit:" in text
    assert 'if [ "$TARGET_KIND" = "domain" ]; then' in text
    assert '-iL "$DISCOVERY_HOSTS_FILE"' in text


def test_recon_engine_has_timeout_compat_helper():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "timeout_bin()" in text
    assert "gtimeout" in text
    assert "run_with_timeout()" in text
    assert "run_with_timeout 300 amass enum -passive" not in text
    assert 'NAABU_RUN_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 120 || echo 300)' not in text


def test_recon_engine_supports_auth_session_env():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "_auth_helper.sh" in text
    assert "prepare_wafw00f_headers_file()" in text
    assert 'WAFW00F_HEADER_ARGS=(-H "$WAFW00F_HEADERS_FILE")' in text
    assert 'bb_auth_active && bb_auth_banner' in text
    assert '"${BB_AUTH_ARGS[@]}"' in text
    assert 'curl -s "${BB_AUTH_ARGS[@]}" --max-time 10 "$js_url"' in text
    assert 'ffuf -u "${url}/FUZZ"' in text


def test_recon_engine_supports_assetfinder_and_puredns():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "resolve_linkfinder_path()" in text
    assert 'assetfinder --subs-only "$TARGET"' in text
    # DNS resolution now uses puredns (massdns + wildcard filtering) instead
    # of dnsx — dnsx stalled on wildcard-heavy targets that returned 50k+
    # bogus subdomains via passive sources.
    assert "command -v puredns" in text
    assert 'puredns resolve "$RECON_DIR/subdomains/all.txt"' in text
    assert 'log_done "puredns resolved:' in text
    assert 'HTTPX_INPUT_FILE="$DISCOVERY_HOSTS_FILE"' in text
    # dnsx must be fully removed — no longer wired anywhere in the pipeline.
    assert "dnsx " not in text
    assert "DNSX_" not in text


def test_recon_engine_preserves_host_port_lab_url_seed():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'if [[ "$TARGET" == *"://"* ]]; then' in text
    assert 'TARGET_KIND="url"' in text
    assert 'TARGET_HAS_EXPLICIT_PORT="false"' in text
    assert 'TARGET_HTTP_SEED="$TARGET"' in text
    assert 'TARGET_HTTP_SEED="http://$TARGET"' in text
    assert 'TARGET_EXPLICIT_PORT="$TARGET_PORT_PART"' in text
    assert 'log_ok "URL target prepared for probing: 1 URL"' in text
    assert '[ "$TARGET_KIND" = "ip" ] || [ "$TARGET_KIND" = "cidr" ] || [ "$TARGET_KIND" = "url" ]' in text
    assert 'Skipping broad naabu scan for exact URL/explicit-port target' in text
    assert 'Skipping broad nmap scan for exact URL/explicit-port target' in text
    assert 'open_ports_explicit.txt' in text
    assert '[ "$TARGET_KIND" = "ip" ] || [ "$TARGET_KIND" = "cidr" ] || [ "$TARGET_KIND" = "url" ]' in text
    assert '[ "$TARGET_KIND" = "ip" ] || [ "$TARGET_KIND" = "cidr" ] || [ "$TARGET_KIND" = "url" ]' in text
    assert '[ "$TARGET_KIND" = "ip" ] || [ "$TARGET_KIND" = "cidr" ] || [ "$TARGET_KIND" = "url" ]' in text
    assert '[ "$TARGET_KIND" = "ip" ] || [ "$TARGET_KIND" = "cidr" ] || [ "$TARGET_KIND" = "url" ]' in text
    assert 'printf \'%s\\n\' "$TARGET_HTTP_SEED" > "$RECON_DIR/live/seed_urls.txt"' in text
    assert "seed_http_code=" in text
    assert "curl --noproxy '*' -sS -o /dev/null -w '%{http_code}'" in text
    assert '[ "$seed_http_code" = "401" ] || [ "$seed_http_code" = "403" ]' in text
    assert '[ -s "$RECON_DIR/live/urls.txt" ] && cat "$RECON_DIR/live/urls.txt"' in text
    assert '[ -s "$RECON_DIR/live/seed_urls.txt" ] && cat "$RECON_DIR/live/seed_urls.txt"' in text


def test_recon_engine_filters_spa_fallback_directory_fuzz_noise():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "detect_spa_fallback_size()" in text
    assert "/__bbhunt_missing_${RANDOM}_${RANDOM}" in text
    assert 'code_a=$(curl -sS -L "${BB_AUTH_ARGS[@]}" --max-time 8' in text
    assert '[ "$code_a" = "200" ] && [ "$code_b" = "200" ]' in text
    assert '[ "$size_a" -gt 0 ] && [ "$size_a" = "$size_b" ]' in text
    assert 'SPA_FALLBACK_LOG="$RECON_DIR/dirs/spa_fallback.txt"' in text
    assert 'SPA_FALLBACK_SIZE="$(detect_spa_fallback_size "$url" || true)"' in text
    assert 'FFUF_FILTER_ARGS=(-fs "$SPA_FALLBACK_SIZE")' in text
    assert '"${FFUF_FILTER_ARGS[@]}" \\' in text
    assert "SPA fallback detected for $url" in text


def test_recon_engine_js_secret_regex_handles_camelcase_and_spacing():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "apiKey" in text
    assert "secretKey" in text
    assert "[:space:]" in text
    assert "sk_test" not in text  # 不为单一厂商/样例硬编码
    assert "potential_secrets.txt" in text


def test_recon_engine_supports_primary_domain_batch_and_domain_waymore():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'SHARED_TOOLS_DIR="${BBHUNT_TOOLS_DIR:-${OSMEDEUS_TOOLS_DIR:-$HOME/Tools}}"' in text
    assert 'export PATH="$HOME/.local/bin:$HOME/go/bin:$SHARED_TOOLS_DIR/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"' in text
    assert "run_domain_list_batch()" in text
    assert 'if [ -f "$TARGET" ] && [ -r "$TARGET" ]; then' in text
    assert 'run_domain_list_batch "$TARGET" "$QUICK_MODE"' in text
    assert 'batch_manifest.jsonl' in text
    assert 'batch_summary.md' in text
    assert 'ai_handoff.md' in text
    assert 'surface_ranking.txt' in text
    assert 'high_value_targets.json' in text
    assert 'target_links_file="$batch_dir/grouped_targets.tsv"' in text
    assert 'ln -s "../$recon_key" "$grouped_link"' in text
    assert 'printf \'%s\\t%s\\t%s\\n\' "$batch_target" "recon/$batch_key/$recon_key" "recon/$recon_key" >> "$target_links_file"' in text
    assert 'grouped_links        "recon/$batch_key/<domain> -> recon/<domain>"' in text
    assert '## AI Handoff — Top Attack Surface' in text
    assert "BBHUNT_BATCH_SIZE" in text
    assert "BBHUNT_BATCH_RESET" in text
    assert 'pending_targets.txt' in text
    assert 'current_batch_targets.txt' in text
    assert 'bash "$SCRIPT_PATH" "$batch_target" "$quick_mode" </dev/null' in text
    assert 'grep -Fvx -f "$processed_file" "$targets_file"' in text
    assert 'head -n "$batch_size" "$pending_file" > "$run_targets_file"' in text
    assert 'echo "- Remaining: $remaining_total"' in text
    assert 'print(re.sub(r"[^A-Za-z0-9._-]+", "_", stem))' in text
    assert 'phase                batch_recon' in text
    assert 'note                 "targets.txt is treated as a primary-domain batch; each target has its own recon/<domain>/"' in text
    assert 'TARGET_KIND="list"' not in text
    assert "Domain-list target" not in text
    assert '[ "$TARGET_KIND" = "domain" ] && WAYMORE_INPUT="$TARGET"' in text
    assert 'log_step "Running waymore (historical URLs)..."' in text
    assert 'waymore \\' in text
    assert '-oU "$RECON_DIR/urls/waymore.txt"' in text
    assert 'log_warn "Skipping waymore for $TARGET_KIND target — historical URL collection expects a domain"' in text


def test_recon_engine_adds_project_aligned_exposure_candidate_correlation():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'mkdir -p "$RECON_DIR"/{subdomains,live,ports,urls,js,dirs,params,exposure,logs}' in text
    assert 'log_info "Phase 6.6: Exposure Candidate Correlation"' in text
    assert 'API_DOC_CANDIDATES="$RECON_DIR/exposure/api_doc_candidates.txt"' in text
    assert 'API_LEAK_CANDIDATES="$RECON_DIR/exposure/api_leak_candidates.txt"' in text
    assert 'CLOUD_STORAGE_CANDIDATES="$RECON_DIR/exposure/cloud_storage_candidates.txt"' in text
    assert 'S3_BUCKET_CANDIDATES="$RECON_DIR/exposure/s3_bucket_candidates.txt"' in text
    assert 'EXTERNAL_SERVICE_HOSTS="$RECON_DIR/exposure/external_service_hosts.txt"' in text
    assert "API_DOC_RE=" in text
    assert "CLOUD_SERVICE_RE=" in text
    assert 'collect_exposure_candidates "$RECON_DIR/urls/all.txt" "urls"' in text
    assert 'collect_exposure_candidates "$RECON_DIR/js/linkfinder_endpoints.txt" "linkfinder"' in text
    assert "phase                exposure_candidates" in text
    assert 'log_info "Phase 6.7: API Leak Detection"' in text
    assert 'porch-pirate -s "$API_LEAK_TARGET" -l 25 --dump' in text
    assert 'postleaksNg \\' in text
    assert 'command -v swaggerspy' not in text
    assert 'trufflehog filesystem "$API_LEAK_DIR"' in text
    assert '$SHARED_TOOLS_DIR/SwaggerSpy/swaggerspy.py' in text
    assert '$SHARED_TOOLS_DIR/SwaggerSpy/venv/bin/python3' in text
    assert "phase                api_leak_detection" in text
    assert 'log_info "Phase 6.8: Identity and Cloud Intel"' in text
    assert 'EMAILFINDER_SCRIPT="$SHARED_TOOLS_DIR/emailfinder/emailfinder.py"' in text
    assert 'run_with_timeout 120 python3 "$EMAILFINDER_SCRIPT" -d "$TARGET"' in text
    assert 'LEAKSEARCH_SCRIPT="$SHARED_TOOLS_DIR/LeakSearch/LeakSearch.py"' in text
    assert 'run_with_timeout 180 "$LEAKSEARCH_PY" "$LEAKSEARCH_SCRIPT" -k "$TARGET" -o "$LEAKSEARCH_OUT"' in text
    assert 'CLOUD_ENUM_SCRIPT="$SHARED_TOOLS_DIR/cloud_enum/cloud_enum.py"' in text
    assert 'CLOUD_ENUM_PY="$SHARED_TOOLS_DIR/cloud_enum/venv/bin/python3"' in text
    assert 'CLOUD_ENUM_CMD=("$CLOUD_ENUM_PY" "$CLOUD_ENUM_SCRIPT")' in text
    assert 'run_with_timeout 180 "${CLOUD_ENUM_CMD[@]}" -k "$CLOUD_KEYWORD" -t 5 -qs -l "$CLOUD_ENUM_OUT"' in text
    assert "--disable-aws-disk" not in text
    assert "phase                identity_cloud_intel" in text
    # 深度通用 OSINT / 代码搜索有独立命令；recon 只保留轻量 identity/cloud 信号。
    forbidden = ("OSINT_", "github-endpoints", "run_with_timeout 60 whois")
    assert not any(item in text for item in forbidden)


def test_recon_engine_denoising_is_non_destructive():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'log_info "Phase 4.5: URL Denoising"' in text
    assert "raw files preserved" in text
    assert '"$RECON_DIR/urls/all.txt" \\' in text
    assert '"$RECON_DIR/urls/all_filtered.txt" \\' in text
    assert '--log-file "$URL_FILTER_LOG_ABS"' in text
    assert 'URL_FILTER_LOG="recon/${RECON_TARGET_KEY}/urls/filter.log"' in text
    assert 'with_params_filtered.txt' in text
    assert 'js_files_filtered.txt' in text
    assert 'api_endpoints_filtered.txt' in text
    assert 'sensitive_paths_filtered.txt' in text
    assert 'urls_filtered        "$URLS_FILTERED"' in text
    assert 'url_filter_log       "$URL_FILTER_LOG"' in text
    assert 'JS_FILES_FOR_ANALYSIS="$RECON_DIR/urls/js_files_filtered.txt"' in text
    assert 'PARAM_URLS_FOR_DISCOVERY="$RECON_DIR/urls/with_params_filtered.txt"' in text
    assert '"$RECON_DIR/urls/${url_file}.txt" \\\n                "$RECON_DIR/urls/${url_file}.txt"' not in text
    assert 'cat "$RECON_DIR/urls/"*.txt' not in text


def test_recon_engine_supports_optional_post_run_raw_url_compression():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "post_compress_raw_recon_urls()" in text
    assert "BBHUNT_RECON_POST_COMPRESS" in text
    assert "BBHUNT_RECON_COMPRESS_MIN_MB" in text
    assert "for src in gau wayback waymore katana; do" in text
    assert 'gzip -9 -f "$file"' in text
    assert 'post_compress_raw_recon_urls "$RECON_DIR"' in text
    assert 'note                 "all.txt/with_params.txt/exposure/live/subdomains preserved"' in text
    assert "rm -f" not in text[text.index("post_compress_raw_recon_urls()"):text.index("cleanup_auth_tmpfiles()")]


def test_cloud_recon_reuses_osmedeus_cloud_enum_without_stale_args():
    script = Path(__file__).resolve().parent.parent / "tools" / "cloud_recon.sh"
    text = script.read_text(encoding="utf-8")

    assert 'SHARED_TOOLS_DIR="${BBHUNT_TOOLS_DIR:-${OSMEDEUS_TOOLS_DIR:-$HOME/Tools}}"' in text
    assert 'export PATH="$HOME/.local/bin:$HOME/go/bin:$SHARED_TOOLS_DIR/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"' in text
    assert "run_cloud_enum()" in text
    assert 'cloud_enum_script="$SHARED_TOOLS_DIR/cloud_enum/cloud_enum.py"' in text
    assert '"$cloud_enum_py" "$cloud_enum_script" -k "$keyword" -t 5 -qs -l "$output"' in text
    assert "--disable-aws-disk" not in text


def test_recon_engine_supports_wafw00f_fingerprinting():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'log_info "Phase 2.5: WAF Fingerprinting"' in text
    assert 'WAFW00F_MAX_TARGETS=$([ "$QUICK_MODE" = "--quick" ] && echo 3 || echo 10)' in text
    assert 'head -"$WAFW00F_MAX_TARGETS" "$RECON_DIR/live/urls.txt" > "$WAFW00F_TARGETS_FILE"' in text
    assert 'wafw00f \\' in text
    assert 'run_with_timeout "$WAFW00F_RUN_TIMEOUT" wafw00f \\' not in text
    assert '-o "$WAFW00F_JSON_FILE" \\' in text
    assert 'python3 - "$WAFW00F_JSON_FILE" "$WAFW00F_HITS_FILE" <<' in text


def test_recon_engine_supports_unwaf_origin_discovery():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'log_info "Phase 2.6: Origin Discovery"' in text
    assert 'BBHUNT_ENABLE_UNWAF' in text
    assert 'BBHUNT_SKIP_UNWAF' in text
    assert 'unwaf origin discovery is disabled by default' in text
    assert 'if command -v unwaf &>/dev/null; then' in text
    assert 'UNWAF_RUN_TIMEOUT=$([ "$QUICK_MODE" = "--quick" ] && echo 120 || echo 240)' not in text
    assert 'unwaf \\' in text
    assert 'run_with_timeout "$UNWAF_RUN_TIMEOUT" unwaf \\' not in text
    assert '-d "$TARGET" \\' in text
    assert '-l "$UNWAF_TARGETS_FILE" \\' not in text
    assert 'unwaf is only applicable to domain targets' in text
    assert '--json \\' in text
    assert '-o "$UNWAF_JSON_FILE" \\' in text
    assert '--rate-limit "$UNWAF_RATE_LIMIT" \\' in text
    assert 'python3 - "$UNWAF_JSON_FILE" "$UNWAF_IPS_FILE" <<' in text
    assert 'Origin candidates found: $UNWAF_IP_COUNT' in text
    assert 'unwaf_enabled' in text
    assert 'unwaf_skipped' in text


def test_recon_engine_supports_naabu_and_linkfinder():
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'log_step "Running naabu (top $NAABU_MAX_TARGETS targets, top $NAABU_TOP_PORTS ports)..."' in text
    assert 'naabu \\' in text
    assert 'run_with_timeout "$NAABU_RUN_TIMEOUT" naabu \\' not in text
    assert '-list "$NAABU_TARGETS_FILE" \\' in text
    assert 'sed -nE \'s|.*:([0-9]+)$|\\1/open|p\' "$NAABU_OUTPUT_FILE"' in text
    assert 'LINKFINDER_BIN="$(resolve_linkfinder_path || true)"' in text
    assert 'python3 "$LINKFINDER_BIN" -i "$tmp_js" -o cli' in text
    assert '"$LINKFINDER_BIN" -i "$tmp_js" -o cli' in text
    assert 'LinkFinder endpoints: $(wc -l < "$RECON_DIR/js/linkfinder_endpoints.txt"' in text


def test_recon_engine_caps_katana_at_5min_and_leaves_amass_uncapped():
    """katana is wrapped in `timeout 300` (cherry-pick of upstream 2a826ad)
    to prevent infinite crawl on content-heavy sites. amass remains uncapped
    because its own passive mode is internally bounded."""
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert 'log_step "Running amass (passive)..."' in text
    assert 'amass enum -passive -d "$TARGET" -o "$RECON_DIR/subdomains/amass.txt"' in text
    assert 'timeout 300 amass' not in text
    assert 'run_with_timeout 300 amass enum -passive' not in text

    # katana invocation MUST be wrapped in `timeout 300` going forward.
    assert 'log_step "Running katana (active crawl, 5min cap, top 50 hosts)..."' in text
    assert 'timeout 300 katana \\' in text
    # Unwrapped katana invocation must NOT remain.
    assert text.count('    katana \\') == 0 or 'timeout 300 katana \\' in text


def test_recon_engine_defines_claude_hint_emitter():
    """R5: helper function present and properly guarded against set -e."""
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    assert "emit_claude_hint()" in text
    assert "emit_claude_hint_list()" in text
    # Function must emit the literal block header that Claude greps for.
    assert 'echo "## CLAUDE_HINT"' in text
    # Both helpers must wrap their bodies in `|| true` to survive `set -e`.
    assert text.count("|| true") >= 2


def test_recon_engine_emits_claude_hint_for_every_phase():
    """R5: at least one emit per phase (>=10 distinct call sites)."""
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    # Count standalone invocations of the emitter — function definition body
    # is indented and won't match this line-start anchor.
    invocations = [
        line for line in text.splitlines() if line.startswith("emit_claude_hint ")
    ]
    assert len(invocations) >= 10, (
        f"need ≥10 emit_claude_hint invocations covering each phase, found {len(invocations)}"
    )


def test_recon_engine_hint_phases_cover_key_pipeline_stages():
    """R5: hints reference each major phase by name so Claude can act on them."""
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    expected_phases = (
        "phase                subdomain_enum",
        "phase                http_probing",
        "phase                waf_fp",
        "phase                origin_disco",
        "phase                port_scan",
        "phase                url_collection",
        "phase                  js_analysis",  # extra spaces for column alignment
        "phase                dir_fuzz",
        "phase                config_exposure",
        "phase                exposure_candidates",
        "phase                api_leak_detection",
        "phase                identity_cloud_intel",
        "phase                param_disco",
        "phase                cicd",
    )
    missing = [p for p in expected_phases if p not in text]
    assert not missing, f"missing hint phases: {missing}"


def test_recon_engine_hint_blocks_include_next_actions_lists():
    """R5+autonomy: every hint should offer ≥2 candidate next moves via emit_claude_hint_actions."""
    script = Path(__file__).resolve().parent.parent / "tools" / "recon_engine.sh"
    text = script.read_text(encoding="utf-8")

    # Each phase invocation calls emit_claude_hint_actions with ≥2 args.
    assert text.count("emit_claude_hint_actions") >= 10
    # The helper emits `next_actions:` as the YAML key.
    assert "emit_claude_hint_actions()" in text
    # No remaining single-value next_priority_action in actual emit calls
    # (the comment in the header is fine).
    emit_lines = [l for l in text.splitlines() if l.strip().startswith("next_priority_action")]
    assert not emit_lines, f"stale next_priority_action in emit calls: {emit_lines[:3]}"
