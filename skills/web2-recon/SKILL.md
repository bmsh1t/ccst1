---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration (subfinder, optional Chaos API, assetfinder), live host discovery (puredns, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), continuous monitoring (new subdomain alerts, JS change detection, GitHub commit watch). Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping.
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

## Runtime Handoff

本 Skill 只负责资产与攻击面发现；共享路由、安全边界和覆盖验收沿用
`skills/runtime-protocol.md`、`CLAUDE.md` 与现有 Rules。输出回到
`surface -> lead -> next action`，需要补漏时再按证据读取匹配知识卡：

- API / 身份边界：`knowledge/cards/api-idor.md`, `knowledge/cards/auth-access.md`
- 缺参与命名规律：`knowledge/cards/missing-parameter-discovery.md`, `knowledge/cards/path-pattern-management-exposure.md`
- URL fetch / GraphQL / 上传：`knowledge/cards/ssrf-url-fetch.md`, `knowledge/cards/graphql.md`, `knowledge/cards/upload-parser.md`
- 覆盖缺口：`knowledge/cards/coverage-prompts.md`

## COMMAND RELATIONSHIP

`/recon` is the concise slash-command entrypoint and on-disk artifact contract.
This skill is the longer playbook for running the pipeline, manual follow-up,
and prioritization after the first pass.

Profile contract: `/recon` and fresh `/autopilot` use normal Recon by default;
raw hosts/URLs/JS remain lossless, while deep JS becomes an Action Queue lane.
`recon_engine.sh TARGET` stays full for direct compatibility, and explicit
`--deep` restores the complete deep-JS path. Host/SNI and AI/LLM baseline only
creates evidence-backed candidates; Autopilot decides whether to validate them.

---

## CLAUDE CODE CLI TOOL PRIORITY

In Claude Code CLI, this skill owns bulk Web2 recon. Continue to prefer
pipelines such as `httpx`, `katana`, `gau`, `waybackurls`, `ffuf`, and
JS/parameter extraction by default.

- Use chrome-devtools MCP for deep live DevTools, Network, Console, DOM, performance,
  and runtime inspection. Use Playwright MCP for page interaction, login state,
  forms, screenshots, and multi-actor workflows.
- After a browser workflow changes context, visit only a few explicit,
  AI-selected same-target candidates in that MCP session and import useful
  artifacts through `tools/browser_mcp_import.py`.
- Do not treat any browser backend as the bulk recon engine. It should run
  after recon identifies a high-value entry point, to reproduce real frontend
  behavior and extract stateful requests.
- For lightweight API replay that does not need browser state, fall back to
  `curl` / `urllib` / local helpers. Burp/Caido proxy history is auxiliary
  replay, comparison, and traffic context.
- For local, lab, or supplied target-set runs, keep using the supplied target
  record. Tool priority only affects evidence capture.
- For local, lab, or supplied target-set runs, bulk recon stays part of the
  workflow. See the "Local / Lab / Supplied Target Shortcut" section below for
  the exact target-record and tool-list wording.

---

## SETUP (one-time)

```bash
# 1. Optional: set a Chaos API key for one additional passive source
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify all tools installed
which subfinder httpx dnsx nuclei katana waybackurls gau ffuf anew gf interactsh-client
```

---

## THE 5-MINUTE LOW-SIGNAL TRIAGE

> Use the first 5 minutes as an attention allocator, not an exclusion rule. If
> recon is low-signal, deprioritize the surface for this timebox, preserve what
> was observed, and revisit when fresh evidence appears.

**Low-signal indicators (do not discard the attack surface):**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- The bounded scanner and dedicated probes return no new high-value leads
- No forms, no authentication, no user data

Record why the surface is low-signal and what would reopen it. Reopen quickly if
browser/XHR traffic, source/JS routes, authenticated workflows, API docs,
object IDs, WebSocket/GraphQL, or business-flow evidence appears.

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: optional Chaos API collector (the integrated engine skips it without a key)
if [ -n "${CHAOS_API_KEY:-}" ]; then
  curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
    -H "Authorization: $CHAOS_API_KEY" \
    | jq -r '(.subdomains // .)[]?' >> /tmp/subs.txt
fi

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Optional targeted template pass
# The normal scanner keeps Nuclei disabled unless a component/CVE justifies it;
# use /scan-cves or the CVE lane env flag.
BBHUNT_ENABLE_NUCLEI_CVES=1 bash tools/vuln_scanner.sh "recon/$TARGET" --quick
```

### AI-selected DNS expansion

Do not make DNS permutation a default pipeline step. After passive Recon, use
the fixed lane only when current evidence shows a naming dialect or a concrete
certificate/JS/source hostname gap:

```bash
python3 tools/dns_expand.py --target "$TARGET" \
  --reason "observed dev/stage and numbered API host naming"
```

AI chooses whether to run and may supply one reviewed `--wordlist`; the tool
owns bounded `alterx`/`dnsgen` generation, `puredns` resolution/wildcard
filtering, target scope, artifacts, and atomic merge. Host count alone is not a
trigger. Refresh `/surface` after new resolved hosts are published.

### AI-selected asset relationship expansion

Do not run corporate/supplier expansion for every target. Select it when current
evidence identifies an organization/brand, certificate, ASN/origin, registrant,
supplier, or an existing relationship worth resolving. Simple labs, localhost,
and isolated IP/CIDR targets without organization evidence are normal skip cases.

Use public structured sources first: corporate registry/LEI, RDAP/WHOIS, CT,
passive DNS, ASN/BGP, TLS/HTTP/favicon fingerprints, supplier records, and optional
mapping providers. Chrome DevTools MCP is only a public dynamic-page collector:
use a browser context without target-application credentials, retain a locatable
source URL/response reference, and do not send the result through
`tools/browser_mcp_import.py` or Browser Surface.

Normalize selected facts into
`recon/<target_key>/exposure/asset_relation_observations.jsonl`, then rebuild the
derived projection:

```bash
python3 tools/recon_candidates.py --target "$TARGET"
```

Quick mode requires explicit intent; normal performs one pass with depth 1; deep
may recurse to depth 3; full may recurse to depth 4. Follow only majority/control
relationships (`ownership_pct > 50` or explicit control), deduplicate by
`entity_ref` with normalized source/entity fallback, and stop after two consecutive
levels add no domains or the lane budget is exhausted. Optional FofaMap and future
Quake/Hunter adapters write the same observation schema; none owns Scope.

Read `asset_relation_summary.json` and refresh `/surface`/`/checkpoint`.
`in_scope` is the only executable status. Resolve `scope-review` through the
existing Action Queue; retain `external-chain-context`, `excluded`, and `unknown`
without active requests. Relationship evidence can propose an explicit target-set
change but never grants it, and candidate limits never truncate raw observations.

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
# Optional Nuclei CVE output → $RECON_DIR/../findings/$TARGET/cves/
```

---

## ATTACK SURFACE TRIAGE

### Find Interesting Targets in URL List

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

### gf Patterns (Quick Classification)

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
```

---

## JS ANALYSIS

### SecretFinder (API keys, tokens in JS bundles)

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### xnLinkFinder（deep/full 的 JS 链接分析）

```bash
xnLinkFinder \
  -sf recon/target.com/js/xnlinkfinder_scope.txt \
  -d 1 -p 5 -rl 50 -t 10 -mtl 10 -all -o cli \
  < recon/target.com/js/xnlinkfinder_targets.txt
```

`quick/normal` 不运行主动逐 bundle 或递归链接分析。`deep/full` 优先运行 xnLinkFinder；缺工具、执行失败或存在
认证 header 时回退逐 URL LinkFinder，避免把同一组认证信息发送到错误 origin。xnLinkFinder v8.2
在非 TTY 环境必须从 stdin 读取目标；`-all` 避免非常见 TLD 的范围内链接被默认规则过滤，
输出仍由 `-sf` 限定。IP 或单标签 scope 会成功返回但过滤全部链接，因此也走 LinkFinder 回退。

### Packer-InfoFinder（证据触发的异步 chunk 恢复）

它不是 Recon profile 的默认步骤。仅在 browser/source/local JS 已出现 webpack runtime、dynamic import、
chunk map、source map、不可读的压缩入口或缺失 lazy chunk 时调用：

```bash
# 已知高价值 bundle：使用上游 -j
python3 tools/deep_js_packer.py --target target.com --mode bundle \
  --signal webpack-runtime --evidence-ref recon/target.com/js_dump/runtime.js \
  --url https://target.com/assets/runtime.js

# 高价值应用入口的 JS inventory 不完整：使用上游 -u --finder
python3 tools/deep_js_packer.py --target target.com --mode page \
  --signal dynamic-import --evidence-ref recon/target.com/browser/network.jsonl \
  --url https://target.com/app
```

`--browser` 只用于已观察到运行时动态加载且静态页面未暴露脚本的 page lane。适配器匿名、限速、
限制 target scope，并将恢复文件发布到 `js_dump/packer/`，继续交给 `/js-read` 与现有 secrets lane；
上游 HTML/SQLite 只作为原始 artifact，不直接生成 finding。

### 可选：动态 JS 请求签名链重建

只在已观察到目标请求、脚本/initiator、运行时参数，或 JS/browser/client 语境中的动态签名、加密参数和 runtime hook 信号时启用。默认 timebox 为 30 分钟；裸 `signature`、`encryption` 或 `hook` 不触发。

```text
Observe  -> 固定正常请求、initiator、脚本 URL/hash 和入口候选
Capture  -> 用当前可用 browser/DevTools 能力做最小断点、hook 或运行时采样
Rebuild  -> 只按已观测的输入、调用顺序和依赖建立本地复现
Patch    -> 每轮只补一个有证据的环境缺口，记录 first divergence 是否前移
DeepDive -> 稳定复现后才做 AST/去混淆或下游安全语义验证
```

输出写入现有 Lead/Candidate 证据：request shape、script/hash、call chain、sample I/O、环境依赖、重建状态、证据路径、next action 和 stop condition。连续两轮 first divergence 未前移且没有新运行时证据时停止；稳定输出只作为签名范围、认证、对象或业务差异验证的输入。详细门见 `knowledge/cards/js-runtime-signature-reconstruction.md`。

### 可选：自定义协议帧与状态恢复

只在有 provenance 的 PCAP/PCAPNG、代理导出、客户端日志、原始帧、source 或二进制，并出现明确 framing/message/state 信号时启用。默认 timebox 为 45 分钟；裸 `pcap`、`protobuf`、`state machine` 或 `handshake` 不触发。

```text
capture -> TCP stream 重组 -> framing -> message dictionary -> state machine
        -> 同类/异类消息 + truncated/invalid controls -> harmless replay
```

先保存 hash、会话、方向、时序和 transport，再区分 TCP segmentation/reassembly 与应用帧，逐步验证 magic、length/endian、TLV、opcode、sequence、checksum/CRC、compression/encryption。输出仍进入现有 evidence/Lead/Candidate；只有多份消息和 negative controls 都能稳定解码、且动作无副作用时才做最小 replay。gRPC/WebSocket 分别转现有专卡。详细门见 `knowledge/cards/custom-protocol-state-recovery.md`。

### 可选：公开包与历史发布物

只在官方源码/文档、lockfile/SBOM、JS、镜像引用或已有 package namespace 信号出现时启用；它不是每个目标默认必跑的 Recon 步骤。先确认 namespace、package/image 与目标的直接归属，名字相似或普通第三方依赖不足以触发。

在本轮 timebox 内只选择少量代表发布物，例如首版、上一个 major、迁移前后版本和最新版。对每个样本保存生态、包名/镜像名、版本或 tag、发布时间、来源 URL、digest/SHA-256 和扫描范围。归档只解压并静态审查，不安装包、不执行 lifecycle script、不运行镜像、不发布或接管 namespace。

本地已解压目录复用现有 Source Hunt：

```bash
python3 tools/source_hunt.py --target TARGET --repo-path /path/to/extracted-artifact
```

输出只作为现有 Lead/Candidate 的补充证据：记录证据路径、最小脱敏片段、归属依据、价值、下一步和停止条件。真实 secret 值只进入现有 triage；dependency confusion 仍要求实际依赖、public fallback 和 namespace 状态三项证据。公开包版本不代表目标已部署，只有目标侧直接观测到精确组件/版本后才交给 `/intel`。

达到代表版本范围、来源无法确认、结果仅重复低信号文件或下一步需要执行未知代码时停止。详细判断门见 `knowledge/cards/public-package-artifact-intelligence.md`。

### Missing Parameter Signal / Target-Specific Params

当任意页面、接口、历史记录、source、schema、浏览器流量或静态资源显示
`missing parameter`、`parameter is null`、`required parameter`、类型错误、
schema mismatch 等缺参/校验信号时，
加载 `knowledge/cards/missing-parameter-discovery.md`。

Recon 阶段只产出候选材料，不把缺参错误当漏洞：

```text
1. 记录 baseline：URL、方法、认证状态、状态码、长度和缺参错误体。
2. 从 JS/source/schema/API docs/browser XHR/history/form/GraphQL/sibling endpoint/路径分段提取目标词表。
3. 将词表写为 lead/next action，交给 web2-vuln-classes 低频验证。
4. 若需要参数发现工具，只用目标词表和限速策略，避免通用大字典喷洒。
```

如果响应疑似进入真实用户数据面，停止在最小证据和 Candidate 线索，不做批量
枚举、导出或保存敏感数据。

---

## DIRECTORY FUZZING

### Baseline FFUF 与 Focused FFUF

`tools/recon_engine.sh` 已自动执行 baseline FFUF：使用固定通用词表、有界 live URL、
SPA/WAF control、压缩 JSONL 和 compact summary。单轮只执行有限目标，但
`dirs/ffuf_target_state.json` 会记录已成功覆盖的 base URL，后续轮次从
`dirs/ffuf_target_plan.json` 轮换未完成服务；原始 `live/urls.txt` 始终是完整攻击面，
不是本轮 FFUF 的截断结果。它是 breadth sensor，不代表路径覆盖完整；Claude 不重复运行，
也不因 baseline 零命中而自动转入 focused fuzz。

Focused fuzz 是 AI 显式选择的 discovery action。仅当 browser/JS/source/API docs/schema/
GraphQL/recon/history 已支持一个具体 URL 或 request template，且它比当前 replay、authz、
object、workflow 等路线更有价值时执行。每次运行前必须由 AI：

1. 从同一目标的真实路径分段、参数、API 名词/动词、XHR、source route、schema 和 sibling
   命名规律建立目标命名画像；孤立缩写只保留为假设，不把模型解释当事实。
2. 为候选绑定 `seed_refs`、`transformation`、`rationale` 和来源强弱；确定性槽位转换与 AI
   语义扩写分开记录，禁止使用模型自报数字置信度代替证据。
3. 生成有界、去重的 `wordlist.txt`；不得机械合并整份通用大字典。
4. 绑定一个明确的 `FUZZ` 位置、认证上下文、证据来源、请求率和停止条件；不同 template
   或认证形态使用不同 run。
5. 设置随机 miss/control 或显式 matcher/filter 来解释 SPA/WAF/fallback 差异；工具只保存
   事实，不替 AI 判断命中价值。

当本轮实际使用目标方言推导时，在现有 run 目录保存两个 run-local 证据附件；它们不拥有
finding、Surface、queue、coverage 或 target-memory 状态：

`naming_profile.json` 的字段只填写当前证据实际支持的维度：

```json
{
  "schema_version": 1,
  "surface": "path",
  "template": "https://HOST/api/FUZZ",
  "method": "<observed-method>",
  "auth_context": "<anonymous-or-session-label>",
  "seed_refs": ["<artifact-ref>"],
  "syntax": {
    "separators": ["<observed>"],
    "case_style": ["<observed>"],
    "slots": ["<observed-slot>"]
  },
  "hypotheses": [{
    "transformation": "<rule>",
    "seed_refs": ["<ref>"],
    "evidence_grade": "<same-target-multiple|same-target-single|generic-supplement>",
    "rationale": "<why-test>"
  }],
  "stop_condition": "<condition>"
}
```

`auth_context` 只记录匿名/会话标签或证据引用，不保存 token、cookie 或其他凭据值。

```jsonl
{"schema_version":1,"candidate":"<value>","seed_refs":["<ref>"],"transformation":"<rule>","rationale":"<why-test>","evidence_grade":"<grade>"}
```

上面是 `candidates.jsonl` 的单行形态；`wordlist.txt` 只是候选去重后的执行投影。候选附件
不记录 `validated`/finding 状态，完整观察仍以 FFUF raw/summary 为准。没有使用目标方言推导的
旧 run 或普通 Focused FFUF run 不要求补这两个附件。

每次 focused run 使用隔离目录，不覆盖 baseline，也不写入 `urls/all.txt`、surface、
action queue 或 coverage：

```bash
RUN_DIR='recon/<target_key>/focused_fuzz/20260710-api-v2-sibling-routes'
mkdir -p "$RUN_DIR/dirs"
# 方言推导时先保存 naming_profile.json/candidates.jsonl，再将去重投影写入 wordlist.txt

set -o pipefail
if ffuf -u 'https://target.com/api/v2/FUZZ' \
  -w "$RUN_DIR/wordlist.txt" \
  -H 'Authorization: Bearer <token>' -b 'session=<cookie>' \
  -mc all -ac -t 5 -timeout 10 \
  -s -json 2> "$RUN_DIR/ffuf.log" \
  | gzip -c > "$RUN_DIR/dirs/ffuf_results.jsonl.gz"; then
  RUN_COUNTS=(--attempted 1 --succeeded 1)
else
  RUN_COUNTS=(--attempted 1 --failed 1)
fi

python3 tools/recon_adapter.py --recon-dir "$RUN_DIR" \
  --summarize-ffuf "${RUN_COUNTS[@]}"
```

根路径 discovery 使用 `ffuf -u 'https://target.com/FUZZ'`；嵌套 API/path 使用当前证据
支持的 `/api/vN/FUZZ`、`/service/FUZZ` 等 prefix。认证请求可以使用 `-H`、`-b`，也可把
browser/proxy 捕获并清理后的 raw request 保存到当前 run：

```bash
RUN_DIR='recon/<target_key>/focused_fuzz/20260710-account-object-values'
mkdir -p "$RUN_DIR/dirs"
# request.txt 中只保留当前测试所需的 method、path、header/cookie 和一个明确 FUZZ 位置。
set -o pipefail
ffuf -request "$RUN_DIR/request.txt" -request-proto https \
  -w "$RUN_DIR/wordlist.txt" \
  -mc all -ac -t 3 -timeout 10 \
  -s -json 2> "$RUN_DIR/ffuf.log" \
  | gzip -c > "$RUN_DIR/dirs/ffuf_results.jsonl.gz"
```

`FUZZ` 可以位于 path、query、body 或 header；每次只改变一个边界，并沿用上面的隔离
artifact 契约：

```bash
# path
ffuf -u 'https://target.com/api/v2/FUZZ' -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
# query
ffuf -u 'https://target.com/api/v2/items?view=FUZZ' -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
# body
ffuf -u 'https://target.com/api/v2/items' -X POST -H 'Content-Type: application/json' \
  -d '{"action":"FUZZ"}' -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
# header
ffuf -u 'https://target.com/api/v2/items' -H 'X-API-Version: FUZZ' \
  -w "$RUN_DIR/wordlist.txt" -mc all -ac -t 3
```

保留 `-ac`；只有 control/baseline 支持时才增加如 `-fc 404`、`-fs <control-size>` 的显式
过滤。摘要之后用现有 adapter 有界分页查看 raw observations，不复制结果集：

```bash
python3 tools/recon_adapter.py --recon-dir "$RUN_DIR" \
  --read-ffuf --offset 0 --limit 100
```

把 ReconAdapter summary 的 status、length、words、lines、content-type、control match、响应
签名，以及有界 observation 页里的 redirect 作为第一层 Route Oracle。只对少量差异组做同方法、
同认证语义的重复只读 replay，
比较普通 404、405/`Allow`、框架错误、SPA/soft-404、登录跳转、统一网关页和 WAF 页面。
路由差异只形成 Signal；不得因收到 200/401/403/405 就自动晋升 Candidate，也不自动轮询
可能改变状态的 HTTP 方法。

复核时以结果 URL、响应特征和保存的 `wordlist.txt` 为完整证据链，不单独依赖 raw
`input.FUZZ`；FFUF 可能对该字段编码，`-ac` 校准值也可能影响它。

由 AI 解释响应差异并写回现有目标记忆。有效线索记录证据路径、价值、下一步和停止条件；
没有新增信息时记录本次有界范围，避免新 session 重复：

```bash
python3 tools/target_memory.py lead \
  "Focused fuzz evidence: $RUN_DIR/dirs/ffuf_summary.json; why: <signal>; next: <verification>; stop: <condition>" \
  --target target.com
python3 tools/target_memory.py dead-end \
  "Focused fuzz scope: <template + evidence>; artifact: $RUN_DIR/dirs/ffuf_results.jsonl.gz; result: <why no useful signal>" \
  --target target.com
```

候选与随机 miss 同质时降低对应转换并停止当前轮；稳定的不同错误族、方法差异或同词根多点
信号可以支持下一轮有界扩写。每轮结束后根据新证据重新决定继续或停止，不设置全局轮数上限。

候选进入具体漏洞验证 lane 后，再按该 lane 的 Evidence Ledger 契约保存 replay 证据。

### Pattern-Based Directory Fuzzing

当目标路径、目录名、文件名、API 前缀、参数名、子域、静态资源或业务短码
出现可归纳命名规律时，加载 `knowledge/cards/path-pattern-management-exposure.md`。

Recon 阶段只生成有界目标词表和只读线索：

```text
1. 提取已有路径分段、文件名、API 前缀、参数名、短码模式、JS/历史 URL/结构化记录里的词。
2. 限制长度、字符集、数量和速率，优先验证目标风格的兄弟目录。
3. 命中管理/监控/日志/统计/配置入口时，只记录标题、认证状态、只读结构化数据和版本线索。
4. 从访问记录、统计接口、配置字段、raw log、JSON/API/导出源提取二次 recon 字典，不访问状态改变路径。
```

不要把管理面登录页在 recon 阶段直接转成口令爆破；口令测试先记录为
credential lead，只有当当前证据选择 credential lane 时，才进入
`/spray` / `credential-attack`。疑似
access key/secret 只进入最小证据和验证计划，不导入云管平台、不接管资源。

---

## TARGET SCORING — BOUNTY ROI ONLY

Score bug bounty targets before spending multi-day effort. This is not an
execution gate for lab, localhost, private-scope, or explicitly authorized
targets. Low score means lower bounty ROI, not absence of attack surface.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Low bounty ROI — deprioritize for target selection only
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Bounty ROI Filters

These filters are for public bounty target selection. Do not apply them as
attack-surface closure on user-supplied labs, localhost/private scopes, or
explicitly authorized targets.

1. Max bounty < $500 → low ROI for multi-day bounty work
2. All recent reports are N/A or duplicate → likely saturated; seek unique evidence before deep dive
3. Scope is only a static marketing page → low-signal until auth, JS/source, API docs, or workflow evidence appears
4. Company < 5 employees with no revenue → payout risk for bounty selection
5. Explicitly excludes your planned bug class in rules → choose another allowed lane for that program

---

## TECH STACK DETECTION (2 min)

```bash
# Response headers reveal backend
curl -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints (/actuator/env) | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## PORT SCANNING (often skipped — don't skip)

```bash
# naabu — fast port scanner from ProjectDiscovery
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

## SECRET SCANNING IN JS BUNDLES

```bash
# trufflehog — high-signal secret detection with entropy analysis
# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already in tools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\|apiKey\|client_secret\|access_token\|private_key\|AWS_SECRET\|AKIA" /tmp/js-files/ 2>/dev/null
```

## GITHUB DORKING FOR TARGET

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

## 30-MINUTE RECON PROTOCOL

### Minutes 0-5: Read Existing Target Notes

```
Note:
- Supplied target set and obvious siblings
- High-value app/API/auth/export/upload/admin labels
- Target-history notes worth preserving for replay
- Whether the current turn already gave focus lanes or exclusions
- Any environment hints that affect recon depth or tool choice
```

### Minutes 5-15: Asset Discovery

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-25: Surface Map

Run gf patterns and the interesting-params grep above.

### Minutes 25-30: Manual Exploration

In Claude Code CLI, use chrome-devtools MCP for deep live debugging and
Playwright MCP for page interaction/session workflows. Import useful artifacts
with `tools/browser_mcp_import.py`. If Burp/Caido is configured, you may
also proxy traffic to retain history as auxiliary evidence:
1. Register an account
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls from browser network evidence or Burp/Caido history
4. Look for endpoints not in your URL list

### After 30 min: Prioritize

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```
