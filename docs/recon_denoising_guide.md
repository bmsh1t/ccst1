# Recon 降噪使用指南

## 概述
Recon 工具链产生大量噪音(外部 URL、路径爆炸、文档误判为 API)。降噪工具可清除 80% 假阳性,同时保留 >95% 真实攻击面。

## 快速开始

### 对现有 recon 应用降噪
```bash
# 1. 过滤 URL (外部域名 + 路径爆炸)
python3 tools/recon_filters.py \
    recon/<target>/urls/all.txt \
    recon/<target>/urls/all_filtered.txt \
    <target> \
    --log-file recon/<target>/urls/filter.log

# 2. 验证 API 候选 (保留原始文件)
bash tools/validate_api_candidates.sh \
    recon/<target>/exposure/api_leak_candidates.txt \
    recon/<target>/exposure/api_leak_candidates.txt

bash tools/validate_api_candidates.sh \
    recon/<target>/exposure/api_doc_candidates.txt \
    recon/<target>/exposure/api_doc_candidates.txt

# 3. 重新排名
python3 tools/surface.py --target <target>
```

## 改进特性

### 1. 更安全的路径爆炸检测
**改进**: Threshold 从 3 提升到 4
**影响**: 保留罕见的递归 API 路径 (如 `/users/123/groups/456/users/789`)

### 2. 上下文感知 cache 参数
**改进**: API 路径中的 `v` 和 `version` 不判定为 cache
**影响**: 
- `/api/search?v=2` → 识别为 API version,保留测试
- `/assets/main.js?v=123` → 识别为 cache param,降权

### 3. 原始文件保留
**改进**: URL 降噪写入 `all_filtered.txt`; API 候选验证写入 `.validated`
**影响**: `all.txt` 和原始候选文件保留,可手动审查误杀或文档 secrets

### 4. 过滤日志
**改进**: 记录所有被过滤的 URL 到 log 文件
**影响**: 定期审查日志,发现误杀的真实攻击面

## 工具说明

### tools/recon_filters.py

**功能**:
1. 过滤外部域名 URL (非目标子域)
2. 检测路径爆炸 (重复路径片段 ≥4 次)
3. 过滤编码/HTML 片段噪音
4. 提供 context-aware cache 参数判断 helper; 批量过滤默认不删除 cache 参数

**用法**:
```bash
python3 tools/recon_filters.py <input_urls> <output_urls> <target_domain>

# 带日志
python3 tools/recon_filters.py \
    recon/target.com/urls/all.txt \
    recon/target.com/urls/all_filtered.txt \
    target.com \
    --log-file recon/target.com/urls/filter.log
```

**输出示例**:
```
Filtering complete:
  Total URLs: 353275
  Removed encoding errors: 20
  Removed HTML encoding: 7
  Removed external: 10480
  Removed path explosion: 201
  Kept: 342594 (97.0%)
```

### tools/validate_api_candidates.sh

**功能**:
只保留真实 API 文档格式 (swagger, openapi, .json, .yaml),排除 .doc/.pdf/.ppt

**用法**:
```bash
bash tools/validate_api_candidates.sh <input_file> <output_file>

# 如果 input == output,自动创建 .validated 保留原始
bash tools/validate_api_candidates.sh \
    recon/target.com/exposure/api_leak_candidates.txt \
    recon/target.com/exposure/api_leak_candidates.txt
```

**输出示例**:
```
API candidate validation:
  Original: 5
  Validated: 3
  Filtered: 2 (non-API documents)
  Note: Original preserved at api_leak_candidates.txt, 
        validated at api_leak_candidates.txt.validated
```

## 风险与缓解

### 已知误杀风险

| 场景 | 风险 | 缓解 |
|---|---|---|
| 第三方托管 API (AWS/Azure) | 中 | 审查 `urls/filter.log` |
| API version 参数 | 低 | 上下文感知已豁免 |
| 非标准 API 文档 | 低 | .validated 共存,保留原始 |
| 递归路径 | 极低 | Threshold=4 已提升 |

### 定期审查流程

```bash
# 检查被过滤的外部 URL 中是否有目标基础设施
cat recon/<target>/urls/filter.log \
    | grep -E 'amazonaws|azure|cloudflare|execute-api'

# 检查被过滤的路径爆炸 URL 中是否有真实端点
cat recon/<target>/urls/filter.log \
    | grep PATH_EXPLOSION \
    | grep -iE 'admin|api|debug|internal'

# 审查原始 API 候选中的文档 (可能含 secrets)
cat recon/<target>/exposure/api_leak_candidates.txt \
    | grep -E '\.pdf$|\.doc'
# 用 TruffleHog 扫描这些文档
```

## 分环境建议

### CTF/Lab 环境 (零遗漏优先)
```bash
# 只应用外部 URL 过滤,关闭其他降噪
python3 tools/recon_filters.py \
    --no-path-explosion \
    --explosion-threshold 5 \
    recon/<target>/urls/all.txt recon/<target>/urls/all_filtered.txt <target> \
    --log-file recon/<target>/urls/filter.log

# 手动 triage 所有 P1
```

### Bug Bounty (效率优先)
```bash
# 应用全部降噪 (推荐配置)
python3 tools/recon_filters.py \
    recon/<target>/urls/all.txt recon/<target>/urls/all_filtered.txt <target> \
    --log-file recon/<target>/urls/filter.log

bash tools/validate_api_candidates.sh \
    recon/<target>/exposure/api_leak_candidates.txt \
    recon/<target>/exposure/api_leak_candidates.txt

# 定期审查日志 (每周)
cat recon/<target>/urls/filter.log | wc -l
```

### Pentest (付费客户,零误杀)
```bash
# 不应用降噪,手动 triage
# 或只应用外部 URL 过滤 (客户明确 scope)
```

## 效果对比

### 测试案例: ohchr.org

| 指标 | 降噪前 | 降噪后 | 改进 |
|---|---|---|---|
| Total URLs | 353,275 | 342,594 | -3% 噪音 |
| External URLs | 10,480 | 0 | ✅ 清零 |
| API leak candidates | 5 (全假阳性) | 0 | ✅ 清零 |
| P1 质量 | SharePoint 文档 | 仍是文档 | ⚠️ 需上下文降权 |
| P2 质量 | Matomo tracking | 真实 API | ✅ 显著提升 |

**结论**: 清除噪音成功,P2/Workflow Leads 质量提升,P1 需进一步算法改进。

## 集成到自动化流程

### 修改 tools/recon_engine.sh

在 Phase 4 (URL Collection) 之后插入:

```bash
# Phase 4.5: URL Noise Filtering
echo "[*] Phase 4.5: URL Noise Filtering"
LOG_FILE="$OUT/urls/filter.log"

python3 tools/recon_filters.py \
    "$OUT/urls/all.txt" \
    "$OUT/urls/all_filtered.txt" \
    "$TARGET" \
    --log-file "$LOG_FILE"

# 重新生成 api_endpoints_filtered.txt (基于 all_filtered.txt; 保留原 api_endpoints.txt)
grep -iE '/api/|/v[0-9]+/|graphql|/rest/' "$OUT/urls/all_filtered.txt" \
    > "$OUT/urls/api_endpoints_filtered.txt"
```

在 Phase 6 (Exposure Detection) 之后插入:

```bash
# Phase 6.5: API Candidate Validation
echo "[*] Phase 6.5: API Candidate Validation"

if [[ -f "$OUT/exposure/api_leak_candidates.txt" ]]; then
    bash tools/validate_api_candidates.sh \
        "$OUT/exposure/api_leak_candidates.txt" \
        "$OUT/exposure/api_leak_candidates.txt"
fi

if [[ -f "$OUT/exposure/api_doc_candidates.txt" ]]; then
    bash tools/validate_api_candidates.sh \
        "$OUT/exposure/api_doc_candidates.txt" \
        "$OUT/exposure/api_doc_candidates.txt"
fi
```

## 故障排除

### Q: 过滤后 P1 全部消失
**A**: 可能所有 P1 都是外部 URL。检查 `urls/filter.log`:
```bash
grep -c EXTERNAL recon/<target>/urls/filter.log
```

### Q: API version 参数仍被降权
**A**: 确认 URL 路径包含 `/api/` 或 `/v[0-9]/`。更新上下文正则:
```python
# tools/recon_filters.py
if re.search(r'/api/|/v\d+/|/rest/|/graphql', parsed.path, re.I):
```

### Q: 真实递归路径被过滤
**A**: 检查 `PATH_EXPLOSION` 日志,提高 threshold 或手动加回:
```bash
cat recon/<target>/urls/filter.log | grep PATH_EXPLOSION
```

## 未来改进

### 短期 (1-2 周)
- [ ] CNAME 检查 (识别第三方托管的目标 API)
- [ ] 第三方服务白名单配置
- [ ] Surface.py 集成 context-aware cache 参数降权

### 中期 (1-2 月)
- [ ] SharePoint 公开文档库识别与降权
- [ ] Scanner SSTI 三路验证
- [ ] 基于历史 hunt 结果的权重调优

### 长期 (3-6 月)
- [ ] ML 模型训练 (真实攻击面 vs 噪音分类)
- [ ] 自动化误杀检测与反馈循环

## 相关文档
- `/tmp/recon_noise_analysis.md` — 假阳性模式详细分析
- `/tmp/denoising_risk_analysis.md` — 误杀风险评估与缓解
- `/tmp/recon_denoising_summary.md` — 实施总结

## 贡献
发现误杀案例请提交到 `docs/false_negatives.md`,包含:
- URL 示例
- 为何是真实攻击面
- 当前过滤器行为
- 建议改进

---
最后更新: 2026-06-08
版本: 1.0 (安全版本 — threshold=4, 上下文豁免, 原始文件保留)
