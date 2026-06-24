# Recon 降噪实施总结

## 执行日期
2026-06-08

## 问题
mb1.txt 批量 hunt 中,所有 9 个目标的高分 signals 都是假阳性,浪费大量测试时间。

## 已实施修复

### 1. 外部 URL 过滤器 (`tools/recon_filters.py`)
**功能**:
- 过滤非目标域名 URL
- 检测路径爆炸(`/API/API/API/...`)
- 识别缓存参数(`v=`, `bust=`, `_=`)

**效果**(ohchr.org 测试):
- 移除 10,480 个外部 URL (3%)
- 移除 201 个路径爆炸 URL
- 保留 342,594 个目标域 URL (97%)

**使用**:
```bash
python3 tools/recon_filters.py <input_urls> <output_urls> <target_domain>
```

### 2. API 候选验证脚本 (`tools/validate_api_candidates.sh`)
**功能**:
- 只保留真实 API 文档格式(swagger, openapi, .json, .yaml)
- 排除普通文档(.doc, .pdf, .ppt)

**效果**(ohchr.org):
- API leak candidates: 5 → 0 (100% 假阳性清除)
- API doc candidates: 5 → 0 (100% 假阳性清除)

**使用**:
```bash
bash tools/validate_api_candidates.sh <input_candidates> <output_validated>
```

### 3. Surface 排名质量提升
**效果**:
- P2 出现真实 API endpoints (`cvstatext.ohchr.org/api/*`)
- Workflow Leads 中 API leak 信号更准确(candidate=0 而非误报 5)

## 仍存在的问题

### P1 URL 质量未根本解决
**问题**: SharePoint `Download.aspx?symbolno=` treaty 文档下载端点仍占据 P1
**原因**: 这些是目标基础设施的真实端点,但是**公开文档下载服务**(按国际条约编号访问),不是 IDOR
**影响**: Ranking 算法将 "sequential object reference" 权重设置过高

**需进一步修复**:
```python
# surface.py 中增加上下文感知降权
def adjust_score_by_context(url, score):
    # SharePoint public document libraries
    if re.search(r'Download\.aspx\?symbolno=', url, re.I):
        # 这些通常是公开的条约/报告库,非 IDOR
        score *= 0.3
    
    # Known public file services
    if re.search(r'/files/|/documents/|/library/|/repository/', url, re.I):
        score *= 0.5
    
    return score
```

### Scanner False Positives
**SSTI 检测仍需改进** — ifw-kiel.de 误报的三路验证尚未集成到 vuln_scanner.sh

## 集成到 Recon 流程

### 立即可用(手动模式):
```bash
# 在现有 recon 数据上应用过滤
python3 tools/recon_filters.py recon/<target>/urls/all.txt recon/<target>/urls/all.txt <target>
bash tools/validate_api_candidates.sh recon/<target>/exposure/api_leak_candidates.txt recon/<target>/exposure/api_leak_candidates.txt

# 重新 surface
python3 tools/surface.py --target <target>
```

### 自动集成(需修改 recon_engine.sh):
在 `tools/recon_engine.sh` Phase 4 和 Phase 6 之间插入:
```bash
# Phase 4.5: Noise Filtering
echo "[*] Phase 4.5: URL Noise Filtering"
python3 tools/recon_filters.py "$OUT/urls/all.txt" "$OUT/urls/all.txt" "$TARGET"

# Phase 6 之后: API Candidate Validation
bash tools/validate_api_candidates.sh "$OUT/exposure/api_leak_candidates.txt" "$OUT/exposure/api_leak_candidates.txt"
bash tools/validate_api_candidates.sh "$OUT/exposure/api_doc_candidates.txt" "$OUT/exposure/api_doc_candidates.txt"
```

## 测试结果

### 成功案例
- ✅ 外部 URL 污染清除(10,681 个)
- ✅ 路径爆炸检测(201 个)
- ✅ API leak 假阳性清零
- ✅ P2 质量提升(真实 API endpoints 浮现)

### 需要迭代
- ⚠️ P1 质量仍需上下文感知降权
- ⚠️ Scanner SSTI/takeover 误报需要三路验证

## 下一步行动

1. **短期**(立即使用):
   - 手动模式应用过滤器到现有 recon
   - 在 `/surface` 前调用过滤脚本

2. **中期**(集成到自动化):
   - 修改 `recon_engine.sh` 集成过滤步骤
   - 修改 `surface.py` 增加上下文感知降权

3. **长期**(算法改进):
   - 训练 ML 模型识别公开文档库 vs 真实 IDOR
   - 基于历史 hunt 结果反馈调整权重

## 文件清单
- `tools/recon_filters.py` — URL 过滤工具(外部域名、路径爆炸、缓存参数)
- `tools/validate_api_candidates.sh` — API 候选格式验证
- `/tmp/recon_noise_analysis.md` — 详细假阳性分析
- `/tmp/recon_integration_patch.md` — 集成方案文档
- `recon/ohchr.org.backup/` — 原始 recon 备份(测试对比)

## 结论
降噪工具已创建并验证有效,显著减少外部 URL 和 API leak 假阳性。P2 质量明显提升。P1 质量需要进一步的上下文感知权重调整。建议立即采用手动模式,中期集成到 recon_engine.sh。
