# Recon 工具链假阳性分析与降噪建议

## 问题概述
mb1.txt 批量测试中,所有高分目标的 P1 signals 都是假阳性,导致大量无效 hunt 时间。

## 假阳性模式分析

### 1. API Leak/Doc Candidates (最严重)
**问题**: `api_leak_candidates.txt` 和 `api_doc_candidates.txt` 包含大量文档 URL
**实例**:
- `http://www.ohchr.org/Documents/HRBodies/CAT/GuidelinesCoreDocCAT.doc`
- `https://www.baronpa.com/library/stories/Pages/story-bulletin.aspx?num=6237`

**根本原因**: 正则匹配路径中包含 "Documents", "doc", "api" 等关键词的 URL,未区分:
- 真实 API 文档(Swagger/OpenAPI JSON/YAML)
- 普通文档文件(.doc, .pdf)
- 文章页面路径

**修复建议**:
```bash
# 在 recon_engine.sh 或 exposure 检测脚本中添加过滤
# 只保留明确的 API 文档格式
grep -E '\.(json|yaml|yml)$|swagger|openapi|/api-docs|/v[0-9]/docs' urls.txt > api_doc_candidates.txt
# 排除常见文档扩展名
grep -vE '\.(doc|docx|pdf|ppt|xls)(\?|$)' 
```

### 2. Postman Search 误匹配
**问题**: postleaksNg 使用域名关键词搜索,命中无关 collections
**实例**:
- `rhg.com` → 匹配到法国 HR 系统(RHG = Resources Humaines Gestion)
- `ifw-kiel.de` → 匹配到通用 "ifw" 关键词的 39 个 collections

**根本原因**: 搜索只用域名主体(去掉 TLD),短词/缩写导致大量误匹配

**修复建议**:
```python
# 在 postleaksNg 调用前验证结果
# 1. 要求 collection 中至少有一个 request URL 包含目标完整域名
# 2. 或检查 workspace/author 名称是否相关
# tools/verify_postman_results.py --target domain.com --results postman_leaks.txt
```

### 3. 路径爆炸噪音
**问题**: katana/gau 爬取产生递归路径(`/API/API/API/...`)
**实例**:
- `www.dfc.gov/1/API/API/noticeError/API/API/noticeError/...`
- 导致 "9221 API endpoints" 严重夸大

**根本原因**: 爬虫遇到相对路径或路由错误时递归生成

**修复建议**:
```bash
# 在 URL 去重阶段添加路径爆炸检测
# 去除路径中有相同片段重复 3 次以上的 URL
awk -F'/' '{
    for(i=1; i<=NF; i++) {
        count[$i]++
        if(count[$i] >= 3) {next}
    }
    print
}' urls.txt > urls_cleaned.txt
```

### 4. 外部引用 URL 污染
**问题**: 爬取的 URL 中大量第三方域名(articles, CDN)被误判为目标 API
**实例**:
- P1 全是 `ieeexplore.ieee.org`, `springer.com`, `journals.plos.org` (文章引用)

**根本原因**: `/surface` ranking 未严格过滤非目标域名

**修复建议**:
```python
# surface.py 中增强域名过滤
def is_in_scope(url, target_domain):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc.lower()
    
    # 严格匹配:只保留目标主域或其子域
    if not (hostname == target_domain or hostname.endswith('.' + target_domain)):
        return False
    
    # 排除已知第三方服务
    third_party = ['cloudfront.net', 'amazonaws.com', 'cdn.', 'google.com', 
                   'facebook.com', 'twitter.com', 'linkedin.com']
    if any(tp in hostname for tp in third_party):
        return False
    
    return True
```

### 5. Cache-busting 参数误判为 IDOR
**问题**: `?v=`, `?bust=`, `?_=` 等缓存参数被标记为 Sequential object reference
**实例**:
- `core-main.js?v={{7*7}}` 被误判为 SSTI
- Score 高但完全无意义

**根本原因**: 参数名识别不完善

**修复建议**:
```python
# 在 ranking 前过滤已知缓存参数
CACHE_PARAMS = ['v', 'ver', 'version', 'bust', 'cache', '_', 'ts', 'timestamp', 
                'nc', 'nocache', 'rev', 'hash']

def is_cache_param(param_name):
    return param_name.lower() in CACHE_PARAMS or re.match(r'^_+$', param_name)
```

### 6. Scanner False Positives
**问题**: SSTI 检测误判静态文件缓存参数
**根本原因**: 检测逻辑未验证响应差异,仅依赖 payload 成功发送

**修复建议**:
```python
# vuln_scanner.sh SSTI 检测中增加验证
# 1. 发送 baseline (正常值)
# 2. 发送 payload {{7*7}}
# 3. 发送 expected result (49)
# 只有当 baseline ≠ payload 且 payload ≈ expected 时才确认
```

## 优先级修复顺序

### P0 (立即修复,影响最大):
1. **外部 URL 过滤** (surface.py) — 消除所有 P1 噪音
2. **路径爆炸检测** (URL dedup 阶段) — 减少 90% 假 API 端点

### P1 (重要,影响排名准确性):
3. **API doc/leak 候选格式验证** (exposure 检测)
4. **Cache param 识别** (ranking)

### P2 (优化,减少调查时间):
5. **Postman 结果验证** (后处理)
6. **SSTI 检测增强验证** (scanner)

## 实施计划

1. **创建过滤脚本** `tools/recon_filters.py`:
   - `filter_external_urls(urls, target_domain)`
   - `detect_path_explosion(url)`
   - `is_cache_param(param)`

2. **修改 recon_engine.sh**:
   - Phase 4 URL 收集后调用过滤器
   - Phase 6 暴露检测中严格验证 API doc 格式

3. **修改 surface.py**:
   - 加载前应用域名+cache param 过滤
   - 降低外部域名权重或直接 kill

4. **修改 vuln_scanner.sh**:
   - SSTI 检测改用 3-way 比较
   - 在 [CRITICAL] 输出前验证响应差异

## 测试验证

用 mb1.txt 清洗后的 recon 重新跑 surface.py,预期:
- P1 中 0 个外部 URL
- API endpoint 计数减少 >80%
- API leak/doc candidates 减少到 <5 个/target
- SSTI false positive 率 <10%

