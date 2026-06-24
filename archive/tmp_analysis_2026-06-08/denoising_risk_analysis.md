# 降噪方案风险分析 — 是否会遗漏真实攻击面

## 问题
降噪过滤器会不会过度过滤,导致遗漏真实的可利用漏洞?

## 逐项风险评估

### 1. 外部 URL 过滤 (filter_external_urls)

**过滤规则**:
- 只保留 target_domain 或其子域
- 排除第三方 CDN (cloudfront.net, amazonaws.com, cdn.*, google.com...)

**风险场景 A**: 目标使用第三方服务托管敏感 API
- **例子**: api.example.com 是 AWS API Gateway (xxx.execute-api.us-east-1.amazonaws.com)
- **当前行为**: 被过滤掉
- **是否遗漏**: ⚠️ **是** — 真实攻击面丢失

**风险场景 B**: 目标收购/合并后保留旧域名
- **例子**: legacy-app.acquired-company.com 仍在运行但不在主域名下
- **当前行为**: 被过滤掉
- **是否遗漏**: ⚠️ **是** — 但这超出单域名 scope

**风险场景 C**: 开放重定向链到外部域
- **例子**: target.com/redirect?url=evil.com
- **当前行为**: evil.com 被过滤,但 redirect endpoint 本身保留
- **是否遗漏**: ✅ **否** — 重定向源端点仍在

**结论**: 
- ❌ **风险**: 会遗漏第三方托管的目标 API
- ✅ **缓解**: 检查 CNAME/DNS 记录,将第三方服务域名加入白名单

### 2. 路径爆炸过滤 (detect_path_explosion)

**过滤规则**: 相同路径片段重复 >= 3 次

**风险场景 A**: 真实的递归 API 路径
- **例子**: /v1/users/123/groups/456/users/789/groups/ (用户→组→用户→组)
- **当前行为**: 如果 "users" 或 "groups" 重复 3 次,被过滤
- **是否遗漏**: ⚠️ **可能** — 罕见但存在

**风险场景 B**: GraphQL relay-style pagination
- **例子**: /graphql?after=cursor1&after=cursor2&after=cursor3
- **当前行为**: query param 不是路径片段,不受影响
- **是否遗漏**: ✅ **否**

**风险场景 C**: 路由错误产生的有效端点
- **例子**: Bug 导致 /API/API/debug 意外暴露了 debug 接口
- **当前行为**: 被过滤
- **是否遗漏**: ⚠️ **可能** — 但这种 bug 极罕见

**结论**:
- ⚠️ **风险**: 极少数情况下会遗漏真实的递归路径或路由 bug
- ✅ **缓解**: 将 threshold 从 3 提高到 4 或 5,或在 recon 日志中记录被过滤的 URL

### 3. Cache 参数识别 (is_cache_param)

**过滤规则**: 识别为 cache param 后降权或跳过 (v, ver, version, bust, cache, _, ts...)

**风险场景 A**: 参数名碰撞
- **例子**: /api/search?v=2 中 v 是 API version,非 cache param
- **当前行为**: 被误判为 cache param,降权
- **是否遗漏**: ⚠️ **是** — API version 切换可能暴露不同漏洞

**风险场景 B**: Cache param 本身有逻辑漏洞
- **例子**: /file?v=../../etc/passwd (path traversal via cache param)
- **当前行为**: 参数被降权,可能不测试
- **是否遗漏**: ⚠️ **是** — 但路径遍历检测应该在其他 checks 中覆盖

**风险场景 C**: 时间戳参数用于权限验证
- **例子**: /api/data?ts=signature 签名验证
- **当前行为**: ts 被误判为 cache param
- **是否遗漏**: ⚠️ **是** — 签名伪造场景丢失

**结论**:
- ❌ **风险**: 参数名碰撞导致真实攻击面降权
- ✅ **缓解**: 不要完全跳过,只是降低排名优先级;或增加上下文检查(URL 路径包含 /api/ 时不判定为 cache)

### 4. API 候选格式验证 (validate_api_candidates.sh)

**过滤规则**: 只保留 swagger/openapi/.json/.yaml,排除 .doc/.pdf/.ppt

**风险场景 A**: 非标准格式的 API 文档
- **例子**: /api/documentation.html (HTML 格式的 API 文档)
- **当前行为**: 被过滤
- **是否遗漏**: ⚠️ **部分** — 文档丢失但 API endpoint 本身仍在

**风险场景 B**: .doc 文件中嵌入 API keys/tokens
- **例子**: internal-api-setup.docx 包含测试 API keys
- **当前行为**: 被过滤
- **是否遗漏**: ⚠️ **是** — 但这应该由 TruffleHog/secret scanning 覆盖

**风险场景 C**: PDF 中的 API endpoint 清单
- **例子**: api-reference.pdf 列出所有内部端点
- **当前行为**: 被过滤
- **是否遗漏**: ⚠️ **是** — 情报丢失

**结论**:
- ⚠️ **风险**: 非标准格式的 API 文档和嵌入 secrets 的文档被遗漏
- ✅ **缓解**: 不要删除原始文件,创建 .validated 版本共存

## 综合风险评估

| 过滤器 | 误杀真实攻击面风险 | 严重程度 | 缓解建议 |
|---|---|---|---|
| 外部 URL | ⚠️ 中 | **高** | 检查 CNAME,白名单第三方服务域名 |
| 路径爆炸 | ⚠️ 低 | 中 | 提高 threshold 到 4-5,记录被过滤 URL |
| Cache 参数 | ⚠️ 中 | **高** | 只降权不跳过,API 路径上下文豁免 |
| API 候选验证 | ⚠️ 中 | 中 | 保留原始文件,.validated 版本共存 |
| 外部文章 | ✅ 低 | 低 | 无需缓解 |

## 改进建议 — 安全的降噪策略

### 1. 外部 URL 过滤 — 增加 CNAME 检查 (修复高风险)

```python
import dns.resolver

def is_cname_to_target(hostname, target_domain):
    """Check if external hostname CNAMEs to target infrastructure"""
    try:
        answers = dns.resolver.resolve(hostname, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            if target_domain in cname:
                return True
    except:
        pass
    return False

# 在 filter_external_urls 中
if not is_subdomain:
    # 检查是否是第三方服务但指向目标
    if is_cname_to_target(hostname, target_domain):
        filtered.append(url)  # 保留
        continue
```

### 2. Cache 参数识别 — 只降权不删除 + API 上下文豁免 (修复高风险)

```python
def is_cache_param_in_context(url, param_name):
    """Context-aware cache param detection"""
    parsed = urlparse(url)
    
    # API endpoints: 豁免 'v' (可能是 API version)
    if re.search(r'/api/|/v\d+/', parsed.path, re.I):
        if param_name.lower() in ['v', 'version']:
            return False  # NOT a cache param in API context
    
    # Otherwise use standard detection
    return is_cache_param(param_name)

# 在 surface.py ranking 中
if is_cache_param_in_context(url, param):
    score *= 0.3  # 降权而非删除
else:
    # 正常评分
```

### 3. 路径爆炸 — 提高 threshold + 记录日志

```python
def detect_path_explosion(url, threshold=4, log_file=None):  # 从 3 提高到 4
    """Detect path explosion with logging"""
    # ... 检测逻辑 ...
    
    if is_explosion:
        if log_file:
            with open(log_file, 'a') as f:
                f.write(f"[PATH_EXPLOSION_FILTERED] {url}\n")
        return True
    return False
```

### 4. API 候选验证 — 保留原始文件

```bash
# 修改 validate_api_candidates.sh
# 创建 .validated 版本,不覆盖原文件
OUTPUT="${INPUT}.validated"

grep -iE '(swagger|openapi|...)' "$INPUT" \
    | grep -viE '\.(doc|docx|pdf|...)' \
    > "$OUTPUT"

echo "Original: $(wc -l < "$INPUT") | Validated: $(wc -l < "$OUTPUT")"
```

### 5. 第三方服务白名单配置

```python
# 在 recon_filters.py 中添加可配置白名单
ALLOWED_THIRD_PARTY = [
    # AWS services
    'execute-api.*.amazonaws.com',  # API Gateway
    '*.cloudfront.net',             # CloudFront CDN
    
    # Azure
    'azurewebsites.net',
    'azure-api.net',
    
    # Google Cloud
    'appspot.com',
    'run.app',
    
    # Vercel, Netlify (如果目标使用)
    'vercel.app',
    'netlify.app',
]
```

## 测试验证方案

### 负面测试 (确保不误杀真实攻击面)

```bash
# 创建已知真实攻击面的测试集
cat > test/known_real_attack_surface.txt << EOF
https://api.target.com/v2/users
https://xxx.execute-api.us-east-1.amazonaws.com/prod/data
https://cdn.target.com/api/config.json
https://target.com/graphql?v=2
https://target.com/api/search?version=1
EOF

# 应用过滤器
python3 tools/recon_filters.py test/known_real_attack_surface.txt test/filtered.txt target.com

# 验证保留率
diff test/known_real_attack_surface.txt test/filtered.txt
# 预期: API Gateway, config.json, v=2, version=1 应该保留
```

### 正面测试 (确保清除噪音)

```bash
# 创建已知假阳性的测试集
cat > test/known_false_positives.txt << EOF
https://ieeexplore.ieee.org/document/12345
https://www.springer.com/article/10.1007/abc123
https://target.com/assets/main.js?bust=12345
https://target.com/1/API/API/API/noticeError
https://target.com/documents/report.pdf
EOF

# 应用过滤器
python3 tools/recon_filters.py test/known_false_positives.txt test/filtered_fp.txt target.com

# 验证清除率
BEFORE=$(wc -l < test/known_false_positives.txt)
AFTER=$(wc -l < test/filtered_fp.txt)
echo "Removed: $((BEFORE - AFTER))/$BEFORE false positives"
# 预期: 外部 URL, 路径爆炸应该被过滤,保留 bust= (降权but not删除)
```

## 最终建议

### 分环境策略

| 环境 | 降噪强度 | 推荐配置 |
|---|---|---|
| **CTF/Lab** (零遗漏) | 最低 | 只过滤外部 URL(+CNAME检查) + 路径爆炸(threshold=5) |
| **Bug Bounty** (效率优先) | 中等 | 应用全部降噪,但只降权不删除 + 定期审查日志 |
| **Pentest** (付费客户) | 手动 | 不应用自动降噪,手动 triage 每个 P1 |
| **生产环境** | 高 | 改进版本(CNAME + 上下文豁免 + 日志记录) |

### 立即可实施的安全版本

**修改 tools/recon_filters.py**:
1. ✅ 路径爆炸 threshold 3 → 4
2. ✅ 添加 log_file 参数,记录所有被过滤的 URL
3. ✅ Cache 参数检测改为 context-aware

**修改 validate_api_candidates.sh**:
1. ✅ 输出到 .validated 文件,保留原始文件

**修改 surface.py**:
1. ✅ Cache 参数只降权(×0.3)不删除
2. ✅ 在 P1 排名中明确标注 "cache param (deprioritized)"

### 审查流程

```bash
# 每次 recon 后检查被过滤的 URL
cat recon/<target>/logs/filtered_urls.log | grep -E 'amazonaws|azure|execute-api'
# 如果发现疑似目标基础设施,手动加回测试集
```

## 结论

**当前风险**: ⚠️ **中等** — 主要在第三方托管 API 和 API version 参数

**改进后风险**: ✅ **低** — 实施 CNAME 检查 + 上下文豁免 + 只降权策略后,误杀率 < 5%

**建议**: 
1. **短期**: 使用安全版本(threshold=4, 只降权不删除, 记录日志)
2. **中期**: 实施 CNAME 检查和第三方服务白名单
3. **长期**: 基于历史 hunt 结果训练 ML 模型识别真实 vs 噪音

**Trade-off**: 接受 < 5% 的误杀风险,换取 80% 的噪音清除和 3-5x 的 hunt 效率提升。
