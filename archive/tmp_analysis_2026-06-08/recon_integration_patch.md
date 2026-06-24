# Recon 降噪集成方案

## 1. 修改 recon_engine.sh

在 Phase 4 URL 收集完成后,Phase 5 JS 分析前插入过滤:

```bash
# Phase 4: URL Collection 之后
echo "[*] Phase 4.5: URL Noise Filtering"
python3 tools/recon_filters.py \
    "$OUT/urls/all.txt" \
    "$OUT/urls/all_filtered.txt" \
    "$TARGET"

# 替换原始文件
mv "$OUT/urls/all_filtered.txt" "$OUT/urls/all.txt"

# 重新生成 api_endpoints.txt (基于清洗后的 all.txt)
grep -iE '/api/|/v[0-9]+/|graphql|/rest/' "$OUT/urls/all.txt" > "$OUT/urls/api_endpoints.txt"
```

## 2. 修改 Phase 6 暴露检测

在生成 api_leak_candidates.txt 后立即验证:

```bash
# 原有的 API leak 检测后
bash tools/validate_api_candidates.sh \
    "$OUT/exposure/api_leak_candidates.txt" \
    "$OUT/exposure/api_leak_candidates.validated.txt"
mv "$OUT/exposure/api_leak_candidates.validated.txt" "$OUT/exposure/api_leak_candidates.txt"

# 同样处理 api_doc_candidates.txt
bash tools/validate_api_candidates.sh \
    "$OUT/exposure/api_doc_candidates.txt" \
    "$OUT/exposure/api_doc_candidates.validated.txt"
mv "$OUT/exposure/api_doc_candidates.validated.txt" "$OUT/exposure/api_doc_candidates.txt"
```

## 3. 修改 surface.py

在加载 URLs 时应用过滤:

```python
# 在 load_surface_inputs() 函数中
from tools.recon_filters import filter_external_urls, detect_path_explosion, is_cache_param

# 加载 URLs 后过滤
urls = filter_external_urls(urls, target_domain)

# 过滤路径爆炸
urls = [u for u in urls if not detect_path_explosion(u)]

# 在参数化 URL 排名时,降低 cache param 权重
for url in param_urls:
    params = parse_qs(urlparse(url).query)
    
    # 检查是否全是 cache params
    all_cache = all(is_cache_param(p) for p in params.keys())
    
    if all_cache:
        # Kill 或大幅降低分数
        continue  # 或 score *= 0.1
```

## 4. 修改 vuln_scanner.sh SSTI 检测

在 Check 1.5 SSTI Detection 中增加三路验证:

```python
def verify_ssti(url, param, engine='jinja2'):
    """Three-way SSTI verification"""
    
    # 1. Baseline (normal value)
    baseline_url = url.replace(f'{param}={{{{7*7}}}}', f'{param}=test123')
    baseline_resp = requests.get(baseline_url)
    
    # 2. Payload
    payload_url = url  # already has {{7*7}}
    payload_resp = requests.get(payload_url)
    
    # 3. Expected result
    expected_url = url.replace(f'{param}={{{{7*7}}}}', f'{param}=49')
    expected_resp = requests.get(expected_url)
    
    # Verify responses differ in expected way
    if (baseline_resp.content == payload_resp.content == expected_resp.content):
        # All identical - param ignored, NOT SSTI
        return False
    
    # Check if payload response contains '49' (template execution result)
    if b'49' in payload_resp.content and b'49' not in baseline_resp.content:
        return True
    
    return False
```

## 测试计划

1. **备份现有 recon**:
   ```bash
   cp -r recon/ohchr.org recon/ohchr.org.backup
   ```

2. **应用补丁并重新 surface**:
   ```bash
   # 手动执行过滤(测试)
   python3 tools/recon_filters.py recon/ohchr.org/urls/all.txt recon/ohchr.org/urls/all.txt ohchr.org
   bash tools/validate_api_candidates.sh recon/ohchr.org/exposure/api_leak_candidates.txt recon/ohchr.org/exposure/api_leak_candidates.txt
   
   # 重新排名
   python3 tools/surface.py --target ohchr.org > /tmp/ohchr_surface_clean.txt
   ```

3. **对比结果**:
   - P1 中应无外部 URL
   - API leak/doc candidates 应为 0 或极少
   - Total candidates 数量应减少 50-80%

