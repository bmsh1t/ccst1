#!/bin/bash
# Test improved recon filters

echo "=== Test 1: Path explosion threshold 3 vs 4 ==="
cat > /tmp/test_paths.txt << 'PATHS'
https://target.com/api/users/123/groups/456/users/789
https://target.com/1/API/API/API/noticeError
https://target.com/v1/api/api/data
https://target.com/users/groups/users/data
PATHS

python3 << 'PYTHON'
from tools.recon_filters import detect_path_explosion

urls = [
    "https://target.com/api/users/123/groups/456/users/789",
    "https://target.com/1/API/API/API/noticeError",
    "https://target.com/v1/api/api/data",
    "https://target.com/users/groups/users/data"
]

print("Threshold=3 (old):")
for url in urls:
    result = detect_path_explosion(url, threshold=3)
    print(f"  {result}: {url}")

print("\nThreshold=4 (new, safer):")
for url in urls:
    result = detect_path_explosion(url, threshold=4)
    print(f"  {result}: {url}")
PYTHON

echo ""
echo "=== Test 2: Context-aware cache param detection ==="
python3 << 'PYTHON'
from tools.recon_filters import is_cache_param_in_context

test_cases = [
    ("https://target.com/api/search?v=2", "v", "API context - should be API version"),
    ("https://target.com/assets/main.js?v=123", "v", "Static asset - should be cache"),
    ("https://target.com/v1/users?version=2", "version", "API path - should be API version"),
    ("https://target.com/page?bust=456", "bust", "Always cache param"),
]

for url, param, desc in test_cases:
    result = is_cache_param_in_context(url, param)
    status = "CACHE" if result else "NOT_CACHE"
    print(f"  [{status}] {param} in {url}")
    print(f"         → {desc}")
PYTHON

echo ""
echo "=== Test 3: API candidate validation with preservation ==="
cat > /tmp/test_api_candidates.txt << 'CANDS'
https://target.com/api/v1/swagger.json
https://target.com/docs/api-reference.pdf
https://target.com/openapi.yaml
https://target.com/internal-setup.docx
https://target.com/api-docs/
CANDS

bash tools/validate_api_candidates.sh /tmp/test_api_candidates.txt /tmp/test_api_candidates.txt
echo "Files created:"
ls -la /tmp/test_api_candidates.txt*

