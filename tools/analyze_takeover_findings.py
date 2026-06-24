#!/usr/bin/env python3
"""
Subdomain Takeover发现分析工具
"""

from pathlib import Path
import re

def analyze_takeover_file(filepath):
    """分析subdomain takeover结果"""
    if not filepath.exists():
        return None
    
    content = filepath.read_text()
    lines = content.split('\n')
    
    vulnerable = []
    not_vulnerable = []
    
    for line in lines:
        if '[Vulnerable]' in line or 'VULNERABLE' in line:
            # 提取子域名
            match = re.search(r'\[Vulnerable\]\s+(\S+)', line)
            if match:
                vulnerable.append(match.group(1))
        elif '[Not Vulnerable]' in line:
            match = re.search(r'\[Not Vulnerable\]\s+(\S+)', line)
            if match:
                not_vulnerable.append(match.group(1))
    
    return {
        'vulnerable': vulnerable,
        'not_vulnerable': not_vulnerable,
        'total_checked': len(vulnerable) + len(not_vulnerable)
    }

def main():
    print("=== Subdomain Takeover 发现分析 ===\n")
    
    targets = ['article19.org', 'chinaaid.org', 'chinachange.org', 'cru.org', 'ifw-kiel.de']
    
    all_vulnerable = []
    
    for target in targets:
        takeover_file = Path(f"findings/{target}/takeover/subjack_results.txt")
        
        if not takeover_file.exists():
            continue
        
        result = analyze_takeover_file(takeover_file)
        
        if result:
            print(f"【{target}】")
            print(f"  检查总数: {result['total_checked']}")
            print(f"  Vulnerable: {len(result['vulnerable'])}")
            print(f"  Not Vulnerable: {len(result['not_vulnerable'])}")
            
            if result['vulnerable']:
                print(f"\n  ⚠️  VULNERABLE子域:")
                for subdomain in result['vulnerable'][:10]:  # 显示前10个
                    print(f"    - {subdomain}")
                    all_vulnerable.append({
                        'target': target,
                        'subdomain': subdomain
                    })
                
                if len(result['vulnerable']) > 10:
                    print(f"    ... 和 {len(result['vulnerable']) - 10} 个更多")
            
            print()
    
    if all_vulnerable:
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f"⚠️  总Vulnerable子域: {len(all_vulnerable)}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        
        # 保存到文件
        output_file = Path("hunt_targets/vulnerable_subdomains.txt")
        with open(output_file, 'w') as f:
            f.write("# Vulnerable Subdomains - REQUIRES VALIDATION\n\n")
            for item in all_vulnerable:
                f.write(f"{item['subdomain']} ({item['target']})\n")
        
        print(f"✅ Vulnerable列表已保存: {output_file}")
        print()
        print("⚠️  重要: 'Vulnerable'表示subjack检测到潜在问题")
        print("        需要手动验证确认是否真的可接管")
    else:
        print("✅ 未发现vulnerable子域")

if __name__ == '__main__':
    main()
