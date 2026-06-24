#!/usr/bin/env python3
"""
Findings分析工具 - 分析扫描发现的详情
"""

from pathlib import Path
import json

def analyze_finding_file(filepath):
    """分析单个finding文件"""
    if filepath.stat().st_size == 0:
        return None
    
    try:
        content = filepath.read_text()
        lines = [l.strip() for l in content.split('\n') if l.strip()]
        
        return {
            'file': str(filepath),
            'size': filepath.stat().st_size,
            'lines': len(lines),
            'preview': lines[:5] if lines else []
        }
    except:
        return None

def main():
    print("=== Findings详细分析 ===\n")
    
    targets = ['article19.org', 'chinaaid.org', 'chinachange.org', 'cru.org', 'ifw-kiel.de']
    
    all_findings = []
    
    for target in targets:
        findings_dir = Path(f"findings/{target}")
        
        if not findings_dir.exists():
            continue
        
        print(f"━━━ {target} ━━━")
        
        # 查找非空文件
        for vuln_type in ['ssti', 'takeover', 'misconfig', 'sqli', 'ssrf', 'idor', 'redirects']:
            type_dir = findings_dir / vuln_type
            
            if not type_dir.exists():
                continue
            
            for finding_file in type_dir.glob('*'):
                if finding_file.is_file() and finding_file.stat().st_size > 0:
                    analysis = analyze_finding_file(finding_file)
                    
                    if analysis:
                        print(f"\n【{vuln_type.upper()}】 {finding_file.name}")
                        print(f"  大小: {analysis['size']} bytes")
                        print(f"  行数: {analysis['lines']}")
                        
                        if analysis['preview']:
                            print(f"  预览:")
                            for line in analysis['preview']:
                                # 截断长行
                                display_line = line[:100] + '...' if len(line) > 100 else line
                                print(f"    {display_line}")
                        
                        all_findings.append({
                            'target': target,
                            'type': vuln_type,
                            **analysis
                        })
        
        print()
    
    # 生成总结
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"总发现: {len(all_findings)} 个文件\n")
    
    # 按类型统计
    by_type = {}
    for f in all_findings:
        vuln_type = f['type']
        if vuln_type not in by_type:
            by_type[vuln_type] = []
        by_type[vuln_type].append(f['target'])
    
    print("按漏洞类型:")
    for vuln_type, targets in sorted(by_type.items()):
        print(f"  {vuln_type.upper()}: {len(targets)} 个目标 ({', '.join(targets)})")
    
    print()
    
    # 保存详细分析
    output_file = Path("reports/findings_analysis.json")
    with open(output_file, 'w') as f:
        json.dump({
            'total': len(all_findings),
            'by_type': {k: len(v) for k, v in by_type.items()},
            'details': all_findings
        }, f, indent=2)
    
    print(f"详细分析已保存: {output_file}")
    
    # 生成markdown报告
    md_file = Path("reports/findings_summary.md")
    with open(md_file, 'w') as f:
        f.write("# Findings Summary\n\n")
        f.write(f"**Total Findings:** {len(all_findings)}\n\n")
        f.write("## By Vulnerability Type\n\n")
        
        for vuln_type, target_list in sorted(by_type.items()):
            f.write(f"### {vuln_type.upper()} ({len(target_list)})\n\n")
            for target in target_list:
                f.write(f"- {target}\n")
            f.write("\n")
        
        f.write("## Detailed Findings\n\n")
        
        for finding in all_findings:
            f.write(f"### {finding['target']} - {finding['type'].upper()}\n\n")
            f.write(f"- **File:** `{finding['file']}`\n")
            f.write(f"- **Size:** {finding['size']} bytes\n")
            f.write(f"- **Lines:** {finding['lines']}\n\n")
            
            if finding['preview']:
                f.write("**Preview:**\n```\n")
                for line in finding['preview'][:3]:
                    f.write(line[:100] + "\n")
                f.write("```\n\n")
    
    print(f"Markdown报告已保存: {md_file}")
    
    print()
    print("⚠️  注意: 这些是扫描器的初步发现，需要验证")
    print("建议: 使用 /validate 命令验证每个候选")

if __name__ == '__main__':
    main()
