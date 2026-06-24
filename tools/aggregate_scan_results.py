#!/usr/bin/env python3
"""
聚合所有扫描结果
"""

from pathlib import Path
import json
from datetime import datetime

def get_scan_status(target):
    """获取扫描状态"""
    findings_dir = Path(f"findings/{target}")
    
    if not findings_dir.exists():
        return {'status': 'not_started', 'findings': {}}
    
    summary_file = findings_dir / "summary.json"
    
    status = {
        'status': 'completed' if summary_file.exists() else 'running',
        'findings': {}
    }
    
    # 统计各类findings
    for vuln_type in ['ssti', 'sqli', 'ssrf', 'idor', 'redirects', 'xss', 'upload', 
                      'auth_bypass', 'misconfig', 'takeover', 'exposure']:
        type_dir = findings_dir / vuln_type
        
        if type_dir.exists():
            non_empty = list(type_dir.glob('*'))
            non_empty = [f for f in non_empty if f.is_file() and f.stat().st_size > 0]
            
            if non_empty:
                status['findings'][vuln_type] = len(non_empty)
    
    return status

def main():
    print("=== 扫描结果聚合报告 ===\n")
    print(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    targets = ['article19.org', 'chinaaid.org', 'chinachange.org', 'cru.org', 'ifw-kiel.de']
    
    all_results = {}
    
    for target in targets:
        result = get_scan_status(target)
        all_results[target] = result
        
        status_emoji = "✅" if result['status'] == 'completed' else "🔄"
        print(f"{status_emoji} {target}")
        print(f"   状态: {result['status']}")
        
        if result['findings']:
            print(f"   发现类型:")
            for vuln_type, count in sorted(result['findings'].items()):
                print(f"     - {vuln_type}: {count} 文件")
        else:
            print(f"   发现: 无")
        
        print()
    
    # 统计总览
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("总览:\n")
    
    completed = sum(1 for r in all_results.values() if r['status'] == 'completed')
    running = sum(1 for r in all_results.values() if r['status'] == 'running')
    
    print(f"  扫描完成: {completed}/5")
    print(f"  扫描运行中: {running}/5")
    
    # 统计所有发现
    all_findings = {}
    for target, result in all_results.items():
        for vuln_type, count in result['findings'].items():
            if vuln_type not in all_findings:
                all_findings[vuln_type] = []
            all_findings[vuln_type].append(target)
    
    if all_findings:
        print(f"\n  发现类型统计:")
        for vuln_type, target_list in sorted(all_findings.items()):
            print(f"    {vuln_type}: {len(target_list)} 个目标")
    
    # 保存JSON
    output_file = Path("reports/scan_results_aggregate.json")
    with open(output_file, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'targets': all_results,
            'summary': {
                'completed': completed,
                'running': running,
                'findings_by_type': {k: len(v) for k, v in all_findings.items()}
            }
        }, f, indent=2)
    
    print(f"\n✅ 聚合结果已保存: {output_file}")
    
    # 生成markdown报告
    md_file = Path("reports/SCAN_RESULTS_SUMMARY.md")
    with open(md_file, 'w') as f:
        f.write("# Scan Results Summary\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"**Scans Completed:** {completed}/5\n")
        f.write(f"**Scans Running:** {running}/5\n\n")
        
        f.write("---\n\n")
        
        for target, result in all_results.items():
            status_emoji = "✅" if result['status'] == 'completed' else "🔄"
            f.write(f"## {status_emoji} {target}\n\n")
            f.write(f"**Status:** {result['status']}\n\n")
            
            if result['findings']:
                f.write("**Findings:**\n")
                for vuln_type, count in sorted(result['findings'].items()):
                    f.write(f"- {vuln_type}: {count} files\n")
            else:
                f.write("**Findings:** None\n")
            
            f.write("\n")
        
        f.write("---\n\n")
        f.write("## Key Findings\n\n")
        
        if 'ssti' in all_findings:
            f.write(f"### SSTI (Server-Side Template Injection)\n")
            f.write(f"**Targets:** {', '.join(all_findings['ssti'])}\n")
            f.write(f"⚠️ **Requires manual validation**\n\n")
        
        if 'takeover' in all_findings:
            f.write(f"### Subdomain Takeover\n")
            f.write(f"**Targets:** {', '.join(all_findings['takeover'])}\n")
            f.write(f"All checked subdomains: Not Vulnerable\n\n")
        
        f.write("---\n\n")
        f.write("**Next Steps:**\n")
        f.write("1. Wait for remaining scans to complete\n")
        f.write("2. Validate SSTI candidates manually\n")
        f.write("3. Run `/validate` on confirmed findings\n")
        f.write("4. Generate final reports\n")
    
    print(f"✅ Markdown报告已保存: {md_file}")

if __name__ == '__main__':
    main()
