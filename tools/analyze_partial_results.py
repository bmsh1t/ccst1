#!/usr/bin/env python3
"""
分析所有扫描的部分结果（包括超时的）
"""

from pathlib import Path
import json

def analyze_target_findings(target):
    """分析单个目标的findings"""
    findings_dir = Path(f"findings/{target}")
    
    if not findings_dir.exists():
        return None
    
    result = {
        'target': target,
        'completed': (findings_dir / "summary.json").exists(),
        'findings': {}
    }
    
    vuln_types = ['ssti', 'sqli', 'ssrf', 'idor', 'redirects', 'xss', 
                  'upload', 'auth_bypass', 'misconfig', 'takeover', 'exposure']
    
    for vuln_type in vuln_types:
        type_dir = findings_dir / vuln_type
        
        if type_dir.exists():
            files = [f for f in type_dir.glob('*') if f.is_file() and f.stat().st_size > 0]
            
            if files:
                result['findings'][vuln_type] = {
                    'count': len(files),
                    'files': [{'name': f.name, 'size': f.stat().st_size} for f in files]
                }
    
    return result

def main():
    print("=== 所有扫描结果分析 (包括部分结果) ===\n")
    
    targets = ['article19.org', 'chinaaid.org', 'chinachange.org', 'cru.org', 'ifw-kiel.de']
    
    all_results = []
    total_candidates = 0
    
    for target in targets:
        result = analyze_target_findings(target)
        
        if result:
            all_results.append(result)
            
            status = "✅ 完成" if result['completed'] else "⏳ 部分结果"
            print(f"{status} {target}")
            
            if result['findings']:
                for vuln_type, data in sorted(result['findings'].items()):
                    print(f"  - {vuln_type}: {data['count']} 文件")
                    total_candidates += data['count']
            else:
                print(f"  - 无findings")
            
            print()
    
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"\n总结:")
    print(f"  扫描目标: {len(targets)}")
    print(f"  完成: {sum(1 for r in all_results if r['completed'])}")
    print(f"  部分结果: {sum(1 for r in all_results if not r['completed'])}")
    print(f"  总findings文件: {total_candidates}")
    
    # 按漏洞类型汇总
    by_type = {}
    for r in all_results:
        for vuln_type in r['findings']:
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(r['target'])
    
    if by_type:
        print(f"\n  按类型汇总:")
        for vuln_type, target_list in sorted(by_type.items()):
            print(f"    {vuln_type}: {len(target_list)} 目标")
    
    # 保存JSON
    output_file = Path("reports/all_scan_results.json")
    with open(output_file, 'w') as f:
        json.dump({
            'targets': all_results,
            'summary': {
                'total': len(targets),
                'completed': sum(1 for r in all_results if r['completed']),
                'partial': sum(1 for r in all_results if not r['completed']),
                'total_findings': total_candidates
            }
        }, f, indent=2)
    
    print(f"\n✅ 详细结果已保存: {output_file}")
    
    # 生成最终总结报告
    md_file = Path("reports/COMPLETE_HUNT_SUMMARY.md")
    with open(md_file, 'w') as f:
        f.write("# Complete Hunt Summary - All Results\n\n")
        f.write(f"**Generated:** 2026-06-08\n")
        f.write(f"**Targets:** {len(targets)}\n")
        f.write(f"**Completed:** {sum(1 for r in all_results if r['completed'])}\n")
        f.write(f"**Partial Results:** {sum(1 for r in all_results if not r['completed'])}\n\n")
        
        f.write("---\n\n")
        
        for r in all_results:
            status = "✅ COMPLETE" if r['completed'] else "⏳ PARTIAL"
            f.write(f"## {status}: {r['target']}\n\n")
            
            if r['findings']:
                f.write("**Findings:**\n")
                for vuln_type, data in sorted(r['findings'].items()):
                    f.write(f"- **{vuln_type}**: {data['count']} files\n")
                    for file_info in data['files']:
                        f.write(f"  - {file_info['name']} ({file_info['size']} bytes)\n")
            else:
                f.write("**Findings:** None\n")
            
            f.write("\n")
        
        f.write("---\n\n")
        f.write("## Key Statistics\n\n")
        f.write(f"- Total targets scanned: {len(targets)}\n")
        f.write(f"- Fully completed: {sum(1 for r in all_results if r['completed'])}\n")
        f.write(f"- Partial results available: {sum(1 for r in all_results if not r['completed'])}\n")
        f.write(f"- Total finding files: {total_candidates}\n\n")
        
        if by_type:
            f.write("## Findings by Type\n\n")
            for vuln_type, target_list in sorted(by_type.items()):
                f.write(f"- **{vuln_type}**: {len(target_list)} targets ({', '.join(target_list)})\n")
        
        f.write("\n---\n\n")
        f.write("**Next Steps:**\n")
        f.write("1. Validate findings from completed scan (chinachange.org)\n")
        f.write("2. Review partial results from other targets\n")
        f.write("3. Consider re-running timed-out scans if needed\n")
    
    print(f"✅ 总结报告已保存: {md_file}")

if __name__ == '__main__':
    main()
