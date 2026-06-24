#!/usr/bin/env python3
"""
实时扫描监控工具
监控所有活跃hunt扫描的进度和发现
"""

import os
import json
from pathlib import Path
from datetime import datetime
import subprocess

def get_active_scans():
    """获取活跃的hunt扫描进程"""
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        
        scans = []
        for line in lines:
            if 'hunt.py' in line and '--target' in line:
                parts = line.split()
                pid = parts[1]
                
                # 提取目标名
                if '--target' in line:
                    idx = line.index('--target')
                    target = line[idx:].split()[1]
                    scans.append({'pid': pid, 'target': target})
        
        return scans
    except Exception as e:
        return []

def analyze_findings(target):
    """分析单个目标的findings"""
    findings_dir = Path(f"findings/{target}")
    
    if not findings_dir.exists():
        return None
    
    stats = {
        'target': target,
        'total_files': 0,
        'non_empty_files': 0,
        'findings_by_type': {},
        'has_summary': False
    }
    
    # 统计文件
    for item in findings_dir.rglob('*'):
        if item.is_file():
            stats['total_files'] += 1
            
            if item.stat().st_size > 0:
                stats['non_empty_files'] += 1
                
                # 按类型分类
                parent_name = item.parent.name
                if parent_name not in ['.tmp', findings_dir.name]:
                    if parent_name not in stats['findings_by_type']:
                        stats['findings_by_type'][parent_name] = 0
                    stats['findings_by_type'][parent_name] += 1
    
    # 检查summary
    summary_file = findings_dir / "summary.json"
    if summary_file.exists():
        stats['has_summary'] = True
        try:
            with open(summary_file) as f:
                summary = json.load(f)
                stats['summary'] = summary
        except:
            pass
    
    return stats

def main():
    print("=== Hunt扫描监控 ===")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 获取活跃扫描
    active_scans = get_active_scans()
    print(f"活跃扫描: {len(active_scans)}")
    
    if active_scans:
        for scan in active_scans:
            print(f"  PID {scan['pid']}: {scan['target']}")
    
    print()
    
    # 分析所有目标的findings
    targets = ['article19.org', 'chinaaid.org', 'chinachange.org', 'cru.org', 'ifw-kiel.de']
    
    print("━━━ Findings状态 ━━━")
    print()
    
    total_findings = 0
    
    for target in targets:
        stats = analyze_findings(target)
        
        if stats:
            print(f"【{target}】")
            print(f"  文件: {stats['non_empty_files']}/{stats['total_files']} 非空")
            
            if stats['findings_by_type']:
                print(f"  发现类型:")
                for vuln_type, count in sorted(stats['findings_by_type'].items()):
                    print(f"    - {vuln_type}: {count} 文件")
                    total_findings += count
            
            if stats['has_summary']:
                print(f"  ✓ summary.json 已生成")
            else:
                print(f"  ⏳ 扫描进行中...")
            
            print()
    
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"总findings文件: {total_findings}")
    print()
    
    # 生成JSON输出
    output_file = Path("reports/scan_monitor_output.json")
    output_data = {
        'timestamp': datetime.now().isoformat(),
        'active_scans': len(active_scans),
        'targets': targets,
        'total_findings': total_findings,
        'details': {}
    }
    
    for target in targets:
        stats = analyze_findings(target)
        if stats:
            output_data['details'][target] = stats
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"详细数据已保存: {output_file}")

if __name__ == '__main__':
    main()
