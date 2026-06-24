#!/usr/bin/env python3
"""
Batch Hunt Preparation Tool
Generates hunt-ready attack surface files from denoised recon data
"""

import json
import os
from pathlib import Path
from collections import defaultdict

def analyze_target(target_dir):
    """Extract hunt-ready metrics from a target directory"""
    urls_dir = target_dir / "urls"
    
    if not urls_dir.exists():
        return None
    
    # Load URL files
    all_urls = set()
    with_params = set()
    api_endpoints = set()
    
    if (urls_dir / "all.txt").exists():
        all_urls = set((urls_dir / "all.txt").read_text().strip().split('\n'))
    
    if (urls_dir / "with_params.txt").exists():
        with_params = set((urls_dir / "with_params.txt").read_text().strip().split('\n'))
    
    if (urls_dir / "api_endpoints.txt").exists():
        api_endpoints = set((urls_dir / "api_endpoints.txt").read_text().strip().split('\n'))
    
    # Parameter diversity analysis
    param_names = defaultdict(int)
    for url in with_params:
        if '?' in url:
            params = url.split('?')[1]
            for param in params.split('&'):
                if '=' in param:
                    name = param.split('=')[0]
                    param_names[name] += 1
    
    # High-value parameter detection
    high_value_params = ['id', 'user', 'file', 'path', 'url', 'redirect', 
                         'callback', 'return', 'next', 'debug', 'admin']
    found_high_value = {k: v for k, v in param_names.items() 
                        if any(hv in k.lower() for hv in high_value_params)}
    
    # Extension analysis for upload testing
    extensions = defaultdict(int)
    for url in all_urls:
        if '.' in url.split('/')[-1]:
            ext = url.split('.')[-1].split('?')[0].lower()
            if len(ext) <= 5:  # reasonable extension length
                extensions[ext] += 1
    
    return {
        'total_urls': len(all_urls),
        'with_params': len(with_params),
        'api_endpoints': len(api_endpoints),
        'param_diversity': len(param_names),
        'high_value_params': found_high_value,
        'top_params': dict(sorted(param_names.items(), key=lambda x: x[1], reverse=True)[:20]),
        'extensions': dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:15]),
        'denoised': (target_dir / ".denoised").exists()
    }

def generate_hunt_priorities(targets_data):
    """Generate hunting priority recommendations"""
    priorities = []
    
    for target, data in targets_data.items():
        if data is None:
            continue
        
        score = 0
        reasons = []
        
        # API surface
        if data['api_endpoints'] > 100:
            score += 30
            reasons.append(f"Rich API surface ({data['api_endpoints']} endpoints)")
        elif data['api_endpoints'] > 10:
            score += 15
            reasons.append(f"Moderate API surface ({data['api_endpoints']} endpoints)")
        
        # Parameter diversity
        if data['param_diversity'] > 50:
            score += 25
            reasons.append(f"High param diversity ({data['param_diversity']} unique)")
        elif data['param_diversity'] > 20:
            score += 15
            reasons.append(f"Moderate param diversity ({data['param_diversity']} unique)")
        
        # High-value parameters
        if data['high_value_params']:
            score += 20
            top_hvp = list(data['high_value_params'].keys())[:3]
            reasons.append(f"High-value params: {', '.join(top_hvp)}")
        
        # URL volume (attack surface breadth)
        if data['with_params'] > 10000:
            score += 15
            reasons.append(f"Large param surface ({data['with_params']})")
        elif data['with_params'] > 1000:
            score += 10
        
        priorities.append({
            'target': target,
            'score': score,
            'reasons': reasons,
            'data': data
        })
    
    return sorted(priorities, key=lambda x: x['score'], reverse=True)

def main():
    recon_dir = Path("recon")
    targets_data = {}
    
    # Scan all target directories
    for target_path in sorted(recon_dir.iterdir()):
        if target_path.is_dir():
            target_name = target_path.name
            targets_data[target_name] = analyze_target(target_path)
    
    # Generate hunt priorities
    priorities = generate_hunt_priorities(targets_data)
    
    # Save detailed JSON report
    output_file = Path("reports/hunt_priorities.json")
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump({
            'targets': targets_data,
            'priorities': priorities[:20]  # Top 20
        }, f, indent=2)
    
    # Generate markdown summary
    md_output = Path("reports/hunt_priorities.md")
    with open(md_output, 'w') as f:
        f.write("# Hunt Priority Recommendations\n\n")
        f.write(f"**Generated:** 2026-06-07\n")
        f.write(f"**Targets Analyzed:** {len([d for d in targets_data.values() if d])}\n\n")
        f.write("## Top 10 Priority Targets\n\n")
        
        for i, p in enumerate(priorities[:10], 1):
            f.write(f"### {i}. {p['target']} (Score: {p['score']})\n\n")
            f.write("**Why hunt here:**\n")
            for reason in p['reasons']:
                f.write(f"- {reason}\n")
            f.write("\n**Attack Surface:**\n")
            f.write(f"- Total URLs: {p['data']['total_urls']:,}\n")
            f.write(f"- URLs with params: {p['data']['with_params']:,}\n")
            f.write(f"- API endpoints: {p['data']['api_endpoints']:,}\n")
            
            if p['data']['high_value_params']:
                f.write("\n**High-Value Parameters:**\n")
                for param, count in list(p['data']['high_value_params'].items())[:5]:
                    f.write(f"- `{param}`: {count} occurrences\n")
            
            f.write(f"\n**Denoised:** {'✅ Yes' if p['data']['denoised'] else '❌ No'}\n\n")
            f.write("---\n\n")
    
    print(f"✅ Hunt priorities generated:")
    print(f"   - {output_file}")
    print(f"   - {md_output}")
    print(f"\n📊 Top 5 targets:")
    for i, p in enumerate(priorities[:5], 1):
        print(f"   {i}. {p['target']} (score: {p['score']})")

if __name__ == '__main__':
    main()
