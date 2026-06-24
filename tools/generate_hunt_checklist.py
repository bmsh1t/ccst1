#!/usr/bin/env python3
"""
Generate actionable hunt checklists for each target
"""

import json
from pathlib import Path

def generate_checklist(target_data):
    """Generate hunt checklist from surface data"""
    
    target = target_data['target']
    vectors = target_data['high_value_vectors']
    
    checklist = []
    
    # Priority order based on bug bounty frequency
    priority_order = [
        ('idor', 'IDOR / Broken Access Control', 'High'),
        ('redirect', 'Open Redirect / URL Redirect', 'Medium'),
        ('ssrf', 'SSRF / URL Fetching', 'High'),
        ('sqli', 'SQL Injection', 'Critical'),
        ('xss', 'XSS / HTML Injection', 'Medium'),
        ('file_ops', 'File Upload/Download', 'High'),
        ('auth_bypass', 'Authentication Bypass', 'Critical'),
    ]
    
    for vuln_key, vuln_name, severity in priority_order:
        if vuln_key in vectors and vectors[vuln_key] > 0:
            checklist.append({
                'vulnerability': vuln_name,
                'severity': severity,
                'candidates': vectors[vuln_key],
                'key': vuln_key
            })
    
    return checklist

def main():
    # Load hunt surfaces
    surfaces_file = Path("reports/hunt_surfaces.json")
    with open(surfaces_file) as f:
        surfaces = json.load(f)
    
    # Generate checklists
    output = Path("reports/hunt_checklists.md")
    
    with open(output, 'w') as f:
        f.write("# Hunt Checklists - Actionable Testing Guide\n\n")
        f.write("**Generated:** 2026-06-07\n")
        f.write("**Purpose:** Step-by-step hunting workflow for each target\n\n")
        f.write("---\n\n")
        
        for target_name, target_data in surfaces.items():
            checklist = generate_checklist(target_data)
            
            f.write(f"## {target_name}\n\n")
            f.write(f"**Attack Surface:** {target_data['stats']['with_params']:,} URLs with params | "
                   f"{target_data['stats']['api_endpoints']:,} API endpoints\n\n")
            
            if not checklist:
                f.write("_No high-value vectors identified_\n\n")
                continue
            
            f.write("### Hunt Priority Order\n\n")
            
            for i, item in enumerate(checklist, 1):
                f.write(f"#### {i}. {item['vulnerability']} [{item['severity']}]\n\n")
                f.write(f"**Candidates:** {item['candidates']}\n\n")
                
                # Add testing methodology
                if item['key'] == 'idor':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify ID parameters (user, id, uid, account, etc.)\n")
                    f.write("2. Create 2 test accounts (User A, User B)\n")
                    f.write("3. Capture User A's ID in requests\n")
                    f.write("4. Replace with User B's ID → check if User A can access User B's data\n")
                    f.write("5. Test horizontal (same role) and vertical (different roles) access\n")
                
                elif item['key'] == 'redirect':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify redirect parameters (url, return, next, callback, etc.)\n")
                    f.write("2. Test: `?url=https://evil.com` → Check if redirects to external domain\n")
                    f.write("3. Bypass filters: `?url=//evil.com`, `?url=https://target.com@evil.com`\n")
                    f.write("4. Check for OAuth/SAML redirect_uri bypass\n")
                    f.write("5. Chain with XSS: `?url=javascript:alert(1)`\n")
                
                elif item['key'] == 'ssrf':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify URL-fetching parameters (url, uri, link, target, etc.)\n")
                    f.write("2. Test internal access: `?url=http://127.0.0.1`, `?url=http://169.254.169.254/`\n")
                    f.write("3. Cloud metadata: `?url=http://169.254.169.254/latest/meta-data/`\n")
                    f.write("4. Bypass: `?url=http://127.1`, `?url=http://[::1]`, DNS rebinding\n")
                    f.write("5. Check response disclosure (blind vs non-blind SSRF)\n")
                
                elif item['key'] == 'sqli':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify DB query parameters (id, search, filter, sort, etc.)\n")
                    f.write("2. Test error-based: `?id=1'` → Check for SQL error messages\n")
                    f.write("3. Test boolean: `?id=1 AND 1=1` vs `?id=1 AND 1=2` → Compare responses\n")
                    f.write("4. Test time-based: `?id=1 AND SLEEP(5)` → Check response delay\n")
                    f.write("5. Use sqlmap for automation: `sqlmap -u 'URL' --batch --level=2`\n")
                
                elif item['key'] == 'xss':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify reflection points (search, q, name, message, etc.)\n")
                    f.write("2. Test basic: `?q=<script>alert(1)</script>`\n")
                    f.write("3. Test stored: Submit payload in forms, check if persisted\n")
                    f.write("4. Bypass WAF: `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>`\n")
                    f.write("5. Check CSP header for restrictions\n")
                
                elif item['key'] == 'file_ops':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify file parameters (file, path, doc, filename, etc.)\n")
                    f.write("2. Test LFI: `?file=../../../etc/passwd`, `?file=....//....//etc/passwd`\n")
                    f.write("3. Test upload: Upload .php/.jsp/.aspx, double extension (.php.jpg)\n")
                    f.write("4. Test unrestricted file download (sensitive files via path traversal)\n")
                    f.write("5. Check file type validation (magic bytes vs extension)\n")
                
                elif item['key'] == 'auth_bypass':
                    f.write("**Test Method:**\n")
                    f.write("1. Identify auth parameters (admin, role, debug, token, etc.)\n")
                    f.write("2. Test parameter pollution: `?role=user&role=admin`\n")
                    f.write("3. Test JWT weaknesses (alg:none, weak secret, expired tokens)\n")
                    f.write("4. Test session fixation/hijacking\n")
                    f.write("5. Check for debug/admin endpoints without proper auth\n")
                
                f.write("\n**Reference:** Check `hunt_surfaces.md` for candidate URLs\n\n")
                f.write("---\n\n")
        
        f.write("\n## General Hunt Workflow\n\n")
        f.write("1. **Setup:** Configure Burp/Caido proxy, set target scope\n")
        f.write("2. **Authentication:** Create test accounts (if required)\n")
        f.write("3. **Baseline:** Browse app normally, understand functionality\n")
        f.write("4. **Systematic Testing:** Follow checklists above in priority order\n")
        f.write("5. **Documentation:** Record all findings with PoC screenshots\n")
        f.write("6. **Validation:** Run `/validate` before reporting\n")
        f.write("7. **Reporting:** Use `/report` to generate submission\n\n")
        
        f.write("## Tool References\n\n")
        f.write("- **High-value URLs:** `reports/hunt_surfaces.md`\n")
        f.write("- **All URLs:** `recon/<target>/urls/with_params.txt`\n")
        f.write("- **API endpoints:** `recon/<target>/urls/api_endpoints.txt`\n")
        f.write("- **Priority ranking:** `reports/hunt_priorities.md`\n")
    
    print(f"✅ Hunt checklists generated: {output}")
    
    # Generate quick stats
    surfaces_data = json.load(open(surfaces_file))
    total_candidates = 0
    
    for target_data in surfaces_data.values():
        total_candidates += sum(target_data['high_value_vectors'].values())
    
    print(f"\n📊 Summary:")
    print(f"   Targets: {len(surfaces_data)}")
    print(f"   Total high-value candidates: {total_candidates}")
    print(f"   Average per target: {total_candidates // len(surfaces_data)}")

if __name__ == '__main__':
    main()
