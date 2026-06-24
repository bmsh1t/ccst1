#!/usr/bin/env python3
"""
Hunt Surface Extractor
Extracts high-value attack vectors from denoised recon data for immediate hunting
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

def extract_high_value_endpoints(target, urls_dir):
    """Extract URLs with high-value parameters and patterns"""
    
    high_value_patterns = {
        'redirect': ['redirect', 'return', 'next', 'callback', 'continue', 'url', 'goto', 'forward'],
        'idor': ['id', 'user', 'uid', 'account', 'profile', 'userid', 'user_id'],
        'file_ops': ['file', 'path', 'doc', 'download', 'upload', 'attachment', 'filename'],
        'ssrf': ['url', 'uri', 'link', 'target', 'host', 'proxy', 'fetch'],
        'sqli': ['id', 'search', 'query', 'filter', 'sort', 'order', 'where'],
        'xss': ['search', 'q', 'query', 'name', 'message', 'comment', 'text'],
        'auth_bypass': ['admin', 'role', 'privilege', 'auth', 'token', 'session', 'debug'],
    }
    
    results = defaultdict(list)
    
    # Load URLs with parameters
    with_params_file = urls_dir / "with_params.txt"
    if not with_params_file.exists():
        return results
    
    urls = with_params_file.read_text().strip().split('\n')
    
    for url in urls:
        if not url or '?' not in url:
            continue
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_names = [p.lower() for p in params.keys()]
        
        # Check each vulnerability class
        for vuln_class, keywords in high_value_patterns.items():
            for param_name in param_names:
                if any(kw in param_name for kw in keywords):
                    results[vuln_class].append({
                        'url': url,
                        'param': param_name,
                        'path': parsed.path
                    })
                    break  # Only count once per URL per class
    
    # Deduplicate by path+param combination
    for vuln_class in results:
        seen = set()
        unique = []
        for item in results[vuln_class]:
            key = f"{item['path']}:{item['param']}"
            if key not in seen:
                seen.add(key)
                unique.append(item)
        results[vuln_class] = unique[:50]  # Top 50 per class
    
    return results

def extract_api_endpoints_by_type(target, urls_dir):
    """Categorize API endpoints by type"""
    
    api_file = urls_dir / "api_endpoints.txt"
    if not api_file.exists():
        return {}
    
    apis = api_file.read_text().strip().split('\n')
    
    categories = {
        'rest_api': [],
        'graphql': [],
        'swagger': [],
        'json_files': [],
        'xml_files': [],
    }
    
    for url in apis[:500]:  # Limit to top 500
        if not url:
            continue
        
        url_lower = url.lower()
        
        if 'graphql' in url_lower:
            categories['graphql'].append(url)
        elif any(x in url_lower for x in ['swagger', 'openapi']):
            categories['swagger'].append(url)
        elif '/api/' in url_lower or '/v1/' in url_lower or '/v2/' in url_lower:
            categories['rest_api'].append(url)
        elif url_lower.endswith('.json'):
            categories['json_files'].append(url)
        elif url_lower.endswith(('.xml', '.wsdl', '.wadl')):
            categories['xml_files'].append(url)
    
    return {k: v for k, v in categories.items() if v}

def generate_hunt_surface(target_name):
    """Generate hunt surface for a target"""
    
    target_dir = Path(f"recon/{target_name}")
    urls_dir = target_dir / "urls"
    
    if not urls_dir.exists():
        return None
    
    # Extract high-value vectors
    high_value = extract_high_value_endpoints(target_name, urls_dir)
    api_categories = extract_api_endpoints_by_type(target_name, urls_dir)
    
    # Count statistics
    total_urls = sum(1 for _ in open(urls_dir / "all.txt")) if (urls_dir / "all.txt").exists() else 0
    with_params = sum(1 for _ in open(urls_dir / "with_params.txt")) if (urls_dir / "with_params.txt").exists() else 0
    
    return {
        'target': target_name,
        'stats': {
            'total_urls': total_urls,
            'with_params': with_params,
            'api_endpoints': sum(len(v) for v in api_categories.values())
        },
        'high_value_vectors': {k: len(v) for k, v in high_value.items()},
        'high_value_urls': high_value,
        'api_categories': api_categories
    }

def main():
    # Top 5 priority targets
    top_targets = [
        'article19.org',
        'chinaaid.org',
        'chinachange.org',
        'cru.org',
        'ifw-kiel.de'
    ]
    
    print("=== Extracting Hunt Surfaces for Top 5 Targets ===\n")
    
    all_surfaces = {}
    
    for target in top_targets:
        print(f"Processing {target}...")
        surface = generate_hunt_surface(target)
        
        if surface:
            all_surfaces[target] = surface
            
            # Output summary
            print(f"  ✓ {surface['stats']['total_urls']:,} URLs")
            print(f"  ✓ {surface['stats']['with_params']:,} with params")
            print(f"  ✓ {surface['stats']['api_endpoints']:,} API endpoints")
            
            if surface['high_value_vectors']:
                print(f"  📊 High-value vectors:")
                for vuln, count in sorted(surface['high_value_vectors'].items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        print(f"      - {vuln}: {count}")
            print()
    
    # Save detailed JSON
    output_json = Path("reports/hunt_surfaces.json")
    with open(output_json, 'w') as f:
        json.dump(all_surfaces, f, indent=2)
    
    # Generate markdown hunt guide
    output_md = Path("reports/hunt_surfaces.md")
    with open(output_md, 'w') as f:
        f.write("# Hunt Surfaces - Top 5 Priority Targets\n\n")
        f.write("**Generated:** 2026-06-07\n")
        f.write("**Purpose:** Immediate hunting guide with high-value attack vectors\n\n")
        f.write("---\n\n")
        
        for target, data in all_surfaces.items():
            f.write(f"## {target}\n\n")
            
            f.write("### Statistics\n")
            f.write(f"- Total URLs: {data['stats']['total_urls']:,}\n")
            f.write(f"- URLs with parameters: {data['stats']['with_params']:,}\n")
            f.write(f"- API endpoints: {data['stats']['api_endpoints']:,}\n\n")
            
            if data['high_value_vectors']:
                f.write("### High-Value Attack Vectors\n\n")
                for vuln_class, count in sorted(data['high_value_vectors'].items(), key=lambda x: x[1], reverse=True):
                    if count > 0:
                        f.write(f"#### {vuln_class.upper().replace('_', ' ')} ({count} candidates)\n\n")
                        
                        # Show top 5 examples
                        examples = data['high_value_urls'][vuln_class][:5]
                        for ex in examples:
                            f.write(f"- Parameter: `{ex['param']}`\n")
                            f.write(f"  ```\n  {ex['url']}\n  ```\n")
                        
                        if len(data['high_value_urls'][vuln_class]) > 5:
                            f.write(f"  _...and {len(data['high_value_urls'][vuln_class]) - 5} more_\n")
                        f.write("\n")
            
            if data['api_categories']:
                f.write("### API Endpoints by Type\n\n")
                for api_type, urls in data['api_categories'].items():
                    f.write(f"#### {api_type.replace('_', ' ').title()} ({len(urls)})\n\n")
                    for url in urls[:3]:
                        f.write(f"- `{url}`\n")
                    if len(urls) > 3:
                        f.write(f"- _...and {len(urls) - 3} more_\n")
                    f.write("\n")
            
            f.write("---\n\n")
    
    print(f"\n✅ Hunt surfaces extracted:")
    print(f"   - {output_json}")
    print(f"   - {output_md}")
    print(f"\n📊 Total high-value vectors across all targets:")
    
    vuln_totals = defaultdict(int)
    for data in all_surfaces.values():
        for vuln, count in data['high_value_vectors'].items():
            vuln_totals[vuln] += count
    
    for vuln, total in sorted(vuln_totals.items(), key=lambda x: x[1], reverse=True):
        if total > 0:
            print(f"   - {vuln}: {total}")

if __name__ == '__main__':
    main()
