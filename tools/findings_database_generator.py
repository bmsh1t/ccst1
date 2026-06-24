#!/usr/bin/env python3
"""
Findings Database Generator
Converts all raw findings into structured JSON database
"""

import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List

class FindingsDatabase:
    def __init__(self):
        self.database = {
            "generated_at": datetime.now().isoformat(),
            "version": "1.0",
            "targets": {},
            "statistics": {}
        }

    def parse_ssti_findings(self, file_path: Path) -> List[Dict]:
        """Parse SSTI candidates from text file"""
        findings = []
        if not file_path.exists():
            return findings

        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('[SSTI'):
                    continue

                # Parse: [SSTI-CONFIRMED] engine=jinja2 url=https://...
                match = re.match(r'\[SSTI-CONFIRMED\]\s+engine=(\w+)\s+url=(.+)', line)
                if match:
                    findings.append({
                        "type": "ssti",
                        "engine": match.group(1),
                        "url": match.group(2),
                        "confidence": "scanner_detected",
                        "status": "candidate",
                        "validated": False
                    })

        return findings

    def parse_cors_findings(self, file_path: Path) -> List[Dict]:
        """Parse CORS misconfig from text file"""
        findings = []
        if not file_path.exists():
            return findings

        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if 'cors-misconfig' not in line.lower():
                    continue

                # Parse nuclei output
                match = re.search(r'(https?://[^\s]+)', line)
                origin_match = re.search(r'cors_origin="([^"]+)"', line)

                if match:
                    finding = {
                        "type": "cors_misconfiguration",
                        "url": match.group(1),
                        "confidence": "high",
                        "status": "confirmed",
                        "validated": False,
                        "tool": "nuclei"
                    }
                    if origin_match:
                        finding["reflected_origin"] = origin_match.group(1)

                    findings.append(finding)

        return findings

    def parse_exposure_findings(self, file_path: Path) -> List[Dict]:
        """Parse information exposure findings"""
        findings = []
        if not file_path.exists():
            return findings

        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    findings.append({
                        "type": "information_exposure",
                        "status_code": int(parts[0]),
                        "url": parts[1],
                        "confidence": "confirmed",
                        "severity": "info",
                        "validated": False
                    })

        return findings

    def parse_ssrf_params(self, file_path: Path) -> List[Dict]:
        """Parse SSRF parameter candidates"""
        findings = []
        if not file_path.exists():
            return findings

        with open(file_path, 'r') as f:
            for line in f:
                param = line.strip()
                if param:
                    findings.append({
                        "type": "ssrf_parameter",
                        "parameter_name": param,
                        "confidence": "low",
                        "status": "parameter_identified",
                        "validated": False,
                        "requires": "endpoint_mapping"
                    })

        return findings

    def parse_redirect_params(self, file_path: Path) -> List[Dict]:
        """Parse redirect parameter candidates"""
        findings = []
        if not file_path.exists():
            return findings

        with open(file_path, 'r') as f:
            for line in f:
                param = line.strip()
                if param:
                    findings.append({
                        "type": "open_redirect_parameter",
                        "parameter_name": param,
                        "confidence": "low",
                        "status": "parameter_identified",
                        "validated": False,
                        "requires": "endpoint_mapping"
                    })

        return findings

    def parse_idor_endpoints(self, file_path: Path, target: str) -> List[Dict]:
        """Parse IDOR API endpoints"""
        findings = []
        if not file_path.exists():
            return findings

        endpoints = defaultdict(list)
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('http'):
                    continue

                if '/wp-json/' in line:
                    parts = line.split('/wp-json/')
                    if len(parts) > 1:
                        api_path = parts[1]
                        base = '/'.join(api_path.split('/')[:3])

                        id_match = re.search(r'/(\d+)/?$', line)
                        if id_match:
                            endpoints[base].append(int(id_match.group(1)))

        for base, ids in endpoints.items():
            findings.append({
                "type": "idor_endpoint",
                "endpoint_base": f"/wp-json/{base}",
                "total_ids_found": len(ids),
                "id_range": {"min": min(ids), "max": max(ids)},
                "confidence": "medium",
                "status": "requires_authentication_test",
                "validated": False,
                "test_plan_available": True
            })

        return findings

    def parse_takeover_findings(self, file_path: Path) -> List[Dict]:
        """Parse subdomain takeover findings"""
        findings = []
        if not file_path.exists():
            return findings

        vulnerable_count = 0
        not_vulnerable_count = 0

        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if '[Vulnerable]' in line:
                    vulnerable_count += 1
                    subdomain = line.split()[1] if len(line.split()) > 1 else 'unknown'
                    findings.append({
                        "type": "subdomain_takeover",
                        "subdomain": subdomain,
                        "status": "vulnerable",
                        "confidence": "high",
                        "validated": False
                    })
                elif '[Not Vulnerable]' in line:
                    not_vulnerable_count += 1

        # Add summary even if no vulnerabilities
        if not_vulnerable_count > 0 and vulnerable_count == 0:
            findings.append({
                "type": "subdomain_takeover_summary",
                "tested": not_vulnerable_count,
                "vulnerable": 0,
                "status": "clean"
            })

        return findings

    def process_target(self, target: str) -> Dict:
        """Process all findings for a target"""
        findings_dir = Path(f"findings/{target}")

        if not findings_dir.exists():
            return None

        target_data = {
            "target": target,
            "findings": [],
            "scan_status": "complete" if (findings_dir / "summary.json").exists() else "partial",
            "findings_by_type": defaultdict(int)
        }

        # Parse each vulnerability type
        parsers = [
            ("ssti/ssti_candidates.txt", self.parse_ssti_findings),
            ("misconfig/cors.txt", self.parse_cors_findings),
            ("exposure/verified_sensitive.txt", self.parse_exposure_findings),
            ("ssrf/ssrf_params_manual.txt", self.parse_ssrf_params),
            ("redirects/redirect_params_manual.txt", self.parse_redirect_params),
            ("takeover/subjack_results.txt", self.parse_takeover_findings),
        ]

        for file_path, parser_func in parsers:
            full_path = findings_dir / file_path
            parsed = parser_func(full_path)
            target_data["findings"].extend(parsed)

        # Parse IDOR separately (needs target param)
        idor_findings = self.parse_idor_endpoints(findings_dir / "idor/api_sequential_ids.txt", target)
        target_data["findings"].extend(idor_findings)

        # Count by type
        for finding in target_data["findings"]:
            target_data["findings_by_type"][finding["type"]] += 1

        return target_data

    def generate_database(self, targets: List[str]) -> Dict:
        """Generate complete findings database"""
        for target in targets:
            target_data = self.process_target(target)
            if target_data:
                self.database["targets"][target] = target_data

        # Generate statistics
        total_findings = 0
        findings_by_type = defaultdict(int)
        confidence_breakdown = defaultdict(int)
        status_breakdown = defaultdict(int)

        for target, data in self.database["targets"].items():
            total_findings += len(data["findings"])
            for finding in data["findings"]:
                findings_by_type[finding["type"]] += 1
                if "confidence" in finding:
                    confidence_breakdown[finding["confidence"]] += 1
                if "status" in finding:
                    status_breakdown[finding["status"]] += 1

        self.database["statistics"] = {
            "total_targets": len(self.database["targets"]),
            "total_findings": total_findings,
            "findings_by_type": dict(findings_by_type),
            "confidence_breakdown": dict(confidence_breakdown),
            "status_breakdown": dict(status_breakdown)
        }

        return self.database

    def export_json(self, output_file: Path):
        """Export database to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.database, f, indent=2)
        print(f"✅ Database exported: {output_file}")

    def export_summary(self, output_file: Path):
        """Export human-readable summary"""
        with open(output_file, 'w') as f:
            f.write("# Findings Database Summary\n\n")
            f.write(f"Generated: {self.database['generated_at']}\n\n")

            f.write("## Statistics\n\n")
            stats = self.database["statistics"]
            f.write(f"- Total Targets: {stats['total_targets']}\n")
            f.write(f"- Total Findings: {stats['total_findings']}\n\n")

            f.write("### Findings by Type\n\n")
            for vuln_type, count in sorted(stats['findings_by_type'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"- {vuln_type}: {count}\n")

            f.write("\n### Confidence Breakdown\n\n")
            for conf, count in sorted(stats['confidence_breakdown'].items()):
                f.write(f"- {conf}: {count}\n")

            f.write("\n## Targets\n\n")
            for target, data in self.database["targets"].items():
                f.write(f"### {target}\n\n")
                f.write(f"- Scan Status: {data['scan_status']}\n")
                f.write(f"- Total Findings: {len(data['findings'])}\n")
                f.write("- Breakdown:\n")
                for vuln_type, count in sorted(data['findings_by_type'].items(), key=lambda x: x[1], reverse=True):
                    f.write(f"  - {vuln_type}: {count}\n")
                f.write("\n")

        print(f"✅ Summary exported: {output_file}")

def main():
    targets = [
        "chinachange.org",
        "chinaaid.org",
        "article19.org",
        "ifw-kiel.de",
        "cru.org"
    ]

    db = FindingsDatabase()
    db.generate_database(targets)

    output_dir = Path("reports")
    db.export_json(output_dir / "findings_database.json")
    db.export_summary(output_dir / "findings_database_summary.md")

    print(f"\n✅ Findings database generated")
    print(f"   Total targets: {db.database['statistics']['total_targets']}")
    print(f"   Total findings: {db.database['statistics']['total_findings']}")

if __name__ == "__main__":
    main()
