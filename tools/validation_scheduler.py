#!/usr/bin/env python3
"""
Validation Scheduler
Schedules and tracks validation tasks across all findings
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict

class ValidationScheduler:
    def __init__(self):
        self.tasks = []
        self.schedule = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "false_positive_check": []
        }

    def load_findings_database(self, db_path: Path) -> Dict:
        """Load findings database"""
        with open(db_path, 'r') as f:
            return json.load(f)

    def prioritize_findings(self, database: Dict):
        """Prioritize findings for validation"""

        for target, data in database["targets"].items():
            for finding in data["findings"]:
                task = {
                    "target": target,
                    "finding": finding,
                    "validation_method": self.get_validation_method(finding),
                    "estimated_time_minutes": self.estimate_time(finding),
                    "requires": self.get_requirements(finding)
                }

                # Prioritize based on confidence and type
                if finding.get("confidence") == "high" and finding["type"] == "cors_misconfiguration":
                    self.schedule["high_priority"].append(task)
                elif finding.get("confidence") in ["high", "confirmed"] and finding.get("validated") == False:
                    self.schedule["high_priority"].append(task)
                elif finding.get("confidence") == "medium":
                    self.schedule["medium_priority"].append(task)
                elif finding.get("confidence") == "low" or finding.get("status") == "parameter_identified":
                    self.schedule["medium_priority"].append(task)
                elif finding["type"] == "ssti" and "static" not in finding.get("notes", ""):
                    self.schedule["false_positive_check"].append(task)

    def get_validation_method(self, finding: Dict) -> str:
        """Determine validation method"""
        methods = {
            "cors_misconfiguration": "HTTP request with Origin header",
            "ssti": "Parameter fuzzing with template syntax",
            "ssrf_parameter": "Test with internal IP payloads",
            "open_redirect_parameter": "Test with external domain redirect",
            "idor_endpoint": "Multi-account access control test",
            "information_exposure": "HTTP request and content analysis",
            "subdomain_takeover": "DNS lookup and service check"
        }
        return methods.get(finding["type"], "Manual inspection")

    def estimate_time(self, finding: Dict) -> int:
        """Estimate validation time in minutes"""
        times = {
            "cors_misconfiguration": 5,
            "ssti": 10,
            "ssrf_parameter": 30,
            "open_redirect_parameter": 20,
            "idor_endpoint": 60,
            "information_exposure": 5,
            "subdomain_takeover": 10
        }
        return times.get(finding["type"], 15)

    def get_requirements(self, finding: Dict) -> List[str]:
        """Get requirements for validation"""
        requirements = []

        if finding["type"] in ["idor_endpoint", "ssrf_parameter", "open_redirect_parameter"]:
            requirements.append("Authentication account")

        if finding.get("requires") == "endpoint_mapping":
            requirements.append("Endpoint discovery (crawling)")

        if finding["type"] == "idor_endpoint":
            requirements.append("Multiple test accounts")

        requirements.append("Network access to target")

        return requirements

    def generate_schedule_report(self, output_path: Path):
        """Generate validation schedule report"""
        report = f"""# Validation Schedule

Generated: {datetime.now().isoformat()}

## Summary

- High Priority Tasks: {len(self.schedule['high_priority'])}
- Medium Priority Tasks: {len(self.schedule['medium_priority'])}
- Low Priority Tasks: {len(self.schedule['low_priority'])}
- False Positive Checks: {len(self.schedule['false_positive_check'])}

Total Validation Time Estimate: {self.calculate_total_time()} hours

---

## High Priority (Execute First)

"""
        for i, task in enumerate(self.schedule["high_priority"], 1):
            report += self.format_task(i, task)

        report += "\n---\n\n## Medium Priority\n\n"
        for i, task in enumerate(self.schedule["medium_priority"], 1):
            report += self.format_task(i, task)

        report += "\n---\n\n## False Positive Checks (Quick Verification)\n\n"
        for i, task in enumerate(self.schedule["false_positive_check"][:10], 1):  # First 10
            report += self.format_task(i, task)

        report += f"\n... and {len(self.schedule['false_positive_check']) - 10} more\n"

        report += "\n---\n\n## Validation Workflow\n\n"
        report += """### Phase 1: High Priority Validation (Immediate)
1. CORS misconfiguration (5 min)
2. High-confidence findings (varies)

### Phase 2: False Positive Elimination (Quick)
1. SSTI static asset check (10 min for all)
2. Reduces workload significantly

### Phase 3: Medium Priority (Requires Prep)
1. Parameter endpoint mapping (30-60 min)
2. SSRF testing (30 min per target)
3. Redirect testing (20 min per target)

### Phase 4: High-Effort Tasks (Extended)
1. IDOR multi-account testing (60 min per endpoint type)
2. Full authentication flow testing

---

## Requirements Checklist

- [ ] Network access to all targets
- [ ] Authentication accounts for:
  - [ ] chinachange.org (2 accounts for IDOR)
  - [ ] chinaaid.org (1 account for parameter testing)
- [ ] Burp Suite or similar proxy
- [ ] Testing environment/VPN if required
- [ ] Permission/authorization documentation

---

## Automation Opportunities

**Can be automated:**
- CORS validation (script ready)
- SSTI false positive check (script ready)
- Information exposure verification

**Requires manual work:**
- IDOR multi-account testing
- SSRF endpoint discovery
- Redirect parameter mapping
"""

        with open(output_path, 'w') as f:
            f.write(report)

        print(f"✅ Validation schedule: {output_path}")

    def format_task(self, num: int, task: Dict) -> str:
        """Format task for report"""
        finding = task["finding"]
        output = f"### {num}. [{task['target']}] {finding['type']}\n\n"

        if finding["type"] == "cors_misconfiguration":
            output += f"**URL:** {finding.get('url', 'N/A')}\n"
            output += f"**Reflected Origin:** {finding.get('reflected_origin', 'N/A')}\n"
        elif "parameter_name" in finding:
            output += f"**Parameter:** `{finding['parameter_name']}`\n"
        elif "endpoint_base" in finding:
            output += f"**Endpoint:** {finding['endpoint_base']}\n"
            output += f"**IDs Found:** {finding.get('total_ids_found', 0)}\n"

        output += f"**Method:** {task['validation_method']}\n"
        output += f"**Estimated Time:** {task['estimated_time_minutes']} minutes\n"

        if task["requires"]:
            output += f"**Requires:** {', '.join(task['requires'])}\n"

        output += "\n"
        return output

    def calculate_total_time(self) -> float:
        """Calculate total estimated time"""
        total = 0
        for priority in self.schedule.values():
            for task in priority:
                total += task["estimated_time_minutes"]
        return round(total / 60, 1)

    def export_json(self, output_path: Path):
        """Export schedule as JSON"""
        with open(output_path, 'w') as f:
            json.dump(self.schedule, f, indent=2)
        print(f"✅ JSON schedule: {output_path}")

def main():
    scheduler = ValidationScheduler()

    db_path = Path("reports/findings_database.json")
    if not db_path.exists():
        print("❌ Run findings_database_generator.py first")
        return

    print("Loading findings database...")
    database = scheduler.load_findings_database(db_path)

    print("Prioritizing findings...")
    scheduler.prioritize_findings(database)

    output_dir = Path("reports")
    scheduler.generate_schedule_report(output_dir / "validation_schedule.md")
    scheduler.export_json(output_dir / "validation_schedule.json")

    print(f"\n✅ Validation schedule complete")
    print(f"   High priority: {len(scheduler.schedule['high_priority'])}")
    print(f"   Medium priority: {len(scheduler.schedule['medium_priority'])}")
    print(f"   FP checks: {len(scheduler.schedule['false_positive_check'])}")
    print(f"   Total time: {scheduler.calculate_total_time()} hours")

if __name__ == "__main__":
    main()
