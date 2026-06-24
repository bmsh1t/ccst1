#!/usr/bin/env python3
"""
IDOR Testing Orchestrator
Manages IDOR test case generation and validation tracking
"""

import json
import sys
from pathlib import Path
from typing import List, Dict
from datetime import datetime

class IDORTestOrchestrator:
    def __init__(self, target: str):
        self.target = target
        self.findings_dir = Path(f"findings/{target}/idor")
        self.test_cases = []

    def load_endpoints(self) -> Dict[str, List[int]]:
        """Load and categorize IDOR endpoints"""
        endpoints = {}

        api_file = self.findings_dir / "api_sequential_ids.txt"
        if not api_file.exists():
            return endpoints

        with open(api_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('http'):
                    continue

                # Parse endpoint
                if '/wp-json/' in line:
                    parts = line.split('/wp-json/')
                    if len(parts) > 1:
                        api_path = parts[1]
                        base = '/'.join(api_path.split('/')[:3])

                        # Extract ID
                        import re
                        id_match = re.search(r'/(\d+)/?$', line)
                        if id_match:
                            id_val = int(id_match.group(1))
                            if base not in endpoints:
                                endpoints[base] = []
                            endpoints[base].append(id_val)

        return endpoints

    def generate_test_matrix(self, endpoints: Dict[str, List[int]]) -> List[Dict]:
        """Generate comprehensive IDOR test matrix"""
        test_cases = []

        for base, ids in endpoints.items():
            if not ids:
                continue

            ids_sorted = sorted(ids)
            min_id = min(ids)
            max_id = max(ids)

            # Test case categories
            test_case = {
                "endpoint_base": base,
                "total_ids": len(ids),
                "id_range": {"min": min_id, "max": max_id},
                "tests": []
            }

            # 1. Sequential ID enumeration
            test_case["tests"].append({
                "type": "sequential_enumeration",
                "description": "Test IDs +1, -1 from known IDs",
                "test_ids": [
                    ids_sorted[0] - 1,
                    ids_sorted[0] + 1,
                    ids_sorted[-1] + 1
                ],
                "expected": "Should return 404 or access denied for non-existent/unauthorized IDs"
            })

            # 2. Boundary testing
            test_case["tests"].append({
                "type": "boundary",
                "description": "Test edge cases",
                "test_ids": [0, 1, -1, 999999, min_id, max_id],
                "expected": "Should handle boundaries gracefully"
            })

            # 3. Random sampling
            if len(ids) >= 10:
                import random
                sample_size = min(5, len(ids) // 2)
                samples = random.sample(ids_sorted, sample_size)
                test_case["tests"].append({
                    "type": "random_sampling",
                    "description": "Test random valid IDs for access control",
                    "test_ids": samples,
                    "expected": "Should verify authentication/authorization required"
                })

            # 4. Gap analysis
            gaps = []
            for i in range(len(ids_sorted) - 1):
                gap = ids_sorted[i + 1] - ids_sorted[i]
                if gap > 1:
                    # Test missing IDs in gaps
                    gaps.append(ids_sorted[i] + 1)

            if gaps:
                test_case["tests"].append({
                    "type": "gap_testing",
                    "description": "Test IDs in gaps (missing from enumeration)",
                    "test_ids": gaps[:5],  # First 5 gaps
                    "expected": "Should return 404 or access denied"
                })

            test_cases.append(test_case)

        return test_cases

    def export_test_plan(self, test_cases: List[Dict], output_file: Path):
        """Export test plan as JSON"""
        plan = {
            "target": self.target,
            "generated_at": datetime.now().isoformat(),
            "total_endpoints": len(test_cases),
            "test_cases": test_cases,
            "execution_notes": [
                "Run tests with both unauthenticated and authenticated sessions",
                "Compare responses to identify access control issues",
                "Look for information disclosure in error messages",
                "Test for horizontal privilege escalation (user A accessing user B's data)",
                "Test for vertical privilege escalation (regular user accessing admin resources)"
            ]
        }

        with open(output_file, 'w') as f:
            json.dump(plan, f, indent=2)

        print(f"✅ Test plan exported: {output_file}")
        return plan

    def generate_bash_runner(self, test_cases: List[Dict], output_file: Path):
        """Generate bash script for automated testing"""
        script = """#!/bin/bash
# IDOR Test Runner for {target}
# Generated: {timestamp}

TARGET="{target}"
COOKIE_FILE="cookies.txt"  # Add your authentication cookie here

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "IDOR Test Runner - $TARGET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

# Test function
test_endpoint() {{
    local url=$1
    local description=$2

    echo "[Testing] $description"
    echo "URL: $url"

    # Unauthenticated test
    unauth_response=$(curl -s -o /dev/null -w "%{{http_code}}" "$url")
    echo "  Unauthenticated: $unauth_response"

    # Authenticated test (if cookie file exists)
    if [ -f "$COOKIE_FILE" ]; then
        auth_response=$(curl -s -o /dev/null -w "%{{http_code}}" -b "$COOKIE_FILE" "$url")
        echo "  Authenticated: $auth_response"

        if [ "$unauth_response" == "200" ] && [ "$auth_response" == "200" ]; then
            echo "  ⚠️  POTENTIAL IDOR: Both return 200"
        fi
    fi
    echo
}}

""".format(target=self.target, timestamp=datetime.now().isoformat())

        # Add test cases
        for tc in test_cases[:5]:  # Limit to first 5 endpoint types
            base = tc["endpoint_base"]
            script += f"\n# Testing {base}\n"

            for test in tc["tests"][:2]:  # Limit to first 2 test types per endpoint
                for test_id in test["test_ids"][:3]:  # Limit to 3 IDs per test
                    url = f"https://{self.target}/wp-json/{base}/{test_id}"
                    desc = f"{test['type']} - ID {test_id}"
                    script += f'test_endpoint "{url}" "{desc}"\n'

        script += '\necho "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"\n'
        script += 'echo "Testing complete"\n'

        with open(output_file, 'w') as f:
            f.write(script)

        output_file.chmod(0o755)
        print(f"✅ Test runner generated: {output_file}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 idor_test_orchestrator.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    orchestrator = IDORTestOrchestrator(target)

    print(f"Loading IDOR endpoints for {target}...")
    endpoints = orchestrator.load_endpoints()

    if not endpoints:
        print(f"❌ No IDOR endpoints found for {target}")
        sys.exit(1)

    print(f"✅ Found {len(endpoints)} endpoint types")

    print("\nGenerating test matrix...")
    test_cases = orchestrator.generate_test_matrix(endpoints)

    # Export test plan
    output_dir = Path(f"hunt_targets/{target}/idor_tests")
    output_dir.mkdir(parents=True, exist_ok=True)

    plan_file = output_dir / "idor_test_plan.json"
    orchestrator.export_test_plan(test_cases, plan_file)

    # Generate bash runner
    runner_file = output_dir / "run_idor_tests.sh"
    orchestrator.generate_bash_runner(test_cases, runner_file)

    print(f"\n✅ IDOR test orchestration complete")
    print(f"   Test plan: {plan_file}")
    print(f"   Test runner: {runner_file}")

if __name__ == "__main__":
    main()
