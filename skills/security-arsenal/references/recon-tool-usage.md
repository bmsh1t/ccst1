# Recon and Tool Usage Reference

Load this file when the task needs concrete command shapes for recon, endpoint discovery, static audit, or ffuf. Keep execution bounded by scope, rate limits, and current-turn authorization. Save raw outputs when they become evidence.

## Tool Roles

| Tool | Use |
|---|---|
| `subfinder`, `assetfinder` | Passive subdomain discovery |
| `dnsx` | DNS resolution |
| `httpx` | Live host probing and tech hints |
| `katana`, `waybackurls`, `gau` | URL collection |
| `nuclei` | Template-based finding leads |
| `ffuf` | Bounded fuzzing and parameter discovery |
| `anew`, `qsreplace`, `gf` | Deduplication, parameter shaping, pattern filtering |
| `interactsh-client` | Controlled OOB callbacks when authorized |
| `trufflehog`, `gitleaks` | Secret scanning of authorized repos |
| `arjun`, `paramspider`, `kiterunner` | Parameter and API endpoint discovery |

## Standard Recon Pipeline

```bash
subfinder -d TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only TARGET | anew /tmp/subs.txt
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect -o /tmp/live.txt
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/urls.txt
echo TARGET | waybackurls | anew /tmp/urls.txt
gau TARGET | anew /tmp/urls.txt
nuclei -l /tmp/live.txt -severity critical,high,medium -silent -o /tmp/nuclei.txt
```

Stop condition: no in-scope live surfaces, repeated 401/403/404 with no route delta, or any next step requiring real-user enumeration without authorization.

## FFUF Usage

Rule: prefer `-ac` calibration, bounded wordlists, low rate, and raw request files for authenticated flows.

```bash
ffuf -w wordlist.txt -u https://target.example/FUZZ -ac
seq 1 10000 | ffuf --request req.txt -w - -ac
ffuf -u https://target.example/api/FUZZ -w wordlist.txt -H "Cookie: session=TOKEN_PLACEHOLDER" -ac
ffuf -w ~/wordlists/burp-parameter-names.txt -u "https://target.example/api/endpoint?FUZZ=test" -ac -mc 200
ffuf -w ~/wordlists/burp-parameter-names.txt -X POST -d "FUZZ=test" -u "https://target.example/api/endpoint" -ac
ffuf -w subs.txt -u https://FUZZ.target.example -ac
```

Useful filters: `-fc`, `-fs`, `-fw`, `-fr`, `-rate`, `-t`, `-e`, `-o`.

## Semgrep Quick Audit

```bash
semgrep --config=p/security-audit ./
semgrep --config=p/owasp-top-ten ./
semgrep --config=p/javascript ./src/
semgrep --config=p/python ./
semgrep --config=p/golang ./
semgrep --config=p/php ./
semgrep --config=p/nodejs ./
semgrep --config=p/sql-injection ./
semgrep --config=p/jwt ./
semgrep --pattern 'cursor.execute("..." + $X)' --lang python .
semgrep --config=p/security-audit ./ --json -o semgrep-results.json 2>/dev/null
```

A static finding is a lead until a reachable path and raw runtime evidence exist.

## Cloud / Storage Asset Discovery

```bash
for suffix in dev staging test backup api data assets static cdn; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET}-${suffix}.s3.amazonaws.com/")
  [ "$code" != "404" ] && echo "$code ${TARGET}-${suffix}.s3.amazonaws.com"
done
```

Do not import keys into cloud panels or take resource control. Use minimal read-only verification and write the validation plan before escalation.

## API Endpoint Discovery

```bash
ffuf -u https://target.example/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,403 -ac
```

When an endpoint returns missing/required parameter, route to `knowledge/cards/missing-parameter-discovery.md` instead of treating the error itself as a finding.

## Scope Retrieval

Use official platform APIs or scope exports only as scope context. The current command target set remains the active execution surface unless the user changes it.

```bash
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { team(handle: \"PROGRAM_HANDLE\") { name url policy_scopes(archived: false) { edges { node { asset_type asset_identifier eligible_for_bounty instruction } } } } }"}' \
  | jq '.data.team.policy_scopes.edges[].node'

```

## Quick Lead Checklist

Use as leads, not automatic reports: subdomain takeover fingerprints, exposed config files, JS secret candidates, open redirects, CORS differences, cloud bucket listing, GraphQL introspection, framework management panels, and source-code breadcrumbs.
