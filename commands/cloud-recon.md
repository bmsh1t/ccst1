---
description: Sweep cloud assets for a target — public S3/Azure/GCP bucket candidates via S3Scanner/cloud_enum and CloudFlare origin-IP hints via CloudFail or fallback DNS history. Usage: /cloud-recon --keyword <name> | /cloud-recon --cf-bypass <domain>
---

# /cloud-recon

Discover cloud-storage and origin-IP candidates. Treat results as candidates until ownership and permissions are verified.

## Run This (the only required step)

```bash
bash tools/cloud_recon.sh --keyword acme
bash tools/cloud_recon.sh --keyword acme --s3-only
bash tools/cloud_recon.sh --cf-bypass api.target.com
```

## What It Runs

| Tool | Mode | What it finds |
|---|---|---|
| `s3scanner` | `--keyword` | Public/listable S3-compatible buckets |
| `cloud_enum` | `--keyword` | AWS/Azure/GCP storage permutations |
| `cloudfail` | `--cf-bypass` | CloudFlare origin-IP candidates |
| built-in fallback | `--cf-bypass` | crt.sh + DNS hints when CloudFail is missing |

## Output

```text
findings/cloud/<timestamp>/s3scanner.txt
findings/cloud/<timestamp>/cloud_enum.txt
findings/cloud/<timestamp>/cloudfail.txt
findings/cloud/<timestamp>/non_cf_ips.txt
```

## When To Use

- `/recon` created non-empty `recon/<target>/exposure/cloud_storage_candidates.txt`, `s3_bucket_candidates.txt`, or `exposure/cloud/cloud_enum.txt`.
- The brand keyword is stable enough for cloud bucket permutations.
- WAF/origin hints suggest a CloudFlare-protected host may expose a direct origin.

After reviewing candidates, use only minimal permission/ownership checks before promoting a Signal.
