# PipelineGuard

**CI/CD-to-cloud identity blast-radius analyzer.** If this pipeline or machine identity is stolen, what can an attacker reach in the cloud, and would you notice?

## What it does

**Scan** → pipelines and OIDC trust policies for the weaknesses behind the 2026 supply chain attacks
**Attack** → replays a stolen-pipeline-token attack against a lab
**Detect** → CloudTrail detections mapped to MITRE ATT&CK
**Respond** → dry-run-by-default fixes, including session quarantine

![Workflow scan]
(<img width="1366" height="702" alt="Screenshot (21)" src="https://github.com/user-attachments/assets/9e5e180e-2145-4711-9356-0cf26f18e74d" /> 

<img width="1366" height="715" alt="Screenshot (22)" src="https://github.com/user-attachments/assets/846d66cf-39a8-441c-812a-011d08f4c5ea" />
)

![Blast radius]
(<img width="1366" height="768" alt="Screenshot (24)" src="https://github.com/user-attachments/assets/1bdb0c6d-856a-4d42-8066-89d7db5e9a84" />
).

![Detections]
(<img width="1366" height="715" alt="Screenshot (22)" src="https://github.com/user-attachments/assets/5c0dfb49-1587-45c7-9269-31a33c2ede17" />
 )

## Why this exists

Identity is now the main way into cloud environments, and CI/CD is where those credentials get stolen. The Cloud Security Alliance's 2026 Top Threats report ranks inadequate IAM first, Mandiant's M-Trends 2026 names machine identities a primary cloud-breach vector, and 2026 supply chain campaigns (Trivy and Checkmarx in March, Megalodon in May, Miasma in June) went after CI/CD secrets and abused GitHub Actions OIDC to reach cloud accounts.

PipelineGuard connects the two halves: how credentials leak from pipelines, and what they unlock once stolen.

## What it does

| Stage | Module | Command |
|---|---|---|
| Scan | GitHub Actions auditor (6 rules: `pull_request_target` abuse, unpinned actions, static cloud keys, token permissions, script injection, self-hosted runners) | `scan-workflows` |
| Scan | AWS OIDC trust-policy auditor (missing `sub`, org-wide wildcard, any-ref, missing `aud`) and key-age check | `audit-trust`, `audit-cloud` |
| Score | Blast-radius scoring of every role/user, with a Mermaid graph | `blast` |
| Attack | Replays a stolen-OIDC-token intrusion against a vulnerable lab | `sim setup`, `sim attack` |
| Detect | 5 CloudTrail detections mapped to MITRE ATT&CK | `detect` |
| Respond | Pin actions to SHAs, harden trust policy, quarantine a role (dry-run by default) | `remediate` |
| Report | Combined Markdown report | `report` |

## Quick start

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest -q
python -m pipelineguard scan-workflows samples/workflows
docker compose up -d
$env:AWS_DEFAULT_REGION="us-east-1"
python -m pipelineguard sim setup --local
python -m pipelineguard blast --local
python -m pipelineguard sim attack --local
python -m pipelineguard detect --events samples/cloudtrail/attack_events.jsonl --config detection.yml
```

## Detections

| ID | Detects | ATT&CK |
|---|---|---|
| PG-DET-001 | OIDC role assumed by a repository outside the allow-list | T1078.004 |
| PG-DET-002 | CI role used from outside expected egress ranges | T1078.004 |
| PG-DET-003 | Burst of Secrets Manager reads | T1555.006 |
| PG-DET-004 | CI role creates credentials or changes IAM | T1098.001 / T1098 |
| PG-DET-005 | Account enumeration burst | T1580 |

## Limitations

- The lab runs on LocalStack, which does not verify OIDC token signatures. Real AWS rejects forged tokens; the lab models the attacker *after* obtaining a valid one (for example via a hijacked workflow).
- Attack events are generated in CloudTrail's JSON schema by the simulator. For real accounts, feed actual CloudTrail logs to `detect`.
- Blast-radius scores do not evaluate Deny statements, permission boundaries, SCPs or Condition blocks, so they are an upper bound.
- GitHub Actions and AWS only. Azure and GCP are natural extensions.
