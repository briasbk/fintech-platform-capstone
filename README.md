# FinTech AWS Security Platform — Capstone Project

> **Lead DevOps Engineer** | Nairobi-based Fintech | Central Bank of Kenya regulated  
> Multi-account, Zero-Trust, Fully Automated Security Platform on AWS

---

## Architecture Overview

```
AWS Organizations
├── Security OU
├── Production OU  ← SCP: DenyEC2Terminate + DenyCloudTrailStop
└── Development OU ← OIDC CI/CD (GitHub Actions, no static keys)

Incident Response Pipeline:
GuardDuty → EventBridge → Step Functions → Lambda → SNS + S3

Compliance:
AWS Config (auto-remediation) → Security Hub (FSBP) → SNS alerts

Edge Protection:
Internet → WAF (RateLimit + CommonRuleSet + SQLiRuleSet) → ALB → ECS Fargate

Encryption:
KMS CMK (auto-rotation) → S3 (aws:kms) → Secrets Manager
```

---

## Project Requirements Delivered

| # | Requirement | Status |
|---|-------------|--------|
| 1 | Multi-Account Organizations + SCPs | ✅ |
| 2 | IAM Permission Boundary + OIDC Federation | ✅ |
| 3 | GuardDuty + Step Functions Incident Response | ✅ |
| 4 | AWS Config Auto-Remediation + Security Hub | ✅ |
| 5 | ECS App + ALB + WAF (SQLi/XSS/Rate blocking) | ✅ |
| 6 | KMS CMK + S3 Encryption + Secrets Manager | ✅ |
| 7 | Attack Simulation (all 4 scenarios) | ✅ |
| 8 | Architecture Diagram + Executive Report | ✅ |

---

## Repository Structure

```
fintech-platform-capstone/
├── terraform/
│   ├── main.tf              # All infrastructure — one apply deploys everything
│   └── lambda_ir.py         # Incident response Lambda function
├── .github/
│   └── workflows/
│       └── deploy.yml       # GitHub Actions OIDC deployment workflow
├── screenshots/             # Evidence screenshots for each requirement
└── README.md
```

---

## How to Deploy

### Prerequisites
```bash
# AWS CLI configured with admin credentials
aws configure

# Terraform >= 1.7
terraform -version
```

### Deploy
```bash
cd terraform

# Create terraform.tfvars
cat > terraform.tfvars << EOF
region      = "us-east-1"
alert_email = "your-email@gmail.com"
github_org  = "your-github-username"
github_repo = "fintech-platform-capstone"
EOF

terraform init
terraform apply
```

### Confirm SNS subscription
Check your email immediately after apply and confirm the SNS subscription.

---

## Key Outputs After Apply

| Output | Description |
|--------|-------------|
| `alb_dns_name` | Use for WAF attack simulation tests |
| `guardduty_detector_id` | Use to generate sample findings |
| `deploy_role_arn` | Paste into GitHub Actions secrets |
| `app_data_bucket` | Upload files to verify KMS encryption |
| `kms_key_id` | Verify rotation in KMS console |

---

## Attack Simulation Commands

```bash
# Set variables from terraform output
ALB=$(terraform output -raw alb_dns_name)
DETECTOR=$(terraform output -raw guardduty_detector_id)

# Scenario 1 — Misconfigured S3 (Config auto-remediates)
aws s3api create-bucket --bucket fintech-test-$(date +%s) --region us-east-1

# Scenario 2 — GuardDuty incident response
aws guardduty create-sample-findings \
  --detector-id $DETECTOR \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce"

# Scenario 3 — OIDC block (fork repo and trigger workflow from fork)

# Scenario 4 — WAF attack simulation
curl -s -o /dev/null -w "Legit:        %{http_code}\n" http://$ALB/
curl -s -o /dev/null -w "SQLi blocked: %{http_code}\n" "http://$ALB/?id=1'+OR+'1'='1"
curl -s -o /dev/null -w "XSS blocked:  %{http_code}\n" "http://$ALB/?q=<script>alert(1)</script>"
```

---

## Screenshots Evidence

| File | Proves |
|------|--------|
| `screenshots/configandGuardduty-findings.png` | Security Hub + Config findings active |
| `screenshots/SNS alert email received.png` | Automated incident notification |
| `screenshots/Devopsboundary.png` | IAM Permission Boundary configured |
| `screenshots/200then403.png` | WAF blocking SQLi/XSS attacks |
| `screenshots/fintech-cmk-key-rotation.png` | KMS CMK with auto-rotation enabled |
| `screenshots/token.actions.githubusercontent.com.png` | OIDC provider registered |
| `screenshots/fintech-webacl.png` | WAF Web ACL rules configured |
| `screenshots/Screenshot 2026-05-30 at 10.25.25 PM.png` | Additional evidence |

---

## Services Used

| Layer | AWS Services |
|-------|-------------|
| Governance | AWS Organizations, SCPs, CloudTrail |
| Identity | IAM, OIDC, Permission Boundaries, STS |
| Detection | GuardDuty, EventBridge |
| Orchestration | Step Functions, Lambda |
| Compliance | AWS Config, Security Hub, SSM Automation |
| Edge Protection | WAF v2, ALB, ECS Fargate |
| Encryption | KMS CMK, S3 SSE, Secrets Manager |
| Alerting | SNS, CloudWatch |
