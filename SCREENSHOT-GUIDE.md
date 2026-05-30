# SCREENSHOT GUIDE — Do these after terraform apply
# ====================================================

## STEP 0 — Install & Deploy (one time)
```bash
# Install Terraform on your machine
sudo apt install terraform   # Linux
# or: brew install terraform  # Mac

# Configure AWS CLI
aws configure
# Enter: Access Key, Secret Key, region=us-east-1, output=json

# Deploy everything
cd fintech-platform-capstone
nano terraform.tfvars        # fill in your email, github info
terraform init
terraform apply              # type yes — takes ~5 minutes
```
** CHECK EMAIL and confirm the SNS subscription immediately after apply **

---

## REQUIREMENT 1 — Organizations + SCP

📸 Screenshot A: Organizations structure
→ Console → AWS Organizations → AWS accounts
→ Shows: Root, Security OU, Production OU, Development OU

📸 Screenshot B: SCP JSON
→ Organizations → Policies → Service Control Policies → DenyDestructiveActions
→ Click it → shows the JSON with DenyEC2Terminate and DenyCloudTrailStop

📸 Screenshot C: SCP blocks action
→ Open AWS CloudShell
→ Run:
  aws ec2 run-instances --image-id ami-0c02fb55956c7d316 --instance-type t2.micro --count 1
  # Wait for it to launch, get the instance ID, then:
  aws ec2 terminate-instances --instance-ids i-XXXXXXXX
→ Expected error: "An error occurred (UnauthorizedOperation)..."
→ Screenshot the error

📸 Screenshot D: CloudTrail trail active
→ CloudTrail → Trails → fintech-trail
→ Shows: Logging ON, Multi-region: Yes, S3 bucket: fintech-cloudtrail-XXXX

---

## REQUIREMENT 2 — IAM Boundary + OIDC

📸 Screenshot E: Permission Boundary policy
→ IAM → Policies → DevOpsBoundary
→ Click → Permissions tab → shows JSON with DenyDestructiveS3

📸 Screenshot F: DevOpsEngineer role with boundary
→ IAM → Roles → DevOpsEngineer
→ Permissions boundary tab → shows DevOpsBoundary

📸 Screenshot G: Prove boundary blocks s3:DeleteBucket
→ CloudShell:
  aws iam create-role --role-name TestBoundary \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    --permissions-boundary arn:aws:iam::ACCOUNT_ID:policy/DevOpsBoundary
  aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/DevOpsEngineer --role-session-name test
  # Use returned credentials, then try:
  aws s3api delete-bucket --bucket any-bucket-name
  # Expected: Access Denied
→ Screenshot the Access Denied

📸 Screenshot H: OIDC Provider in IAM
→ IAM → Identity providers
→ Shows: token.actions.githubusercontent.com (OpenID Connect)

📸 Screenshot I: GitHub Actions — successful deploy from main
→ Your GitHub repo → Actions → Deploy to AWS
→ Green checkmark → expand steps → shows aws sts get-caller-identity output
→ Role shown: GitHubActionsDeployRole

📸 Screenshot J: GitHub Actions — blocked from fork
→ Fork the repo → Actions → Run workflow from the fork
→ Red X on "Configure AWS via OIDC" step
→ Error: "Not authorized to perform: sts:AssumeRoleWithWebIdentity"

---

## REQUIREMENT 3 — GuardDuty + Step Functions

📸 Screenshot K: GuardDuty enabled
→ GuardDuty → Summary
→ Shows: Detector active

📸 Screenshot L: EventBridge rule
→ EventBridge → Rules → guardduty-high-findings
→ Shows the event pattern JSON

```bash
# Trigger sample finding
DETECTOR=$(terraform output -raw guardduty_detector_id)
aws guardduty create-sample-findings \
  --detector-id $DETECTOR \
  --finding-types "UnauthorizedAccess:EC2/SSHBruteForce"
```

📸 Screenshot M: GuardDuty finding visible
→ GuardDuty → Findings
→ Shows the HIGH severity finding

# Wait 30 seconds then:
📸 Screenshot N: Step Functions execution succeeded
→ Step Functions → fintech-incident-response → Executions
→ Latest execution → all states green

📸 Screenshot O: SNS alert email received
→ Check your inbox
→ Shows: [ALERT] GuardDuty: UnauthorizedAccess... email

📸 Screenshot P: S3 finding logged
→ S3 → fintech-findings-XXXX → findings/YYYY/MM/DD/
→ Shows the .json file

---

## REQUIREMENT 4 — Config + Security Hub

📸 Screenshot Q: Config recorder ON
→ Config → Dashboard → Recording is on

📸 Screenshot R: Config rule listed
→ Config → Rules → s3-bucket-server-side-encryption-enabled

```bash
# Create unencrypted bucket to trigger the rule
aws s3api create-bucket --bucket test-no-encrypt-$(date +%s) --region us-east-1
# Wait 3-5 minutes for Config to evaluate
```

📸 Screenshot S: NON_COMPLIANT finding
→ Config → Rules → s3-bucket-server-side-encryption-enabled
→ Resources → your new bucket shows NON_COMPLIANT

# Wait another 3 minutes for auto-remediation
📸 Screenshot T: COMPLIANT after auto-remediation
→ Same page → bucket now COMPLIANT
→ OR: S3 → bucket → Properties → Server-side encryption → AES-256

📸 Screenshot U: Security Hub enabled
→ Security Hub → Summary
→ Shows: AWS Foundational Security Best Practices standard enabled

📸 Screenshot V: Findings in Security Hub
→ Security Hub → Findings
→ Shows GuardDuty and Config findings imported

---

## REQUIREMENT 5 — WAF + ALB + ECS

📸 Screenshot W: ECS cluster running
→ ECS → Clusters → fintech-cluster → Services → fintech-app
→ Shows 1/1 running tasks

📸 Screenshot X: ALB listening
→ EC2 → Load Balancers → fintech-alb → Listeners tab
→ Shows port 80 listener

📸 Screenshot Y: WAF Web ACL with rules
→ WAF & Shield → Web ACLs → fintech-webacl → Rules
→ Shows: RateLimit (priority 1), CommonRuleSet (2), SQLiRuleSet (3)

```bash
ALB=$(terraform output -raw alb_dns_name)

# Legitimate request (expect 200)
curl -s -o /dev/null -w "Legit request: %{http_code}\n" http://$ALB/

# SQLi (expect 403)
curl -s -o /dev/null -w "SQLi attempt: %{http_code}\n" \
  "http://$ALB/login?id=1'+OR+'1'='1"

# XSS (expect 403)
curl -s -o /dev/null -w "XSS attempt: %{http_code}\n" \
  "http://$ALB/search?q=<script>alert(1)</script>"

# Rate limit — 110 rapid requests
echo "Rate limit test:"
for i in $(seq 1 110); do
  curl -s -o /dev/null -w "%{http_code} " http://$ALB/
done | tr ' ' '\n' | tail -15
```

📸 Screenshot Z: curl output showing attacks blocked
→ Terminal showing: 200, then 403 403 403 for attacks

📸 Screenshot AA: WAF sampled requests
→ WAF → fintech-webacl → Sampled requests tab
→ Shows blocked requests with rule that matched

---

## REQUIREMENT 6 — KMS + Encryption

📸 Screenshot BB: KMS CMK with rotation enabled
→ KMS → Customer managed keys → fintech-cmk
→ Key rotation tab → "Automatic key rotation: Enabled"

```bash
# Upload a file and check encryption metadata
BUCKET=$(terraform output -raw app_data_bucket)
echo "test" | aws s3 cp - s3://$BUCKET/test.txt
aws s3api head-object --bucket $BUCKET --key test.txt \
  --query '{SSE:ServerSideEncryption,KMSKey:SSEKMSKeyId}'
```

📸 Screenshot CC: S3 object encrypted with aws:kms
→ Terminal output shows: "SSE": "aws:kms" and KMS key ARN

📸 Screenshot DD: Secrets Manager secret encrypted with CMK
→ Secrets Manager → fintech/prod/db-password
→ Shows: Encryption key: alias/fintech-cmk
