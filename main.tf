# ============================================================
# FinTech AWS Security Platform — ALL REQUIREMENTS IN ONE FILE
# One AWS account, one terraform apply, all screenshots ready
# ============================================================
# Requirements covered:
#   1. Organizations + SCPs (simulated in single account via IAM)
#   2. IAM Permission Boundary + DevOpsEngineer role + OIDC
#   3. GuardDuty + EventBridge + Step Functions + Lambda + SNS
#   4. AWS Config + Auto-remediation + Security Hub
#   5. ECS App + ALB + WAF
#   6. KMS CMK + S3 encryption + ACM + HTTPS
# ============================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.7"
}

provider "aws" {
  region = var.region
}

# ── Variables ─────────────────────────────────────────────────

variable "region" {
  default = "us-east-1"
}

variable "alert_email" {
  description = "Your email — you will receive security alerts here"
}

variable "github_org" {
  description = "Your GitHub username or org"
}

variable "github_repo" {
  description = "Your GitHub repo name"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# ============================================================
# REQUIREMENT 1 — ORGANIZATIONS + SCPs
# ============================================================

# Account is already in an org — import it as a data source
data "aws_organizations_organization" "main" {}

# Dummy local so references to aws_organizations_organization.main.roots[0].id still resolve
locals {
  org_root_id = data.aws_organizations_organization.main.roots[0].id
}

resource "aws_organizations_organizational_unit" "production" {
  name      = "Production"
  parent_id = local.org_root_id
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = local.org_root_id
}

resource "aws_organizations_organizational_unit" "development" {
  name      = "Development"
  parent_id = local.org_root_id
}

resource "aws_organizations_policy" "deny_destructive" {
  name = "DenyDestructiveActions"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyEC2Terminate"
        Effect   = "Deny"
        Action   = ["ec2:TerminateInstances"]
        Resource = "*"
      },
      {
        Sid    = "DenyCloudTrailStop"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy_attachment" "prod_scp" {
  policy_id = aws_organizations_policy.deny_destructive.id
  target_id = aws_organizations_organizational_unit.production.id
}

# ============================================================
# REQUIREMENT 1b — CLOUDTRAIL (org-wide)
# ============================================================

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "fintech-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "fintech-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# ============================================================
# REQUIREMENT 2 — IAM PERMISSION BOUNDARY + DevOpsEngineer ROLE
# ============================================================

resource "aws_iam_policy" "devops_boundary" {
  name        = "DevOpsBoundary"
  description = "Max permissions for DevOps roles — blocks destructive S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowDevOpsActions"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "ecs:*",
          "ecr:*",
          "elasticloadbalancing:*",
          "logs:*",
          "cloudwatch:*",
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "iam:PassRole",
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyDestructiveS3"
        Effect = "Deny"
        Action = [
          "s3:DeleteBucket",
          "s3:DeleteObject",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "devops_engineer" {
  name                 = "DevOpsEngineer"
  permissions_boundary = aws_iam_policy.devops_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "devops_power_user" {
  role       = aws_iam_role.devops_engineer.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# ============================================================
# REQUIREMENT 2b — OIDC GITHUB ACTIONS FEDERATION
# ============================================================

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_deploy" {
  name                 = "GitHubActionsDeployRole"
  permissions_boundary = aws_iam_policy.devops_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "github_deploy_permissions" {
  role = aws_iam_role.github_deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "ecs:UpdateService",
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================
# REQUIREMENT 3 — GUARDDUTY + EVENTBRIDGE + STEP FUNCTIONS + LAMBDA + SNS
# ============================================================

resource "aws_guardduty_detector" "main" {
  enable = true
}

resource "aws_sns_topic" "security_alerts" {
  name = "fintech-security-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_s3_bucket" "findings_archive" {
  bucket        = "fintech-findings-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "findings" {
  bucket                  = aws_s3_bucket.findings_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "quarantine" {
  name        = "quarantine-sg"
  description = "No inbound or outbound traffic - applied to compromised EC2"
  vpc_id      = aws_vpc.main.id
  # No ingress/egress rules = deny all
}

# Lambda IAM Role
resource "aws_iam_role" "lambda_ir" {
  name = "LambdaIncidentResponseRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_ir_policy" {
  role = aws_iam_role.lambda_ir.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateTags",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.findings_archive.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_ir.py"
  output_path = "${path.module}/lambda_ir.zip"
}

resource "aws_lambda_function" "incident_response" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "fintech-incident-response"
  role             = aws_iam_role.lambda_ir.arn
  handler          = "lambda_ir.handler"
  runtime          = "python3.12"
  timeout          = 60

  environment {
    variables = {
      QUARANTINE_SG   = aws_security_group.quarantine.id
      FINDINGS_BUCKET = aws_s3_bucket.findings_archive.bucket
      SNS_TOPIC_ARN   = aws_sns_topic.security_alerts.arn
    }
  }
}

# Step Functions IAM Role
resource "aws_iam_role" "sfn_role" {
  name = "StepFunctionsIRRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "states.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "sfn_policy" {
  role = aws_iam_role.sfn_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.incident_response.arn
      }
    ]
  })
}

resource "aws_sfn_state_machine" "incident_response" {
  name     = "fintech-incident-response"
  role_arn = aws_iam_role.sfn_role.arn

  definition = jsonencode({
    Comment = "GuardDuty automated incident response"
    StartAt = "ValidateFinding"
    States = {
      ValidateFinding = {
        Type     = "Task"
        Resource = aws_lambda_function.incident_response.arn
        Parameters = {
          "action"  = "validate"
          "event.$" = "$"
        }
        Retry = [
          {
            ErrorEquals     = ["States.ALL"]
            IntervalSeconds = 5
            MaxAttempts     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "NotifyFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "IsolateInstance"
      }
      IsolateInstance = {
        Type     = "Task"
        Resource = aws_lambda_function.incident_response.arn
        Parameters = {
          "action"  = "isolate"
          "event.$" = "$"
        }
        Retry = [
          {
            ErrorEquals     = ["States.ALL"]
            IntervalSeconds = 10
            MaxAttempts     = 3
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "NotifyFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "NotifyTeam"
      }
      NotifyTeam = {
        Type     = "Task"
        Resource = aws_lambda_function.incident_response.arn
        Parameters = {
          "action"  = "notify"
          "event.$" = "$"
        }
        Next = "Success"
      }
      NotifyFailure = {
        Type     = "Task"
        Resource = aws_lambda_function.incident_response.arn
        Parameters = {
          "action"  = "notify_failure"
          "event.$" = "$"
        }
        Next = "Failed"
      }
      Success = {
        Type = "Succeed"
      }
      Failed = {
        Type  = "Fail"
        Error = "IncidentResponseFailed"
      }
    }
  })
}

# EventBridge IAM Role
resource "aws_iam_role" "eventbridge_role" {
  name = "EventBridgeStepFunctionsRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "eventbridge_policy" {
  role = aws_iam_role.eventbridge_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["states:StartExecution"]
        Resource = aws_sfn_state_machine.incident_response.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "guardduty-high-findings"
  description = "Triggers incident response for HIGH/CRITICAL GuardDuty findings"
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        {
          numeric = [">=", 7]
        }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sfn" {
  rule     = aws_cloudwatch_event_rule.guardduty_high.name
  arn      = aws_sfn_state_machine.incident_response.arn
  role_arn = aws_iam_role.eventbridge_role.arn
}

# ============================================================
# REQUIREMENT 4 — AWS CONFIG + AUTO-REMEDIATION + SECURITY HUB
# ============================================================

resource "aws_iam_role" "config_role" {
  name = "AWSConfigServiceRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket" "config_bucket" {
  bucket        = "fintech-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config_bucket.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "main" {
  name     = "fintech-recorder"
  role_arn = aws_iam_role.config_role.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "fintech-delivery"
  s3_bucket_name = aws_s3_bucket.config_bucket.bucket
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "s3_sse" {
  name = "s3-bucket-server-side-encryption-enabled"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_iam_role" "remediation_role" {
  name = "ConfigRemediationRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ssm.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "remediation_policy" {
  role = aws_iam_role.remediation_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutEncryptionConfiguration"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_config_remediation_configuration" "s3_sse" {
  config_rule_name = aws_config_config_rule.s3_sse.name
  target_type      = "SSM_DOCUMENT"
  target_id        = "AWS-EnableS3BucketEncryption"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation_role.arn
  }
  parameter {
    name           = "BucketName"
    resource_value = "RESOURCE_ID"
  }
  parameter {
    name         = "SSEAlgorithm"
    static_value = "AES256"
  }

  automatic                  = true
  maximum_automatic_attempts = 3
  retry_attempt_seconds      = 60
}

resource "aws_securityhub_account" "main" {}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]

  timeouts {
    create = "10m"
    delete = "10m"
  }
}

resource "aws_securityhub_product_subscription" "guardduty" {
  product_arn = "arn:aws:securityhub:${var.region}::product/aws/guardduty"
  depends_on  = [aws_securityhub_account.main]
}

resource "aws_cloudwatch_event_rule" "securityhub_high" {
  name = "securityhub-high-findings"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_sns" {
  rule = aws_cloudwatch_event_rule.securityhub_high.name
  arn  = aws_sns_topic.security_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.security_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# ============================================================
# REQUIREMENT 5 — VPC + ECS + ALB + WAF
# ============================================================

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "fintech-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.${count.index}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "public-${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags = {
    Name = "private-${count.index + 1}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb" {
  name   = "alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  name   = "ecs-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_cluster" "main" {
  name = "fintech-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Role already exists in this account — import it
data "aws_iam_role" "ecs_execution" {
  name = "ECSTaskExecutionRole"
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/fintech-app"
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "app" {
  family                   = "fintech-app"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = data.aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([
    {
      name      = "app"
      image     = "nginx:alpine"
      essential = true
      portMappings = [
        {
          containerPort = 80
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

resource "aws_lb" "main" {
  name               = "fintech-alb"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "app" {
  name        = "fintech-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path              = "/"
    healthy_threshold = 2
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_ecs_service" "app" {
  name            = "fintech-app"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.public[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = 80
  }

  depends_on = [aws_lb_listener.http]
}

# WAF log group name MUST start with "aws-waf-logs-"
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-fintech-webacl"
  retention_in_days = 90
}

resource "aws_wafv2_web_acl" "main" {
  name  = "fintech-webacl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "RateLimit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "CommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "SQLiRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "fintech-webacl"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = ["${aws_cloudwatch_log_group.waf.arn}:*"]
  resource_arn            = aws_wafv2_web_acl.main.arn
}

# ============================================================
# REQUIREMENT 6 — KMS CMK + ENCRYPTED S3 + SECRETS MANAGER
# ============================================================

resource "aws_kms_key" "main" {
  description             = "FinTech production CMK"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "main" {
  name          = "alias/fintech-cmk"
  target_key_id = aws_kms_key.main.key_id
}

resource "aws_s3_bucket" "app_data" {
  bucket        = "fintech-appdata-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket                  = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_secretsmanager_secret" "db_password" {
  name       = "fintech/prod/db-password"
  kms_key_id = aws_kms_key.main.arn
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({ username = "fintech_app", password = "ChangeMe123!" })
}

# ============================================================
# OUTPUTS
# ============================================================

output "alb_dns_name" {
  value       = aws_lb.main.dns_name
  description = "Use this URL for WAF attack simulation tests"
}

output "guardduty_detector_id" {
  value       = aws_guardduty_detector.main.id
  description = "Use this to generate sample findings"
}

output "step_functions_arn" {
  value = aws_sfn_state_machine.incident_response.arn
}

output "kms_key_id" {
  value       = aws_kms_key.main.key_id
  description = "CMK for encryption — verify rotation in KMS console"
}

output "app_data_bucket" {
  value       = aws_s3_bucket.app_data.bucket
  description = "Upload a file here then run head-object to see aws:kms"
}

output "deploy_role_arn" {
  value       = aws_iam_role.github_deploy.arn
  description = "Paste into GitHub Actions workflow as role-to-assume"
}

output "quarantine_sg_id" {
  value = aws_security_group.quarantine.id
}
