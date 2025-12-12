# Advanced-AI-threat-detection-and-Phishing

## Quick overview (what we’ll create)
EventBridge rule that listens for GuardDuty findings (simulated for PoC) and invokes a Lambda.

Lambda (Python) that dedupes, enriches slightly, persists to S3 & DynamoDB, and publishes to SNS (email).

SNS topic with email subscription (you’ll confirm subscription).

DynamoDB table for dedupe.

S3 bucket for archived findings.

Minimal IAM roles/policies (least privilege for PoC).

Everything deployed via Terraform from this small repo.


Project layout (create these files)

Create files exactly as below.

providers.tf

terraform {
  required_providers {
    aws = { source = "hashicorp/aws"; version = "~> 5.0" }
    random = { source = "hashicorp/random"; version = "~> 3.0" }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = var.aws_region
}


variables.tf

variable "aws_region" { type = string; default = "eu-west-1" }
variable "alert_email" { type = string }
variable "lambda_memory" { type = number; default = 256 }
variable "lambda_timeout" { type = number; default = 10 }
variable "s3_retention_days" { type = number; default = 30 }
variable "lambda_zip_path" { type = string; default = "${path.module}/lambda_src/detector.zip" }


main.tf

locals {
  project = "phish-detect-poc"
}

resource "random_id" "bucket_id" {
  byte_length = 4
}

# S3 bucket for archived findings
resource "aws_s3_bucket" "archive" {
  bucket = "${local.project}-archive-${random_id.bucket_id.hex}"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
  lifecycle_rule {
    id      = "expire"
    enabled = true
    expiration {
      days = var.s3_retention_days
    }
  }
  tags = { Project = local.project }
}

# DynamoDB table for dedupe
resource "aws_dynamodb_table" "findings" {
  name         = "${local.project}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }
  tags = { Project = local.project }
}

# SNS topic + subscription (email)
resource "aws_sns_topic" "alerts" {
  name = "${local.project}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# IAM role for Lambda
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_role" {
  name               = "${local.project}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem"
    ]
    resources = [ aws_dynamodb_table.findings.arn ]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.archive.arn,
      "${aws_s3_bucket.archive.arn}/*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "sns:Publish"
    ]
    resources = [ aws_sns_topic.alerts.arn ]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:CreateLogGroup"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${local.project}-lambda-policy"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

# Lambda function (uploaded as local zip)
resource "aws_lambda_function" "processor" {
  function_name = "${local.project}-processor"
  filename      = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  handler       = "handler.lambda_handler"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_role.arn
  memory_size   = var.lambda_memory
  timeout       = var.lambda_timeout

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      DDB_TABLE       = aws_dynamodb_table.findings.name
      S3_BUCKET       = aws_s3_bucket.archive.id
    }
  }

  tags = { Project = local.project }
}

# EventBridge rule to accept GuardDuty findings (filter severity >= 4)
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.project}-guardduty-rule"
  description = "Forward GuardDuty MEDIUM/HIGH findings to Lambda (PoC)"
  event_pattern = jsonencode({
    "source": ["aws.guardduty"],
    "detail-type": ["GuardDuty Finding"],
    "detail": {
      "severity": [{ "numeric": [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_lambda" {
  rule = aws_cloudwatch_event_rule.guardduty_findings.name
  arn  = aws_lambda_function.processor.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "s3_bucket" {
  value = aws_s3_bucket.archive.id
}
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
output "lambda_name" {
  value = aws_lambda_function.processor.function_name
}
output "ddb_table" {
  value = aws_dynamodb_table.findings.name
}


outputs.tf (optional — main.tf already contains outputs)

# leave empty or keep outputs in main.tf


lambda_src/handler.py (create folder lambda_src and put this file)

import json, os, time, re
import boto3
from botocore.exceptions import ClientError

ddb = boto3.resource('dynamodb')
sns = boto3.client('sns')
s3 = boto3.client('s3')

TABLE_NAME = os.environ.get('DDB_TABLE')
ALERT_TOPIC = os.environ.get('ALERT_TOPIC_ARN')
S3_BUCKET = os.environ.get('S3_BUCKET')

table = ddb.Table(TABLE_NAME)

def lambda_handler(event, context):
    # EventBridge test will often deliver our test object at top-level; GuardDuty real events hold 'detail'.
    detail = event.get('detail') if event.get('detail') else event
    finding_id = detail.get('id') or detail.get('findingId') or str(time.time())
    if is_duplicate(finding_id):
        return {"status": "skipped", "reason": "duplicate", "id": finding_id}

    enriched = enrich(detail)
    persist(enriched)
    publish(enriched)
    return {"status": "processed", "id": finding_id}

def is_duplicate(fid):
    try:
        table.put_item(Item={'finding_id': fid, 'ts': int(time.time())}, ConditionExpression='attribute_not_exists(finding_id)')
        return False
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return True
        raise

def enrich(detail):
    enriched = {}
    enriched['id'] = detail.get('id')
    enriched['title'] = detail.get('title', 'No title')
    enriched['severity'] = detail.get('severity', 0)
    enriched['description'] = detail.get('description', '')
    enriched['urls'] = extract_urls(enriched['description'])
    # Simple score: severity * (1 + n_urls)
    enriched['score'] = enriched['severity'] * (1 + len(enriched['urls']))
    enriched['raw'] = detail
    return enriched

def extract_urls(text):
    if not text:
        return []
    return re.findall(r'https?://[^\s,"]+', text)

def persist(enriched):
    # store to s3
    if S3_BUCKET:
        key = f"guardduty/{enriched.get('id', str(time.time()))}.json"
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=json.dumps(enriched).encode('utf-8'))
    return

def publish(enriched):
    subject = f"[ALERT] {enriched.get('title')} sev:{enriched.get('severity')}"
    message = json.dumps(enriched, default=str)
    try:
        sns.publish(TopicArn=ALERT_TOPIC, Subject=subject, Message=message)
    except Exception as e:
        print("SNS publish failed:", str(e))


lambda_src/__init__.py (empty file)

sample-event.json (a test EventBridge event to simulate GuardDuty)

{
  "version": "0",
  "id": "test-finding-1",
  "detail-type": "GuardDuty Finding",
  "source": "aws.guardduty",
  "account": "123456789012",
  "time": "2025-12-11T12:00:00Z",
  "region": "eu-west-1",
  "detail": {
    "id": "poc-finding-1",
    "arn": "arn:aws:guardduty:eu-west-1:123456789012:detector/xxx/finding/poc-finding-1",
    "title": "PoC phishing link detected",
    "severity": 5.5,
    "description": "Detected suspicious email with link https://malicious.example/phish"
  }
}

2) Package the Lambda

From repo root:

# make sure you're in phish-detect-poc
cd lambda_src
zip -r ../lambda_src/detector.zip .  # creates lambda_src/detector.zip
cd ..


Important: If you modify the ZIP, Terraform needs the source_code_hash to match — our main.tf includes filebase64sha256(var.lambda_zip_path) so re-run terraform apply after zipping.

3) Initialize Terraform and apply

From project root:

terraform init
# set your email directly in a prompt or use -var
terraform apply -var="alert_email=youremail@example.com" -auto-approve


What this creates:

S3 bucket (archive)

DynamoDB table

SNS topic + email subscription (you must confirm by clicking the link that's emailed)

Lambda function

EventBridge rule

Important: check the terminal for outputs (S3 bucket name, SNS ARN, Lambda name). If terraform fails because the zip path hash changed, re-run zip then terraform apply again.

4) Confirm SNS subscription

Check your email for a subject like “AWS Notification — Subscription Confirmation” and click Confirm subscription. Until you confirm, email alerts won’t deliver.

5) Test the flow by simulating a GuardDuty event

Use AWS CLI to put the test event to EventBridge (same region as Terraform deployment):

aws events put-events --entries file://sample-event.json --region eu-west-1


If successful, the EventBridge rule will invoke the Lambda.

Check:

Lambda CloudWatch logs: aws logs tail /aws/lambda/phish-detect-poc-processor --follow --region eu-west-1

SNS email (you should receive the alert soon after Lambda publishes)

S3 bucket aws s3 ls s3://<bucket-name>/guardduty/ to see archived JSON

DynamoDB table for the record (PutItem used to record dedupe key)

6) Validate key PoC behaviors

Dedup: If you send the same detail.id again, Lambda should enqueue but DynamoDB conditional write prevents duplicate processing.

Filtering: The EventBridge rule only passes severity >= 4. Tweak sample-event.json severity to 2 to see it not trigger.

Error handling: If SNS fails (no confirmed subscription), Lambda still logs the error — check CloudWatch.

7) Cost-control & security quick wins (apply now)

Keep Lambda memory to 256MB & timeout short (10s).

In the TF, avoid enabling GuardDuty or CloudTrail Insights — we used simulated events so you pay nothing for GuardDuty.

Use email-only SNS (no SMS).

Encrypt S3; retention = 30 days (adjust s3_retention_days).

For production, switch S3 encryption to KMS and secure IAM policies further — in PoC we used default AES256.

8) Clean up (when finished with PoC)

To avoid charges, destroy the infra:

terraform destroy -var="alert_email=youremail@example.com" -auto-approve
