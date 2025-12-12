⭐ Project Overview

This Proof-of-Concept demonstrates how to detect phishing-related GuardDuty findings using a serverless, event-driven architecture on AWS — all deployed via Terraform, low-cost, and free-tier friendly.

🧩 Architecture Components

EventBridge Rule listening for GuardDuty findings (severity ≥ 4)

Lambda function (Python)

dedupes findings using DynamoDB

lightly enriches and scores threat data

archives to S3

sends notifications via SNS

DynamoDB Table for dedupe logic

S3 Bucket for threat-archive retention

SNS Topic with email subscription

IAM Roles with least privilege

Terraform-managed end-to-end infrastructure

phish-detect-poc/
│
├── providers.tf
├── main.tf
├── variables.tf
├── outputs.tf     # (optional – included in main.tf)
│
├── lambda_src/
│   ├── handler.py
│   ├── __init__.py
│   └── detector.zip   # created after packaging
│
└── sample-event.json

1️⃣ Terraform Files
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
2️⃣ Lambda Function Code

Inside lambda_src/handler.py:

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
        table.put_item(
            Item={'finding_id': fid, 'ts': int(time.time())},
            ConditionExpression='attribute_not_exists(finding_id)'
        )
        return False
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return True
        raise

def enrich(detail):
    enriched = {
        'id': detail.get('id'),
        'title': detail.get('title', 'No title'),
        'severity': detail.get('severity', 0),
        'description': detail.get('description', ''),
        'urls': extract_urls(detail.get('description', ''))
    }
    enriched['score'] = enriched['severity'] * (1 + len(enriched['urls']))
    enriched['raw'] = detail
    return enriched

def extract_urls(text):
    return re.findall(r'https?://[^\s,"]+', text) if text else []

def persist(enriched):
    if S3_BUCKET:
        key = f"guardduty/{enriched.get('id', str(time.time()))}.json"
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(enriched).encode('utf-8')
        )

def publish(enriched):
    subject = f"[ALERT] {enriched.get('title')} sev:{enriched.get('severity')}"
    message = json.dumps(enriched, default=str)
    try:
        sns.publish(TopicArn=ALERT_TOPIC, Subject=subject, Message=message)
    except Exception as e:
        print("SNS publish failed:", str(e))

3️⃣ Packaging the Lambda

From project root:
cd lambda_src
zip -r ../lambda_src/detector.zip .
cd ..

Terraform validates the ZIP via:
filebase64sha256()

4️⃣ Deploy
terraform init

terraform apply \
  -var="alert_email=youremail@example.com" \
  -auto-approve

Terraform will output:

S3 archive bucket

DynamoDB table name

Lambda function name

SNS topic ARN

5️⃣ Confirm SNS Subscription

Check your inbox for:

AWS Notification — Subscription Confirmation

Click Confirm subscription.

Without confirmation, Lambda alerts won't email you.

6️⃣ Test With Sample Event
Run:

aws events put-events --entries file://sample-event.json --region eu-west-1

Then check:

Lambda logs

aws logs tail /aws/lambda/phish-detect-poc-processor --follow --region eu-west-1

S3 archive

aws s3 ls s3://<bucket-name>/guardduty/

7️⃣ PoC Validations
Behavior	    How to Validate
Deduping works	    Send same finding twice → 2nd is skipped
Severity filter works    	Change severity to 2 → EventBridge won’t invoke
S3 archival    	JSON file appears in bucket
SNS alert       	Email arrives
IAM least-privilege	  Only required permissions included

8️⃣ Cost Control

✔ Uses only free-tier services
✔ Does not enable GuardDuty (events are simulated)
✔ DynamoDB is PAY_PER_REQUEST
✔ S3 has 30-day auto-expire lifecycle
✔ Lambda optimized: 256MB, 10-second timeout

9️⃣ Cleanup

To avoid charges:

terraform destroy \
  -var="alert_email=youremail@example.com" \
  -auto-approve
