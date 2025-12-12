# Advanced-AI-threat-detection-and-Phishing

Quick overview (what we’ll create)
EventBridge rule that listens for GuardDuty findings (simulated for PoC) and invokes a Lambda.
Lambda (Python) that dedupes, enriches slightly, persists to S3 & DynamoDB, and publishes to SNS (email).
SNS topic with email subscription (you’ll confirm subscription).
DynamoDB table for dedupe.
S3 bucket for archived findings.
Minimal IAM roles/policies (least privilege for PoC).
Everything deployed via Terraform from this small repo.
