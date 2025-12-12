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
