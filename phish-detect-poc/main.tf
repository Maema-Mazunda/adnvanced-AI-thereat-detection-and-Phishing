# Random suffix for unique resources
resource "random_id" "suffix" {
byte_length = 4
}


# S3 bucket for phishing artifacts
resource "aws_s3_bucket" "archive" {
bucket = "${var.project_name}-${random_id.suffix.hex}"
}


resource "aws_s3_bucket_lifecycle_configuration" "archive_lifecycle" {
bucket = aws_s3_bucket.archive.id


rule {
id = "expire"
status = "Enabled"


expiration {
days = var.s3_retention_days
}
}
}


# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
name = "${var.project_name}-alerts"
}


resource "aws_sns_topic_subscription" "email" {
topic_arn = aws_sns_topic.alerts.arn
protocol = "email"
endpoint = var.alert_email
}


# DynamoDB table
resource "aws_dynamodb_table" "phish_events" {
name = "${var.project_name}-events"
billing_mode = "PAY_PER_REQUEST"
hash_key = "event_id"


attribute {
name = "event_id"
type = "S"
}
}


# IAM role for Lambda
resource "aws_iam_role" "lambda_role" {
name = "${var.project_name}-lambda-role"


assume_role_policy = jsonencode({
Version = "2012-10-17"
Statement = [{
Effect = "Allow"
Principal = { Service = "lambda.amazonaws.com" }
Action = "sts:AssumeRole"
}]
})
}


resource "aws_iam_role_policy_attachment" "basic" {
role = aws_iam_role.lambda_role.name
policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}


# Lambda function (placeholder zip)
resource "aws_lambda_function" "phish_detector" {
function_name = "${var.project_name}-lambda"
role = aws_iam_role.lambda_role.arn
handler = "handler.lambda_handler"
runtime = "python3.12"


filename = "lambda.zip"
source_code_hash = filebase64sha256("lambda.zip")


environment {
variables = {
TABLE_NAME = aws_dynamodb_table.phish_events.name
TOPIC_ARN = aws_sns_topic.alerts.arn
}
}
}