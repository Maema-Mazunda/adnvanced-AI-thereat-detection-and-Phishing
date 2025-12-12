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