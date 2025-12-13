output "s3_bucket" {
value = aws_s3_bucket.archive.bucket
}


output "sns_topic_arn" {
value = aws_sns_topic.alerts.arn
}


output "lambda_name" {
value = aws_lambda_function.phish_detector.function_name
}


output "ddb_table" {
value = aws_dynamodb_table.phish_events.name
}