variable "aws_region" { type = string; default = "eu-west-1" }
variable "alert_email" { type = string }
variable "lambda_memory" { type = number; default = 256 }
variable "lambda_timeout" { type = number; default = 10 }
variable "s3_retention_days" { type = number; default = 30 }
variable "lambda_zip_path" { type = string; default = "${path.module}/lambda_src/detector.zip" }
