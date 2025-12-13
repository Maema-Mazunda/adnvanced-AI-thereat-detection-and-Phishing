variable "aws_region" {
description = "AWS region"
type = string
default = "eu-west-1"
}


variable "project_name" {
description = "Project name"
type = string
default = "phish-detect-poc"
}


variable "s3_retention_days" {
description = "Days to retain S3 objects"
type = number
default = 30
}


variable "alert_email" {
description = "Email address for SNS alerts"
type = string
}