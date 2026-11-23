variable "s3_buckets" {
  description = "Names of the S3 buckets Macie should classify"
  type        = list(string)
}
