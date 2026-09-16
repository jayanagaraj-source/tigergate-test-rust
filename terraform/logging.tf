# DELIBERATELY INSECURE logging/monitoring — IaC scanner fixture. Do not apply.

resource "aws_cloudtrail" "main" {
  name                          = "tigergate-trail"
  s3_bucket_name                = aws_s3_bucket.public_fixture.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
  # no KMS encryption; no CloudWatch integration
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/tigergate/app"
  retention_in_days = 1 # no KMS key, very short retention
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled = true

  origin {
    domain_name = aws_s3_bucket.public_fixture.bucket_regional_domain_name
    origin_id   = "s3-origin"
  }

  default_cache_behavior {
    target_origin_id       = "s3-origin"
    viewer_protocol_policy = "allow-all" # HTTP allowed
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1" # outdated TLS
  }
  # access logging disabled; no WAF
}
