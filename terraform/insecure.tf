# Deliberately insecure IaC fixture for scanner validation. Do not apply.
resource "aws_s3_bucket" "public_fixture" {
  bucket = "tigergate-test-rust-public-fixture"
  acl    = "public-read-write" # public ACL

  # no server-side encryption
  # versioning disabled
  versioning {
    enabled = false
  }
  # access logging disabled
}

resource "aws_s3_bucket_public_access_block" "public_fixture" {
  bucket                  = aws_s3_bucket.public_fixture.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public_fixture.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadWrite"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
      Resource  = "${aws_s3_bucket.public_fixture.arn}/*"
    }]
  })
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

resource "aws_kms_key" "no_rotation" {
  description         = "tigergate fixture key"
  enable_key_rotation = false
}

resource "aws_sqs_queue" "unencrypted" {
  name = "tigergate-orders" # queue not encrypted
}

resource "aws_sns_topic" "unencrypted" {
  name = "tigergate-alerts" # topic not encrypted
}

resource "aws_dynamodb_table" "no_pitr" {
  name         = "tigergate-sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }
}
