# DELIBERATELY INSECURE IAM — IaC scanner fixture. Do not apply.

resource "aws_iam_policy" "admin_everything" {
  name = "tigergate-admin-everything"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*" # wildcard action
      Resource = "*" # wildcard resource
    }]
  })
}

resource "aws_iam_user" "ci" {
  name = "tigergate-ci"
}

resource "aws_iam_user_policy_attachment" "ci_admin" {
  user       = aws_iam_user.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # policy on user
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name # long-lived static access key
}

resource "aws_iam_role" "assume_by_anyone" {
  name = "tigergate-assume-by-anyone"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" } # any AWS account can assume this role
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length      = 6
  require_symbols              = false
  require_numbers              = false
  require_uppercase_characters = false
  require_lowercase_characters = false
  password_reuse_prevention    = 0
  max_password_age             = 0
}
