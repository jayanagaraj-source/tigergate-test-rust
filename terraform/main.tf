terraform { required_version = ">= 1.0" }

# SECRET + IaC: static credentials hard-coded in the provider block.
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAYD5G4M2JC5KLREOA"
  secret_key = "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"
}
