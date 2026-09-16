# DELIBERATELY INSECURE compute — IaC scanner fixture. Do not apply.

resource "aws_instance" "bastion" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.wide_open.id]
  associate_public_ip_address = true

  # IMDSv1 allowed (http_tokens not required)
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted = false
  }

  # SECRET: credentials in user_data
  user_data = <<-EOT
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAYD5G4M2JC5KLREOA
    export AWS_SECRET_ACCESS_KEY=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
    echo "root:password123" | chpasswd
    sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
  EOT
}

resource "aws_launch_configuration" "workers" {
  name_prefix   = "tigergate-workers-"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  root_block_device {
    encrypted = false
  }
}

resource "aws_ecr_repository" "app" {
  name                 = "tigergate-test-rust"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_eks_cluster" "main" {
  name     = "tigergate"
  role_arn = aws_iam_role.assume_by_anyone.arn

  vpc_config {
    subnet_ids             = [aws_subnet.public.id]
    endpoint_public_access = true
    public_access_cidrs    = ["0.0.0.0/0"]
  }
  # control plane logging disabled
}
