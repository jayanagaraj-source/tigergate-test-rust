# DELIBERATELY INSECURE networking — IaC scanner fixture. Do not apply.

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  # VPC flow logs not enabled.
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # public IPs assigned automatically
}

resource "aws_security_group" "wide_open" {
  name   = "tigergate-wide-open"
  vpc_id = aws_vpc.main.id
  # missing description

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SSH open to the internet
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # RDP open to the internet
  }

  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"] # all ports, all protocols
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # unrestricted egress
  }
}

resource "aws_network_acl_rule" "allow_all" {
  network_acl_id = aws_vpc.main.default_network_acl_id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0" #  / 0102: NACL allows everything
}

resource "aws_lb" "public" {
  name                       = "tigergate-public-alb"
  internal                   = false # internet-facing
  load_balancer_type         = "application"
  subnets                    = [aws_subnet.public.id]
  drop_invalid_header_fields = false
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.public.arn
  port              = 80
  protocol          = "HTTP" # plain HTTP listener

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}
