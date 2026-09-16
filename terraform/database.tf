# DELIBERATELY INSECURE databases — IaC scanner fixture. Do not apply.

resource "aws_db_instance" "orders" {
  identifier                          = "tigergate-orders"
  engine                              = "mysql"
  engine_version                      = "5.6.51" # end-of-life engine
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  password                            = "YD1BE4nRNpELLvMz9Arn" # SECRET: hard-coded DB password
  publicly_accessible                 = true
  storage_encrypted                   = false
  backup_retention_period             = 0
  skip_final_snapshot                 = true
  deletion_protection                 = false
  iam_database_authentication_enabled = false
  vpc_security_group_ids              = [aws_security_group.wide_open.id]
}

resource "aws_rds_cluster" "analytics" {
  cluster_identifier      = "tigergate-analytics"
  engine                  = "aurora-postgresql"
  master_username         = "postgres"
  master_password         = "Sup3rS3cretSmtpP@ssw0rd"
  storage_encrypted       = false
  backup_retention_period = 1
}

resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id          = "tigergate-sessions"
  replication_group_description = "sessions"
  node_type                     = "cache.t3.micro"
  number_cache_clusters         = 1
  at_rest_encryption_enabled    = false
  transit_encryption_enabled    = false
}

resource "aws_elasticsearch_domain" "logs" {
  domain_name = "tigergate-logs"

  encrypt_at_rest {
    enabled = false
  }

  node_to_node_encryption {
    enabled = false
  }

  domain_endpoint_options {
    enforce_https = false
  }
}
