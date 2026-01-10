terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "matverse-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b", "${var.aws_region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = false
  enable_vpn_gateway = false

  tags = {
    Environment = var.environment
    Project     = "cassandra-matverse"
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = "matverse-cluster"
  cluster_version = "1.27"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    main = {
      min_size     = 3
      max_size     = 10
      desired_size = 3

      instance_types = ["t3.large", "m5.large"]
      capacity_type  = "ON_DEMAND"

      labels = {
        node-type = "cassandra"
      }

      taints = []
    }
  }

  tags = {
    Environment = var.environment
    Project     = "cassandra-matverse"
  }
}

module "rds" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = "matverse-db"

  engine               = "postgres"
  engine_version       = "15"
  family               = "postgres15"
  major_engine_version = "15"
  instance_class       = "db.t3.large"

  allocated_storage     = 100
  max_allocated_storage = 200
  storage_encrypted     = true

  db_name  = "cassandra_ledger"
  username = var.db_username
  port     = 5432

  vpc_security_group_ids = [module.vpc.default_security_group_id]
  subnet_ids             = module.vpc.private_subnets

  maintenance_window = "Mon:00:00-Mon:03:00"
  backup_window      = "03:00-06:00"
  backup_retention_period = 30

  tags = {
    Environment = var.environment
    Project     = "cassandra-matverse"
  }
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "matverse-redis-subnets"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id            = "matverse-redis"
  engine                = "redis"
  node_type             = "cache.t3.medium"
  num_cache_nodes       = 3
  parameter_group_name  = "default.redis7"
  port                  = 6379
  security_group_ids    = [module.vpc.default_security_group_id]
  subnet_group_name     = aws_elasticache_subnet_group.redis.name

  tags = {
    Environment = var.environment
    Project     = "cassandra-matverse"
  }
}

resource "aws_s3_bucket" "backups" {
  bucket = "matverse-backups-${var.environment}"

  tags = {
    Environment = var.environment
    Project     = "cassandra-matverse"
  }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "backup-retention"
    status = "Enabled"

    expiration {
      days = var.backup_retention_days
    }
  }
}

resource "aws_iam_policy" "s3_backup" {
  name        = "matverse-s3-backup"
  description = "Permite acesso ao bucket de backups do Cassandra-MatVerse."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BackupBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          aws_s3_bucket.backups.arn,
          "${aws_s3_bucket.backups.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "rds_access" {
  name        = "matverse-rds-access"
  description = "Permite acesso de leitura à metadata do RDS Cassandra-MatVerse."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RdsDescribe"
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters"
        ]
        Resource = "*"
      }
    ]
  })
}

module "iam_assumable_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc"
  version = "~> 5.0"

  create_role = true

  role_name = "matverse-node-role"

  provider_url = module.eks.cluster_oidc_issuer_url
  role_policy_arns = [
    aws_iam_policy.s3_backup.arn,
    aws_iam_policy.rds_access.arn
  ]

  oidc_fully_qualified_subjects = [
    "system:serviceaccount:production:cassandra-matverse"
  ]
}

output "cluster_endpoint" {
  description = "EKS Cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.rds.db_instance_address
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis endpoint"
  value       = aws_elasticache_cluster.redis.cache_nodes[0].address
}
