variable "aws_region" {
  description = "Região AWS para provisionamento do stack."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Ambiente de implantação (production, staging, development)."
  type        = string
  default     = "production"
}

variable "db_username" {
  description = "Usuário master do PostgreSQL."
  type        = string
  default     = "matverse"
}

variable "backup_retention_days" {
  description = "Número de dias de retenção dos backups no S3."
  type        = number
  default     = 30
}
