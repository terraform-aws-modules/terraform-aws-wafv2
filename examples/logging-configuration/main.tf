provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "logging-config-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# Logging Configuration
################################################################################

module "logging_configuration" {
  source = "../../modules/logging-configuration"

  resource_arn            = module.wafv2.web_acl_arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_fields = [
    {
      single_header = {
        name = "authorization"
      }
    }
  ]

  logging_filter = {
    default_behavior = "KEEP"
    filters = [
      {
        behavior    = "DROP"
        requirement = "MEETS_ALL"
        conditions = [
          {
            action_condition = {
              action = "ALLOW"
            }
          }
        ]
      }
    ]
  }
}

################################################################################
# Disabled
################################################################################

module "disabled" {
  source = "../../modules/logging-configuration"

  create = false

  resource_arn            = "arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/disabled/00000000-0000-0000-0000-000000000000"
  log_destination_configs = ["arn:aws:logs:eu-west-1:123456789012:log-group:aws-waf-logs-disabled"]
}

################################################################################
# Supporting Resources
################################################################################

module "wafv2" {
  source = "../.."

  name  = local.name
  scope = "REGIONAL"

  default_action = "allow"

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = 7

  tags = local.tags
}
