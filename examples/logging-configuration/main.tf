provider "aws" {
  region = local.region
}

locals {
  name   = "logging-config-${basename(path.cwd)}"
  region = "eu-west-1"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# Logging Configuration - full feature coverage
################################################################################

module "logging_configuration" {
  source = "../../modules/logging-configuration"

  region = local.region

  resource_arn            = module.wafv2.web_acl_arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  # Alternative destinations (uncomment to use):
  #   aws_kinesis_firehose_delivery_stream.waf.arn,
  #   "arn:aws:s3:::aws-waf-logs-${local.name}",

  redacted_fields = [
    { single_header = { name = "authorization" } },
    { single_header = { name = "cookie" } },
    { method = {} },
    { query_string = {} },
    { uri_path = {} },
  ]

  logging_filter = {
    default_behavior = "KEEP"
    filters = [
      {
        behavior    = "DROP"
        requirement = "MEETS_ALL"
        conditions = [
          { action_condition = { action = "ALLOW" } },
          { label_name_condition = { label_name = "awswaf:managed:aws:core-rule-set:NoUserAgent_Header" } },
        ]
      },
      {
        behavior    = "KEEP"
        requirement = "MEETS_ANY"
        conditions = [
          { action_condition = { action = "BLOCK" } },
          { action_condition = { action = "CAPTCHA" } },
          { action_condition = { action = "CHALLENGE" } },
        ]
      },
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
