provider "aws" {
  region = local.region
}

locals {
  region = "eu-west-1"
  name   = "wafv2-walrule-ex-${basename(path.cwd)}"
}

################################################################################
# Web ACL (raw resource — needs `lifecycle { ignore_changes = [rule] }` so the
# inline-rule field stops fighting with the standalone rule resources below.
# The root module does not expose lifecycle overrides, hence the raw resource.)
################################################################################

resource "aws_wafv2_web_acl" "this" {
  name        = local.name
  description = "Example showing standalone web-acl-rule attachments"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }

  lifecycle {
    ignore_changes = [rule]
  }

  tags = {
    Example = local.name
  }
}

################################################################################
# Standalone Rules
#
# These resources fix the WAFAssociatedItemException deletion-ordering issue
# you hit when removing IP sets / rule groups that are referenced by inline
# rules. Terraform deletes the rule first and the referenced resource second.
################################################################################

module "block_high_risk_geos" {
  source = "../../modules/web-acl-rule"

  name        = "block-high-risk-geos"
  priority    = 1
  web_acl_arn = aws_wafv2_web_acl.this.arn

  action = "block"

  statement = {
    geo_match_statement = {
      country_codes = ["RU", "BY", "KP"]
    }
  }

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "block-high-risk-geos"
    sampled_requests_enabled   = true
  }
}

module "rate_limit_per_ip" {
  source = "../../modules/web-acl-rule"

  name        = "rate-limit-per-ip"
  priority    = 2
  web_acl_arn = aws_wafv2_web_acl.this.arn

  action = "block"

  statement = {
    rate_based_statement = {
      limit              = 2000
      aggregate_key_type = "IP"
    }
  }

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "rate-limit-per-ip"
    sampled_requests_enabled   = true
  }
}
