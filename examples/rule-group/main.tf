provider "aws" {
  region = local.region
}

locals {
  region = "eu-west-1"
  name   = "wafv2-rule-group-ex-${basename(path.cwd)}"
}

################################################################################
# Rule Group
################################################################################

module "rule_group" {
  source = "../../modules/rule-group"

  name        = local.name
  description = "Example WAFv2 rule group"
  scope       = "REGIONAL"
  capacity    = 50

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }

  rules = {
    block-high-risk-geos = {
      priority = 0
      action   = "block"
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

    count-admin-uri = {
      priority = 1
      action   = "count"
      statement = {
        byte_match_statement = {
          search_string         = "/admin"
          positional_constraint = "STARTS_WITH"
          field_to_match = {
            uri_path = {}
          }
          text_transformations = [
            {
              priority = 0
              type     = "LOWERCASE"
            },
          ]
        }
      }
      visibility_config = {
        cloudwatch_metrics_enabled = true
        metric_name                = "count-admin-uri"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = {
    Example     = local.name
    Environment = "dev"
  }
}
