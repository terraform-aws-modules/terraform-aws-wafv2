provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "basic-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# WAF v2 Web ACL
################################################################################

module "wafv2" {
  source = "../.."

  name  = local.name
  scope = "REGIONAL"

  default_action = "allow"

  rules = {
    common-rule-set = {
      priority        = 1
      override_action = "none"

      statement = {
        managed_rule_group_statement = {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
        }
      }
    }
  }

  tags = local.tags
}
