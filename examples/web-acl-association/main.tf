provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "web-acl-assoc-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# Web ACL Association
################################################################################

module "web_acl_association" {
  source = "../../modules/web-acl-association"

  web_acl_arn  = module.wafv2.web_acl_arn
  resource_arn = aws_cognito_user_pool.this.arn
}

################################################################################
# Disabled
################################################################################

module "disabled" {
  source = "../../modules/web-acl-association"

  create = false

  web_acl_arn  = "arn:aws:wafv2:eu-west-1:123456789012:regional/webacl/disabled/00000000-0000-0000-0000-000000000000"
  resource_arn = "arn:aws:cognito-idp:eu-west-1:123456789012:userpool/eu-west-1_disabled"
}

################################################################################
# Supporting Resources
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

resource "aws_cognito_user_pool" "this" {
  name = local.name

  tags = local.tags
}
