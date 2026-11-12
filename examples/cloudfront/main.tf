provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "cloudfront-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# WAF v2 Web ACL For Cloudfront
# For Cloudfront region of all WAFv2 resources should be us-east-1
# Also do not use association_resource_arns to associate a WAFv2 Web ACL with a Cloudfront Distribution. The AWS API call backing this resource notes that you should use the web_acl_id property on the cloudfront_distribution instead.
################################################################################

module "wafv2" {
  source = "../.."

  # Cloudfront WAF Should use us-east-1 region
  region = "us-east-1"

  name  = local.name
  scope = "CLOUDFRONT"

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
