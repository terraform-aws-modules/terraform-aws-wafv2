provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "rg-assoc-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# Web ACL (must use lifecycle.ignore_changes = [rule]) — created via raw resource for clarity
################################################################################

resource "aws_wafv2_web_acl" "this" {
  name  = local.name
  scope = "REGIONAL"

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

  tags = local.tags
}

################################################################################
# Custom rule group (so the example is self-contained)
################################################################################

resource "aws_wafv2_rule_group" "this" {
  name     = "${local.name}-rg"
  scope    = "REGIONAL"
  capacity = 10

  rule {
    name     = "block-cn"
    priority = 1

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = ["CN"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "block-cn"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-rg"
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

################################################################################
# Association — managed rule group
################################################################################

module "association_managed" {
  source = "../../modules/web-acl-rule-group-association"

  rule_name   = "aws-common-rules"
  priority    = 50
  web_acl_arn = aws_wafv2_web_acl.this.arn

  managed_rule_group = {
    name        = "AWSManagedRulesCommonRuleSet"
    vendor_name = "AWS"
  }
}

################################################################################
# Association — custom rule group
################################################################################

module "association_custom" {
  source = "../../modules/web-acl-rule-group-association"

  rule_name   = "custom-geo-block"
  priority    = 100
  web_acl_arn = aws_wafv2_web_acl.this.arn

  rule_group_reference = {
    arn = aws_wafv2_rule_group.this.arn
  }
}
