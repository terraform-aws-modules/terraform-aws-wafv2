provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "regex-pattern-set-${basename(path.cwd)}"

  tags = {
    Example     = local.name
    Environment = "dev"
    Terraform   = "true"
  }
}

################################################################################
# Regex Pattern Set
################################################################################

module "regex_pattern_set" {
  source = "../../modules/regex-pattern-set"

  name        = local.name
  description = "Example regex pattern set for bot detection"
  scope       = "REGIONAL"

  regular_expressions = [
    "^BadBot.*$",
    "^EvilScraper/\\d+\\.\\d+$",
  ]

  tags = local.tags
}

################################################################################
# Disabled
################################################################################

module "disabled" {
  source = "../../modules/regex-pattern-set"

  create = false

  name = "disabled-${local.name}"
}
