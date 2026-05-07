provider "aws" {
  region = "eu-west-1"
}

################################################################################
# API Key
################################################################################

module "api_key" {
  source = "../../modules/api-key"

  scope         = "REGIONAL"
  token_domains = ["example.com", "app.example.com"]
}

################################################################################
# Disabled
################################################################################

module "disabled" {
  source = "../../modules/api-key"

  create = false

  scope         = "REGIONAL"
  token_domains = ["disabled.example.com"]
}
