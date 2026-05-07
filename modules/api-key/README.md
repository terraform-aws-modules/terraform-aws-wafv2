# AWS WAF v2 API Key Submodule

Terraform submodule which creates an AWS WAFv2 API Key for CAPTCHA / JavaScript challenge integrations on a set of token domains.

## Usage

```hcl
module "api_key" {
  source = "terraform-aws-modules/wafv2/aws//modules/api-key"

  scope         = "REGIONAL"
  token_domains = ["example.com", "app.example.com"]
}
```

> **Note:** When `scope = "CLOUDFRONT"`, the resource must be created in the `us-east-1` region.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.37 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.37 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_wafv2_api_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_api_key) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created | `bool` | `true` | no |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Specifies whether this is for an AWS CloudFront distribution or for a regional application. Valid values are `CLOUDFRONT` or `REGIONAL`. Note: WAFv2 API Keys for `CLOUDFRONT` must be created in the `us-east-1` region | `string` | `"REGIONAL"` | no |
| <a name="input_token_domains"></a> [token\_domains](#input\_token\_domains) | The domains the API key may be used with (up to 5) | `list(string)` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_key"></a> [api\_key](#output\_api\_key) | The generated API key. Sensitive — do not log |
| <a name="output_scope"></a> [scope](#output\_scope) | The scope (REGIONAL or CLOUDFRONT) of the API key |
| <a name="output_token_domains"></a> [token\_domains](#output\_token\_domains) | The token domains the API key is bound to |
<!-- END_TF_DOCS -->
