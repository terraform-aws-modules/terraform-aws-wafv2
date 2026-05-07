# AWS WAFv2 Rule Group Terraform sub-module

Manages a standalone [`aws_wafv2_rule_group`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_rule_group) resource. Rule groups are reusable collections of rules that can be referenced by one or more Web ACLs.

> Rule groups cannot reference managed rule groups, rate-based statements, or other rule groups. Those statement types are intentionally not supported by this sub-module.

## Usage

```hcl
module "rule_group" {
  source = "terraform-aws-modules/wafv2/aws//modules/rule-group"

  name        = "example-rg"
  scope       = "REGIONAL"
  capacity    = 50
  description = "Reusable rule group with geo + URI controls"

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "example-rg"
    sampled_requests_enabled   = true
  }

  rules = {
    block-anonymous-proxies = {
      priority = 0
      action   = "block"
      statement = {
        geo_match_statement = {
          country_codes = ["RU", "BY"]
        }
      }
      visibility_config = {
        metric_name = "block-anonymous-proxies"
      }
    }
    block-admin-uri = {
      priority = 1
      action   = "count"
      statement = {
        byte_match_statement = {
          search_string         = "/admin"
          positional_constraint = "STARTS_WITH"
          field_to_match = {
            uri_path = {}
          }
          text_transformation = [{
            priority = 0
            type     = "LOWERCASE"
          }]
        }
      }
      visibility_config = {
        metric_name = "block-admin-uri"
      }
    }
  }

  tags = {
    Environment = "dev"
  }
}
```

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
| [aws_wafv2_rule_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_rule_group) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_capacity"></a> [capacity](#input\_capacity) | The web ACL capacity units (WCUs) required for this rule group. Valid range is 1 to 1500 | `number` | n/a | yes |
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created (affects all resources) | `bool` | `true` | no |
| <a name="input_custom_response_body"></a> [custom\_response\_body](#input\_custom\_response\_body) | Map of custom response body configurations. Key is the reference key, used in custom responses | `any` | `{}` | no |
| <a name="input_description"></a> [description](#input\_description) | A friendly description of the rule group | `string` | `null` | no |
| <a name="input_name"></a> [name](#input\_name) | A friendly name of the rule group. Conflicts with `name_prefix` | `string` | `""` | no |
| <a name="input_name_prefix"></a> [name\_prefix](#input\_name\_prefix) | Creates a unique name beginning with the specified prefix. Conflicts with `name` | `string` | `null` | no |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_rules"></a> [rules](#input\_rules) | Map of WAF rule configurations. The key is used as the rule name.<br/><br/>Each rule supports:<br/>- `priority`          - (Required) Rule priority (lower = evaluated first)<br/>- `action`            - Action: string (`allow`, `block`, `count`, `captcha`, `challenge`) or object for custom response<br/>- `statement`         - (Required) Rule statement configuration. See AWS provider docs for statement structure.<br/>                        NOTE: rule groups cannot reference managed rule groups, rate-based statements,<br/>                        or other rule groups, so those statement types are not supported here.<br/>- `visibility_config` - CloudWatch metrics config. Auto-generated from rule key if omitted<br/>- `captcha_config`    - Optional CAPTCHA configuration<br/>- `challenge_config`  - Optional challenge configuration<br/>- `rule_labels`       - Optional list of labels to add to matching requests | `any` | `{}` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Specifies whether this is for an AWS CloudFront distribution or for a regional application. Valid values are `CLOUDFRONT` or `REGIONAL` | `string` | `"REGIONAL"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |
| <a name="input_visibility_config"></a> [visibility\_config](#input\_visibility\_config) | Visibility configuration for the rule group. Defines CloudWatch metrics configuration | <pre>object({<br/>    cloudwatch_metrics_enabled = optional(bool, true)<br/>    metric_name                = optional(string)<br/>    sampled_requests_enabled   = optional(bool, true)<br/>  })</pre> | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_arn"></a> [arn](#output\_arn) | The ARN of the WAF rule group |
| <a name="output_capacity"></a> [capacity](#output\_capacity) | The capacity (WCUs) configured for the rule group |
| <a name="output_id"></a> [id](#output\_id) | The ID of the WAF rule group |
| <a name="output_lock_token"></a> [lock\_token](#output\_lock\_token) | Lock token used by AWS to detect concurrent modifications |
| <a name="output_tags_all"></a> [tags\_all](#output\_tags\_all) | Map of tags assigned to the resource, including those inherited from the provider default\_tags configuration block |
<!-- END_TF_DOCS -->

## License

Apache-2.0. See [LICENSE](../../LICENSE).
