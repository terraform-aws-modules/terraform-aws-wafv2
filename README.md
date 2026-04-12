# AWS WAF v2 Terraform Module

Terraform module which creates AWS WAF v2 Web ACL resources with comprehensive rule support.

[![SWUbanner](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner2-direct.svg)](https://github.com/vshymanskyy/StandWithUkraine/blob/main/docs/README.md)

## Usage

```hcl
module "wafv2" {
  source  = "terraform-aws-modules/wafv2/aws"

  name  = "my-web-acl"
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

    rate-limit = {
      priority = 2
      action   = "block"

      statement = {
        rate_based_statement = {
          limit = 1000
        }
      }
    }
  }

  tags = {
    Environment = "dev"
    Terraform   = "true"
  }
}
```

## Features

- AWS WAF v2 Web ACL with comprehensive rule statement support
- All 12+ statement types: byte match, geo match, IP set reference, label match, managed rule group, rate based, regex match, regex pattern set reference, rule group reference, size constraint, SQLi match, XSS match
- Compound statements (AND, OR, NOT) with 2 levels of nesting
- Dual-mode actions: simple string (`"allow"`, `"block"`, `"count"`, `"captcha"`, `"challenge"`) or objects with custom response/request handling
- Custom response bodies
- CAPTCHA and challenge configuration
- Association configuration for request body size limits
- Optional inline Web ACL associations
- Optional inline logging configuration
- Submodules for IP sets, regex pattern sets, Web ACL associations, and logging configuration

## Conditional Creation

The module supports conditional resource creation:

```hcl
module "wafv2" {
  source = "terraform-aws-modules/wafv2/aws"

  create = false
}
```

## Submodules

- [ip-set](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/modules/ip-set) - Manages WAF v2 IP sets
- [regex-pattern-set](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/modules/regex-pattern-set) - Manages WAF v2 regex pattern sets
- [web-acl-association](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/modules/web-acl-association) - Manages WAF v2 Web ACL associations
- [logging-configuration](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/modules/logging-configuration) - Manages WAF v2 logging configuration

## Examples

- [Basic](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/examples/basic) - Minimal example with a single managed rule group
- [Complete](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/examples/complete) - Comprehensive example with all major features
- [IP Set](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/examples/ip-set) - IP set submodule with IPv4 and IPv6 sets
- [Regex Pattern Set](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/examples/regex-pattern-set) - Regex pattern set submodule
- [Web ACL Association](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/examples/web-acl-association) - Web ACL association with a Cognito User Pool
- [Logging Configuration](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/examples/logging-configuration) - Logging configuration with CloudWatch Logs

## Module Wrappers

For managing multiple similar resources, see [wrappers](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/wrappers).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
| ---- | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.75 |

## Providers

| Name | Version |
| ---- | ------- |
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.75 |

## Modules

No modules.

## Resources

| Name | Type |
| ---- | ---- |
| [aws_wafv2_web_acl.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [aws_wafv2_web_acl_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |
| [aws_wafv2_web_acl_logging_configuration.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |

## Inputs

| Name | Description | Type | Default | Required |
| ---- | ----------- | ---- | ------- | :------: |
| <a name="input_association_config"></a> [association\_config](#input\_association\_config) | Configuration for body inspection size limits per resource type. Keys are resource types (e.g., `CLOUDFRONT`, `API_GATEWAY`, `COGNITO_USER_POOL`, `APP_RUNNER_SERVICE`, `VERIFIED_ACCESS_INSTANCE`) | <pre>map(object({<br/>    default_size_inspection_limit = string<br/>  }))</pre> | `{}` | no |
| <a name="input_association_resource_arns"></a> [association\_resource\_arns](#input\_association\_resource\_arns) | Map of resource ARNs to associate with the Web ACL. Key is a friendly name, value is the resource ARN | `map(string)` | `{}` | no |
| <a name="input_captcha_config"></a> [captcha\_config](#input\_captcha\_config) | CAPTCHA configuration for the Web ACL. Specifies how long a CAPTCHA timestamp is considered valid | <pre>object({<br/>    immunity_time_property = object({<br/>      immunity_time = number<br/>    })<br/>  })</pre> | `null` | no |
| <a name="input_challenge_config"></a> [challenge\_config](#input\_challenge\_config) | Challenge configuration for the Web ACL. Specifies how long a challenge timestamp is considered valid | <pre>object({<br/>    immunity_time_property = object({<br/>      immunity_time = number<br/>    })<br/>  })</pre> | `null` | no |
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created (affects all resources) | `bool` | `true` | no |
| <a name="input_create_logging_configuration"></a> [create\_logging\_configuration](#input\_create\_logging\_configuration) | Controls if a logging configuration should be created for the Web ACL | `bool` | `false` | no |
| <a name="input_custom_response_bodies"></a> [custom\_response\_bodies](#input\_custom\_response\_bodies) | Map of custom response body configurations. Key is the reference key, used in custom responses | <pre>map(object({<br/>    content      = string<br/>    content_type = string<br/>  }))</pre> | `{}` | no |
| <a name="input_default_action"></a> [default\_action](#input\_default\_action) | Action to perform if none of the rules contained in the Web ACL match. Use `allow` or `block` for simple actions, or provide an object for custom request handling/response. See examples for object structure | `any` | `"allow"` | no |
| <a name="input_description"></a> [description](#input\_description) | A friendly description of the Web ACL | `string` | `null` | no |
| <a name="input_logging_filter"></a> [logging\_filter](#input\_logging\_filter) | A configuration block that specifies which web requests are kept in the logs and which are dropped | <pre>object({<br/>    default_behavior = string<br/>    filters = list(object({<br/>      behavior    = string<br/>      requirement = string<br/>      conditions = list(object({<br/>        action_condition = optional(object({<br/>          action = string<br/>        }))<br/>        label_name_condition = optional(object({<br/>          label_name = string<br/>        }))<br/>      }))<br/>    }))<br/>  })</pre> | `null` | no |
| <a name="input_logging_log_destination_configs"></a> [logging\_log\_destination\_configs](#input\_logging\_log\_destination\_configs) | The Amazon Kinesis Data Firehose, CloudWatch Log Group, or S3 Bucket ARNs for the logging destination | `list(string)` | `[]` | no |
| <a name="input_logging_redacted_fields"></a> [logging\_redacted\_fields](#input\_logging\_redacted\_fields) | The parts of the request that you want to keep out of the logs | `any` | `[]` | no |
| <a name="input_name"></a> [name](#input\_name) | A friendly name of the Web ACL | `string` | `""` | no |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_rule_json"></a> [rule\_json](#input\_rule\_json) | Escape hatch: JSON string of WAF rules for cases where dynamic blocks cannot represent all provider features. Mutually exclusive with `rules` | `string` | `null` | no |
| <a name="input_rules"></a> [rules](#input\_rules) | Map of WAF rule configurations. The key is used as the rule name.<br/><br/>Each rule supports:<br/>- `priority`          - (Required) Rule priority (lower = evaluated first)<br/>- `action`            - Action for standalone rules. Use string (`allow`, `block`, `count`, `captcha`, `challenge`) or object for custom response<br/>- `override_action`   - Override action for managed/rule group rules. Use string (`none`, `count`) or object<br/>- `statement`         - (Required) Rule statement configuration. See AWS provider docs for statement structure<br/>- `visibility_config` - CloudWatch metrics config. Auto-generated from rule key if omitted<br/>- `captcha_config`    - Optional CAPTCHA configuration<br/>- `challenge_config`  - Optional challenge configuration<br/>- `rule_labels`       - Optional list of labels to add to matching requests<br/><br/>See examples/complete for usage patterns. | `any` | `{}` | no |
| <a name="input_scope"></a> [scope](#input\_scope) | Specifies whether this is for an AWS CloudFront distribution or for a regional application. Valid values are `CLOUDFRONT` or `REGIONAL` | `string` | `"REGIONAL"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |
| <a name="input_token_domains"></a> [token\_domains](#input\_token\_domains) | Specifies the domains that AWS WAF should accept in a web request token. Enables token use across multiple protected resources | `list(string)` | `[]` | no |
| <a name="input_visibility_config"></a> [visibility\_config](#input\_visibility\_config) | Visibility configuration for the Web ACL. Defines CloudWatch metrics configuration | <pre>object({<br/>    cloudwatch_metrics_enabled = optional(bool, true)<br/>    metric_name                = optional(string)<br/>    sampled_requests_enabled   = optional(bool, true)<br/>  })</pre> | `{}` | no |

## Outputs

| Name | Description |
| ---- | ----------- |
| <a name="output_logging_configuration_id"></a> [logging\_configuration\_id](#output\_logging\_configuration\_id) | The ID of the WAF logging configuration |
| <a name="output_web_acl_application_integration_url"></a> [web\_acl\_application\_integration\_url](#output\_web\_acl\_application\_integration\_url) | The URL to use in SDK integrations with managed rule groups |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | The ARN of the Web ACL |
| <a name="output_web_acl_association_ids"></a> [web\_acl\_association\_ids](#output\_web\_acl\_association\_ids) | Map of Web ACL association IDs |
| <a name="output_web_acl_capacity"></a> [web\_acl\_capacity](#output\_web\_acl\_capacity) | Web ACL capacity units (WCUs) currently being used by this Web ACL |
| <a name="output_web_acl_description"></a> [web\_acl\_description](#output\_web\_acl\_description) | The description of the Web ACL |
| <a name="output_web_acl_id"></a> [web\_acl\_id](#output\_web\_acl\_id) | The ID of the Web ACL |
| <a name="output_web_acl_lock_token"></a> [web\_acl\_lock\_token](#output\_web\_acl\_lock\_token) | A token used for optimistic locking |
| <a name="output_web_acl_name"></a> [web\_acl\_name](#output\_web\_acl\_name) | The name of the Web ACL |
| <a name="output_web_acl_rule_names"></a> [web\_acl\_rule\_names](#output\_web\_acl\_rule\_names) | List of rule names in the Web ACL |
| <a name="output_web_acl_tags_all"></a> [web\_acl\_tags\_all](#output\_web\_acl\_tags\_all) | A map of tags assigned to the resource, including those inherited from the provider default\_tags configuration block |
| <a name="output_web_acl_visibility_config"></a> [web\_acl\_visibility\_config](#output\_web\_acl\_visibility\_config) | The visibility configuration of the Web ACL |
<!-- END_TF_DOCS -->

## Authors

Module is maintained by [Anton Babenko](https://github.com/antonbabenko) with help from [these awesome contributors](https://github.com/terraform-aws-modules/terraform-aws-wafv2/graphs/contributors).

## License

Apache 2 Licensed. See [LICENSE](https://github.com/terraform-aws-modules/terraform-aws-wafv2/tree/master/LICENSE) for full details.

## Additional information for users from Russia and Belarus

* Russia has [illegally annexed Crimea in 2014](https://en.wikipedia.org/wiki/Annexation_of_Crimea_by_the_Russian_Federation) and [brought the war in Donbas](https://en.wikipedia.org/wiki/War_in_Donbas) followed by [full-scale invasion of Ukraine in 2022](https://en.wikipedia.org/wiki/2022_Russian_invasion_of_Ukraine).
* Russia has brought sorrow and devastations to millions of Ukrainians, killed hundreds of innocent people, damaged thousands of buildings, and forced several million people to flee.
* [Putin khuylo!](https://en.wikipedia.org/wiki/Putin_khuylo!)
