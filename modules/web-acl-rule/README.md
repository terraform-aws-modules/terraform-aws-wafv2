# AWS WAFv2 Web ACL Rule Terraform sub-module

Manages a single [`aws_wafv2_web_acl_rule`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_rule) resource attached to an existing Web ACL. Each invocation creates one rule.

This resource fixes the `WAFAssociatedItemException` deletion-ordering issue you hit when removing IP sets, regex pattern sets, or rule groups that are referenced by inline rules in `aws_wafv2_web_acl`. By managing rules as separate resources, Terraform can safely delete the rule first and the referenced resource second.

> Set `lifecycle { ignore_changes = [rule] }` on the corresponding `aws_wafv2_web_acl` resource (or pass `manage_rules_externally = true` to the root module) so the inline-rule field does not fight with the standalone rule resources.

## Usage

```hcl
module "block_bad_ips" {
  source = "terraform-aws-modules/wafv2/aws//modules/web-acl-rule"

  name        = "block-bad-ips"
  priority    = 1
  web_acl_arn = module.wafv2.web_acl_arn

  action = "block"

  statement = {
    ip_set_reference_statement = {
      arn = aws_wafv2_ip_set.blocked.arn
    }
  }

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "block-bad-ips"
    sampled_requests_enabled   = true
  }
}
```

For a managed rule group, use `override_action` instead of `action`:

```hcl
module "aws_managed_common" {
  source = "terraform-aws-modules/wafv2/aws//modules/web-acl-rule"

  name        = "aws-managed-common"
  priority    = 10
  web_acl_arn = module.wafv2.web_acl_arn

  override_action = "none"

  statement = {
    managed_rule_group_statement = {
      name        = "AWSManagedRulesCommonRuleSet"
      vendor_name = "AWS"
    }
  }

  visibility_config = {
    cloudwatch_metrics_enabled = true
    metric_name                = "aws-managed-common"
    sampled_requests_enabled   = true
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
| [aws_wafv2_web_acl_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_rule) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_action"></a> [action](#input\_action) | Action to take when the rule matches. Use string (`allow`, `block`, `count`, `captcha`, `challenge`) or object for custom request handling/response. Conflicts with `override_action` | `any` | `null` | no |
| <a name="input_captcha_config"></a> [captcha\_config](#input\_captcha\_config) | CAPTCHA configuration that overrides the Web ACL level setting | <pre>object({<br/>    immunity_time_property = object({<br/>      immunity_time = number<br/>    })<br/>  })</pre> | `null` | no |
| <a name="input_challenge_config"></a> [challenge\_config](#input\_challenge\_config) | Challenge configuration that overrides the Web ACL level setting | <pre>object({<br/>    immunity_time_property = object({<br/>      immunity_time = number<br/>    })<br/>  })</pre> | `null` | no |
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created (affects all resources) | `bool` | `true` | no |
| <a name="input_name"></a> [name](#input\_name) | Name of the rule. Must be unique within the Web ACL | `string` | n/a | yes |
| <a name="input_override_action"></a> [override\_action](#input\_override\_action) | Override action for managed rule groups and rule group reference statements. Use string (`none`, `count`) or object. Conflicts with `action` | `any` | `null` | no |
| <a name="input_priority"></a> [priority](#input\_priority) | Rule priority. Rules with lower priority are evaluated first | `number` | n/a | yes |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_rule_label"></a> [rule\_label](#input\_rule\_label) | List of labels to apply to matching web requests. Each entry must have a `name` field | <pre>list(object({<br/>    name = string<br/>  }))</pre> | `[]` | no |
| <a name="input_statement"></a> [statement](#input\_statement) | Rule statement configuration. Required. Supports the full WAFv2 statement schema including managed\_rule\_group\_statement, rate\_based\_statement, rule\_group\_reference\_statement, and nested AND/OR/NOT logical statements | `any` | n/a | yes |
| <a name="input_visibility_config"></a> [visibility\_config](#input\_visibility\_config) | CloudWatch metrics configuration for this rule | <pre>object({<br/>    cloudwatch_metrics_enabled = optional(bool, true)<br/>    metric_name                = optional(string)<br/>    sampled_requests_enabled   = optional(bool, true)<br/>  })</pre> | n/a | yes |
| <a name="input_web_acl_arn"></a> [web\_acl\_arn](#input\_web\_acl\_arn) | ARN of the Web ACL to add the rule to | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_name"></a> [name](#output\_name) | Name of the rule |
| <a name="output_priority"></a> [priority](#output\_priority) | Priority of the rule |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the Web ACL the rule is attached to |
<!-- END_TF_DOCS -->

## License

Apache-2.0. See [LICENSE](../../LICENSE).
