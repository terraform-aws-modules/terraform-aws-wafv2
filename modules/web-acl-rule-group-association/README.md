# AWS WAF v2 Web ACL Rule Group Association Submodule

Terraform submodule which associates a WAFv2 Rule Group (custom or managed) with an existing Web ACL by adding a rule that references the Rule Group.

> **Important:** The parent `aws_wafv2_web_acl` resource must include `lifecycle { ignore_changes = [rule] }` to avoid drift between this resource and the Web ACL's inline rules.

## Usage — Custom Rule Group

```hcl
module "association" {
  source = "terraform-aws-modules/wafv2/aws//modules/web-acl-rule-group-association"

  rule_name   = "custom-rule-group-attachment"
  priority    = 100
  web_acl_arn = aws_wafv2_web_acl.example.arn

  rule_group_reference = {
    arn = aws_wafv2_rule_group.example.arn

    rule_action_overrides = {
      noisy-rule = "count"
    }
  }
}
```

## Usage — Managed Rule Group

```hcl
module "association_managed" {
  source = "terraform-aws-modules/wafv2/aws//modules/web-acl-rule-group-association"

  rule_name   = "aws-common-rule-set"
  priority    = 50
  web_acl_arn = aws_wafv2_web_acl.example.arn

  managed_rule_group = {
    name        = "AWSManagedRulesCommonRuleSet"
    vendor_name = "AWS"
    version     = "Version_1.0"
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
| [aws_wafv2_web_acl_rule_group_association.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_rule_group_association) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_create"></a> [create](#input\_create) | Controls if resources should be created | `bool` | `true` | no |
| <a name="input_managed_rule_group"></a> [managed\_rule\_group](#input\_managed\_rule\_group) | Managed Rule Group configuration. One of `managed_rule_group` or `rule_group_reference` must be set | `any` | `null` | no |
| <a name="input_override_action"></a> [override\_action](#input\_override\_action) | Override action for the rule group. Valid values are `none` and `count`. Defaults to `none` | `string` | `null` | no |
| <a name="input_priority"></a> [priority](#input\_priority) | Priority of the rule within the Web ACL. Lower numbers are evaluated first | `number` | n/a | yes |
| <a name="input_putin_khuylo"></a> [putin\_khuylo](#input\_putin\_khuylo) | Do you agree that Putin doesn't respect Ukrainian sovereignty and territorial integrity? More info: https://en.wikipedia.org/wiki/Russian_invasion_of_Ukraine | `bool` | `true` | no |
| <a name="input_rule_group_reference"></a> [rule\_group\_reference](#input\_rule\_group\_reference) | Custom Rule Group reference. One of `managed_rule_group` or `rule_group_reference` must be set | `any` | `null` | no |
| <a name="input_rule_name"></a> [rule\_name](#input\_rule\_name) | Name of the rule to create in the Web ACL that references the rule group (1-128 chars) | `string` | n/a | yes |
| <a name="input_visibility_config"></a> [visibility\_config](#input\_visibility\_config) | CloudWatch metrics + sampled requests configuration | <pre>object({<br/>    cloudwatch_metrics_enabled = optional(bool, true)<br/>    metric_name                = string<br/>    sampled_requests_enabled   = optional(bool, true)<br/>  })</pre> | `null` | no |
| <a name="input_web_acl_arn"></a> [web\_acl\_arn](#input\_web\_acl\_arn) | ARN of the Web ACL to associate the Rule Group with | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_priority"></a> [priority](#output\_priority) | Priority of the rule |
| <a name="output_rule_name"></a> [rule\_name](#output\_rule\_name) | Name of the rule created in the Web ACL |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the parent Web ACL |
<!-- END_TF_DOCS -->
