# AWS WAFv2 Rule Group example

Creates a single regional WAFv2 rule group with two illustrative rules:

1. `block-high-risk-geos` — blocks traffic from a list of country codes via `geo_match_statement`.
2. `count-admin-uri` — counts requests whose URI path starts with `/admin` via `byte_match_statement` on `field_to_match.uri_path`.

The example outputs the rule group ARN, ID, and capacity for downstream consumption.

## Usage

```sh
terraform init
terraform plan
terraform apply
```

Note: applying this example will create real AWS resources and may incur cost. Run `terraform destroy` when finished.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.37 |

## Providers

No providers.

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_rule_group"></a> [rule\_group](#module\_rule\_group) | ../../modules/rule-group | n/a |

## Resources

No resources.

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_rule_group_arn"></a> [rule\_group\_arn](#output\_rule\_group\_arn) | ARN of the WAFv2 rule group created by this example |
| <a name="output_rule_group_capacity"></a> [rule\_group\_capacity](#output\_rule\_group\_capacity) | Capacity (WCUs) configured for the rule group |
| <a name="output_rule_group_id"></a> [rule\_group\_id](#output\_rule\_group\_id) | ID of the WAFv2 rule group |
<!-- END_TF_DOCS -->
