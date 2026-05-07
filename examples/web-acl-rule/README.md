# AWS WAFv2 standalone rule (web-acl-rule) example

Demonstrates the deletion-ordering fix:

1. Creates a regional Web ACL via the root module with `rules = {}` (no inline rules).
2. Attaches two standalone rules with `modules/web-acl-rule`:
   - `block-high-risk-geos` — geo-match block on a country list.
   - `rate-limit-per-ip` — rate-based block at 2000 req per 5 minutes per source IP.

To prevent the inline-rule field from fighting the standalone rule resources, you must add `lifecycle { ignore_changes = [rule] }` to the underlying `aws_wafv2_web_acl` resource. Recent versions of the root module accept a flag for this; see the root module README. For this example we keep `rules = {}` so the inline-rule field is empty.

## Usage

```sh
terraform init
terraform plan
terraform apply
```

Note: applying creates real AWS resources. Run `terraform destroy` when finished — Terraform deletes rules before the Web ACL, demonstrating the safer ordering.

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

| Name | Source | Version |
|------|--------|---------|
| <a name="module_block_high_risk_geos"></a> [block\_high\_risk\_geos](#module\_block\_high\_risk\_geos) | ../../modules/web-acl-rule | n/a |
| <a name="module_rate_limit_per_ip"></a> [rate\_limit\_per\_ip](#module\_rate\_limit\_per\_ip) | ../../modules/web-acl-rule | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_wafv2_web_acl.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_block_high_risk_geos_name"></a> [block\_high\_risk\_geos\_name](#output\_block\_high\_risk\_geos\_name) | Name of the geo-match standalone rule |
| <a name="output_rate_limit_per_ip_name"></a> [rate\_limit\_per\_ip\_name](#output\_rate\_limit\_per\_ip\_name) | Name of the rate-based standalone rule |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the Web ACL the standalone rules are attached to |
<!-- END_TF_DOCS -->
