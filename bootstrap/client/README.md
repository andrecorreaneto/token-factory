# Token Factory Bootstrap Client

This Terraform root module calls the parent Token Factory bootstrap module and displays outputs needed by downstream Token Factory deployments.

## Usage

Rename *terraform.tfvars.example* to *terraform.tfvars*, provide real values and run the typical terraform workflow (init/plan/apply).

## Outputs

- *token_factory_config_env*: exposes Token Factory runtime settings to be plugged into Token Factory runtimes.
- *provisioned_resource_ids*: exposes managed resource IDs. Use to look up provisioned resources in OCI.