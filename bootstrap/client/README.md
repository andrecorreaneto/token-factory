# Token Factory Bootstrap Client Example

Use this folder as a runnable example or a starting point for Token Factory bootstrapping.

Rename [*terraform.tfvars.template*](./terraform.tfvars.template) to *terraform.tfvars*, providing your environment-specific inputs and execute the typical Terraform workflow: init/plan/apply.

Upon apply, this client module outputs the required information to be plugged into Token Factory runtime environments.

| Output | Purpose |
| --- | --- |
| `runtime_config_env` | Shared shell `export` lines for runtime config. Use this when the hosting runtime is configured through environment variables. |
| `runtime_config` | Shared `TokenFactoryRuntimeConfig` constructor-shaped config. Use `TokenFactoryRuntimeConfig(**runtime_config)`. |
| `oauth_apps` | Non-sensitive `OAuthClientInfo`-shaped resolver config by OAuth app key. Use `OAuthClientInfo(**oauth_apps["mcp_server"])`. |
| `provisioned_resources` | Names and OCIDs of shared resources, OAuth apps, runtime principals, policies, and secrets for lookup. Null unless `output_provisioned_resources = true`. |

Use shared `runtime_config` plus `oauth_apps[<client_key>]` for normal constructor-based deployments. Use shared `runtime_config_env` when the hosting runtime is configured through environment variables. Set `output_provisioned_resources = true` only when you want the lookup-friendly resource names and OCIDs output.
