# Token Factory Bootstrap Client Example

This folder is a shallow client of the root `token-factory-bootstrap` super module.

It passes `oauth_apps` directly to the root module. There is no flat-variable translation in `main.tf`; shape `oauth_apps` in `terraform.tfvars` exactly as the root module expects.

Use this folder as a runnable example or a starting point for an environment-specific root module. For reusable module documentation, see the root `README.md`.

## Key Pattern

```hcl
oauth_apps = {
  MCP_SERVER = {
    # Optional. Defaults to "mcp-server" from the map key.
    resource_name_prefix = null

    display_name       = "mcp-server-token-factory-client"
    description        = "OAuth client and resource-server config for MCP server."
    issuer             = "https://mcp-server.example.com/token-factory"
    kid                = "mcp-server-token-factory-cert"
    resource_audiences = ["mcp-server"]
    resource_scopes    = ["invoke"]
    allowed_scopes     = []
    app_roles          = []

    runtime = {
      principal_type   = "compute-instance"
      compartment_ocid = "ocid1.compartment.oc1..runtime"
      resource_ocid    = "ocid1.instance.oc1..compute"
      oci_auth_profile = null
      oci_region       = null
    }

    enable_identity_propagation_trust = true
    propagation_trust_claim_name      = "upstclient"
    propagation_trust_claim_value     = "tokenexchange"

    jwt_key_material_source = "generate"

    jwt_private_key_pem                     = null
    jwt_private_key_passphrase              = null
    jwt_certificate_pem                     = null
    jwt_certificate_pem_for_identity_domain = null

    private_key_secret_existing_ocid            = null
    private_key_passphrase_secret_existing_ocid = null
    certificate_secret_existing_ocid            = null
  }
}
```

`TOKEN_FACTORY_OCI_AUTH_MODE` is derived by the root module from `runtime.principal_type`.
`resource_scopes` defines incoming resource-server scopes and makes the Identity Domain app an OAuth resource when non-empty. `allowed_scopes` defines OAuth client authorized scopes and must contain Identity Domain FQS strings. `app_roles` controls Identity Domain app-role grants and defaults to no grants.

## Outputs

The wrapper exposes a concise client-facing surface:

| Output | Purpose |
| --- | --- |
| `runtime_config_env` | Shared shell `export` lines for runtime config. Use this when the hosting runtime is configured through environment variables. |
| `runtime_config` | Shared `TokenFactoryRuntimeConfig` constructor-shaped config. Use `TokenFactoryRuntimeConfig(**runtime_config)`. |
| `oauth_apps` | Non-sensitive `OAuthClientInfo`-shaped resolver config by OAuth app key. Use `OAuthClientInfo(**oauth_apps["mcp_server"])`. |
| `provisioned_resources` | Names and OCIDs of shared resources, OAuth apps, runtime principals, policies, and secrets for lookup. Null unless `output_provisioned_resources = true`. |

Use shared `runtime_config` plus `oauth_apps[<client_key>]` for normal constructor-based deployments. Use shared `runtime_config_env` when the hosting runtime is configured through environment variables. Set `output_provisioned_resources = true` only when you want the lookup-friendly resource names and OCIDs output.
