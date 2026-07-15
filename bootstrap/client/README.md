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

      database_access = {
        target_database_compartment_ocid = "ocid1.compartment.oc1..database"
        target_database_ocid             = "ocid1.autonomousdatabase.oc1..database"
      }
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

`TF_SHARED_OCI_AUTH_MODE` is derived by the root module from `runtime.principal_type`.
`resource_scopes` defines incoming resource-server scopes and makes the Identity Domain app an OAuth resource when non-empty. `allowed_scopes` defines OAuth client authorized scopes and must contain Identity Domain FQS strings. `app_roles` controls Identity Domain app-role grants and defaults to no grants.
Set `runtime.database_access` only when the runtime dynamic group should be allowed to request Oracle Database `db-token`s for TokenFactory `credential="OCI_PRINCIPAL"` calls.

## Outputs

The wrapper exposes a concise client-facing surface:

| Output | Purpose |
| --- | --- |
| `shared_runtime_config` | Shared Token Factory runtime config object. |
| `shared_runtime_config_exports` | Shell `export` lines derived from `shared_runtime_config`. |
| `clients_runtime_config` | Per-client non-sensitive OAuth resolver config with secret OCID references and optional database setup commands. |
| `clients_runtime_config_exports` | Per-client shell `export` lines derived from `clients_runtime_config[*].oauth_client_config`. |
| `provisioned_resources` | Names, OCIDs/IDs, policy statements, and selected Identity Domain metadata. |

Use `shared_runtime_config` plus `clients_runtime_config[<client_key>]` for normal deployments. Use `shared_runtime_config_exports` and `clients_runtime_config_exports[<client_key>]` when the hosting runtime is configured through shell environment variables.
