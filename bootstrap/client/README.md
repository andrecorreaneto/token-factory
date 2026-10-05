# Token Factory Bootstrap Client Example

This folder is a shallow client of the root `token-factory-bootstrap` super module.

It passes `oauth_apps` directly to the root module. There is no flat-variable translation in `main.tf`; shape `oauth_apps` in `terraform.tfvars` exactly as the root module expects.

Use this folder as a runnable example or a starting point for an environment-specific root module. For reusable module documentation, see the root `README.md`.

## Bootstrap Runner Prerequisites

Install the repository requirements into the Python interpreter selected by `certificate_registration_python_command` before applying a `BOOTSTRAP_MANAGED` signing key. From this directory on Windows:

```powershell
python -m pip install -r ..\..\requirements.txt
```

The certificate utility reuses the bootstrap runner's OCI authentication for both KMS and Identity Domains. After changing the module or certificate utility command, create a fresh Terraform plan; saved plan files retain the earlier provisioner command.

## Key Pattern

```hcl
oauth_apps = {
  MCP_SERVER = {
    # Optional. Defaults to normalized display_name.
    resource_name_prefix = null

    display_name       = "mcp-server-token-factory-client"
    description        = "OAuth client and resource-server config for MCP server."
    issuer             = "https://mcp-server.example.com/token-factory"
    kid                = "mcp-server-token-factory-cert"
    resource_audiences = ["mcp-server"]
    resource_scopes    = ["invoke"]
    allowed_scopes     = []
    app_roles          = []

    # Optional. Other oauth_apps keys allowed to call this app; the app itself is always allowed.
    # allowed_clients = ["AGENT"]

    compute_runtime = {
      instance_ocid = "ocid1.instance.oc1..compute"
    }

    database_access = {
      target_database_compartment_ocid = "ocid1.compartment.oc1..database"
      target_database_ocid             = "ocid1.autonomousdatabase.oc1..database"
    }

    enable_identity_propagation_trust = true
    propagation_trust_claim_name      = "upstclient"
    propagation_trust_claim_value     = "tokenexchange"

    signing_key = {
      mode                     = "BOOTSTRAP_MANAGED"
      signing_key_ocid         = null
      signing_key_version_ocid = null
      signing_certificate_pem  = null
      signing_certificate_path = null
    }
  }
}
```

`TF_SHARED_OCI_AUTH_MODE` is derived from the one configured runtime object. `TF_SHARED_OCI_REGION` comes from top-level `region`, falling back to `identity_domain_region`.
`resource_scopes` defines incoming resource-server scopes and makes the Identity Domain app an OAuth resource when non-empty. `allowed_scopes` defines OAuth client authorized scopes and must contain Identity Domain FQS strings. `app_roles` controls Identity Domain app-role grants and defaults to no grants.
Set sibling `database_access` when the selected runtime should be allowed to request Oracle Database `db-token`s. The output describes the OCI policy and database prerequisites; it does not generate or execute database administration SQL.

## Outputs

The wrapper exposes a concise client-facing surface:

| Output | Purpose |
| --- | --- |
| `shared_runtime_config` | Shared Token Factory runtime config object. |
| `shared_runtime_config_exports` | Shell `export` lines derived from `shared_runtime_config`. |
| `clients_runtime_config` | Per-client runtime config with client-credential Secret references, version-pinned KMS signing metadata, and optional database guidance. |
| `clients_runtime_config_exports` | Per-client shell `export` lines derived from `clients_runtime_config[*].oauth_client_config`. |
| `provisioned_resources` | Names, OCIDs/IDs, policy statements, and selected Identity Domain metadata. |

Use `shared_runtime_config` plus `clients_runtime_config[<client_key>]` for normal deployments. Use `shared_runtime_config_exports` and `clients_runtime_config_exports[<client_key>]` when the hosting runtime is configured through shell environment variables.
