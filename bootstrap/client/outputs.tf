output "shared_runtime_config" {
  description = "Shared Token Factory runtime configuration base."
  value       = module.token_factory_bootstrap.shared_runtime_config
}

output "shared_runtime_config_exports" {
  description = "Shell export lines for shared Token Factory runtime configuration."
  value = join("\n", [
    for key, value in {
      TF_SHARED_DOMAIN_URL                  = module.token_factory_bootstrap.shared_runtime_config.domain_url
      TF_SHARED_DOMAIN_REGION               = module.token_factory_bootstrap.shared_runtime_config.domain_region
      TF_SHARED_TIMEOUT_SECONDS             = module.token_factory_bootstrap.shared_runtime_config.timeout_seconds
      TF_SHARED_SUBJECT_CLAIM               = module.token_factory_bootstrap.shared_runtime_config.subject_claim
      TF_SHARED_GROUPS_CLAIM                = module.token_factory_bootstrap.shared_runtime_config.groups_claim
      TF_SHARED_LOG_FULL_ASSERTION          = module.token_factory_bootstrap.shared_runtime_config.log_full_assertion
      TF_SHARED_AUTHZ_POLICY_SECRET_OCID    = try(module.token_factory_bootstrap.shared_runtime_config.authz_policy_secret_ocid, null)
      TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE = module.token_factory_bootstrap.shared_runtime_config.authz_policy_signature_mode
      TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON  = try(jsonencode(module.token_factory_bootstrap.shared_runtime_config.authz_trusted_signers), null)
      TF_SHARED_AUTHZ_POLICY_ENVIRONMENT    = try(module.token_factory_bootstrap.shared_runtime_config.authz_policy_environment, null)
      TF_SHARED_AUTHZ_POLICY_TENANT_ID      = try(module.token_factory_bootstrap.shared_runtime_config.authz_policy_tenant_id, null)
    } :
    "export ${key}=${jsonencode(tostring(value))}"
    if value != null
  ])
}

output "clients_runtime_config" {
  description = "Token Factory per-client runtime and OAuth resolver configuration."
  value       = module.token_factory_bootstrap.clients_runtime_config
}

output "clients_runtime_config_exports" {
  description = "Shell export lines for Token Factory per-client OAuth resolver configuration."
  value = {
    for client_key, config in module.token_factory_bootstrap.clients_runtime_config :
    client_key => join("\n", [
      for key, value in {
        TF_CLIENT_KEY                      = client_key
        TF_CLIENT_CREDS_SECRET_OCID        = lookup(config.oauth_client_config, "client_credentials_secret_ocid", null)
        TF_CLIENT_ISSUER                   = lookup(config.oauth_client_config, "issuer", null)
        TF_CLIENT_KID                      = lookup(config.oauth_client_config, "kid", null)
        TF_CLIENT_KMS_KEY_ID               = lookup(config.oauth_client_config, "kms_key_id", null)
        TF_CLIENT_KMS_KEY_VERSION_ID       = lookup(config.oauth_client_config, "kms_key_version_id", null)
        TF_CLIENT_KMS_CRYPTO_ENDPOINT      = lookup(config.oauth_client_config, "kms_crypto_endpoint", null)
        TF_CLIENT_RESOURCE_AUDIENCES       = join(",", lookup(config.oauth_client_config, "resource_audiences", []))
        TF_CLIENT_REQUIRED_INCOMING_SCOPES = length(lookup(config.oauth_client_config, "required_incoming_scopes", [])) == 0 ? null : join(",", lookup(config.oauth_client_config, "required_incoming_scopes", []))
        TF_CLIENT_PROPAGATION_TRUST_CLAIM  = lookup(config.oauth_client_config, "propagation_trust_claim", null)
        TF_CLIENT_ALLOWED_CLIENT_IDS       = lookup(config.oauth_client_config, "allowed_client_ids", null) == null ? null : join(",", lookup(config.oauth_client_config, "allowed_client_ids", null))
      } :
      "export ${key}=${jsonencode(tostring(value))}"
      if value != null
    ])
  }
}

output "provisioned_resources" {
  description = "Provisioned shared and OAuth app/runtime resources with names, OCIDs, policy statements, and database requirement guidance."
  value       = module.token_factory_bootstrap.provisioned_resources
}
