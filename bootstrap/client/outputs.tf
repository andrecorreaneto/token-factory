output "runtime_shared_env" {
  description = "Shared shell export lines for TokenFactory runtime configuration."
  value = join("\n", [
    for key, value in module.token_factory_bootstrap.token_factory_shared_runtime_config :
    "export ${key}=${jsonencode(tostring(value))}"
  ])
}

output "runtime_shared" {
  description = "Shared TokenFactoryRuntimeConfig constructor-shaped runtime config."
  value = {
    for config_key, config_value in {
      domain_url                  = trimsuffix(var.identity_domain_url, "/")
      domain_region               = var.identity_domain_region
      timeout_seconds             = var.token_factory_timeout_seconds
      subject_claim               = var.token_factory_subject_claim
      groups_claim                = var.token_factory_groups_claim
      authz_policy_secret_ocid    = var.token_factory_authz_policy_secret_ocid
      authz_policy_signature_mode = var.token_factory_authz_policy_signature_mode
      authz_trusted_signers       = length(var.token_factory_authz_policy_trusted_signers) == 0 ? null : var.token_factory_authz_policy_trusted_signers
      authz_policy_environment    = var.token_factory_authz_policy_environment
      authz_policy_tenant_id      = var.emit_authz_policy_tenant_id ? var.tenancy_ocid : null
      log_full_assertion          = var.token_factory_log_full_assertion
    } : config_key => config_value if config_value != null
  }
}

output "runtime_clients_env" {
  description = "Shell export lines for Token Factory OAuth client configuration by OAuth app key. Contains TF_CLIENT_* values with secret OCID references, not inline secrets."
  value       = module.token_factory_bootstrap.token_factory_client_config_env
}

output "runtime_clients" {
  description = "Non-sensitive OAuthClientInfo-shaped resolver config by OAuth app key."
  value       = module.token_factory_bootstrap.oauth_app_configs
}

output "sensitive_runtime_client_envs" {
  description = "Sensitive shell export lines for Token Factory OAuth client configuration by OAuth app key, including inline credentials and PEM values when enable_oci_secrets = false."
  value       = module.token_factory_bootstrap.token_factory_client_sensitive_config_env
  sensitive   = true
}

output "provisioned_resources" {
  description = "Provisioned shared and OAuth app/runtime resources with names and OCIDs for lookup. Null unless output_provisioned_resources is true."
  value       = var.output_provisioned_resources ? module.token_factory_bootstrap.provisioned_resources : null
}
