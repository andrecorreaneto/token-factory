output "token_factory_config_env" {
  description = "Token Factory runtime configuration."
  value = join("\n", [
    for key, value in local.token_factory_config :
    "export ${key}=${jsonencode(tostring(value))}"
  ])
}

output "provisioned_resource_ids" {
  description = "Provisioned resource IDs."
  value = {
    identity_domain_app_id                 = oci_identity_domains_app.client.id
    identity_domain_certificate_id         = oci_identity_domains_oauth_partner_certificate.jwt.id
    identity_propagation_trust_id          = oci_identity_domains_identity_propagation_trust.jwt.id
    oci_vault_id                           = local.vault_id
    oci_master_key_id                      = local.master_key_id
    token_factory_creds_secret_ocid        = local.token_factory_creds_secret_ocid
    oci_private_key_secret_ocid            = local.private_key_secret_ocid
    oci_private_key_passphrase_secret_ocid = local.private_key_passphrase_secret_ocid
    oci_certificate_secret_ocid            = local.certificate_secret_ocid
    runtime_dynamic_group_id               = local.runtime_dynamic_group_id
    runtime_group_id                       = local.runtime_group_id
    runtime_policy_id                      = var.enable_oci_secrets ? oci_identity_policy.secrets[0].id : null
  }
}
