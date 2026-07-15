module "token_factory_bootstrap" {
  source = "../"

  tenancy_ocid         = var.tenancy_ocid
  region               = var.region
  user_ocid            = var.user_ocid
  fingerprint          = var.fingerprint
  private_key_path     = var.private_key_path
  private_key_password = var.private_key_password

  resource_name_prefix   = var.resource_name_prefix
  identity_domain_compartment_ocid = var.identity_domain_compartment_ocid
  identity_domain_url              = var.identity_domain_url
  identity_domain_region           = var.identity_domain_region

  enable_oci_secrets                     = var.enable_oci_secrets
  oci_secrets_compartment_ocid           = var.oci_secrets_compartment_ocid
  oci_vault_existing_ocid                = var.oci_vault_existing_ocid
  oci_master_key_existing_ocid           = var.oci_master_key_existing_ocid
  oci_secrets_region                     = var.oci_secrets_region
  restrict_secret_policy_to_secret_ocids = var.restrict_secret_policy_to_secret_ocids

  token_factory_timeout_seconds              = var.token_factory_timeout_seconds
  token_factory_subject_claim                = var.token_factory_subject_claim
  token_factory_groups_claim                 = var.token_factory_groups_claim
  token_factory_log_full_assertion           = var.token_factory_log_full_assertion
  token_factory_authz_policy_secret_ocid     = var.token_factory_authz_policy_secret_ocid
  token_factory_authz_policy_signature_mode  = var.token_factory_authz_policy_signature_mode
  token_factory_authz_policy_trusted_signers = var.token_factory_authz_policy_trusted_signers
  token_factory_authz_policy_environment     = var.token_factory_authz_policy_environment
  emit_authz_policy_tenant_id                = var.emit_authz_policy_tenant_id

  oauth_apps = var.oauth_apps
}
