module "token_factory_bootstrap" {
  source = "../"

  tenancy_ocid         = var.tenancy_ocid
  region               = var.region
  user_ocid            = var.user_ocid
  fingerprint          = var.fingerprint
  private_key_path     = var.private_key_path
  private_key_password = var.private_key_password

  resource_name_prefix            = var.resource_name_prefix
  identity_domain_name            = var.identity_domain_name
  identity_domain_name_for_groups = var.identity_domain_name_for_groups
  identity_domain_region          = var.identity_domain_region

  token_factory_issuer = var.token_factory_issuer
  token_factory_kid    = var.token_factory_kid

  identity_propagation_trust_claim_name  = var.identity_propagation_trust_claim_name
  identity_propagation_trust_claim_value = var.identity_propagation_trust_claim_value

  enable_oci_secrets                     = var.enable_oci_secrets
  jwt_key_material_source                = var.jwt_key_material_source
  oci_secrets_compartment_ocid           = var.oci_secrets_compartment_ocid
  oci_vault_existing_ocid                = var.oci_vault_existing_ocid
  oci_master_key_existing_ocid           = var.oci_master_key_existing_ocid
  oci_secrets_region                     = var.oci_secrets_region
  restrict_secret_policy_to_secret_ocids = var.restrict_secret_policy_to_secret_ocids

  oci_private_key_secret_existing_ocid            = var.oci_private_key_secret_existing_ocid
  oci_private_key_passphrase_secret_existing_ocid = var.oci_private_key_passphrase_secret_existing_ocid
  oci_certificate_secret_existing_ocid            = var.oci_certificate_secret_existing_ocid

  jwt_private_key_pem                     = var.jwt_private_key_pem
  jwt_private_key_passphrase              = var.jwt_private_key_passphrase
  jwt_certificate_pem                     = var.jwt_certificate_pem
  jwt_certificate_pem_for_identity_domain = var.jwt_certificate_pem_for_identity_domain

  token_factory_client_display_name = var.token_factory_client_display_name
  token_factory_client_description  = var.token_factory_client_description

  token_factory_runtime_iam_auth_mode      = var.token_factory_runtime_iam_auth_mode
  token_factory_runtime_iam_principal_type = var.token_factory_runtime_iam_principal_type
  token_factory_runtime_compartment_ocid   = var.token_factory_runtime_compartment_ocid
  token_factory_runtime_resource_ocid      = var.token_factory_runtime_resource_ocid
}
