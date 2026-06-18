resource "oci_identity_dynamic_group" "runtime" {
  provider = oci.home
  count    = var.enable_oci_secrets && var.token_factory_runtime_iam_principal_type != "user-group" && local.identity_domain_for_groups_is_default ? 1 : 0

  compartment_id = var.tenancy_ocid
  description    = local.runtime_dynamic_group_description
  matching_rule  = local.runtime_matching_rule
  name           = local.runtime_dynamic_group_name
}

resource "oci_identity_group" "runtime" {
  provider = oci.home
  count    = var.enable_oci_secrets && var.token_factory_runtime_iam_principal_type == "user-group" && local.identity_domain_for_groups_is_default ? 1 : 0

  compartment_id = var.tenancy_ocid
  description    = local.descriptions.api_key_group
  name           = local.names.api_key_group
}

resource "oci_identity_policy" "secrets" {
  provider = oci.home
  count    = var.enable_oci_secrets ? 1 : 0

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.policy
  name           = local.names.policy
  statements     = local.secret_policy_statements
}
