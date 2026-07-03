resource "oci_identity_dynamic_group" "these" {
  provider = oci.home
  for_each = local.dynamic_group_components

  compartment_id = var.tenancy_ocid
  description    = local.descriptions.oauth_apps[each.key].dynamic_group
  matching_rule  = local.runtime_matching_rules[each.key]
  name           = local.names.oauth_apps[each.key].dynamic_group
}

resource "oci_identity_group" "these" {
  provider = oci.home
  for_each = local.user_group_components

  compartment_id = var.tenancy_ocid
  description    = local.descriptions.oauth_apps[each.key].user_group
  name           = local.names.oauth_apps[each.key].user_group
}

resource "oci_identity_policy" "these" {
  provider = oci.home
  for_each = var.oauth_apps

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.oauth_apps[each.key].policy
  name           = local.names.oauth_apps[each.key].policy
  statements     = local.secret_policy_statements[each.key]
}
