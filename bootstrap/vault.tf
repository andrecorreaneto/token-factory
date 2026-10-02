data "oci_kms_vault" "existing" {
  count = local.use_existing_vault ? 1 : 0

  vault_id = var.oci_vault_existing_ocid
}
resource "oci_kms_vault" "this" {
  count = local.create_vault ? 1 : 0

  compartment_id = var.oci_secrets_compartment_ocid
  display_name   = local.names.vault
  vault_type     = "DEFAULT"
}

resource "oci_kms_key" "this" {
  count = local.create_master_key ? 1 : 0

  compartment_id      = var.oci_secrets_compartment_ocid
  display_name        = local.names.master_key
  management_endpoint = local.vault_management_endpoint

  key_shape {
    algorithm = "AES"
    length    = 32
  }
}

resource "oci_vault_secret" "client_credentials" {
  for_each = var.enable_oci_secrets ? var.oauth_apps : {}

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.oauth_apps[each.key].client_credentials
  key_id         = local.master_key_id
  secret_name    = local.names.oauth_apps[each.key].client_credentials
  vault_id       = local.vault_id

  secret_content {
    content      = sensitive(base64encode(local.client_credentials[each.key]))
    content_type = "BASE64"
    name         = "current"
  }
}
