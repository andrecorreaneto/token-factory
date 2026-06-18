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
  count = var.enable_oci_secrets ? 1 : 0

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.client_credentials
  key_id         = local.master_key_id
  secret_name    = local.names.client_credentials
  vault_id       = local.vault_id

  secret_content {
    content      = base64encode(local.client_credentials)
    content_type = "BASE64"
    name         = "current"
  }
}

resource "oci_vault_secret" "private_key" {
  count = local.create_vault_key_material ? 1 : 0

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.private_key
  key_id         = local.master_key_id
  secret_name    = local.names.private_key
  vault_id       = local.vault_id

  secret_content {
    content      = base64encode(local.jwt_private_key_pem_value)
    content_type = "BASE64"
    name         = "current"
  }
}

resource "oci_vault_secret" "private_key_passphrase" {
  count = local.create_vault_key_material && var.jwt_private_key_passphrase != null ? 1 : 0

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.private_key_passphrase
  key_id         = local.master_key_id
  secret_name    = local.names.private_key_passphrase
  vault_id       = local.vault_id

  secret_content {
    content      = base64encode(var.jwt_private_key_passphrase)
    content_type = "BASE64"
    name         = "current"
  }
}

resource "oci_vault_secret" "certificate" {
  count = local.create_vault_key_material ? 1 : 0

  compartment_id = var.oci_secrets_compartment_ocid
  description    = local.descriptions.certificate
  key_id         = local.master_key_id
  secret_name    = local.names.certificate
  vault_id       = local.vault_id

  secret_content {
    content      = base64encode(local.jwt_certificate_pem_value)
    content_type = "BASE64"
    name         = "current"
  }
}
