resource "oci_kms_key" "signing" {
  for_each = local.managed_signing_components

  compartment_id           = var.oci_secrets_compartment_ocid
  display_name             = "${local.normalized_oauth_app_resource_names[each.key]}-jwt-signing-key"
  management_endpoint      = local.vault_management_endpoint
  protection_mode          = "HSM"
  is_auto_rotation_enabled = false

  key_shape {
    algorithm = "RSA"
    length    = 256
  }
}

data "oci_kms_key" "external" {
  for_each = local.external_signing_components

  key_id              = each.value.signing_key.signing_key_ocid
  management_endpoint = local.vault_management_endpoint
}

data "oci_kms_key_version" "external" {
  for_each = local.external_signing_components

  key_id              = each.value.signing_key.signing_key_ocid
  key_version_id      = each.value.signing_key.signing_key_version_ocid
  management_endpoint = local.vault_management_endpoint
}

resource "terraform_data" "managed_certificate_registration" {
  for_each = local.managed_signing_components

  triggers_replace = [local.signing_key_ids[each.key], local.signing_key_version_ids[each.key], each.value.kid]

  provisioner "local-exec" {
    command     = "${var.certificate_registration_python_command} scripts/register_kms_certificate.py --from-env"
    working_dir = abspath("${path.module}/..")
    environment = merge(local.certificate_registration_oci_environment, {
      TF_CERT_ACTION                  = "generate-register"
      TF_CERT_IDCS_ENDPOINT           = var.identity_domain_url
      TF_CERT_ALIAS                   = each.value.kid
      TF_CERT_COMMON_NAME             = each.value.display_name
      TF_CERT_KMS_KEY_ID              = local.signing_key_ids[each.key]
      TF_CERT_KMS_KEY_VERSION_ID      = local.signing_key_version_ids[each.key]
      TF_CERT_KMS_MANAGEMENT_ENDPOINT = local.vault_management_endpoint
      TF_CERT_KMS_CRYPTO_ENDPOINT     = local.vault_crypto_endpoint
    })
  }
}

resource "terraform_data" "external_certificate_verification" {
  for_each = local.external_signing_components

  triggers_replace = [local.signing_key_ids[each.key], local.signing_key_version_ids[each.key], sha256(local.external_signing_certificate_pem_values[each.key])]

  lifecycle {
    precondition {
      condition     = data.oci_kms_key.external[each.key].vault_id == local.vault_id
      error_message = "Externally managed signing keys must belong to the shared Token Factory Vault."
    }
    precondition {
      condition     = data.oci_kms_key.external[each.key].key_shape[0].algorithm == "RSA"
      error_message = "Externally managed signing keys must be RSA keys."
    }
    precondition {
      condition     = data.oci_kms_key.external[each.key].protection_mode == "HSM"
      error_message = "Externally managed signing keys must use HSM protection so private key material cannot be exported."
    }
  }

  provisioner "local-exec" {
    command     = "${var.certificate_registration_python_command} scripts/register_kms_certificate.py --from-env"
    working_dir = abspath("${path.module}/..")
    environment = merge(local.certificate_registration_oci_environment, {
      TF_CERT_ACTION                  = "verify"
      TF_CERT_PEM_BASE64              = base64encode(local.external_signing_certificate_pem_values[each.key])
      TF_CERT_KMS_KEY_ID              = local.signing_key_ids[each.key]
      TF_CERT_KMS_KEY_VERSION_ID      = local.signing_key_version_ids[each.key]
      TF_CERT_KMS_MANAGEMENT_ENDPOINT = local.vault_management_endpoint
    })
  }
}

resource "terraform_data" "managed_certificate_verification" {
  for_each = local.managed_signing_components

  triggers_replace = [local.signing_key_ids[each.key], local.signing_key_version_ids[each.key], data.oci_identity_domains_oauth_partner_certificates.managed[each.key].oauth_partner_certificates[0].sha256thumbprint]

  provisioner "local-exec" {
    command     = "${var.certificate_registration_python_command} scripts/register_kms_certificate.py --from-env"
    working_dir = abspath("${path.module}/..")
    environment = merge(local.certificate_registration_oci_environment, {
      TF_CERT_ACTION                  = "verify"
      TF_CERT_PEM_BASE64              = base64encode("-----BEGIN CERTIFICATE-----\n${data.oci_identity_domains_oauth_partner_certificates.managed[each.key].oauth_partner_certificates[0].x509base64certificate}\n-----END CERTIFICATE-----")
      TF_CERT_KMS_KEY_ID              = local.signing_key_ids[each.key]
      TF_CERT_KMS_KEY_VERSION_ID      = local.signing_key_version_ids[each.key]
      TF_CERT_KMS_MANAGEMENT_ENDPOINT = local.vault_management_endpoint
    })
  }
}
