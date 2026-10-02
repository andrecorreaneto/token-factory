resource "terraform_data" "validate_inputs" {
  input = true

  lifecycle {
    precondition {
      condition     = length(local.selected_identity_domain_matches) == 1
      error_message = "VALIDATION FAILURE: identity_domain_url must resolve to exactly one OCI Identity Domain."
    }

    precondition {
      condition = !(
        (var.enable_oci_secrets || length(var.oauth_apps) > 0) &&
        var.oci_secrets_compartment_ocid == null
      )
      error_message = "VALIDATION FAILURE: oci_secrets_compartment_ocid is required when enable_oci_secrets = true or oauth_apps is non-empty."
    }

    precondition {
      condition = !(
        var.enable_oci_secrets &&
        var.oci_master_key_existing_ocid != null &&
        var.oci_vault_existing_ocid == null
      )
      error_message = "VALIDATION FAILURE: oci_master_key_existing_ocid can be set only when oci_vault_existing_ocid is also set."
    }

    precondition {
      condition = !(
        var.token_factory_authz_policy_signature_mode == "on" &&
        var.token_factory_authz_policy_secret_ocid == null
      )
      error_message = "VALIDATION FAILURE: token_factory_authz_policy_signature_mode = on requires token_factory_authz_policy_secret_ocid."
    }

    precondition {
      condition = !(
        var.token_factory_authz_policy_signature_mode == "on" &&
        length(var.token_factory_authz_policy_trusted_signers) == 0
      )
      error_message = "VALIDATION FAILURE: token_factory_authz_policy_signature_mode = on requires at least one token_factory_authz_policy_trusted_signers entry."
    }

    precondition {
      condition = alltrue([
        for signer in var.token_factory_authz_policy_trusted_signers :
        signer.algorithm == "SHA_256_RSA_PKCS_PSS"
      ])
      error_message = "VALIDATION FAILURE: token_factory_authz_policy_trusted_signers supports only SHA_256_RSA_PKCS_PSS."
    }
  }
}

