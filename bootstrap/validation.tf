resource "terraform_data" "validate_inputs" {
  input = true

  lifecycle {
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
      condition = alltrue([
        for component in var.oauth_apps :
        !(
          var.enable_oci_secrets == false &&
          component.jwt_key_material_source == "existing_secret_ocids"
        )
      ])
      error_message = "VALIDATION FAILURE: oauth_apps[*].jwt_key_material_source = existing_secret_ocids requires enable_oci_secrets = true."
    }

    precondition {
      condition = alltrue([
        for component in var.oauth_apps :
        !(
          component.jwt_key_material_source == "provided_pem" &&
          (component.jwt_private_key_pem == null || component.jwt_certificate_pem == null)
        )
      ])
      error_message = "VALIDATION FAILURE: oauth_apps[*].jwt_key_material_source = provided_pem requires jwt_private_key_pem and jwt_certificate_pem."
    }

    precondition {
      condition = alltrue([
        for component in var.oauth_apps :
        !(
          component.jwt_key_material_source == "existing_secret_ocids" &&
          (component.private_key_secret_existing_ocid == null || component.certificate_secret_existing_ocid == null)
        )
      ])
      error_message = "VALIDATION FAILURE: oauth_apps[*].jwt_key_material_source = existing_secret_ocids requires private_key_secret_existing_ocid and certificate_secret_existing_ocid."
    }

    precondition {
      condition = alltrue([
        for component in var.oauth_apps :
        !(
          component.jwt_key_material_source == "existing_secret_ocids" &&
          component.jwt_certificate_pem_for_identity_domain == null
        )
      ])
      error_message = "VALIDATION FAILURE: oauth_apps[*].jwt_key_material_source = existing_secret_ocids requires jwt_certificate_pem_for_identity_domain so the Identity Domain certificate and trust can be configured."
    }

    precondition {
      condition = alltrue([
        for component in var.oauth_apps :
        !(
          component.runtime.principal_type == "user-group" &&
          component.runtime.resource_ocid != null
        )
      ])
      error_message = "VALIDATION FAILURE: oauth_apps[*].runtime.resource_ocid must be omitted when runtime.principal_type = user-group."
    }

    precondition {
      condition = alltrue([
        for key, component in var.oauth_apps :
        !(
          var.restrict_secret_policy_to_secret_ocids &&
          length(local.runtime_secret_ocids[key]) == 0
        )
      ])
      error_message = "VALIDATION FAILURE: restrict_secret_policy_to_secret_ocids = true requires at least one readable secret OCID for each oauth_apps entry."
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

