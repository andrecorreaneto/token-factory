resource "terraform_data" "validate_inputs" {
  input = true

  lifecycle {
    precondition {
      condition     = local.identity_domain != null
      error_message = "VALIDATION FAILURE: identity_domain_name did not match an Identity Domain in identity_domain_region."
    }

    precondition {
      condition = !(
        var.enable_oci_secrets &&
        local.identity_domain_for_groups == null
      )
      error_message = "VALIDATION FAILURE: identity_domain_name_for_groups did not match an Identity Domain in identity_domain_region."
    }

    precondition {
      condition = !(
        var.enable_oci_secrets == false &&
        var.jwt_key_material_source == "existing_secret_ocids"
      )
      error_message = "VALIDATION FAILURE: jwt_key_material_source = existing_secret_ocids requires enable_oci_secrets = true."
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
        var.jwt_key_material_source == "provided_pem" &&
        (var.jwt_private_key_pem == null || var.jwt_certificate_pem == null)
      )
      error_message = "VALIDATION FAILURE: jwt_key_material_source = provided_pem requires jwt_private_key_pem and jwt_certificate_pem."
    }

    precondition {
      condition = !(
        var.jwt_key_material_source == "existing_secret_ocids" &&
        (var.oci_private_key_secret_existing_ocid == null || var.oci_certificate_secret_existing_ocid == null)
      )
      error_message = "VALIDATION FAILURE: jwt_key_material_source = existing_secret_ocids requires oci_private_key_secret_existing_ocid and oci_certificate_secret_existing_ocid."
    }

    precondition {
      condition = !(
        var.jwt_key_material_source == "existing_secret_ocids" &&
        var.jwt_certificate_pem_for_identity_domain == null
      )
      error_message = "VALIDATION FAILURE: jwt_key_material_source = existing_secret_ocids requires jwt_certificate_pem_for_identity_domain so the Identity Domain certificate and trust can be configured."
    }

    precondition {
      condition = !(
        var.enable_oci_secrets &&
        var.oci_secrets_compartment_ocid == null
      )
      error_message = "VALIDATION FAILURE: enable_oci_secrets = true requires oci_secrets_compartment_ocid."
    }

    precondition {
      condition = !(
        var.enable_oci_secrets &&
        var.token_factory_runtime_iam_principal_type != "user-group" &&
        var.token_factory_runtime_compartment_ocid == null
      )
      error_message = "VALIDATION FAILURE: enable_oci_secrets = true requires token_factory_runtime_compartment_ocid for instance-principal and resource-principal runtime IAM."
    }

    precondition {
      condition = !(
        var.token_factory_runtime_iam_auth_mode == "oci-profile" &&
        var.token_factory_runtime_iam_principal_type != "user-group"
      )
      error_message = "VALIDATION FAILURE: token_factory_runtime_iam_auth_mode = oci-profile requires token_factory_runtime_iam_principal_type = user-group."
    }

    precondition {
      condition = !(
        var.token_factory_runtime_iam_auth_mode == "instance-principal" &&
        var.token_factory_runtime_iam_principal_type != "compute-instance"
      )
      error_message = "VALIDATION FAILURE: token_factory_runtime_iam_auth_mode = instance-principal requires token_factory_runtime_iam_principal_type = compute-instance."
    }

    precondition {
      condition = !(
        var.token_factory_runtime_iam_auth_mode == "resource-principal" &&
        !contains(["oci-function", "oke-cluster"], var.token_factory_runtime_iam_principal_type)
      )
      error_message = "VALIDATION FAILURE: token_factory_runtime_iam_auth_mode = resource-principal requires token_factory_runtime_iam_principal_type = oci-function or oke-cluster."
    }

    precondition {
      condition = !(
        var.token_factory_runtime_iam_principal_type == "user-group" &&
        var.token_factory_runtime_resource_ocid != null
      )
      error_message = "VALIDATION FAILURE: token_factory_runtime_resource_ocid must be omitted when token_factory_runtime_iam_principal_type = user-group."
    }

    precondition {
      condition = (
        (var.identity_propagation_trust_claim_name == null && var.identity_propagation_trust_claim_value == null) ||
        (var.identity_propagation_trust_claim_name != null && var.identity_propagation_trust_claim_value != null)
      )
      error_message = "VALIDATION FAILURE: identity_propagation_trust_claim_name and identity_propagation_trust_claim_value must either both be set or both be omitted."
    }
  }
}
