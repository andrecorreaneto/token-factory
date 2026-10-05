output "shared_runtime_config" {
  description = "Shared Token Factory runtime configuration base."
  value       = local.shared_runtime_config
}

output "clients_runtime_config" {
  description = "Token Factory per-client runtime and OAuth resolver configuration."
  value = {
    for key, component in var.oauth_apps :
    key => {
      oauth_client_config = local.oauth_app_configs[key]
      database_access = contains(keys(local.database_access_components), key) ? {
        target_database_compartment_ocid = component.database_access.target_database_compartment_ocid
        target_database_ocid             = component.database_access.target_database_ocid
        iam_policy_statements            = local.database_access_policy_statements[key]
        database_configuration_required  = true
        requirement_note                 = "Enable OCI IAM authentication and map the intended IAM identity to a database schema using a mapping supported by the target database service."
      } : null
    }
  }
}

output "provisioned_resources" {
  description = "Provisioned shared and OAuth app/runtime resources with names, OCIDs, policy statements, and database requirement guidance."
  value = var.output_provisioned_resources ? {
    identity_domain = {
      name       = local.selected_identity_domain_name
      id         = local.selected_identity_domain_id
      type       = local.selected_identity_domain_type
      url        = local.selected_identity_domain_url
      is_default = local.selected_identity_domain_is_default
    }
    shared = {
      vault = {
        name = local.create_vault ? local.names.vault : null
        ocid = local.vault_id
      }
      master_key = {
        name = local.create_master_key ? local.names.master_key : null
        ocid = local.master_key_id
      }
      authz_policy_secret = {
        name = null
        ocid = var.token_factory_authz_policy_secret_ocid
      }
    }
    oauth_apps = {
      for key, component in var.oauth_apps :
      key => {
        identity_domain_app = {
          name           = local.identity_domain_apps[key].name
          display_name   = component.display_name
          client_id      = local.identity_domain_apps[key].name
          application_id = local.identity_domain_apps[key].id
          ocid           = local.identity_domain_apps[key].ocid
        }
        oauth_partner_certificate = {
          name = component.kid
          ocid = component.signing_key.mode == "BOOTSTRAP_MANAGED" ? data.oci_identity_domains_oauth_partner_certificates.managed[key].oauth_partner_certificates[0].ocid : oci_identity_domains_oauth_partner_certificate.these[key].ocid
        }
        signing_key = {
          mode             = component.signing_key.mode
          key_ocid         = local.signing_key_ids[key]
          key_version_ocid = local.signing_key_version_ids[key]
          crypto_endpoint  = local.vault_crypto_endpoint
          protection_mode  = component.signing_key.mode == "BOOTSTRAP_MANAGED" ? oci_kms_key.signing[key].protection_mode : data.oci_kms_key.external[key].protection_mode
          access_policy = {
            name       = "${local.normalized_oauth_app_resource_names[key]}-signing-key-policy"
            ocid       = oci_identity_policy.signing_key[key].id
            statements = [local.signing_key_policy_statements[key]]
          }
        }
        identity_domain_app_role_grants = {
          for grant_key, grant in local.identity_domain_app_role_grants :
          grant.role_name => {
            name = grant.role_name
            ocid = oci_identity_domains_grant.these[grant_key].ocid
          }
          if grant.app_key == key
        }
        identity_propagation_trust = component.enable_identity_propagation_trust ? {
          name = local.names.oauth_apps[key].propagation_trust
          ocid = oci_identity_domains_identity_propagation_trust.these[key].ocid
        } : null
        runtime_principal = {
          name           = local.runtime_principal_names[key]
          id             = local.runtime_principal_ids[key]
          subject        = local.runtime_principal_subjects[key]
          principal_kind = local.runtime_principal_kinds[key]
          principal_type = local.runtime_configs[key].principal_type
          matching_rule  = try(local.runtime_matching_rules[key], null)
        }
        vault_read_policy = contains(keys(local.secret_access_components), key) ? {
          name       = local.names.oauth_apps[key].policy
          ocid       = oci_identity_policy.these[key].id
          statements = local.secret_policy_statements[key]
        } : null
        database_access_policy = contains(keys(local.database_access_components), key) ? {
          name       = local.names.oauth_apps[key].database_access_policy
          ocid       = oci_identity_policy.database_access[key].id
          statements = local.database_access_policy_statements[key]
        } : null
        secrets = {
          client_credentials = {
            name = var.enable_oci_secrets ? local.names.oauth_apps[key].client_credentials : null
            ocid = local.client_credentials_secret_ocids[key]
          }
        }
      }
    }
  } : null
}
