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
        commands_to_enable_db_authentication = local.database_access_requirement_commands[key]
      } : null
    }
  }
}

output "provisioned_resources" {
  description = "Provisioned shared and OAuth app/runtime resources with names, OCIDs, policy statements, and database setup commands."
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
          name           = oci_identity_domains_app.these[key].name
          display_name   = component.display_name
          client_id      = oci_identity_domains_app.these[key].name
          application_id = oci_identity_domains_app.these[key].id
          ocid           = oci_identity_domains_app.these[key].ocid
        }
        oauth_partner_certificate = {
          name = component.kid
          ocid = oci_identity_domains_oauth_partner_certificate.these[key].ocid
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
          principal_type = component.runtime.principal_type
          matching_rule  = component.runtime.principal_type == "user-group" ? null : local.runtime_matching_rules[key]
        }
        vault_read_policy = {
          name       = local.names.oauth_apps[key].policy
          ocid       = oci_identity_policy.these[key].id
          statements = local.secret_policy_statements[key]
        }
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
          private_key = {
            name = var.enable_oci_secrets && component.jwt_key_material_source != "existing_secret_ocids" ? local.names.oauth_apps[key].private_key : null
            ocid = local.private_key_secret_ocids[key]
          }
          private_key_passphrase = {
            name = var.enable_oci_secrets && component.jwt_key_material_source != "existing_secret_ocids" && component.jwt_private_key_passphrase != null ? local.names.oauth_apps[key].private_key_passphrase : null
            ocid = local.private_key_passphrase_secret_ocids[key]
          }
          certificate = {
            name = var.enable_oci_secrets && component.jwt_key_material_source != "existing_secret_ocids" ? local.names.oauth_apps[key].certificate : null
            ocid = local.certificate_secret_ocids[key]
          }
        }
      }
    }
  } : null
}
