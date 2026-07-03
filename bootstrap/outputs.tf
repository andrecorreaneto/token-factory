output "token_factory_shared_runtime_config" {
  description = "Shared Token Factory runtime configuration base. Excludes OAuth app identity fields and per-runtime OCI auth values."
  value       = local.token_factory_shared_runtime_config
}

output "token_factory_runtime_configs" {
  description = "Full Token Factory runtime configuration by OAuth app key."
  value       = local.token_factory_runtime_configs
}

output "token_factory_runtime_config_env" {
  description = "Shell export lines for Token Factory runtime configuration by OAuth app key."
  value = {
    for component_key, config in local.token_factory_runtime_configs :
    component_key => join("\n", [
      for key, value in config :
      "export ${key}=${jsonencode(tostring(value))}"
    ])
  }
}

output "oauth_app_configs" {
  description = "Token Factory OAuthClientInfo-shaped resolver config by OAuth app key. Regular output contains only non-secret values and secret OCID references."
  value       = local.oauth_app_configs
}

output "oauth_app_configs_json" {
  description = "JSON-encoded Token Factory OAuthClientInfo-shaped resolver config. Regular output contains only non-secret values and secret OCID references."
  value       = jsonencode(local.oauth_app_configs)
}

output "oauth_app_sensitive_configs" {
  description = "Sensitive OAuthClientInfo-shaped resolver config including inline credentials and PEM values when enable_oci_secrets = false."
  value       = local.oauth_app_sensitive_configs
  sensitive   = true
}

output "oauth_app_sensitive_configs_json" {
  description = "Sensitive JSON-encoded resolver config including inline credentials and PEM values when enable_oci_secrets = false."
  value       = jsonencode(local.oauth_app_sensitive_configs)
  sensitive   = true
}

output "oauth_app_runtime_secret_ocids" {
  description = "OAuth material secret OCIDs each OAuth app runtime must read."
  value       = local.oauth_app_runtime_secret_ocids
}

output "runtime_secret_ocids" {
  description = "All secret OCIDs each OAuth app runtime can read, including the shared authorization policy secret when configured."
  value       = local.runtime_secret_ocids
}

output "runtime_principals" {
  description = "Runtime IAM principal details by OAuth app key."
  value       = local.runtime_principals
}

output "secret_policy_statements" {
  description = "Generated Vault read policy statements by OAuth app key."
  value       = local.secret_policy_statements
}

output "oauth_app_resource_ids" {
  description = "Provisioned OAuth app/runtime resource identifiers by OAuth app key."
  value = {
    for key, component in var.oauth_apps :
    key => {
      identity_domain_app_id          = oci_identity_domains_app.these[key].id
      identity_domain_oauth_client_id = oci_identity_domains_app.these[key].name
      identity_domain_certificate_id  = oci_identity_domains_oauth_partner_certificate.these[key].id
      identity_domain_app_role_grant_ids = {
        for grant_key, grant in local.identity_domain_app_role_grants :
        grant.role_name => oci_identity_domains_grant.these[grant_key].id
        if grant.app_key == key
      }
      identity_propagation_trust_id = component.enable_identity_propagation_trust ? oci_identity_domains_identity_propagation_trust.these[key].id : null

      client_credentials_secret_ocid     = local.client_credentials_secret_ocids[key]
      private_key_secret_ocid            = local.private_key_secret_ocids[key]
      private_key_passphrase_secret_ocid = local.private_key_passphrase_secret_ocids[key]
      certificate_secret_ocid            = local.certificate_secret_ocids[key]
      runtime_dynamic_group_id           = component.runtime.principal_type == "user-group" ? null : oci_identity_dynamic_group.these[key].id
      runtime_group_id                   = component.runtime.principal_type == "user-group" ? oci_identity_group.these[key].id : null
      runtime_policy_id                  = oci_identity_policy.these[key].id
      runtime_policy_compartment_ocid    = oci_identity_policy.these[key].compartment_id
      runtime_secret_ocids               = local.runtime_secret_ocids[key]
    }
  }
}

output "provisioned_resource_ids" {
  description = "Provisioned shared and OAuth app/runtime resource IDs."
  value = {
    shared = {
      oci_vault_id             = local.vault_id
      oci_master_key_id        = local.master_key_id
      authz_policy_secret_ocid = var.token_factory_authz_policy_secret_ocid
    }
    oauth_apps = {
      for key, component in var.oauth_apps :
      key => {
        identity_domain_app_id         = oci_identity_domains_app.these[key].id
        identity_domain_certificate_id = oci_identity_domains_oauth_partner_certificate.these[key].id
        identity_domain_app_role_grant_ids = {
          for grant_key, grant in local.identity_domain_app_role_grants :
          grant.role_name => oci_identity_domains_grant.these[grant_key].id
          if grant.app_key == key
        }
        identity_propagation_trust_id          = component.enable_identity_propagation_trust ? oci_identity_domains_identity_propagation_trust.these[key].id : null
        token_factory_creds_secret_ocid        = local.client_credentials_secret_ocids[key]
        oci_private_key_secret_ocid            = local.private_key_secret_ocids[key]
        oci_private_key_passphrase_secret_ocid = local.private_key_passphrase_secret_ocids[key]
        oci_certificate_secret_ocid            = local.certificate_secret_ocids[key]
        runtime_dynamic_group_id               = component.runtime.principal_type == "user-group" ? null : oci_identity_dynamic_group.these[key].id
        runtime_group_id                       = component.runtime.principal_type == "user-group" ? oci_identity_group.these[key].id : null
        runtime_policy_id                      = oci_identity_policy.these[key].id
      }
    }
  }
}

output "provisioned_resources" {
  description = "Provisioned shared and OAuth app/runtime resources with names and OCIDs for lookup."
  value = {
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
          ocid           = local.runtime_principal_ids[key]
          principal_kind = local.runtime_principal_kinds[key]
          principal_type = component.runtime.principal_type
        }
        vault_read_policy = {
          name = local.names.oauth_apps[key].policy
          ocid = oci_identity_policy.these[key].id
        }
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
  }
}
