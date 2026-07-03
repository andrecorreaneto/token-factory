data "oci_identity_regions" "these" {}

data "oci_identity_tenancy" "this" {
  tenancy_id = var.tenancy_ocid
}

locals {
  provider_region = coalesce(var.region, var.identity_domain_region)

  regions_map         = { for r in data.oci_identity_regions.these.regions : r.key => r.name }
  regions_map_reverse = { for r in data.oci_identity_regions.these.regions : r.name => r.key }
  home_region_key     = data.oci_identity_tenancy.this.home_region_key
  region_key          = lower(local.regions_map_reverse[local.provider_region])

  raw_resource_name_prefix        = trimspace(coalesce(var.resource_name_prefix, "token-factory"))
  effective_resource_name_prefix  = local.raw_resource_name_prefix == "" ? "token-factory" : local.raw_resource_name_prefix
  normalized_resource_name_prefix = replace(replace(lower(local.effective_resource_name_prefix), "_", "-"), " ", "-")

  raw_oauth_app_resource_names = {
    for key, component in var.oauth_apps :
    key => trimspace(coalesce(component.resource_name_prefix, key))
  }
  normalized_oauth_app_resource_names = {
    for key, value in local.raw_oauth_app_resource_names :
    key => replace(replace(lower(value == "" ? key : value), "_", "-"), " ", "-")
  }
  identity_domain_app_role_grants = {
    for grant in flatten([
      for app_key, component in var.oauth_apps : [
        for role_name in component.app_roles : {
          key       = "${app_key}:${role_name}"
          app_key   = app_key
          role_name = role_name
        }
      ]
    ]) :
    grant.key => {
      app_key   = grant.app_key
      role_name = grant.role_name
    }
  }
  identity_domain_app_role_display_names = toset([
    for grant in values(local.identity_domain_app_role_grants) :
    grant.role_name
  ])
  identity_domain_allowed_scope_refs = {
    for scope in flatten([
      for app_key, component in var.oauth_apps : [
        for allowed_scope in component.allowed_scopes : {
          key              = "${app_key}:${allowed_scope}"
          consumer_app_key = app_key
          fqs              = allowed_scope
        }
      ]
    ]) :
    scope.key => {
      consumer_app_key = scope.consumer_app_key
      fqs              = scope.fqs
    }
  }

  names = {
    vault      = "${local.normalized_resource_name_prefix}-vault"
    master_key = "${local.normalized_resource_name_prefix}-master-key"
    oauth_apps = {
      for key, component in var.oauth_apps :
      key => {
        client_app             = "${local.normalized_oauth_app_resource_names[key]}-client"
        propagation_trust      = "${local.normalized_oauth_app_resource_names[key]}-identity-propagation-trust"
        client_credentials     = "${local.normalized_oauth_app_resource_names[key]}-client-credentials-secret"
        private_key            = "${local.normalized_oauth_app_resource_names[key]}-jwt-private-key-secret"
        private_key_passphrase = "${local.normalized_oauth_app_resource_names[key]}-jwt-private-key-passphrase-secret"
        certificate            = "${local.normalized_oauth_app_resource_names[key]}-jwt-certificate-secret"
        dynamic_group          = "${local.normalized_oauth_app_resource_names[key]}-runtime-dynamic-group"
        user_group             = "${local.normalized_oauth_app_resource_names[key]}-runtime-user-group"
        policy                 = "${local.normalized_oauth_app_resource_names[key]}-secrets-policy"
      }
    }
  }

  descriptions = {
    vault      = "Token Factory shared secrets vault."
    master_key = "Token Factory shared secrets encryption key."
    oauth_apps = {
      for key, component in var.oauth_apps :
      key => {
        client_app             = coalesce(component.description, "Token Factory OAuth app/client identity for ${key}.")
        propagation_trust      = "Token Factory JWT trust for ${key} UPST exchange."
        client_credentials     = "Token Factory OAuth client credentials for ${key}."
        private_key            = "Token Factory JWT private key for ${key}."
        private_key_passphrase = "Token Factory JWT private key passphrase for ${key}."
        certificate            = "Token Factory JWT certificate for ${key}."
        dynamic_group          = "Token Factory runtime identity for ${key}."
        user_group             = "Token Factory API-key runtime identity for ${key}."
        policy                 = "Token Factory Vault secret read access for ${key}."
      }
    }
  }

  create_vault       = var.enable_oci_secrets && var.oci_vault_existing_ocid == null
  use_existing_vault = var.enable_oci_secrets && var.oci_vault_existing_ocid != null
  create_master_key  = var.enable_oci_secrets && var.oci_master_key_existing_ocid == null

  generated_key_material_components = {
    for key, component in var.oauth_apps :
    key => component
    if component.jwt_key_material_source == "generate"
  }
  vault_key_material_components = {
    for key, component in var.oauth_apps :
    key => component
    if var.enable_oci_secrets && contains(["generate", "provided_pem"], component.jwt_key_material_source)
  }

  jwt_private_key_pem_values = {
    for key, component in var.oauth_apps :
    key => component.jwt_key_material_source == "generate" ? tls_private_key.these[key].private_key_pem : component.jwt_private_key_pem
  }
  jwt_certificate_pem_values = {
    for key, component in var.oauth_apps :
    key => component.jwt_key_material_source == "generate" ? tls_self_signed_cert.these[key].cert_pem : component.jwt_certificate_pem
  }
  identity_domain_certificate_pem_values = {
    for key, component in var.oauth_apps :
    key => component.jwt_key_material_source == "existing_secret_ocids" ? component.jwt_certificate_pem_for_identity_domain : local.jwt_certificate_pem_values[key]
  }
  identity_domain_certificate_compact_pem_values = {
    for key, value in local.identity_domain_certificate_pem_values :
    key => value == null ? null : replace(replace(value, "\r", ""), "\n", "")
  }
  identity_domain_certificate_base64_values = {
    for key, value in local.identity_domain_certificate_compact_pem_values :
    key => value == null ? null : replace(replace(value, "-----BEGIN CERTIFICATE-----", ""), "-----END CERTIFICATE-----", "")
  }

  vault_id = var.enable_oci_secrets ? (
    local.create_vault ? oci_kms_vault.this[0].id : var.oci_vault_existing_ocid
  ) : null
  vault_management_endpoint = var.enable_oci_secrets ? (
    local.create_vault ? oci_kms_vault.this[0].management_endpoint : data.oci_kms_vault.existing[0].management_endpoint
  ) : null
  master_key_id = var.enable_oci_secrets ? (
    local.create_master_key ? oci_kms_key.this[0].id : var.oci_master_key_existing_ocid
  ) : null

  client_credentials = {
    for key, component in var.oauth_apps :
    key => "${oci_identity_domains_app.these[key].name}:${oci_identity_domains_app.these[key].client_secret}"
  }

  client_credentials_secret_ocids = {
    for key, component in var.oauth_apps :
    key => var.enable_oci_secrets ? oci_vault_secret.client_credentials[key].id : null
  }
  private_key_secret_ocids = {
    for key, component in var.oauth_apps :
    key => var.enable_oci_secrets ? (
      component.jwt_key_material_source == "existing_secret_ocids" ? component.private_key_secret_existing_ocid : oci_vault_secret.private_keys[key].id
    ) : null
  }
  private_key_passphrase_secret_ocids = {
    for key, component in var.oauth_apps :
    key => var.enable_oci_secrets ? (
      component.jwt_key_material_source == "existing_secret_ocids" ? component.private_key_passphrase_secret_existing_ocid : (
        component.jwt_private_key_passphrase == null ? null : oci_vault_secret.private_key_passphrases[key].id
      )
    ) : null
  }
  certificate_secret_ocids = {
    for key, component in var.oauth_apps :
    key => var.enable_oci_secrets ? (
      component.jwt_key_material_source == "existing_secret_ocids" ? component.certificate_secret_existing_ocid : oci_vault_secret.certificates[key].id
    ) : null
  }

  dynamic_group_components = {
    for key, component in var.oauth_apps :
    key => component
    if component.runtime.principal_type != "user-group"
  }
  user_group_components = {
    for key, component in var.oauth_apps :
    key => component
    if component.runtime.principal_type == "user-group"
  }

  runtime_resource_types = {
    for key, component in var.oauth_apps :
    key => (
      component.runtime.principal_type == "oke-cluster" ? "cluster" :
      component.runtime.principal_type == "oci-function" ? "fnfunc" :
      null
    )
  }
  runtime_matching_rules = {
    for key, component in local.dynamic_group_components :
    key => (
      component.runtime.principal_type == "compute-instance" && component.runtime.resource_ocid == null ? "instance.compartment.id = '${component.runtime.compartment_ocid}'" :
      component.runtime.principal_type == "compute-instance" ? "instance.id = '${component.runtime.resource_ocid}'" :
      component.runtime.resource_ocid == null ? "ALL {resource.type = '${local.runtime_resource_types[key]}', resource.compartment.id = '${component.runtime.compartment_ocid}'}" :
      "ALL {resource.type = '${local.runtime_resource_types[key]}', resource.id = '${component.runtime.resource_ocid}', resource.compartment.id = '${component.runtime.compartment_ocid}'}"
    )
  }

  runtime_principal_names = {
    for key, component in var.oauth_apps :
    key => component.runtime.principal_type == "user-group" ? oci_identity_group.these[key].name : oci_identity_dynamic_group.these[key].name
  }
  runtime_principal_ids = {
    for key, component in var.oauth_apps :
    key => component.runtime.principal_type == "user-group" ? oci_identity_group.these[key].id : oci_identity_dynamic_group.these[key].id
  }
  runtime_principal_kinds = {
    for key, component in var.oauth_apps :
    key => component.runtime.principal_type == "user-group" ? "group" : "dynamic-group"
  }

  oauth_app_runtime_secret_ocids = {
    for key, component in var.oauth_apps :
    key => compact([
      local.client_credentials_secret_ocids[key],
      local.private_key_secret_ocids[key],
      local.private_key_passphrase_secret_ocids[key],
      local.certificate_secret_ocids[key],
    ])
  }
  runtime_secret_ocids = {
    for key, component in var.oauth_apps :
    key => distinct(compact(concat(
      [var.token_factory_authz_policy_secret_ocid],
      local.oauth_app_runtime_secret_ocids[key]
    )))
  }

  base_secret_policy_statements = {
    for key, component in var.oauth_apps :
    key => [
      "allow ${local.runtime_principal_kinds[key]} ${local.runtime_principal_names[key]} to read secret-bundles in compartment id ${var.oci_secrets_compartment_ocid}"
    ]
  }
  restricted_secret_policy_statements = {
    for key, component in var.oauth_apps :
    key => [
      for secret_ocid in local.runtime_secret_ocids[key] :
      "allow ${local.runtime_principal_kinds[key]} ${local.runtime_principal_names[key]} to read secret-bundles in compartment id ${var.oci_secrets_compartment_ocid} where target.secret.id = '${secret_ocid}'"
    ]
  }
  secret_policy_statements = {
    for key, component in var.oauth_apps :
    key => var.restrict_secret_policy_to_secret_ocids ? local.restricted_secret_policy_statements[key] : local.base_secret_policy_statements[key]
  }

  token_factory_shared_runtime_config = {
    for key, value in {
      TOKEN_FACTORY_DOMAIN_URL                  = var.identity_domain_url
      TOKEN_FACTORY_DOMAIN_REGION               = var.identity_domain_region
      TOKEN_FACTORY_TIMEOUT_SECONDS             = var.token_factory_timeout_seconds
      TOKEN_FACTORY_SUBJECT_CLAIM               = var.token_factory_subject_claim
      TOKEN_FACTORY_GROUPS_CLAIM                = var.token_factory_groups_claim
      TOKEN_FACTORY_LOG_FULL_ASSERTION          = var.token_factory_log_full_assertion ? "true" : null
      TOKEN_FACTORY_AUTHZ_POLICY_SECRET_OCID    = var.token_factory_authz_policy_secret_ocid
      TOKEN_FACTORY_AUTHZ_POLICY_SIGNATURE_MODE = var.token_factory_authz_policy_signature_mode
      TOKEN_FACTORY_AUTHZ_TRUSTED_SIGNERS_JSON  = length(var.token_factory_authz_policy_trusted_signers) == 0 ? null : jsonencode(var.token_factory_authz_policy_trusted_signers)
      TOKEN_FACTORY_AUTHZ_POLICY_ENVIRONMENT    = var.token_factory_authz_policy_environment
      TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID      = var.emit_authz_policy_tenant_id ? var.tenancy_ocid : null
    } : key => value if value != null
  }

  runtime_oci_auth_modes = {
    for key, component in var.oauth_apps :
    key => (
      component.runtime.principal_type == "compute-instance" ? "instance-principal" :
      component.runtime.principal_type == "user-group" ? "oci-profile" :
      "resource-principal"
    )
  }

  token_factory_runtime_configs = {
    for key, component in var.oauth_apps :
    key => merge(
      local.token_factory_shared_runtime_config,
      {
        for runtime_key, runtime_value in {
          TOKEN_FACTORY_OCI_AUTH_MODE           = local.runtime_oci_auth_modes[key]
          TOKEN_FACTORY_OCI_AUTH_PROFILE        = component.runtime.principal_type == "user-group" ? coalesce(component.runtime.oci_auth_profile, "DEFAULT") : null
          TOKEN_FACTORY_OCI_REGION              = coalesce(component.runtime.oci_region, var.oci_secrets_region, var.identity_domain_region)
          TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM = component.propagation_trust_claim_name == null ? null : "${component.propagation_trust_claim_name}:${component.propagation_trust_claim_value}"
        } : runtime_key => runtime_value if runtime_value != null
      }
    )
  }

  oauth_app_configs = {
    for key, component in var.oauth_apps :
    key => {
      for config_key, config_value in {
        client_credentials_secret_ocid     = local.client_credentials_secret_ocids[key]
        issuer                             = component.issuer
        private_key_path                   = null
        private_key_secret_ocid            = local.private_key_secret_ocids[key]
        private_key_passphrase_secret_ocid = local.private_key_passphrase_secret_ocids[key]
        certificate_path                   = null
        certificate_secret_ocid            = local.certificate_secret_ocids[key]
        kid                                = component.kid
        resource_audiences                 = component.resource_audiences
        required_incoming_scopes           = component.resource_scopes
      } : config_key => config_value if config_value != null
    }
  }

  oauth_app_sensitive_configs = {
    for key, component in var.oauth_apps :
    key => merge(
      local.oauth_app_configs[key],
      {
        for config_key, config_value in {
          client_credentials     = var.enable_oci_secrets ? null : local.client_credentials[key]
          private_key_pem        = var.enable_oci_secrets ? null : local.jwt_private_key_pem_values[key]
          private_key_passphrase = var.enable_oci_secrets ? null : component.jwt_private_key_passphrase
          certificate_pem        = var.enable_oci_secrets ? null : local.jwt_certificate_pem_values[key]
        } : config_key => config_value if config_value != null
      }
    )
  }

  runtime_principals = {
    for key, component in var.oauth_apps :
    key => {
      principal_type = component.runtime.principal_type
      principal_kind = local.runtime_principal_kinds[key]
      name           = local.runtime_principal_names[key]
      id             = local.runtime_principal_ids[key]
      matching_rule  = component.runtime.principal_type == "user-group" ? null : local.runtime_matching_rules[key]
    }
  }
}
