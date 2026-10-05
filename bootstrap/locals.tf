data "oci_identity_regions" "these" {}

data "oci_identity_tenancy" "this" {
  tenancy_id = var.tenancy_ocid
}

locals {
  provider_region = coalesce(var.region, var.identity_domain_region)
  certificate_registration_oci_environment = {
    TF_CERT_OCI_TENANCY_OCID         = var.tenancy_ocid
    TF_CERT_OCI_USER_OCID            = var.user_ocid == null ? "" : var.user_ocid
    TF_CERT_OCI_FINGERPRINT          = var.fingerprint == null ? "" : var.fingerprint
    TF_CERT_OCI_PRIVATE_KEY_PATH     = var.private_key_path == null ? "" : var.private_key_path
    TF_CERT_OCI_PRIVATE_KEY_PASSWORD = var.private_key_password == null ? "" : var.private_key_password
    TF_CERT_OCI_REGION               = local.provider_region
  }

  normalized_identity_domain_url              = lower(trimsuffix(var.identity_domain_url, "/"))
  normalized_identity_domain_url_without_port = replace(local.normalized_identity_domain_url, "/:443$/", "")
  selected_identity_domain_matches = [
    for domain in data.oci_identity_domains.selected.domains :
    domain
    if contains([
      lower(trimsuffix(domain.url, "/")),
      replace(lower(trimsuffix(domain.url, "/")), "/:443$/", ""),
      lower(trimsuffix(domain.home_region_url, "/")),
      replace(lower(trimsuffix(domain.home_region_url, "/")), "/:443$/", ""),
      ], local.normalized_identity_domain_url) || contains([
      lower(trimsuffix(domain.url, "/")),
      replace(lower(trimsuffix(domain.url, "/")), "/:443$/", ""),
      lower(trimsuffix(domain.home_region_url, "/")),
      replace(lower(trimsuffix(domain.home_region_url, "/")), "/:443$/", ""),
    ], local.normalized_identity_domain_url_without_port)
  ]
  selected_identity_domain      = try(local.selected_identity_domain_matches[0], null)
  selected_identity_domain_name = try(local.selected_identity_domain.display_name, "")
  selected_identity_domain_type = lower(try(local.selected_identity_domain.type, ""))
  selected_identity_domain_url  = trimsuffix(try(local.selected_identity_domain.url, ""), "/")
  selected_identity_domain_id   = try(local.selected_identity_domain.id, null)
  selected_identity_domain_is_default = (
    contains(["default", "default_domain", "defaultdomain"], replace(local.selected_identity_domain_type, "-", "_")) ||
    lower(local.selected_identity_domain_name) == "default"
  )

  regions_map         = { for r in data.oci_identity_regions.these.regions : r.key => r.name }
  regions_map_reverse = { for r in data.oci_identity_regions.these.regions : r.name => r.key }
  home_region_key     = data.oci_identity_tenancy.this.home_region_key
  region_key          = lower(local.regions_map_reverse[local.provider_region])

  raw_resource_name_prefix        = trimspace(coalesce(var.resource_name_prefix, "token-factory"))
  effective_resource_name_prefix  = local.raw_resource_name_prefix == "" ? "token-factory" : local.raw_resource_name_prefix
  normalized_resource_name_prefix = replace(replace(lower(local.effective_resource_name_prefix), "_", "-"), " ", "-")

  raw_oauth_app_resource_names = {
    for key, component in var.oauth_apps :
    key => trimspace(coalesce(component.resource_name_prefix, component.display_name))
  }
  effective_oauth_app_resource_names = {
    for key, value in local.raw_oauth_app_resource_names :
    key => value == "" ? trimspace(var.oauth_apps[key].display_name) : value
  }
  normalized_oauth_app_resource_names = {
    for key, value in local.effective_oauth_app_resource_names :
    key => replace(replace(lower(value), "_", "-"), " ", "-")
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
  identity_domain_scope_independent_apps = {
    for key, component in var.oauth_apps :
    key => component
    if length(component.allowed_scopes) == 0
  }
  identity_domain_scope_consuming_apps = {
    for key, component in var.oauth_apps :
    key => component
    if length(component.allowed_scopes) > 0
  }
  identity_domain_apps = merge(oci_identity_domains_app.these, oci_identity_domains_app.scope_consumers)

  names = {
    vault      = "${local.normalized_resource_name_prefix}-vault"
    master_key = "${local.normalized_resource_name_prefix}-master-key"
    oauth_apps = {
      for key, component in var.oauth_apps :
      key => {
        client_app             = "${local.normalized_oauth_app_resource_names[key]}-client"
        propagation_trust      = "${local.normalized_oauth_app_resource_names[key]}-identity-propagation-trust"
        client_credentials     = "${local.normalized_oauth_app_resource_names[key]}-client-credentials-secret"
        dynamic_group          = "${local.normalized_oauth_app_resource_names[key]}-dynamic-group"
        user_group             = "${local.normalized_oauth_app_resource_names[key]}-user-group"
        policy                 = "${local.normalized_oauth_app_resource_names[key]}-policy"
        database_access_policy = "${local.normalized_oauth_app_resource_names[key]}-database-access-policy"
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
        dynamic_group          = "Token Factory runtime identity for ${key}."
        user_group             = "Token Factory API-key runtime identity for ${key}."
        policy                 = "Token Factory Vault secret read access for ${key}."
        database_access_policy = "Token Factory database connectivity access for ${key}."
      }
    }
  }

  requires_vault     = var.enable_oci_secrets || length(var.oauth_apps) > 0
  create_vault       = local.requires_vault && var.oci_vault_existing_ocid == null
  use_existing_vault = local.requires_vault && var.oci_vault_existing_ocid != null
  create_master_key  = var.enable_oci_secrets && var.oci_master_key_existing_ocid == null

  managed_signing_components = {
    for key, component in var.oauth_apps : key => component
    if component.signing_key.mode == "BOOTSTRAP_MANAGED"
  }
  external_signing_components = {
    for key, component in var.oauth_apps : key => component
    if component.signing_key.mode == "EXTERNALLY_MANAGED"
  }
  external_signing_certificate_pem_values = {
    for key, component in local.external_signing_components :
    key => component.signing_key.signing_certificate_pem != null ? component.signing_key.signing_certificate_pem : file(component.signing_key.signing_certificate_path)
  }
  identity_domain_certificate_pem_values = {
    for key, component in var.oauth_apps :
    key => component.signing_key.mode == "BOOTSTRAP_MANAGED" ? try(data.oci_identity_domains_oauth_partner_certificates.managed[key].oauth_partner_certificates[0].x509base64certificate, null) : local.external_signing_certificate_pem_values[key]
  }
  identity_domain_certificate_compact_pem_values = {
    for key, value in local.identity_domain_certificate_pem_values :
    key => value == null ? null : replace(replace(value, "\r", ""), "\n", "")
  }
  identity_domain_certificate_base64_values = {
    for key, value in local.identity_domain_certificate_compact_pem_values :
    key => value == null ? null : replace(replace(value, "-----BEGIN CERTIFICATE-----", ""), "-----END CERTIFICATE-----", "")
  }

  vault_id = local.requires_vault ? (
    local.create_vault ? oci_kms_vault.this[0].id : var.oci_vault_existing_ocid
  ) : null
  vault_management_endpoint = local.requires_vault ? (
    local.create_vault ? oci_kms_vault.this[0].management_endpoint : data.oci_kms_vault.existing[0].management_endpoint
  ) : null
  vault_crypto_endpoint = local.requires_vault ? (
    local.create_vault ? oci_kms_vault.this[0].crypto_endpoint : data.oci_kms_vault.existing[0].crypto_endpoint
  ) : null
  master_key_id = var.enable_oci_secrets ? (
    local.create_master_key ? oci_kms_key.this[0].id : var.oci_master_key_existing_ocid
  ) : null

  signing_key_ids = {
    for key, component in var.oauth_apps :
    key => component.signing_key.mode == "BOOTSTRAP_MANAGED" ? oci_kms_key.signing[key].id : component.signing_key.signing_key_ocid
  }
  signing_key_version_ids = {
    for key, component in var.oauth_apps :
    key => component.signing_key.mode == "BOOTSTRAP_MANAGED" ? coalesce(component.signing_key.signing_key_version_ocid, oci_kms_key.signing[key].current_key_version) : component.signing_key.signing_key_version_ocid
  }
  signing_key_compartment_ids = {
    for key, component in var.oauth_apps :
    key => component.signing_key.mode == "BOOTSTRAP_MANAGED" ? var.oci_secrets_compartment_ocid : data.oci_kms_key.external[key].compartment_id
  }

  runtime_configs = {
    for key, component in var.oauth_apps :
    key => component.compute_runtime != null ? {
      principal_type   = "compute-instance"
      resource_ocid    = component.compute_runtime.instance_ocid
      cluster_ocid     = null
      namespace        = null
      service_account  = null
      oci_auth_profile = null
      database_access  = component.database_access
      } : component.function_runtime != null ? {
      principal_type   = "oci-function"
      resource_ocid    = component.function_runtime.function_ocid
      cluster_ocid     = null
      namespace        = null
      service_account  = null
      oci_auth_profile = null
      database_access  = component.database_access
      } : component.oke_runtime != null ? {
      principal_type   = "oke-workload"
      resource_ocid    = null
      cluster_ocid     = component.oke_runtime.cluster_ocid
      namespace        = component.oke_runtime.namespace
      service_account  = component.oke_runtime.service_account
      oci_auth_profile = null
      database_access  = component.database_access
      } : {
      principal_type   = "user-group"
      resource_ocid    = null
      cluster_ocid     = null
      namespace        = null
      service_account  = null
      oci_auth_profile = component.local_runtime.oci_auth_profile
      database_access  = component.database_access
    }
  }

  client_credentials = {
    for key, component in var.oauth_apps :
    key => "${local.identity_domain_apps[key].name}:${local.identity_domain_apps[key].client_secret}"
  }

  # null disables the runtime client check; a list (even empty) enables it, and each app always accepts its own client ID.
  allowed_client_ids = {
    for key, component in var.oauth_apps :
    key => component.allowed_clients == null ? null : [for caller in component.allowed_clients : local.identity_domain_apps[caller].name]
  }

  client_credentials_secret_ocids = {
    for key, component in var.oauth_apps :
    key => var.enable_oci_secrets ? oci_vault_secret.client_credentials[key].id : null
  }
  dynamic_group_components = {
    for key, component in var.oauth_apps :
    key => component
    if !contains(["user-group", "oke-workload"], local.runtime_configs[key].principal_type)
  }
  default_dynamic_group_components = local.selected_identity_domain_is_default ? local.dynamic_group_components : {}
  custom_dynamic_group_components  = local.selected_identity_domain_is_default ? {} : local.dynamic_group_components

  user_group_components = {
    for key, component in var.oauth_apps :
    key => component
    if local.runtime_configs[key].principal_type == "user-group"
  }
  default_user_group_components = local.selected_identity_domain_is_default ? local.user_group_components : {}
  custom_user_group_components  = local.selected_identity_domain_is_default ? {} : local.user_group_components

  runtime_resource_types = {
    for key, component in var.oauth_apps :
    key => (
      local.runtime_configs[key].principal_type == "oci-function" ? "fnfunc" :
      null
    )
  }
  runtime_matching_rules = {
    for key, component in local.dynamic_group_components :
    key => (
      local.runtime_configs[key].principal_type == "compute-instance" ? "instance.id = '${local.runtime_configs[key].resource_ocid}'" :
      "ALL {resource.type = '${local.runtime_resource_types[key]}', resource.id = '${local.runtime_configs[key].resource_ocid}'}"
    )
  }

  runtime_principal_names = {
    for key, component in var.oauth_apps :
    key => local.runtime_configs[key].principal_type == "oke-workload" ? "OKE workload ${local.runtime_configs[key].cluster_ocid}/${local.runtime_configs[key].namespace}/${local.runtime_configs[key].service_account}" : local.runtime_configs[key].principal_type == "user-group" ? (
      local.selected_identity_domain_is_default ? oci_identity_group.these[key].name : oci_identity_domains_group.these[key].display_name
      ) : (
      local.selected_identity_domain_is_default ? oci_identity_dynamic_group.these[key].name : oci_identity_domains_dynamic_resource_group.these[key].display_name
    )
  }
  runtime_principal_ids = {
    for key, component in var.oauth_apps :
    key => local.runtime_configs[key].principal_type == "oke-workload" ? null : local.runtime_configs[key].principal_type == "user-group" ? (
      local.selected_identity_domain_is_default ? oci_identity_group.these[key].id : coalesce(oci_identity_domains_group.these[key].ocid, oci_identity_domains_group.these[key].id)
      ) : (
      local.selected_identity_domain_is_default ? oci_identity_dynamic_group.these[key].id : coalesce(oci_identity_domains_dynamic_resource_group.these[key].ocid, oci_identity_domains_dynamic_resource_group.these[key].id)
    )
  }
  runtime_principal_kinds = {
    for key, component in var.oauth_apps :
    key => local.runtime_configs[key].principal_type == "oke-workload" ? "any-user" : local.runtime_configs[key].principal_type == "user-group" ? "group" : "dynamic-group"
  }
  runtime_principal_subject_names = {
    for key, component in var.oauth_apps :
    key => local.runtime_configs[key].principal_type == "oke-workload" ? null : local.selected_identity_domain_is_default ? local.runtime_principal_names[key] : "'${local.selected_identity_domain_name}'/'${local.runtime_principal_names[key]}'"
  }
  runtime_principal_subjects = {
    for key, component in var.oauth_apps :
    key => local.runtime_configs[key].principal_type == "oke-workload" ? "any-user" : "${local.runtime_principal_kinds[key]} ${local.runtime_principal_subject_names[key]}"
  }

  runtime_principal_conditions = {
    for key, component in var.oauth_apps :
    key => local.runtime_configs[key].principal_type == "oke-workload" ? [
      "request.principal.type = 'workload'",
      "request.principal.cluster_id = '${local.runtime_configs[key].cluster_ocid}'",
      "request.principal.namespace = '${local.runtime_configs[key].namespace}'",
      "request.principal.service_account = '${local.runtime_configs[key].service_account}'",
    ] : []
  }
  oke_workload_mapping_groups = {
    for key, component in var.oauth_apps :
    "${local.runtime_configs[key].cluster_ocid}:${local.runtime_configs[key].namespace}" => local.runtime_configs[key]...
    if local.runtime_configs[key].principal_type == "oke-workload"
  }
  oke_workload_mappings = { for identity, runtimes in local.oke_workload_mapping_groups : identity => runtimes[0] }

  oauth_app_runtime_secret_ocids = {
    for key, component in var.oauth_apps :
    key => compact([
      local.client_credentials_secret_ocids[key],
    ])
  }
  runtime_secret_ocids = {
    for key, component in var.oauth_apps :
    key => distinct(compact(concat(
      [var.token_factory_authz_policy_secret_ocid],
      local.oauth_app_runtime_secret_ocids[key]
    )))
  }

  restricted_secret_policy_statements = {
    for key, component in var.oauth_apps :
    key => [
      for secret_ocid in local.runtime_secret_ocids[key] :
      "allow ${local.runtime_principal_subjects[key]} to read secret-bundles in compartment id ${var.oci_secrets_compartment_ocid} where all {${join(", ", concat(local.runtime_principal_conditions[key], ["target.secret.id = '${secret_ocid}'"]))}}"
    ]
  }
  secret_policy_statements = {
    for key, component in var.oauth_apps :
    key => local.restricted_secret_policy_statements[key]
  }
  secret_access_components = {
    for key, component in var.oauth_apps : key => component
    if var.enable_oci_secrets || var.token_factory_authz_policy_secret_ocid != null
  }
  signing_key_policy_statements = {
    for key, component in var.oauth_apps :
    key => "allow ${local.runtime_principal_subjects[key]} to use keys in compartment id ${local.signing_key_compartment_ids[key]} where all {${join(", ", concat(local.runtime_principal_conditions[key], ["target.key.id = '${local.signing_key_ids[key]}'"]))}}"
  }
  database_access_components = {
    for key, component in var.oauth_apps :
    key => component
    if component.database_access != null
  }
  database_access_policy_statements = {
    for key, component in local.database_access_components :
    key => [
      "allow ${local.runtime_principal_subjects[key]} to use database-connections in compartment id ${component.database_access.target_database_compartment_ocid} where all {${join(", ", concat(local.runtime_principal_conditions[key], ["target.database.id = '${component.database_access.target_database_ocid}'"]))}}"
    ]
  }
  token_factory_shared_runtime_config = {
    for key, value in {
      TF_SHARED_DOMAIN_URL                  = var.identity_domain_url
      TF_SHARED_DOMAIN_REGION               = var.identity_domain_region
      TF_SHARED_TIMEOUT_SECONDS             = var.token_factory_timeout_seconds
      TF_SHARED_SUBJECT_CLAIM               = var.token_factory_subject_claim
      TF_SHARED_GROUPS_CLAIM                = var.token_factory_groups_claim
      TF_SHARED_LOG_FULL_ASSERTION          = var.token_factory_log_full_assertion ? "true" : null
      TF_SHARED_AUTHZ_POLICY_SECRET_OCID    = var.token_factory_authz_policy_secret_ocid
      TF_SHARED_AUTHZ_POLICY_SIGNATURE_MODE = var.token_factory_authz_policy_signature_mode
      TF_SHARED_AUTHZ_TRUSTED_SIGNERS_JSON  = length(var.token_factory_authz_policy_trusted_signers) == 0 ? null : jsonencode(var.token_factory_authz_policy_trusted_signers)
      TF_SHARED_AUTHZ_POLICY_ENVIRONMENT    = var.token_factory_authz_policy_environment
      TF_SHARED_AUTHZ_POLICY_TENANT_ID      = var.emit_authz_policy_tenant_id ? var.tenancy_ocid : null
    } : key => value if value != null
  }
  shared_runtime_config = {
    for key, value in {
      domain_url                  = var.identity_domain_url
      domain_region               = var.identity_domain_region
      timeout_seconds             = var.token_factory_timeout_seconds
      subject_claim               = var.token_factory_subject_claim
      groups_claim                = var.token_factory_groups_claim
      log_full_assertion          = var.token_factory_log_full_assertion
      authz_policy_secret_ocid    = var.token_factory_authz_policy_secret_ocid
      authz_policy_signature_mode = var.token_factory_authz_policy_signature_mode
      authz_trusted_signers       = length(var.token_factory_authz_policy_trusted_signers) == 0 ? null : var.token_factory_authz_policy_trusted_signers
      authz_policy_environment    = var.token_factory_authz_policy_environment
      authz_policy_tenant_id      = var.emit_authz_policy_tenant_id ? var.tenancy_ocid : null
    } : key => value if value != null
  }

  runtime_oci_auth_modes = {
    for key, component in var.oauth_apps :
    key => (
      local.runtime_configs[key].principal_type == "compute-instance" ? "instance-principal" :
      local.runtime_configs[key].principal_type == "user-group" ? "oci-profile" :
      local.runtime_configs[key].principal_type == "oke-workload" ? "oke-workload-identity" :
      "resource-principal"
    )
  }

  token_factory_runtime_configs = {
    for key, component in var.oauth_apps :
    key => merge(
      local.token_factory_shared_runtime_config,
      {
        for runtime_key, runtime_value in {
          TF_SHARED_OCI_AUTH_MODE    = local.runtime_oci_auth_modes[key]
          TF_SHARED_OCI_AUTH_PROFILE = local.runtime_configs[key].principal_type == "user-group" ? local.runtime_configs[key].oci_auth_profile : null
          TF_SHARED_OCI_REGION       = local.provider_region
        } : runtime_key => runtime_value if runtime_value != null
      }
    )
  }

  oauth_app_configs = {
    for key, component in var.oauth_apps :
    key => {
      for config_key, config_value in {
        client_credentials_secret_ocid = local.client_credentials_secret_ocids[key]
        issuer                         = component.issuer
        kid                            = component.kid
        kms_key_id                     = local.signing_key_ids[key]
        kms_key_version_id             = local.signing_key_version_ids[key]
        kms_crypto_endpoint            = local.vault_crypto_endpoint
        resource_audiences             = component.resource_audiences
        required_incoming_scopes       = component.resource_scopes
        allowed_client_ids             = local.allowed_client_ids[key]
        propagation_trust_claim        = component.propagation_trust_claim_name == null ? null : "${component.propagation_trust_claim_name}:${component.propagation_trust_claim_value}"
      } : config_key => config_value if config_value != null
    }
  }

  oauth_app_sensitive_configs = {
    for key, component in var.oauth_apps :
    key => merge(
      local.oauth_app_configs[key],
      {
        for config_key, config_value in {
          client_credentials = var.enable_oci_secrets ? null : local.client_credentials[key]
        } : config_key => config_value if config_value != null
      }
    )
  }

  token_factory_client_configs = {
    for key, component in var.oauth_apps :
    key => {
      for config_key, config_value in {
        TF_CLIENT_KEY                      = key
        TF_CLIENT_CREDS_SECRET_OCID        = local.client_credentials_secret_ocids[key]
        TF_CLIENT_ISSUER                   = component.issuer
        TF_CLIENT_KID                      = component.kid
        TF_CLIENT_KMS_KEY_ID               = local.signing_key_ids[key]
        TF_CLIENT_KMS_KEY_VERSION_ID       = local.signing_key_version_ids[key]
        TF_CLIENT_KMS_CRYPTO_ENDPOINT      = local.vault_crypto_endpoint
        TF_CLIENT_RESOURCE_AUDIENCES       = join(",", component.resource_audiences)
        TF_CLIENT_REQUIRED_INCOMING_SCOPES = length(component.resource_scopes) == 0 ? null : join(",", component.resource_scopes)
        TF_CLIENT_PROPAGATION_TRUST_CLAIM  = component.propagation_trust_claim_name == null ? null : "${component.propagation_trust_claim_name}:${component.propagation_trust_claim_value}"
        TF_CLIENT_ALLOWED_CLIENT_IDS       = local.allowed_client_ids[key] == null ? null : join(",", local.allowed_client_ids[key])
      } : config_key => config_value if config_value != null
    }
  }

  token_factory_client_sensitive_configs = {
    for key, component in var.oauth_apps :
    key => merge(
      local.token_factory_client_configs[key],
      {
        for config_key, config_value in {
          TF_CLIENT_CREDS = var.enable_oci_secrets ? null : local.client_credentials[key]
        } : config_key => config_value if config_value != null
      }
    )
  }

  runtime_principals = {
    for key, component in var.oauth_apps :
    key => {
      principal_type = local.runtime_configs[key].principal_type
      principal_kind = local.runtime_principal_kinds[key]
      name           = local.runtime_principal_names[key]
      id             = local.runtime_principal_ids[key]
      subject        = local.runtime_principal_subjects[key]
      matching_rule  = try(local.runtime_matching_rules[key], null)
    }
  }
}
