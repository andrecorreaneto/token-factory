data "oci_identity_regions" "these" {}

data "oci_identity_tenancy" "this" {
  tenancy_id = var.tenancy_ocid
}

data "oci_identity_domains" "client" {
  provider = oci.identity_domain

  compartment_id = var.tenancy_ocid
  name           = trimspace(var.identity_domain_name)
}

data "oci_identity_domains" "groups" {
  provider = oci.identity_domain
  count    = var.enable_oci_secrets ? 1 : 0

  compartment_id = var.tenancy_ocid
  name           = trimspace(coalesce(var.identity_domain_name_for_groups, var.identity_domain_name))
}

locals {

  regions_map         = { for r in data.oci_identity_regions.these.regions : r.key => r.name } # All regions indexed by region key.
  regions_map_reverse = { for r in data.oci_identity_regions.these.regions : r.name => r.key } # All regions indexed by region name.
  home_region_key     = data.oci_identity_tenancy.this.home_region_key                         # Home region key obtained from the tenancy data source
  region_key          = lower(local.regions_map_reverse[var.region])                           # Region key obtained from the region name

  normalized_resource_name_prefix = replace(replace(lower(trimspace(var.resource_name_prefix)), "_", "-"), " ", "-")

  identity_domain_name_for_groups_effective = trimspace(coalesce(var.identity_domain_name_for_groups, var.identity_domain_name))
  identity_domain                           = try(one(data.oci_identity_domains.client.domains), null)
  identity_domain_url                       = try(local.identity_domain.url, null)
  identity_domain_for_groups                = var.enable_oci_secrets ? try(one(data.oci_identity_domains.groups[0].domains), null) : null
  identity_domain_url_for_groups_effective  = try(local.identity_domain_for_groups.url, null)
  identity_domain_for_groups_is_default     = var.enable_oci_secrets ? lower(try(local.identity_domain_for_groups.display_name, "")) == "default" : false

  names = {
    client_app             = "${local.normalized_resource_name_prefix}-client"
    propagation_trust      = "${local.normalized_resource_name_prefix}-identity-propagation-trust"
    vault                  = "${local.normalized_resource_name_prefix}-vault"
    master_key             = "${local.normalized_resource_name_prefix}-master-key"
    client_credentials     = "${local.normalized_resource_name_prefix}-client-credentials"
    private_key            = "${local.normalized_resource_name_prefix}-jwt-private-key"
    private_key_passphrase = "${local.normalized_resource_name_prefix}-jwt-private-key-passphrase"
    certificate            = "${local.normalized_resource_name_prefix}-jwt-certificate"
    instance_dynamic_group = "${local.normalized_resource_name_prefix}-instance-principal-dynamic-group"
    oke_dynamic_group      = "${local.normalized_resource_name_prefix}-oke-cluster-dynamic-group"
    functions_group        = "${local.normalized_resource_name_prefix}-functions-dynamic-group"
    api_key_group          = "${local.normalized_resource_name_prefix}-api-key-group"
    policy                 = "${local.normalized_resource_name_prefix}-secrets-policy"
  }

  descriptions = {
    client_app             = "Token Factory confidential OAuth client."
    propagation_trust      = "Token Factory JWT trust for UPST exchange."
    vault                  = "Token Factory secrets vault."
    master_key             = "Token Factory secrets encryption key."
    client_credentials     = "Token Factory OAuth client credentials."
    private_key            = "Token Factory JWT private key."
    private_key_passphrase = "Token Factory JWT private key passphrase."
    certificate            = "Token Factory JWT certificate."
    instance_dynamic_group = "Token Factory instance-principal runtime identity."
    oke_dynamic_group      = "Token Factory OKE resource-principal runtime identity."
    functions_group        = "Token Factory Functions resource-principal runtime identity."
    api_key_group          = "Token Factory API-key runtime identity."
    policy                 = "Token Factory Vault secret read access."
  }

  create_vault       = var.enable_oci_secrets && var.oci_vault_existing_ocid == null
  use_existing_vault = var.enable_oci_secrets && var.oci_vault_existing_ocid != null
  create_master_key  = var.enable_oci_secrets && var.oci_master_key_existing_ocid == null

  create_generated_key_material = var.jwt_key_material_source == "generate"
  create_vault_key_material     = var.enable_oci_secrets && contains(["generate", "provided_pem"], var.jwt_key_material_source)
  use_existing_key_secrets      = var.enable_oci_secrets && var.jwt_key_material_source == "existing_secret_ocids"

  generated_private_key_pem = local.create_generated_key_material ? tls_private_key.jwt[0].private_key_pem : null
  generated_certificate_pem = local.create_generated_key_material ? tls_self_signed_cert.jwt[0].cert_pem : null

  jwt_private_key_pem_value          = var.jwt_key_material_source == "generate" ? local.generated_private_key_pem : var.jwt_private_key_pem
  jwt_certificate_pem_value          = var.jwt_key_material_source == "generate" ? local.generated_certificate_pem : var.jwt_certificate_pem
  identity_domain_certificate_pem    = var.jwt_key_material_source == "existing_secret_ocids" ? var.jwt_certificate_pem_for_identity_domain : local.jwt_certificate_pem_value
  identity_domain_certificate_base64 = local.identity_domain_certificate_pem == null ? null : replace(replace(local.identity_domain_certificate_pem, "\r", ""), "\n", "")

  vault_id = var.enable_oci_secrets ? (
    local.create_vault ? oci_kms_vault.this[0].id : var.oci_vault_existing_ocid
  ) : null
  vault_management_endpoint = var.enable_oci_secrets ? (
    local.create_vault ? oci_kms_vault.this[0].management_endpoint : data.oci_kms_vault.existing[0].management_endpoint
  ) : null
  master_key_id = var.enable_oci_secrets ? (
    local.create_master_key ? oci_kms_key.this[0].id : var.oci_master_key_existing_ocid
  ) : null

  client_credentials = "${oci_identity_domains_app.client.id}:${oci_identity_domains_app.client.client_secret}"

  token_factory_creds_secret_ocid = var.enable_oci_secrets ? oci_vault_secret.client_credentials[0].id : null
  private_key_secret_ocid = var.enable_oci_secrets ? (
    local.use_existing_key_secrets ? var.oci_private_key_secret_existing_ocid : oci_vault_secret.private_key[0].id
  ) : null
  private_key_passphrase_secret_ocid = var.enable_oci_secrets ? (
    local.use_existing_key_secrets ? var.oci_private_key_passphrase_secret_existing_ocid : (
      var.jwt_private_key_passphrase == null ? null : oci_vault_secret.private_key_passphrase[0].id
    )
  ) : null
  certificate_secret_ocid = var.enable_oci_secrets ? (
    local.use_existing_key_secrets ? var.oci_certificate_secret_existing_ocid : oci_vault_secret.certificate[0].id
  ) : null

  runtime_dynamic_group_name = (
    var.token_factory_runtime_iam_principal_type == "oke-cluster" ? local.names.oke_dynamic_group :
    var.token_factory_runtime_iam_principal_type == "oci-function" ? local.names.functions_group :
    local.names.instance_dynamic_group
  )
  runtime_dynamic_group_description = (
    var.token_factory_runtime_iam_principal_type == "oke-cluster" ? local.descriptions.oke_dynamic_group :
    var.token_factory_runtime_iam_principal_type == "oci-function" ? local.descriptions.functions_group :
    local.descriptions.instance_dynamic_group
  )

  runtime_resource_type = (
    var.token_factory_runtime_iam_principal_type == "oke-cluster" ? "cluster" :
    var.token_factory_runtime_iam_principal_type == "oci-function" ? "fnfunc" :
    null
  )
  runtime_matching_rule = (
    var.token_factory_runtime_iam_principal_type == "user-group" ? null :
    var.token_factory_runtime_iam_principal_type == "compute-instance" && var.token_factory_runtime_resource_ocid == null ? "instance.compartment.id = '${var.token_factory_runtime_compartment_ocid}'" :
    var.token_factory_runtime_iam_principal_type == "compute-instance" ? "instance.id = '${var.token_factory_runtime_resource_ocid}'" :
    var.token_factory_runtime_resource_ocid == null ? "ALL {resource.type = '${local.runtime_resource_type}', resource.compartment.id = '${var.token_factory_runtime_compartment_ocid}'}" :
    "ALL {resource.type = '${local.runtime_resource_type}', resource.id = '${var.token_factory_runtime_resource_ocid}', resource.compartment.id = '${var.token_factory_runtime_compartment_ocid}'}"
  )

  runtime_principal_name = var.enable_oci_secrets ? (
    var.token_factory_runtime_iam_principal_type == "user-group" ? (
      local.identity_domain_for_groups_is_default ? oci_identity_group.runtime[0].name : oci_identity_domains_group.runtime[0].display_name
      ) : (
      local.identity_domain_for_groups_is_default ? oci_identity_dynamic_group.runtime[0].name : oci_identity_domains_dynamic_resource_group.runtime[0].display_name
    )
  ) : null
  runtime_principal_kind = var.token_factory_runtime_iam_principal_type == "user-group" ? "group" : "dynamic-group"
  runtime_dynamic_group_id = var.enable_oci_secrets && var.token_factory_runtime_iam_principal_type != "user-group" ? (
    local.identity_domain_for_groups_is_default ? try(oci_identity_dynamic_group.runtime[0].id, null) : try(oci_identity_domains_dynamic_resource_group.runtime[0].ocid, null)
  ) : null
  runtime_group_id = var.enable_oci_secrets && var.token_factory_runtime_iam_principal_type == "user-group" ? (
    local.identity_domain_for_groups_is_default ? try(oci_identity_group.runtime[0].id, null) : try(oci_identity_domains_group.runtime[0].ocid, null)
  ) : null
  runtime_principal_identifier = (
    local.identity_domain_for_groups_is_default ?
    local.runtime_principal_name :
    "'${local.identity_domain_name_for_groups_effective}'/'${local.runtime_principal_name}'"
  )

  created_secret_ocids = compact([
    local.token_factory_creds_secret_ocid,
    local.private_key_secret_ocid,
    local.private_key_passphrase_secret_ocid,
    local.certificate_secret_ocid
  ])

  base_secret_policy_statements = [
    "allow ${local.runtime_principal_kind} ${local.runtime_principal_identifier} to read secret-bundles in compartment id ${var.oci_secrets_compartment_ocid}"
  ]
  restricted_secret_policy_statements = [
    for secret_ocid in local.created_secret_ocids :
    "allow ${local.runtime_principal_kind} ${local.runtime_principal_identifier} to read secret-bundles in compartment id ${var.oci_secrets_compartment_ocid} where target.secret.id = '${secret_ocid}'"
  ]
  secret_policy_statements = var.restrict_secret_policy_to_secret_ocids ? local.restricted_secret_policy_statements : local.base_secret_policy_statements

  token_factory_config = {
    for key, value in {
      TOKEN_FACTORY_DOMAIN_URL                         = local.identity_domain_url
      TOKEN_FACTORY_DOMAIN_REGION                      = var.identity_domain_region
      TOKEN_FACTORY_CREDS_SECRET_OCID                  = local.token_factory_creds_secret_ocid
      TOKEN_FACTORY_CREDS                              = var.enable_oci_secrets ? null : local.client_credentials
      TOKEN_FACTORY_ISSUER                             = var.token_factory_issuer
      TOKEN_FACTORY_PRIVATE_KEY_SECRET_OCID            = local.private_key_secret_ocid
      TOKEN_FACTORY_PRIVATE_KEY_PATH                   = null
      TOKEN_FACTORY_PRIVATE_KEY_PEM                    = var.enable_oci_secrets ? null : local.jwt_private_key_pem_value
      TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE_SECRET_OCID = local.private_key_passphrase_secret_ocid
      TOKEN_FACTORY_PRIVATE_KEY_PASSPHRASE             = var.enable_oci_secrets ? null : var.jwt_private_key_passphrase
      TOKEN_FACTORY_CERT_SECRET_OCID                   = local.certificate_secret_ocid
      TOKEN_FACTORY_CERT_PATH                          = null
      TOKEN_FACTORY_CERT_PEM                           = var.enable_oci_secrets ? null : local.jwt_certificate_pem_value
      TOKEN_FACTORY_KID                                = var.token_factory_kid
      TOKEN_FACTORY_OCI_REGION                         = var.enable_oci_secrets ? coalesce(var.oci_secrets_region, var.identity_domain_region) : null
      TOKEN_FACTORY_OCI_AUTH_MODE                      = var.enable_oci_secrets ? var.token_factory_runtime_iam_auth_mode : null
      TOKEN_FACTORY_OCI_AUTH_PROFILE                   = var.enable_oci_secrets && var.token_factory_runtime_iam_auth_mode == "oci-profile" ? "DEFAULT" : null
      TOKEN_FACTORY_PROPAGATION_TRUST_CLAIM            = var.identity_propagation_trust_claim_name == null ? null : "${var.identity_propagation_trust_claim_name}:${var.identity_propagation_trust_claim_value}"
    } : key => value if value != null
  }
}
