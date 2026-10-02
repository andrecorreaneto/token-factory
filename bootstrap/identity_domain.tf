data "oci_identity_domains" "selected" {
  provider       = oci.home
  compartment_id = coalesce(var.identity_domain_compartment_ocid, var.tenancy_ocid)
}

resource "oci_identity_domains_oauth_partner_certificate" "these" {
  provider = oci.home
  for_each = local.external_signing_components

  certificate_alias     = each.value.kid
  idcs_endpoint         = var.identity_domain_url
  schemas               = ["urn:ietf:params:scim:schemas:oracle:idcs:OAuthPartnerCertificate"]
  x509base64certificate = local.identity_domain_certificate_base64_values[each.key] == null ? "" : local.identity_domain_certificate_base64_values[each.key]

  depends_on = [terraform_data.external_certificate_verification]

  lifecycle {
    create_before_destroy = true
  }
}

data "oci_identity_domains_oauth_partner_certificates" "managed" {
  provider = oci.home
  for_each = local.managed_signing_components

  idcs_endpoint                    = var.identity_domain_url
  oauth_partner_certificate_count  = 1
  oauth_partner_certificate_filter = "certificateAlias eq \"${each.value.kid}\""

  depends_on = [terraform_data.managed_certificate_registration]
}

data "oci_identity_domains_app_roles" "these" {
  provider = oci.home
  for_each = local.identity_domain_app_role_display_names

  app_role_count  = 1
  app_role_filter = "displayName eq \"${each.value}\""
  idcs_endpoint   = var.identity_domain_url
}

resource "oci_identity_domains_app" "these" {
  provider = oci.home
  for_each = local.identity_domain_scope_independent_apps

  active             = true
  allowed_grants     = ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
  allowed_operations = ["introspect"]
  audience           = each.value.resource_audiences[0]
  client_type        = "confidential"
  description        = local.descriptions.oauth_apps[each.key].client_app
  display_name       = each.value.display_name
  force_delete       = true
  idcs_endpoint      = var.identity_domain_url
  is_oauth_client    = true
  is_oauth_resource  = length(each.value.resource_scopes) > 0
  schemas            = ["urn:ietf:params:scim:schemas:oracle:idcs:App", "urn:ietf:params:scim:schemas:oracle:idcs:extension:OCITags"]
  secondary_audiences = toset(slice(
    each.value.resource_audiences,
    1,
    length(each.value.resource_audiences)
  ))

  based_on_template {
    value         = "CustomWebAppTemplateId"
    well_known_id = "CustomWebAppTemplateId"
  }

  dynamic "allowed_scopes" {
    for_each = {
      for scope_key, scope in local.identity_domain_allowed_scope_refs :
      scope.fqs => scope
      if scope.consumer_app_key == each.key
    }

    content {
      fqs = allowed_scopes.value.fqs
    }
  }

  dynamic "scopes" {
    for_each = toset(each.value.resource_scopes)

    content {
      description      = "Resource server scope ${scopes.value}."
      display_name     = scopes.value
      requires_consent = false
      value            = scopes.value
    }
  }
}

resource "oci_identity_domains_app" "scope_consumers" {
  provider = oci.home
  for_each = local.identity_domain_scope_consuming_apps

  active             = true
  allowed_grants     = ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
  allowed_operations = ["introspect"]
  audience           = each.value.resource_audiences[0]
  client_type        = "confidential"
  description        = local.descriptions.oauth_apps[each.key].client_app
  display_name       = each.value.display_name
  force_delete       = true
  idcs_endpoint      = var.identity_domain_url
  is_oauth_client    = true
  is_oauth_resource  = length(each.value.resource_scopes) > 0
  schemas            = ["urn:ietf:params:scim:schemas:oracle:idcs:App", "urn:ietf:params:scim:schemas:oracle:idcs:extension:OCITags"]
  secondary_audiences = toset(slice(
    each.value.resource_audiences,
    1,
    length(each.value.resource_audiences)
  ))

  based_on_template {
    value         = "CustomWebAppTemplateId"
    well_known_id = "CustomWebAppTemplateId"
  }

  dynamic "allowed_scopes" {
    for_each = {
      for scope_key, scope in local.identity_domain_allowed_scope_refs :
      scope.fqs => scope
      if scope.consumer_app_key == each.key
    }

    content {
      fqs = allowed_scopes.value.fqs
    }
  }

  dynamic "scopes" {
    for_each = toset(each.value.resource_scopes)

    content {
      description      = "Resource server scope ${scopes.value}."
      display_name     = scopes.value
      requires_consent = false
      value            = scopes.value
    }
  }

  depends_on = [oci_identity_domains_app.these]
}

resource "oci_identity_domains_grant" "these" {
  provider = oci.home
  for_each = local.identity_domain_app_role_grants

  grant_mechanism = "ADMINISTRATOR_TO_APP"
  idcs_endpoint   = var.identity_domain_url
  schemas         = ["urn:ietf:params:scim:schemas:oracle:idcs:Grant"]

  app {
    value = data.oci_identity_domains_app_roles.these[each.value.role_name].app_roles[0].app[0].value
  }

  entitlement {
    attribute_name  = "appRoles"
    attribute_value = data.oci_identity_domains_app_roles.these[each.value.role_name].app_roles[0].id
  }

  grantee {
    type  = "App"
    value = local.identity_domain_apps[each.value.app_key].id
  }
}

resource "oci_identity_domains_dynamic_resource_group" "these" {
  provider = oci.home
  for_each = local.custom_dynamic_group_components

  description   = local.descriptions.oauth_apps[each.key].dynamic_group
  display_name  = local.names.oauth_apps[each.key].dynamic_group
  idcs_endpoint = var.identity_domain_url
  matching_rule = local.runtime_matching_rules[each.key]
  schemas       = ["urn:ietf:params:scim:schemas:oracle:idcs:DynamicResourceGroup"]
}

resource "oci_identity_domains_group" "these" {
  provider = oci.home
  for_each = local.custom_user_group_components

  display_name  = local.names.oauth_apps[each.key].user_group
  idcs_endpoint = var.identity_domain_url
  schemas       = ["urn:ietf:params:scim:schemas:core:2.0:Group"]
}

resource "oci_identity_domains_identity_propagation_trust" "these" {
  provider = oci.home
  for_each = {
    for key, component in var.oauth_apps :
    key => component
    if component.enable_identity_propagation_trust
  }

  active                    = true
  allow_impersonation       = false
  client_claim_name         = each.value.propagation_trust_claim_name
  client_claim_values       = each.value.propagation_trust_claim_value == null ? null : [each.value.propagation_trust_claim_value]
  description               = local.descriptions.oauth_apps[each.key].propagation_trust
  idcs_endpoint             = var.identity_domain_url
  issuer                    = each.value.issuer
  name                      = local.names.oauth_apps[each.key].propagation_trust
  oauth_clients             = [local.identity_domain_apps[each.key].name]
  public_certificate        = local.identity_domain_certificate_base64_values[each.key] == null ? "" : local.identity_domain_certificate_base64_values[each.key]
  schemas                   = ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]
  subject_claim_name        = "sub"
  subject_mapping_attribute = "userName"
  subject_type              = "User"
  type                      = "JWT"

  depends_on = [terraform_data.managed_certificate_verification, terraform_data.external_certificate_verification]
}
