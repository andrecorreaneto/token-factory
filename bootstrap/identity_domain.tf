resource "oci_identity_domains_oauth_partner_certificate" "these" {
  provider = oci.home
  for_each = var.oauth_apps

  certificate_alias     = each.value.kid
  idcs_endpoint         = var.identity_domain_url
  schemas               = ["urn:ietf:params:scim:schemas:oracle:idcs:OAuthPartnerCertificate"]
  x509base64certificate = local.identity_domain_certificate_base64_values[each.key] == null ? "" : local.identity_domain_certificate_base64_values[each.key]
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
  for_each = var.oauth_apps

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
    value = oci_identity_domains_app.these[each.value.app_key].id
  }
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
  oauth_clients             = [oci_identity_domains_app.these[each.key].name]
  public_certificate        = local.identity_domain_certificate_base64_values[each.key] == null ? "" : local.identity_domain_certificate_base64_values[each.key]
  schemas                   = ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]
  subject_claim_name        = "sub"
  subject_mapping_attribute = "userName"
  subject_type              = "User"
  type                      = "JWT"
}

data "oci_identity_domains_oauth_partner_certificates" "these" {
  idcs_endpoint = var.identity_domain_url
}
