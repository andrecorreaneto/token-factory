resource "oci_identity_domains_oauth_partner_certificate" "jwt" {
  provider              = oci.home
  certificate_alias     = var.token_factory_kid
  idcs_endpoint         = local.identity_domain_url
  schemas               = ["urn:ietf:params:scim:schemas:oracle:idcs:OAuthPartnerCertificate"]
  x509base64certificate = replace(replace(local.identity_domain_certificate_base64, "-----BEGIN CERTIFICATE-----", ""), "-----END CERTIFICATE-----", "")
}

resource "oci_identity_domains_app" "client" {
  provider        = oci.home
  active          = true
  allowed_grants  = ["client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"]
  client_type     = "confidential"
  description     = var.token_factory_client_description
  display_name    = var.token_factory_client_display_name
  force_delete    = true
  idcs_endpoint   = local.identity_domain_url
  is_oauth_client = true
  name            = local.names.client_app
  schemas         = ["urn:ietf:params:scim:schemas:oracle:idcs:App", "urn:ietf:params:scim:schemas:oracle:idcs:extension:OCITags"]

  based_on_template {
    value         = "CustomWebAppTemplateId"
    well_known_id = "CustomWebAppTemplateId"
  }

}

resource "oci_identity_domains_identity_propagation_trust" "jwt" {
  provider                  = oci.home
  active                    = true
  allow_impersonation       = false
  client_claim_name         = var.identity_propagation_trust_claim_name
  client_claim_values       = var.identity_propagation_trust_claim_value == null ? null : [var.identity_propagation_trust_claim_value]
  description               = local.descriptions.propagation_trust
  idcs_endpoint             = local.identity_domain_url
  issuer                    = var.token_factory_issuer
  name                      = local.names.propagation_trust
  oauth_clients             = [oci_identity_domains_app.client.id]
  public_certificate        = local.identity_domain_certificate_base64
  schemas                   = ["urn:ietf:params:scim:schemas:oracle:idcs:IdentityPropagationTrust"]
  subject_claim_name        = "sub"
  subject_mapping_attribute = "userName"
  subject_type              = "User"
  type                      = "JWT"
}

data "oci_identity_domains_oauth_partner_certificates" "these" {
  idcs_endpoint = local.identity_domain_url
}

resource "oci_identity_domains_dynamic_resource_group" "runtime" {
  provider = oci.home
  count    = var.enable_oci_secrets && var.token_factory_runtime_iam_principal_type != "user-group" && !local.identity_domain_for_groups_is_default ? 1 : 0

  description   = local.runtime_dynamic_group_description
  display_name  = local.runtime_dynamic_group_name
  idcs_endpoint = local.identity_domain_url_for_groups_effective
  matching_rule = local.runtime_matching_rule
  schemas       = ["urn:ietf:params:scim:schemas:oracle:idcs:DynamicResourceGroup"]
}

resource "oci_identity_domains_group" "runtime" {
  provider = oci.home
  count    = var.enable_oci_secrets && var.token_factory_runtime_iam_principal_type == "user-group" && !local.identity_domain_for_groups_is_default ? 1 : 0

  display_name  = local.names.api_key_group
  idcs_endpoint = local.identity_domain_url_for_groups_effective
  schemas       = ["urn:ietf:params:scim:schemas:core:2.0:Group"]

  urnietfparamsscimschemasoracleidcsextensiongroup_group {
    description = local.descriptions.api_key_group
  }
}
