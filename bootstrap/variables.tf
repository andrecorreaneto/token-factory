variable "region" {
  description = "OCI provider region. Defaults to identity_domain_region when omitted."
  type        = string
  default     = null
}

variable "tenancy_ocid" {
  description = "Tenancy OCID where module-managed IAM dynamic groups, groups, and policies are created."
  type        = string
}

variable "user_ocid" {
  description = "Optional OCI API-key user OCID for local Terraform runs."
  type        = string
  default     = null
}

variable "fingerprint" {
  description = "Optional OCI API-key fingerprint for local Terraform runs."
  type        = string
  default     = null
}

variable "private_key_path" {
  description = "Optional OCI API private key path for local Terraform runs."
  type        = string
  default     = null
}

variable "private_key_password" {
  description = "Optional OCI API private key password for local Terraform runs."
  type        = string
  default     = null
  sensitive   = true
}

variable "resource_name_prefix" {
  description = "Prefix used for module-managed resource names."
  type        = string
  default     = "token-factory"
}

variable "identity_domain_name" {
  description = "Identity Domain name used for Token Factory OAuth client, certificate, and propagation trust resources."
  type        = string

  validation {
    condition = (
      length(trimspace(var.identity_domain_name)) > 0
    )
    error_message = "VALIDATION FAILURE: identity_domain_name must not be empty."
  }
}

variable "identity_domain_name_for_groups" {
  description = "Identity Domain name used for generated runtime groups and dynamic groups. Defaults to identity_domain_name."
  type        = string
  default     = null

  validation {
    condition = (
      var.identity_domain_name_for_groups == null ||
      length(try(trimspace(var.identity_domain_name_for_groups), "")) > 0
    )
    error_message = "VALIDATION FAILURE: identity_domain_name_for_groups must be null or a non-empty Identity Domain name."
  }
}

variable "identity_domain_region" {
  description = "OCI region used by TokenFactory for token exchange and identity data plane calls."
  type        = string
}

variable "token_factory_issuer" {
  description = "JWT issuer and IdentityPropagationTrust issuer."
  type        = string
  default     = "https://upst.tokenfactory/"
}

variable "token_factory_kid" {
  description = "Certificate alias and JWT kid header value."
  type        = string
  default     = "token-factory-cert"
}

variable "identity_propagation_trust_claim_name" {
  description = "Optional IdentityPropagationTrust client claim name."
  type        = string
  default     = null
}

variable "identity_propagation_trust_claim_value" {
  description = "Optional IdentityPropagationTrust client claim value."
  type        = string
  default     = null
}

variable "enable_oci_secrets" {
  description = "When true, store sensitive runtime values in OCI Secrets and output secret OCIDs."
  type        = bool
  default     = true
}

variable "jwt_key_material_source" {
  description = "Source for JWT private key and certificate material. Valid values: generate, provided_pem, existing_secret_ocids."
  type        = string
  default     = "generate"

  validation {
    condition     = contains(["generate", "provided_pem", "existing_secret_ocids"], var.jwt_key_material_source)
    error_message = "VALIDATION FAILURE: jwt_key_material_source must be one of generate, provided_pem, or existing_secret_ocids."
  }
}

variable "oci_secrets_compartment_ocid" {
  description = "Compartment for created or existing OCI Secrets."
  type        = string
  default     = null
}

variable "oci_vault_existing_ocid" {
  description = "Existing Vault OCID to use. When omitted, the module provisions a Vault."
  type        = string
  default     = null
}

variable "oci_master_key_existing_ocid" {
  description = "Existing Vault master encryption key OCID to use. When omitted, the module provisions a master key."
  type        = string
  default     = null
}

variable "oci_secrets_region" {
  description = "Region TokenFactory should use for OCI Secrets access. Feeds TOKEN_FACTORY_OCI_REGION."
  type        = string
  default     = null
}

variable "oci_private_key_secret_existing_ocid" {
  description = "Existing OCI Secret OCID for private key PEM when jwt_key_material_source is existing_secret_ocids."
  type        = string
  default     = null
}

variable "oci_private_key_passphrase_secret_existing_ocid" {
  description = "Existing OCI Secret OCID for private-key passphrase."
  type        = string
  default     = null
}

variable "oci_certificate_secret_existing_ocid" {
  description = "Existing OCI Secret OCID for certificate PEM when jwt_key_material_source is existing_secret_ocids."
  type        = string
  default     = null
}

variable "jwt_private_key_pem" {
  description = "Caller-provided JWT signing private key PEM when jwt_key_material_source is provided_pem."
  type        = string
  default     = null
  sensitive   = true
}

variable "jwt_private_key_passphrase" {
  description = "Optional passphrase for the JWT signing private key."
  type        = string
  default     = null
  sensitive   = true
}

variable "jwt_certificate_pem" {
  description = "Caller-provided X.509 certificate PEM when jwt_key_material_source is provided_pem."
  type        = string
  default     = null
  sensitive   = true
}

variable "jwt_certificate_pem_for_identity_domain" {
  description = "Public X.509 certificate PEM used to configure Identity Domains when jwt_key_material_source is existing_secret_ocids."
  type        = string
  default     = null
}

variable "token_factory_client_display_name" {
  description = "Display name for the generated confidential OAuth app client."
  type        = string
  default     = "token-factory-client"
}

variable "token_factory_client_description" {
  description = "Description for the generated confidential OAuth app client."
  type        = string
  default     = "Token Factory confidential OAuth client."
}

variable "token_factory_runtime_iam_auth_mode" {
  description = "Runtime OCI authentication mode. Valid values: instance-principal, resource-principal, oci-profile."
  type        = string
  default     = "instance-principal"

  validation {
    condition     = contains(["instance-principal", "resource-principal", "oci-profile"], var.token_factory_runtime_iam_auth_mode)
    error_message = "VALIDATION FAILURE: token_factory_runtime_iam_auth_mode must be one of instance-principal, resource-principal, or oci-profile."
  }
}

variable "token_factory_runtime_iam_principal_type" {
  description = "Runtime principal type. Valid values: compute-instance, oci-function, oke-cluster, user-group."
  type        = string
  default     = "compute-instance"

  validation {
    condition     = contains(["compute-instance", "oci-function", "oke-cluster", "user-group"], var.token_factory_runtime_iam_principal_type)
    error_message = "VALIDATION FAILURE: token_factory_runtime_iam_principal_type must be one of compute-instance, oci-function, oke-cluster, or user-group."
  }
}

variable "token_factory_runtime_compartment_ocid" {
  description = "Compartment used by generated runtime IAM matching rules."
  type        = string
  default     = null
}

variable "token_factory_runtime_resource_ocid" {
  description = "Optional OCID restricting the generated runtime IAM rule to one compute instance, OKE cluster, or OCI Function."
  type        = string
  default     = null
}

variable "restrict_secret_policy_to_secret_ocids" {
  description = "When true, generated Vault read policies include where clauses for individual secret OCIDs."
  type        = bool
  default     = false
}
