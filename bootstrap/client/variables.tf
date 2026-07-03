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
  description = "Prefix used for shared Token Factory resource names. Null or empty string falls back to token-factory."
  type        = string
  default     = "token-factory"
}

variable "identity_domain_url" {
  description = "Identity Domain base URL."
  type        = string
}

variable "identity_domain_region" {
  description = "OCI region used by TokenFactory for token exchange and identity data plane calls."
  type        = string
}

variable "enable_oci_secrets" {
  description = "When true, store OAuth app material in OCI Secrets and output secret OCIDs."
  type        = bool
  default     = true
}

variable "oci_secrets_compartment_ocid" {
  description = "Compartment for created or existing OCI Secrets and per-runtime secret-read policies."
  type        = string
  default     = null
}

variable "oci_vault_existing_ocid" {
  description = "Existing Vault OCID to use. When omitted and enable_oci_secrets is true, the module provisions a Vault."
  type        = string
  default     = null
}

variable "oci_master_key_existing_ocid" {
  description = "Existing Vault master encryption key OCID to use. When omitted and enable_oci_secrets is true, the module provisions a master key."
  type        = string
  default     = null
}

variable "oci_secrets_region" {
  description = "Fallback region TokenFactory should use for OCI Secrets access when an OAuth app runtime does not set runtime.oci_region."
  type        = string
  default     = null
}

variable "restrict_secret_policy_to_secret_ocids" {
  description = "When true, generated per-runtime Vault read policies include where clauses for individual secret OCIDs."
  type        = bool
  default     = false
}

variable "output_provisioned_resources" {
  description = "When true, output names and OCIDs for provisioned shared and OAuth app/runtime resources."
  type        = bool
  default     = false
}

variable "token_factory_timeout_seconds" {
  description = "TokenFactory HTTP timeout in seconds."
  type        = number
  default     = 30
}

variable "token_factory_subject_claim" {
  description = "Claim name TokenFactory uses to extract the validated end-user subject."
  type        = string
  default     = "sub"

  validation {
    condition     = trimspace(var.token_factory_subject_claim) != ""
    error_message = "token_factory_subject_claim must not be empty."
  }
}

variable "token_factory_groups_claim" {
  description = "Claim name TokenFactory uses to extract groups for authorization."
  type        = string
  default     = "groups"

  validation {
    condition     = trimspace(var.token_factory_groups_claim) != ""
    error_message = "token_factory_groups_claim must not be empty."
  }
}

variable "token_factory_log_full_assertion" {
  description = "When true, emits TOKEN_FACTORY_LOG_FULL_ASSERTION=true for each hosting runtime config."
  type        = bool
  default     = false
}

variable "token_factory_authz_policy_secret_ocid" {
  description = "Existing OCI Vault secret OCID containing the TokenFactory authorization policy JSON or signed policy envelope."
  type        = string
  default     = null
}

variable "token_factory_authz_policy_signature_mode" {
  description = "Authorization policy signature mode. Valid values: off, on."
  type        = string
  default     = "off"

  validation {
    condition     = contains(["off", "on"], var.token_factory_authz_policy_signature_mode)
    error_message = "token_factory_authz_policy_signature_mode must be one of off or on."
  }
}

variable "token_factory_authz_policy_trusted_signers" {
  description = "Trusted signer bundle for signed authorization policy envelopes. Required when token_factory_authz_policy_signature_mode is on."
  type = list(object({
    key_id         = string
    key_version_id = string
    algorithm      = string
    public_key_pem = string
  }))
  default = []
}

variable "token_factory_authz_policy_environment" {
  description = "Optional expected environment binding for signed authorization policy envelopes."
  type        = string
  default     = null
}

variable "emit_authz_policy_tenant_id" {
  description = "When true, emits TOKEN_FACTORY_AUTHZ_POLICY_TENANT_ID using tenancy_ocid."
  type        = bool
  default     = false
}

variable "oauth_apps" {
  description = "Hosting application OAuth apps used by TokenFactory. Map keys are the canonical CallerContext.client_key values."
  type = map(object({
    resource_name_prefix = optional(string, null)
    display_name         = string
    description          = optional(string, null)
    issuer               = string
    kid                  = string
    resource_audiences   = list(string)
    resource_scopes      = optional(list(string), [])
    allowed_scopes       = optional(list(string), [])
    app_roles            = optional(list(string), [])

    runtime = object({
      principal_type   = string
      compartment_ocid = string
      resource_ocid    = optional(string, null)
      oci_auth_profile = optional(string, null)
      oci_region       = optional(string, null)
    })

    enable_identity_propagation_trust = optional(bool, true)
    propagation_trust_claim_name      = optional(string, null)
    propagation_trust_claim_value     = optional(string, null)

    jwt_key_material_source = optional(string, "generate")

    jwt_private_key_pem                     = optional(string, null)
    jwt_private_key_passphrase              = optional(string, null)
    jwt_certificate_pem                     = optional(string, null)
    jwt_certificate_pem_for_identity_domain = optional(string, null)

    private_key_secret_existing_ocid            = optional(string, null)
    private_key_passphrase_secret_existing_ocid = optional(string, null)
    certificate_secret_existing_ocid            = optional(string, null)
  }))
  default = {}

  validation {
    condition = alltrue([
      for key, component in var.oauth_apps :
      trimspace(key) != "" &&
      key == upper(key) &&
      trimspace(component.display_name) != "" &&
      trimspace(component.issuer) != "" &&
      trimspace(component.kid) != "" &&
      length(component.resource_audiences) > 0
    ])
    error_message = "Each oauth_apps key must be non-empty and uppercase; display_name, issuer, kid, and resource_audiences must be non-empty."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      contains(["compute-instance", "oci-function", "oke-cluster", "user-group"], component.runtime.principal_type)
    ])
    error_message = "oauth_apps[*].runtime.principal_type must be one of compute-instance, oci-function, oke-cluster, or user-group."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      trimspace(component.runtime.compartment_ocid) != ""
    ])
    error_message = "oauth_apps[*].runtime.compartment_ocid must not be empty."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      contains(["generate", "provided_pem", "existing_secret_ocids"], component.jwt_key_material_source)
    ])
    error_message = "oauth_apps[*].jwt_key_material_source must be one of generate, provided_pem, or existing_secret_ocids."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      (component.propagation_trust_claim_name == null && component.propagation_trust_claim_value == null) ||
      (component.propagation_trust_claim_name != null && component.propagation_trust_claim_value != null)
    ])
    error_message = "oauth_apps[*].propagation_trust_claim_name and propagation_trust_claim_value must either both be set or both be omitted."
  }

  validation {
    condition = alltrue(flatten([
      for component in var.oauth_apps : [
        for scope in component.allowed_scopes :
        trimspace(scope) != ""
      ]
    ]))
    error_message = "oauth_apps[*].allowed_scopes values must not be empty."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      length(component.app_roles) == length(distinct(component.app_roles)) &&
      alltrue([
        for role in component.app_roles :
        trimspace(role) != "" &&
        contains([
          "Me",
          "Approval Workflow Administrator",
          "Identity Domain Administrator",
          "Reset Password",
          "User Manager",
          "User Administrator",
          "Kerberos Administrator",
          "Verify Email",
          "Change Password",
          "Posix Viewer",
          "DB Administrator",
          "Me Password Validator",
          "Digitalid Wallet",
          "Digitalid Verifier",
          "Digitalid Issuer",
          "Digitalid Admin",
          "Help Desk Administrator",
          "Audit Administrator",
          "MFA Client",
          "Security Administrator",
          "Authenticator Client",
          "Self Registration",
          "Cloud Gate",
          "Forgot Password",
          "Signin",
          "Application Administrator"
        ], role)
      ])
    ])
    error_message = "oauth_apps[*].app_roles must contain unique supported Identity Domain app role display names."
  }
}
