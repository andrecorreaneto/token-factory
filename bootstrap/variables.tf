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

variable "identity_domain_compartment_ocid" {
  description = "Compartment OCID of the provided Identity Domain."
  type        = string
  default     = null
}

variable "identity_domain_url" {
  description = "Identity Domain base URL."
  type        = string
}

variable "identity_domain_region" {
  description = "OCI region used by TokenFactory for token exchange and identity data plane calls."
  type        = string
}

variable "certificate_registration_python_command" {
  description = "Python command used by the bootstrap-managed KMS certificate registration utility."
  type        = string
  default     = "python"
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
  default     = "group"

  validation {
    condition     = trimspace(var.token_factory_groups_claim) != ""
    error_message = "token_factory_groups_claim must not be empty."
  }
}

variable "token_factory_log_full_assertion" {
  description = "When true, emits TF_SHARED_LOG_FULL_ASSERTION=true for each hosting runtime config."
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
  description = "When true, emits TF_SHARED_AUTHZ_POLICY_TENANT_ID using tenancy_ocid."
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

    compute_runtime = optional(object({
      instance_ocid = string
    }), null)
    function_runtime = optional(object({
      function_ocid = string
    }), null)
    oke_runtime = optional(object({
      cluster_ocid    = string
      namespace       = string
      service_account = string
    }), null)
    local_runtime = optional(object({
      oci_auth_profile = optional(string, "DEFAULT")
    }), null)
    database_access = optional(object({
      target_database_compartment_ocid = string
      target_database_ocid             = string
    }), null)

    enable_identity_propagation_trust = optional(bool, true)
    propagation_trust_claim_name      = optional(string, null)
    propagation_trust_claim_value     = optional(string, null)

    signing_key = object({
      mode                     = string
      signing_key_ocid         = optional(string, null)
      signing_key_version_ocid = optional(string, null)
      signing_certificate_pem  = optional(string, null)
      signing_certificate_path = optional(string, null)
    })
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
      can(regex("^[A-Za-z0-9._-]+$", component.kid)) &&
      length(component.resource_audiences) > 0
    ])
    error_message = "Each oauth_apps key must be non-empty and uppercase; display_name, issuer, and resource_audiences must be non-empty; kid must use only letters, digits, dot, underscore, and hyphen."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      length(compact([
        component.compute_runtime != null ? "compute" : null,
        component.function_runtime != null ? "function" : null,
        component.oke_runtime != null ? "oke" : null,
        component.local_runtime != null ? "local" : null,
      ])) == 1
    ])
    error_message = "Exactly one of compute_runtime, function_runtime, oke_runtime, or local_runtime must be configured for each oauth_apps entry."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      (component.compute_runtime == null || try(trimspace(component.compute_runtime.instance_ocid), "") != "") &&
      (component.function_runtime == null || try(trimspace(component.function_runtime.function_ocid), "") != "") &&
      (component.oke_runtime == null || (try(trimspace(component.oke_runtime.cluster_ocid), "") != "" && try(trimspace(component.oke_runtime.namespace), "") != "" && try(trimspace(component.oke_runtime.service_account), "") != "")) &&
      (component.local_runtime == null || try(trimspace(component.local_runtime.oci_auth_profile), "") != "")
    ])
    error_message = "Runtime identifiers and local_runtime.oci_auth_profile must not be empty."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      contains(["BOOTSTRAP_MANAGED", "EXTERNALLY_MANAGED"], component.signing_key.mode)
    ])
    error_message = "oauth_apps[*].signing_key.mode must be BOOTSTRAP_MANAGED or EXTERNALLY_MANAGED."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      component.signing_key.mode != "BOOTSTRAP_MANAGED" || (
        component.signing_key.signing_key_ocid == null &&
        component.signing_key.signing_certificate_pem == null &&
        component.signing_key.signing_certificate_path == null
      )
    ])
    error_message = "BOOTSTRAP_MANAGED signing keys must not provide a key OCID or certificate input; an explicitly rotated version OCID is allowed."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      component.signing_key.mode != "EXTERNALLY_MANAGED" || (
        try(trimspace(component.signing_key.signing_key_ocid), "") != "" &&
        try(trimspace(component.signing_key.signing_key_version_ocid), "") != "" &&
        (component.signing_key.signing_certificate_pem != null) != (component.signing_key.signing_certificate_path != null)
      )
    ])
    error_message = "EXTERNALLY_MANAGED signing keys require key OCID, exact key-version OCID, and exactly one certificate PEM or path."
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
    condition = alltrue([
      for component in var.oauth_apps :
      component.database_access == null ? true :
      trimspace(component.database_access.target_database_compartment_ocid) != ""
    ])
    error_message = "oauth_apps[*].database_access.target_database_compartment_ocid must not be empty."
  }

  validation {
    condition = alltrue([
      for component in var.oauth_apps :
      component.database_access == null ? true :
      trimspace(component.database_access.target_database_ocid) != ""
    ])
    error_message = "oauth_apps[*].database_access.target_database_ocid must not be empty."
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

variable "output_provisioned_resources" {
  description = "When true, outputs provisioned shared and OAuth app/runtime resources with names, OCIDs, policy statements, and database requirement guidance."
  type        = bool
  default     = false
}
