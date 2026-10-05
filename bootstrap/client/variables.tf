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

}

variable "token_factory_groups_claim" {
  description = "Claim name TokenFactory uses to extract groups for authorization."
  type        = string
  default     = "groups"

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
    allowed_clients      = optional(list(string), null)

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











}
