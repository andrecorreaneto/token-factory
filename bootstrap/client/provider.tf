provider "oci" {
  region = trimspace(coalesce(var.region, var.identity_domain_region))

  tenancy_ocid         = trimspace(var.tenancy_ocid)
  user_ocid            = var.user_ocid == null ? null : trimspace(var.user_ocid)
  fingerprint          = var.fingerprint == null ? null : trimspace(var.fingerprint)
  private_key_path     = var.private_key_path == null ? null : trimspace(var.private_key_path)
  private_key_password = var.private_key_password

  ignore_defined_tags = ["Oracle-Tags.CreatedBy", "Oracle-Tags.CreatedOn"]
}

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    oci = {
      source                = "oracle/oci"
      configuration_aliases = [oci.home]
    }
    tls = {
      source  = "hashicorp/tls"
    }
  }
}