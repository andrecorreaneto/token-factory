mock_provider "oci" {
  mock_data "oci_identity_regions" {
    defaults = { regions = [{ key = "IAD", name = "us-ashburn-1" }] }
  }
  mock_data "oci_identity_tenancy" {
    defaults = { home_region_key = "IAD" }
  }
  mock_data "oci_identity_domains" {
    defaults = {
      domains = [{ id = "ocid1.domain.oc1..test", display_name = "Default", type = "DEFAULT", url = "https://example.identity.oraclecloud.com", home_region_url = "https://example.identity.oraclecloud.com" }]
    }
  }
  mock_data "oci_kms_vault" {
    defaults = { id = "ocid1.vault.oc1..shared", management_endpoint = "https://management.example", crypto_endpoint = "https://crypto.example" }
  }
  mock_data "oci_kms_key" {
    defaults = { id = "ocid1.key.oc1..external", vault_id = "ocid1.vault.oc1..shared", compartment_id = "ocid1.compartment.oc1..keys", protection_mode = "HSM", key_shape = [{ algorithm = "RSA", length = 256 }] }
  }
  mock_data "oci_kms_key_version" {
    defaults = { id = "ocid1.keyversion.oc1..external", key_version_id = "ocid1.keyversion.oc1..external", public_key = "PUBLIC KEY" }
  }
  mock_resource "oci_kms_key" {
    override_during = plan
    defaults        = { id = "ocid1.key.oc1..managed", current_key_version = "ocid1.keyversion.oc1..managed", vault_id = "ocid1.vault.oc1..shared", protection_mode = "HSM" }
  }
}

run "managed_mode_emits_created_version_pinned_kms_config" {
  command = plan

  override_data {
    target = data.oci_identity_domains.selected
    values = {
      domains = [{ id = "ocid1.domain.oc1..test", display_name = "Default", type = "DEFAULT", url = "https://example.identity.oraclecloud.com", home_region_url = "https://example.identity.oraclecloud.com" }]
    }
  }

  variables {
    tenancy_ocid                 = "ocid1.tenancy.oc1..test"
    identity_domain_url          = "https://example.identity.oraclecloud.com"
    identity_domain_region       = "us-ashburn-1"
    enable_oci_secrets           = false
    oci_secrets_compartment_ocid = "ocid1.compartment.oc1..secrets"
    oci_vault_existing_ocid      = "ocid1.vault.oc1..shared"
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        compute_runtime = {
          instance_ocid = "ocid1.instance.oc1..orders"
        }
        signing_key = {
          mode = "BOOTSTRAP_MANAGED"
        }
      }
    }
  }

  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.kms_key_id == "ocid1.key.oc1..managed"
    error_message = "Managed signing key OCID was not emitted."
  }
  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.kms_key_version_id == "ocid1.keyversion.oc1..managed"
    error_message = "Managed signing key version OCID was not emitted."
  }
}

mock_provider "oci" {
  alias = "home"
}

run "external_mode_emits_version_pinned_kms_config" {
  command = plan

  override_data {
    target = data.oci_identity_domains.selected
    values = {
      domains = [{ id = "ocid1.domain.oc1..test", display_name = "Default", type = "DEFAULT", url = "https://example.identity.oraclecloud.com", home_region_url = "https://example.identity.oraclecloud.com" }]
    }
  }

  variables {
    tenancy_ocid                 = "ocid1.tenancy.oc1..test"
    identity_domain_url          = "https://example.identity.oraclecloud.com"
    identity_domain_region       = "us-ashburn-1"
    enable_oci_secrets           = false
    oci_secrets_compartment_ocid = "ocid1.compartment.oc1..secrets"
    oci_vault_existing_ocid      = "ocid1.vault.oc1..shared"
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        compute_runtime = {
          instance_ocid = "ocid1.instance.oc1..orders"
        }
        signing_key = {
          mode                     = "EXTERNALLY_MANAGED"
          signing_key_ocid         = "ocid1.key.oc1..external"
          signing_key_version_ocid = "ocid1.keyversion.oc1..external"
          signing_certificate_pem  = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
        }
      }
    }
  }

  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.kms_key_id == "ocid1.key.oc1..external"
    error_message = "External signing key OCID was not emitted."
  }
  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.kms_key_version_id == "ocid1.keyversion.oc1..external"
    error_message = "External signing key version OCID was not emitted."
  }
  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.kms_crypto_endpoint == "https://crypto.example"
    error_message = "Shared Vault cryptographic endpoint was not emitted."
  }
}

run "oke_key_policy_is_workload_and_key_constrained" {
  command = plan

  override_data {
    target = data.oci_identity_domains.selected
    values = {
      domains = [{ id = "ocid1.domain.oc1..test", display_name = "Default", type = "DEFAULT", url = "https://example.identity.oraclecloud.com", home_region_url = "https://example.identity.oraclecloud.com" }]
    }
  }

  variables {
    tenancy_ocid                 = "ocid1.tenancy.oc1..test"
    identity_domain_url          = "https://example.identity.oraclecloud.com"
    identity_domain_region       = "us-ashburn-1"
    enable_oci_secrets           = false
    oci_secrets_compartment_ocid = "ocid1.compartment.oc1..secrets"
    oci_vault_existing_ocid      = "ocid1.vault.oc1..shared"
    output_provisioned_resources = true
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        oke_runtime = {
          cluster_ocid    = "ocid1.cluster.oc1..orders"
          namespace       = "orders"
          service_account = "orders-service"
        }
        signing_key = {
          mode                     = "EXTERNALLY_MANAGED"
          signing_key_ocid         = "ocid1.key.oc1..external"
          signing_key_version_ocid = "ocid1.keyversion.oc1..external"
          signing_certificate_pem  = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
        }
      }
    }
  }

  assert {
    condition = alltrue([
      for expected in [
        "allow any-user to use keys",
        "request.principal.type = 'workload'",
        "request.principal.cluster_id = 'ocid1.cluster.oc1..orders'",
        "request.principal.namespace = 'orders'",
        "request.principal.service_account = 'orders-service'",
        "target.key.id = 'ocid1.key.oc1..external'",
      ] : strcontains(output.provisioned_resources.oauth_apps["ORDERS"].signing_key.access_policy.statements[0], expected)
    ])
    error_message = "OKE signing-key policy was not constrained to the workload tuple and selected key."
  }
  assert {
    condition     = output.provisioned_resources.oauth_apps["ORDERS"].runtime_principal.principal_kind == "any-user" && output.provisioned_resources.oauth_apps["ORDERS"].runtime_principal.matching_rule == null
    error_message = "OKE workload identity must not create or reference a dynamic group."
  }
}
