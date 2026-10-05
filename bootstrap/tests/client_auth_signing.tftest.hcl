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

mock_provider "oci" {
  alias = "home"
}

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
}

run "client_auth_defaults_to_assertion_key_and_kid" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
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
    condition     = oci_identity_domains_oauth_client_certificate.these["ORDERS"].certificate_alias == "orders-v1" && oci_identity_domains_oauth_client_certificate.these["ORDERS"].x509base64certificate == oci_identity_domains_oauth_partner_certificate.these["ORDERS"].x509base64certificate
    error_message = "Without client-auth inputs, the client certificate must reuse the assertion certificate and kid."
  }
  assert {
    condition     = [for certificate in oci_identity_domains_app.these["ORDERS"].certificates : certificate.cert_alias] == ["orders-v1"]
    error_message = "The app must reference the shared kid as its client certificate alias."
  }
  assert {
    condition     = length(setintersection(keys(output.clients_runtime_config["ORDERS"].oauth_client_config), ["client_auth_kid", "client_auth_kms_key_id", "client_auth_kms_key_version_id"])) == 0
    error_message = "No client-auth runtime config may be emitted when the assertion key is shared."
  }
  assert {
    condition     = length(oci_kms_key.client_auth) == 0 && length(oci_identity_policy.client_auth_signing_key) == 0 && output.provisioned_resources.oauth_apps["ORDERS"].client_auth_signing_key == null
    error_message = "No client-auth key resources may be created when the assertion key is shared."
  }
}

run "client_auth_kid_alone_renames_shared_certificate" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        client_auth_kid    = "orders-client-v1"
        resource_audiences = ["orders"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
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
    condition     = oci_identity_domains_oauth_client_certificate.these["ORDERS"].certificate_alias == "orders-client-v1" && oci_identity_domains_oauth_client_certificate.these["ORDERS"].x509base64certificate == "AA=="
    error_message = "client_auth_kid alone must rename the client certificate alias while keeping the assertion certificate."
  }
  assert {
    condition     = oci_identity_domains_oauth_partner_certificate.these["ORDERS"].certificate_alias == "orders-v1"
    error_message = "The partner certificate must keep the assertion kid."
  }
  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.client_auth_kid == "orders-client-v1" && !contains(keys(output.clients_runtime_config["ORDERS"].oauth_client_config), "client_auth_kms_key_id")
    error_message = "client_auth_kid alone must be emitted without client-auth key OCIDs."
  }
}

run "external_client_auth_key_uses_its_own_certificate_and_policy" {
  command = plan

  override_data {
    target = data.oci_kms_key.client_auth_external["ORDERS"]
    values = { id = "ocid1.key.oc1..client-auth", vault_id = "ocid1.vault.oc1..shared", compartment_id = "ocid1.compartment.oc1..client-keys", protection_mode = "HSM", key_shape = [{ algorithm = "RSA", length = 256 }] }
  }

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        client_auth_kid    = "orders-client-v1"
        resource_audiences = ["orders"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key = {
          mode                     = "EXTERNALLY_MANAGED"
          signing_key_ocid         = "ocid1.key.oc1..external"
          signing_key_version_ocid = "ocid1.keyversion.oc1..external"
          signing_certificate_pem  = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"
        }
        client_auth_signing_key = {
          mode                     = "EXTERNALLY_MANAGED"
          signing_key_ocid         = "ocid1.key.oc1..client-auth"
          signing_key_version_ocid = "ocid1.keyversion.oc1..client-auth"
          signing_certificate_pem  = "-----BEGIN CERTIFICATE-----\nBB==\n-----END CERTIFICATE-----"
        }
      }
    }
  }

  assert {
    condition     = oci_identity_domains_oauth_client_certificate.these["ORDERS"].x509base64certificate == "BB==" && oci_identity_domains_oauth_partner_certificate.these["ORDERS"].x509base64certificate == "AA=="
    error_message = "Client and partner certificates must carry different key material."
  }
  assert {
    condition     = oci_identity_domains_identity_propagation_trust.these["ORDERS"].public_certificate == "AA=="
    error_message = "IdentityPropagationTrust must stay on the assertion certificate."
  }
  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.client_auth_kms_key_id == "ocid1.key.oc1..client-auth" && output.clients_runtime_config["ORDERS"].oauth_client_config.client_auth_kms_key_version_id == "ocid1.keyversion.oc1..client-auth" && output.clients_runtime_config["ORDERS"].oauth_client_config.kms_key_id == "ocid1.key.oc1..external"
    error_message = "Both the assertion and client-auth key versions must be emitted."
  }
  assert {
    condition     = oci_identity_policy.client_auth_signing_key["ORDERS"].compartment_id == "ocid1.compartment.oc1..client-keys" && strcontains(oci_identity_policy.client_auth_signing_key["ORDERS"].statements[0], "target.key.id = 'ocid1.key.oc1..client-auth'")
    error_message = "The runtime must get a key-constrained use-keys policy for the client-auth key in its compartment."
  }
}

run "managed_client_auth_key_is_registered_by_the_certificate_utility" {
  command = plan

  override_resource {
    target          = oci_kms_key.client_auth["ORDERS"]
    override_during = plan
    values          = { id = "ocid1.key.oc1..managed-client-auth", current_key_version = "ocid1.keyversion.oc1..managed-client-auth", vault_id = "ocid1.vault.oc1..shared", protection_mode = "HSM" }
  }

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        client_auth_kid    = "orders-client-v1"
        resource_audiences = ["orders"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key = {
          mode = "BOOTSTRAP_MANAGED"
        }
        client_auth_signing_key = {
          mode = "BOOTSTRAP_MANAGED"
        }
      }
    }
  }

  assert {
    condition     = length(oci_identity_domains_oauth_client_certificate.these) == 0
    error_message = "Bootstrap-managed client-auth certificates are registered by the certificate utility, not the Terraform resource."
  }
  assert {
    condition     = terraform_data.managed_client_auth_certificate_registration["ORDERS"].triggers_replace[2] == "orders-client-v1"
    error_message = "The certificate utility must register the client-auth alias."
  }
  assert {
    condition     = [for certificate in oci_identity_domains_app.these["ORDERS"].certificates : certificate.cert_alias] == ["orders-client-v1"]
    error_message = "The app must reference the client-auth alias."
  }
  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.client_auth_kms_key_id == "ocid1.key.oc1..managed-client-auth" && output.clients_runtime_config["ORDERS"].oauth_client_config.kms_key_id == "ocid1.key.oc1..managed"
    error_message = "Managed assertion and client-auth keys must be distinct and both emitted."
  }
}

run "client_auth_key_requires_distinct_client_auth_kid" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key = {
          mode = "BOOTSTRAP_MANAGED"
        }
        client_auth_signing_key = {
          mode = "BOOTSTRAP_MANAGED"
        }
      }
    }
  }

  expect_failures = [var.oauth_apps]
}

run "client_auth_inputs_require_private_key_jwt" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name               = "orders"
        issuer                     = "https://orders.example.com"
        kid                        = "orders-v1"
        client_auth_kid            = "orders-client-v1"
        token_endpoint_auth_method = "client_secret_basic"
        resource_audiences         = ["orders"]
        compute_runtime            = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key = {
          mode = "BOOTSTRAP_MANAGED"
        }
      }
    }
  }

  expect_failures = [var.oauth_apps]
}
