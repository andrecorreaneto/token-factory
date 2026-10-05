mock_provider "oci" {
  mock_data "oci_identity_regions" {
    defaults = { regions = [{ key = "IAD", name = "us-ashburn-1" }] }
  }
  mock_data "oci_identity_tenancy" {
    defaults = { home_region_key = "IAD" }
  }
  mock_data "oci_kms_vault" {
    defaults = { id = "ocid1.vault.oc1..shared", management_endpoint = "https://management.example", crypto_endpoint = "https://crypto.example" }
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

override_resource {
  target          = oci_identity_domains_app.these["AGENT"]
  override_during = plan
  values          = { name = "agent-client-id" }
}

override_resource {
  target          = oci_identity_domains_app.these["ORDERS"]
  override_during = plan
  values          = { name = "orders-client-id" }
}

variables {
  tenancy_ocid                 = "ocid1.tenancy.oc1..test"
  identity_domain_url          = "https://example.identity.oraclecloud.com"
  identity_domain_region       = "us-ashburn-1"
  enable_oci_secrets           = false
  oci_secrets_compartment_ocid = "ocid1.compartment.oc1..secrets"
  oci_vault_existing_ocid      = "ocid1.vault.oc1..shared"
}

run "allowed_clients_resolve_to_client_ids" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        allowed_clients    = ["AGENT"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key        = { mode = "BOOTSTRAP_MANAGED" }
      }
      AGENT = {
        display_name       = "agent"
        issuer             = "https://agent.example.com"
        kid                = "agent-v1"
        resource_audiences = ["agent"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..agent" }
        signing_key        = { mode = "BOOTSTRAP_MANAGED" }
      }
    }
  }

  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.allowed_client_ids == ["agent-client-id"]
    error_message = "allowed_clients must resolve oauth_apps keys to their Identity Domain client IDs."
  }
  assert {
    condition     = !contains(keys(output.clients_runtime_config["AGENT"].oauth_client_config), "allowed_client_ids")
    error_message = "Apps without allowed_clients must not emit a caller allow-list, so the runtime check stays off."
  }
}

run "empty_allowed_clients_keeps_the_check_on_for_self_only" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        allowed_clients    = []
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key        = { mode = "BOOTSTRAP_MANAGED" }
      }
    }
  }

  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.allowed_client_ids == []
    error_message = "An empty allowed_clients list must be emitted so the runtime accepts only the app itself."
  }
}

run "allowed_clients_reject_unknown_keys" {
  command = plan

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["orders"]
        allowed_clients    = ["0df25252bc99480ab67be944cf5d14bf"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key        = { mode = "BOOTSTRAP_MANAGED" }
      }
    }
  }

  expect_failures = [var.oauth_apps]
}

run "mutual_allowed_clients_across_app_resources_plan_without_cycles" {
  command = plan

  override_resource {
    target          = oci_identity_domains_app.scope_consumers["AGENT"]
    override_during = plan
    values          = { name = "agent-client-id" }
  }

  variables {
    oauth_apps = {
      ORDERS = {
        display_name       = "orders"
        issuer             = "https://orders.example.com"
        kid                = "orders-v1"
        resource_audiences = ["https://orders.example.com/"]
        resource_scopes    = ["invoke"]
        allowed_clients    = ["AGENT", "ORDERS"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..orders" }
        signing_key        = { mode = "BOOTSTRAP_MANAGED" }
      }
      AGENT = {
        display_name       = "agent"
        issuer             = "https://agent.example.com"
        kid                = "agent-v1"
        resource_audiences = ["https://agent.example.com/"]
        allowed_scopes     = ["https://orders.example.com/invoke"]
        allowed_clients    = ["ORDERS"]
        compute_runtime    = { instance_ocid = "ocid1.instance.oc1..agent" }
        signing_key        = { mode = "BOOTSTRAP_MANAGED" }
      }
    }
  }

  assert {
    condition     = output.clients_runtime_config["ORDERS"].oauth_client_config.allowed_client_ids == ["agent-client-id", "orders-client-id"]
    error_message = "A regular app must resolve a scope-consumer caller and itself."
  }
  assert {
    condition     = output.clients_runtime_config["AGENT"].oauth_client_config.allowed_client_ids == ["orders-client-id"]
    error_message = "A scope-consumer app must resolve a regular-app caller."
  }
}
