import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BootstrapDatabaseBoundaryTests(unittest.TestCase):
    def test_database_access_is_guidance_not_database_sql(self):
        terraform = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "bootstrap").rglob("*.tf"))
        documentation = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "bootstrap").rglob("*.md"))

        self.assertNotIn("CREATE USER", terraform)
        self.assertNotIn("GRANT CREATE SESSION", terraform)
        self.assertNotIn("commands_to_enable_db_authentication", terraform)
        self.assertIn("database_configuration_required", terraform)
        self.assertIn("requirement_note", terraform)
        self.assertNotIn("CREATE USER", documentation)
        self.assertNotIn("GRANT CREATE SESSION", documentation)


class BootstrapKmsSigningContractTests(unittest.TestCase):
    def test_managed_and_external_signing_modes_are_complete(self):
        variables = (ROOT / "bootstrap" / "variables.tf").read_text(encoding="utf-8")
        key_material = (ROOT / "bootstrap" / "key_material.tf").read_text(encoding="utf-8")
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")
        identity_domain = (ROOT / "bootstrap" / "identity_domain.tf").read_text(encoding="utf-8")

        self.assertIn('contains(["BOOTSTRAP_MANAGED", "EXTERNALLY_MANAGED"]', variables)
        self.assertIn("signing_key_ocid", variables)
        self.assertIn("signing_key_version_ocid", variables)
        self.assertIn("signing_certificate_pem", variables)
        self.assertIn("signing_certificate_path", variables)
        self.assertNotIn("jwt_private_key_pem", variables)
        self.assertNotIn("private_key_secret_existing_ocid", variables)
        self.assertIn("for_each = local.managed_signing_components", key_material)
        self.assertIn('protection_mode          = "HSM"', key_material)
        self.assertIn("length    = 256", key_material)
        self.assertNotIn("length    = 2048", key_material)
        self.assertIn('protection_mode == "HSM"', key_material)
        self.assertIn("current_key_version", locals_text)
        self.assertIn("kms_key_id", locals_text)
        self.assertIn("kms_key_version_id", locals_text)
        self.assertIn("kms_crypto_endpoint", locals_text)
        self.assertIn("external_signing_components", identity_domain)
        self.assertNotIn("for_each = var.oauth_apps", identity_domain.split('resource "oci_identity_domains_oauth_partner_certificate" "these"', 1)[1].split("}", 1)[0])

    def test_certificate_utility_is_wired_into_managed_bootstrap(self):
        key_material = (ROOT / "bootstrap" / "key_material.tf").read_text(encoding="utf-8")
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")
        utility = (ROOT / "scripts" / "register_kms_certificate.py").read_text(encoding="utf-8")

        self.assertIn('resource "terraform_data" "managed_certificate_registration"', key_material)
        self.assertEqual(key_material.count('command     = "${var.certificate_registration_python_command} scripts/register_kms_certificate.py --from-env"'), 3)
        self.assertEqual(key_material.count('working_dir = abspath("${path.module}/..")'), 3)
        self.assertEqual(key_material.count("environment = merge(local.certificate_registration_oci_environment"), 3)
        self.assertNotIn('\"${path.module}/../scripts/register_kms_certificate.py\"', key_material)
        self.assertIn("TF_CERT_OCI_TENANCY_OCID", locals_text)
        self.assertIn("TF_CERT_OCI_USER_OCID", locals_text)
        self.assertIn("TF_CERT_OCI_FINGERPRINT", locals_text)
        self.assertIn("TF_CERT_OCI_PRIVATE_KEY_PATH", locals_text)
        self.assertIn("TF_CERT_OCI_PRIVATE_KEY_PASSWORD", locals_text)
        self.assertIn("TF_CERT_OCI_REGION", locals_text)
        self.assertIn("KmsCryptoClient", utility)
        self.assertIn("IdentityDomainsClient", utility)
        self.assertIn("get_key_version", utility)
        self.assertIn("public key does not match", utility)
        self.assertNotIn("OCI_IDENTITY_DOMAINS_ACCESS_TOKEN", utility)
        self.assertNotIn("requests.get", utility)

    def test_client_credentials_are_redacted_from_terraform_plans(self):
        vault = (ROOT / "bootstrap" / "vault.tf").read_text(encoding="utf-8")

        self.assertIn("content      = sensitive(base64encode(local.client_credentials[each.key]))", vault)

    def test_runtime_key_access_is_constrained_to_selected_key_and_identity(self):
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")

        self.assertIn("target.key.id = '${local.signing_key_ids[key]}'", locals_text)
        self.assertIn("in compartment id ${local.signing_key_compartment_ids[key]}", locals_text)
        self.assertIn("request.principal.type = 'workload'", locals_text)
        self.assertIn("request.principal.cluster_id", locals_text)
        self.assertIn("request.principal.namespace", locals_text)
        self.assertIn("request.principal.service_account", locals_text)
        self.assertNotIn("to use keys in compartment id ${var.oci_secrets_compartment_ocid}\"", locals_text)

    def test_scope_consuming_apps_wait_for_scope_independent_apps(self):
        identity_domain = (ROOT / "bootstrap" / "identity_domain.tf").read_text(encoding="utf-8")
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")

        self.assertIn("identity_domain_scope_independent_apps", locals_text)
        self.assertIn("identity_domain_scope_consuming_apps", locals_text)
        self.assertIn('resource "oci_identity_domains_app" "scope_consumers"', identity_domain)
        self.assertIn("depends_on = [oci_identity_domains_app.these]", identity_domain)
        self.assertIn("identity_domain_apps = merge(oci_identity_domains_app.these, oci_identity_domains_app.scope_consumers)", locals_text)


class BootstrapAllowedClientContractTests(unittest.TestCase):
    def test_allowed_clients_are_oauth_app_keys_resolved_to_client_ids(self):
        variables = (ROOT / "bootstrap" / "variables.tf").read_text(encoding="utf-8")
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")

        self.assertIn("allowed_clients      = optional(list(string), null)", variables)
        self.assertIn("contains(keys(var.oauth_apps), caller)", variables)
        self.assertIn("[for caller in component.allowed_clients : local.identity_domain_apps[caller].name]", locals_text)

    def test_allowed_client_ids_reach_runtime_config_and_exports(self):
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")
        client_outputs = (ROOT / "bootstrap" / "client" / "outputs.tf").read_text(encoding="utf-8")
        resolution = (ROOT / "_oauth_client_resolution.py").read_text(encoding="utf-8")

        self.assertIn("allowed_client_ids             = local.allowed_client_ids[key]", locals_text)
        self.assertIn('lookup(config.oauth_client_config, "allowed_client_ids", null)', client_outputs)
        self.assertIn("TF_CLIENT_ALLOWED_CLIENT_IDS", client_outputs)
        self.assertIn("allowed_client_ids: Optional[List[str]] = None", resolution)

    def test_allowed_client_ids_feed_outputs_only_so_apps_cannot_form_a_cycle(self):
        # The allow-list reads every app's client ID; any resource reading it back would create a cycle.
        for path in (ROOT / "bootstrap").glob("*.tf"):
            if path.name in ("locals.tf", "outputs.tf", "variables.tf"):
                continue
            text = path.read_text(encoding="utf-8")
            for name in ("allowed_client", "oauth_app_configs", "token_factory_client_configs"):
                self.assertNotIn(name, text, f"{path.name} must not read {name}")


class BootstrapRuntimeShapeTests(unittest.TestCase):
    def test_identity_domain_runtime_inputs_remain_base_url_and_regions(self):
        variables = (ROOT / "bootstrap" / "variables.tf").read_text(encoding="utf-8")
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")

        self.assertIn('variable "identity_domain_url"', variables)
        self.assertIn('variable "identity_domain_region"', variables)
        self.assertIn('variable "region"', variables)
        self.assertIn("TF_SHARED_DOMAIN_URL                  = var.identity_domain_url", locals_text)
        self.assertIn("TF_SHARED_DOMAIN_REGION               = var.identity_domain_region", locals_text)
        self.assertIn("TF_SHARED_OCI_REGION       = local.provider_region", locals_text)
        for forbidden in ("TF_SHARED_TOKEN_ENDPOINT", "TF_SHARED_INTROSPECTION_ENDPOINT", "TF_SHARED_JWKS_URI", "TF_SHARED_IDENTITY_DOMAIN_ISSUER"):
            self.assertNotIn(forbidden, variables)
            self.assertNotIn(forbidden, locals_text)

    def test_runtime_uses_exactly_one_typed_object(self):
        variables = (ROOT / "bootstrap" / "variables.tf").read_text(encoding="utf-8")
        template = (ROOT / "bootstrap" / "client" / "terraform.tfvars.template").read_text(encoding="utf-8")
        client_variables = (ROOT / "bootstrap" / "client" / "variables.tf").read_text(encoding="utf-8")

        for name in ("compute_runtime", "function_runtime", "oke_runtime", "local_runtime"):
            self.assertIn(f"{name} = optional(object", variables)
        self.assertNotIn("runtime = object", variables)
        self.assertNotIn("principal_type", variables)
        self.assertIn("Exactly one of compute_runtime, function_runtime, oke_runtime, or local_runtime", variables)
        self.assertIn("compute_runtime = {", template)
        self.assertNotIn("principal_type", template)
        self.assertIn("database_access = {", template)
        self.assertNotIn("validation {", client_variables)

    def test_resource_names_default_to_oauth_display_name(self):
        locals_text = (ROOT / "bootstrap" / "locals.tf").read_text(encoding="utf-8")

        self.assertIn("coalesce(component.resource_name_prefix, component.display_name)", locals_text)
        self.assertNotIn("coalesce(component.resource_name_prefix, key)", locals_text)


if __name__ == "__main__":
    unittest.main()
