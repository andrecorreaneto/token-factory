# TokenFactory OCI Workload Usage

Each hosting application receives version-pinned KMS signing metadata from `clients_runtime_config[<client_key>].oauth_client_config`. The runtime principal needs `use keys` on only that app's signing key and `read secret-bundles` only for its client-credential and authorization-policy Secrets.

```python
factory = TokenFactory(oauth_apps={
    "orders-api": {
        "client_credentials_secret_ocid": "ocid1.vaultsecret.oc1..<orders-creds>",
        "issuer": "https://orders.example.com/",
        "kid": "orders-kms-v1",
        "kms_key_id": "ocid1.key.oc1..<key>",
        "kms_key_version_id": "ocid1.keyversion.oc1..<version>",
        "kms_crypto_endpoint": "https://<vault>-crypto.kms.us-chicago-1.oraclecloud.com",
        "resource_audiences": ["orders-api"],
        "required_incoming_scopes": ["orders-api.invoke"],
    }
})
result = factory.get_token(incoming_access_token, "oauth", "urn:opc:idm:orders.read", client_key="orders-api")
```

Compute uses an exact instance principal, Functions use an exact resource principal, and OKE uses workload identity constrained by cluster, namespace, and service account. Local profile mode is supported but discouraged for OCI-hosted workloads.

For `BOOTSTRAP_MANAGED`, Terraform creates the RSA KMS key and invokes the certificate registrar. The Terraform runner identity must have OCI KMS and Identity Domains access, and the selected Python interpreter must have `asn1crypto` installed through `requirements.txt`.

For `EXTERNALLY_MANAGED`, provide the exact key and key-version OCIDs plus one public certificate PEM or path. Bootstrap verifies the certificate public key against the selected KMS key version before registering it.
