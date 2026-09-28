## Advanced Scenarios

TokenFactory signs hosting-application JWT assertions only through OCI KMS. `OAuthClientInfo` accepts the exact key OCID, key-version OCID, cryptographic endpoint, and `kid`; hosting private-key PEM is not supported.

```python
from token_factory import OAuthClientInfo, TokenFactory, TokenFactoryRuntimeConfig

runtime_config = TokenFactoryRuntimeConfig(domain_url="https://<domain>.identity.oraclecloud.com:443", domain_region="us-chicago-1", oci_auth_mode="instance-principal", oci_region="us-chicago-1")
oauth_apps = {
    "orders-api": OAuthClientInfo(
        client_credentials_secret_ocid="ocid1.vaultsecret.oc1..<client-credentials>",
        issuer="https://orders-api.example.com/token-factory",
        kid="orders-api-kms-v1",
        kms_key_id="ocid1.key.oc1..<key>",
        kms_key_version_id="ocid1.keyversion.oc1..<version>",
        kms_crypto_endpoint="https://<vault>-crypto.kms.us-chicago-1.oraclecloud.com",
        resource_audiences=["orders-api"],
        required_incoming_scopes=["orders-api.invoke"],
    )
}
factory = TokenFactory(runtime_config=runtime_config, oauth_apps=oauth_apps)
result = factory.get_token("<incoming-caller-access-token>", "oauth", "urn:opc:idm:orders.read", client_key="orders-api")
```

OAuth client credentials may still be supplied directly for controlled local testing. KMS signing remains mandatory for assertion-backed OAuth, Oracle Database, and OCI-service flows.

`get_token_with_oci_credential()` remains independent of hosting-app KMS signing. Oracle Database session key pairs also remain ephemeral output material and are not hosting signing keys.
