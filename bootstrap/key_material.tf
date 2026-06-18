resource "tls_private_key" "jwt" {
  count = local.create_generated_key_material ? 1 : 0

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "jwt" {
  count = local.create_generated_key_material ? 1 : 0

  private_key_pem = tls_private_key.jwt[0].private_key_pem

  subject {
    common_name  = "Token Factory"
    organization = "Token Factory"
  }

  validity_period_hours = 8760
  early_renewal_hours   = 720

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
  ]
}
