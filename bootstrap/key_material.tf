resource "tls_private_key" "these" {
  for_each = local.generated_key_material_components

  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "these" {
  for_each = local.generated_key_material_components

  private_key_pem = tls_private_key.these[each.key].private_key_pem

  subject {
    common_name  = each.value.display_name
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
