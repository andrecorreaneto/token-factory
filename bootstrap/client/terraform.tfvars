tenancy_ocid         = "ocid1.tenancy.oc1..aaaaaaaahbsqqoq6hngruus5z4e3zclij32obawvlsxsrz4culbvq5k5p2ia"
user_ocid            = "ocid1.user.oc1..aaaaaaaai27yv6a7jyl4qkmkgudtspxfm65imcevxoed4rvslposjsnpqvqa" # tenancy admin
fingerprint          = "19:42:ef:92:39:b3:40:2f:34:ea:9d:59:86:be:02:ba"
private_key_path     = "C:\\Users\\AXCORRE\\work\\code\\creds\\cislzteam\\tenancy-admin_cislzteam.pem"
private_key_password = ""
region               = "us-chicago-1"

identity_domain_url    = "https://idcs-1a15d6dbb17047d5a4a61c6bf5e414d8.identity.oraclecloud.com:443"
identity_domain_region = "us-chicago-1"

oci_secrets_compartment_ocid = "ocid1.compartment.oc1..aaaaaaaabhvxbtv7mupf6ubxk4yeh3efwvi6bneo2i3e3izhacumxbcuez4q" # dbsec-security-cmp
oci_vault_existing_ocid      = "ocid1.vault.oc1.us-chicago-1.ijvbbqwoaabsa.abxxeljsmgyhzgxfa73nfzrv2paidfshum6gqcg5f6msyvtxc2nuu7uejnga"
oci_master_key_existing_ocid = "ocid1.key.oc1.us-chicago-1.ijvbbqwoaabsa.abxxeljs2pb7sjrvyeu3zgcn4no2z5vm7kr3vcfq7ixzj7wmdixcv5kmypda"
output_provisioned_resources = false

oauth_apps = {
  PLAYGROUND-MCP-SERVER = {
    display_name       = "playground-mcp-server"
    description        = "Playground MCP server application"
    issuer             = "https://playground.mcp.server/"
    kid                = "playground-mcp-server-cert"
    resource_audiences = ["https://playground.mcp.server/"]
    resource_scopes    = ["tools.get_user_info", "tools.search_employees", "tools.get_oci_resources", "tools.get_stock_quote", "tools.calculator"]
    app_roles          = ["Me"]

    runtime = {
      principal_type   = "compute-instance"
      compartment_ocid = "ocid1.compartment.oc1..aaaaaaaabcha3jpddse2n5m7cp7atko3wwnvqoahfc36nslzysylchpauf2a" # dbsec-app-cmp
      resource_ocid    = null
    }

    enable_identity_propagation_trust = true

    jwt_key_material_source = "generate"
  }

  PLAYGROUND-AGENT = {
    display_name       = "playground-agent"
    description        = "Playground agent application"
    issuer             = "https://playground.agent/"
    kid                = "playground-agent-cert"
    resource_audiences = ["https://playground.agent/"]
    resource_scopes    = ["invoke"]
    allowed_scopes     = ["https://playground.mcp.server/tools.get_user_info","https://playground.mcp.server/tools.search_employees", "https://playground.mcp.server/tools.get_oci_resources", "https://playground.mcp.server/tools.get_stock_quote", "https://playground.mcp.server/tools.calculator"]
    app_roles          = ["Me"]

    runtime = {
      principal_type   = "compute-instance"
      compartment_ocid = "ocid1.compartment.oc1..aaaaaaaabcha3jpddse2n5m7cp7atko3wwnvqoahfc36nslzysylchpauf2a" # dbsec-app-cmp
      resource_ocid    = null
    }

    enable_identity_propagation_trust = false

    jwt_key_material_source = "generate"
  }
}
