
output "token_factory_config_env" {
  description = "Token Factory runtime configuration as newline-delimited shell export statements."
  value       = module.token_factory_bootstrap.token_factory_config_env
}

output "provisioned_resource_ids" {
  description = "OCIDs and IDs for resources managed or selected by the Token Factory bootstrap module."
  value       = module.token_factory_bootstrap.provisioned_resource_ids
}
