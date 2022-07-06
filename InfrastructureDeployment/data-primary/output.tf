output "resource_group" {
  value = data.azurerm_resource_group.data-primary.name
}

output "key_vault_id" {
  value = azurerm_key_vault.data-primary.id
}

#output "psql_server_name" {
#  value = azurerm_postgresql_server.bdp.name
#}
#
#output "psql_admin_user_key_vault_name" {
#  value = azurerm_key_vault_secret.pgsql_admin_user.name
#}
#
#output "psql_admin_pass_key_vault_name" {
#  value = azurerm_key_vault_secret.pgsql_admin_pass.name
#}
#
#output "bdp_account_id" {
#  value = azurerm_storage_account.bdp.id
#}
#
#output "bdp_account_name" {
#  value = azurerm_storage_account.bdp.name
#}
#
#output "bdp_container_name" {
#  value = azurerm_storage_container.bdp.name
#}

#output "bdp_data_factory_name" {
#  value = azurerm_data_factory.bdp.name
#}

#output "bdp_databrick_workspace_url" {
#  value = local.databrick_url
#}
#
#output "bdp_databrick_workspace_id" {
#  value = azurerm_databricks_workspace.bdp.id
#}
#
#output "redis_name" {
#  value = azurerm_redis_cache.environment.name
#}
#
#output "iot_storage_account_name" {
#  value = azurerm_storage_account.iot.name
#}
#
#output "iot_storage_container_name" {
#  value = azurerm_storage_container.iot.name
#}
#
#output "etib-control2_storage_account_name" {
#  value = azurerm_storage_account.etib-control2.name
#}
