output "location_short" {
  value = local.regions[var.location]
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "state_resource_group" {
  value = data.azurerm_resource_group.terraform_state.name
}

output "state_storage_account" {
  value = data.azurerm_storage_account.terraform_state.name
}

output "state_container_name" {
  value = data.azurerm_storage_container.terraform_state.name
}

output "all_authorized_ip_ranges" {
  value = local.all_authorized_ip_ranges
}

#output "authorized_ip_ranges_extra" {
#  value = local.authorized_ip_ranges_extra
#}
#
#output "authorized_ip_ranges_zscaler" {
#  value = local.authorized_ip_ranges_zscaler
#}
#
#output "dns_ubiwhere_netmask" {
#  value = local.dns_ubiwhere_netmask
#}
#
#output "dns_ubiwhere" {
#  value = local.dns_ubiwhere
#}
