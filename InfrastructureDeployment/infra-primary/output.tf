output "resource_group" {
  value = data.azurerm_resource_group.infra-primary.name
}

output "enabled_aks_cluster" {
  value = local.detailed_enabled_aks_cluster
}

#output "databrick_vnet_id" {
#  value = azurerm_virtual_network.databrick.id
#}
#
#output "databrick_public_snet" {
#  value = azurerm_subnet.databrick["pub"].name
#}
#
#output "databrick_public_snet_nsg_association_id" {
#  value = azurerm_subnet_network_security_group_association.databrick["pub"].id
#}
#
#output "databrick_private_snet" {
#  value = azurerm_subnet.databrick["prv"].name
#}
#
#output "databrick_private_snet_nsg_association_id" {
#  value = azurerm_subnet_network_security_group_association.databrick["prv"].id
#}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.environment.id
}

output "environment_vnet" {
  value = azurerm_virtual_network.environment.name
}

output "environment_vnet_id" {
  value = azurerm_virtual_network.environment.id
}

output "environment_subnets" {
  value = { for snet in local.enable_snets : snet.name => azurerm_subnet.environment[snet.name].name }
}

output "gateway_managed_identity_principal_id" {
  value = azurerm_user_assigned_identity.gateway.principal_id
}

#output "bastion_snet_name" {
#  value = azurerm_subnet.bastion["AzureBastionSubnet"].name
#}
#
#output "bastion_snet_id" {
#  value = azurerm_subnet.bastion["AzureBastionSubnet"].id
#}

output "account_id" {
  value = data.azurerm_client_config.current.client_id
}

output "recommendations" {
  value = data.azurerm_advisor_recommendations.ad-recommandations.recommendations
}