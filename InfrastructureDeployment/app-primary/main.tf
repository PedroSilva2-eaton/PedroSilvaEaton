provider "azurerm" {
  features {
    # so it doesn't purge them in key vault when deleting it from terraform
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

data "azurerm_resource_group" "app-primary" {
  name = "ETN-ES-DERMS-ContainerOrchestration"
  #  name = "ETN-ES-DERMS-App-Primary"
}

locals {
  common_naming                         = "${var.environment}-${data.terraform_remote_state.ado-automation.outputs.location_short}-${var.environment_qualifier}"
  infra_primary_resource_group          = data.terraform_remote_state.infra-primary.outputs.resource_group
  enabled_aks_cluster                   = data.terraform_remote_state.infra-primary.outputs.enabled_aks_cluster
  all_authorized_ip_ranges              = data.terraform_remote_state.ado-automation.outputs.all_authorized_ip_ranges
  environment_vnet_name                 = data.terraform_remote_state.infra-primary.outputs.environment_vnet
  environment_vnet_resource_group       = data.terraform_remote_state.infra-primary.outputs.resource_group
  environment_subnets                   = data.terraform_remote_state.infra-primary.outputs.environment_subnets
  gateway_managed_identity_principal_id = data.terraform_remote_state.infra-primary.outputs.gateway_managed_identity_principal_id
}

data "azurerm_resource_group" "infra-primary" {
  name = data.terraform_remote_state.infra-primary.outputs.resource_group
}

data "azurerm_subnet" "environment" {
  for_each             = local.environment_subnets
  name                 = each.value
  virtual_network_name = local.environment_vnet_name
  resource_group_name  = local.environment_vnet_resource_group
}

# aks blue/green deployment

resource "azurerm_key_vault" "aks" {
  name                       = "kv-${var.project_naming_convention}-aks-${local.common_naming}01"
  resource_group_name        = data.azurerm_resource_group.app-primary.name
  location                   = data.azurerm_resource_group.app-primary.location
  tenant_id                  = data.terraform_remote_state.ado-automation.outputs.tenant_id
  soft_delete_retention_days = 90 # The retention period must be kept at 90 days, the default value, as the Application Gateway doesn't support a different retention period yet
  purge_protection_enabled   = true
  sku_name                   = "standard"

  network_acls {
    default_action = "Allow"
    #    ip_rules       = local.all_authorized_ip_ranges
    bypass = "AzureServices"
  }
}

data "azurerm_monitor_diagnostic_categories" "kv_aks" {
  resource_id = azurerm_key_vault.aks.id
}

resource "azurerm_monitor_diagnostic_setting" "kv_aks" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_key_vault.aks.id
  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_aks.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_aks.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_private_endpoint" "kv_aks" {
  name                = "pe-${azurerm_key_vault.aks.name}"
  location            = data.azurerm_resource_group.app-primary.location
  resource_group_name = local.infra_primary_resource_group
  subnet_id           = data.azurerm_subnet.environment["keyvault"].id

  private_service_connection {
    name                           = azurerm_key_vault.aks.name
    private_connection_resource_id = azurerm_key_vault.aks.id
    is_manual_connection           = false
    subresource_names              = ["Vault"]
  }
}

resource "azurerm_key_vault_access_policy" "azure_devops_service_connection" {
  key_vault_id = azurerm_key_vault.aks.id
  tenant_id    = data.terraform_remote_state.ado-automation.outputs.tenant_id
  object_id    = var.azure_devops_service_principal_object_id
  key_permissions = [
    "backup",
    "create",
    "decrypt",
    "delete",
    "encrypt",
    "get",
    "import",
    "list",
    "purge",
    "recover",
    "restore",
    "sign",
    "unwrapKey",
    "update",
    "verify",
    "wrapKey"
  ]
  secret_permissions = [
    "backup",
    "delete",
    "get",
    "list",
    "purge",
    "recover",
    "restore",
    "set"
  ]
  certificate_permissions = [
    "backup",
    "create",
    "delete",
    "get",
    "import",
    "list",
    "purge",
    "recover",
    "restore",
    "update"
  ]
  storage_permissions = [
    "backup",
    "delete",
    "deletesas",
    "get",
    "getsas",
    "list",
    "listsas",
    "purge",
    "recover",
    "regeneratekey",
    "restore",
    "set",
    "setsas",
    "update"
  ]
}

resource "tls_private_key" "aks" {
  for_each  = { for aks in local.enabled_aks_cluster : aks.name => aks }
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "azurerm_key_vault_secret" "aks_node_ssh_admin_user" {
  for_each     = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name         = "aks-${var.project_naming_convention}-${each.value.name}-${local.common_naming}01-ssh-admin-user"
  value        = var.project_naming_convention
  key_vault_id = azurerm_key_vault.aks.id
  depends_on = [
    azurerm_key_vault_access_policy.azure_devops_service_connection
  ]
}

resource "azurerm_key_vault_secret" "aks_node_private_ssh_key" {
  for_each     = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name         = "aks-${var.project_naming_convention}-${each.value.name}-${local.common_naming}01-ssh-priv-key"
  value        = tls_private_key.aks[each.value.name].private_key_pem
  key_vault_id = azurerm_key_vault.aks.id
  depends_on = [
    azurerm_key_vault_access_policy.azure_devops_service_connection
  ]
}

resource "azurerm_key_vault_secret" "aks_node_public_ssh_key" {
  for_each     = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name         = "aks-${var.project_naming_convention}-${each.value.name}-${local.common_naming}01-ssh-pub-key"
  value        = tls_private_key.aks[each.value.name].public_key_pem
  key_vault_id = azurerm_key_vault.aks.id
  depends_on = [
    azurerm_key_vault_access_policy.azure_devops_service_connection
  ]
}

resource "azurerm_key_vault_secret" "aks_node_public_key_openssh" {
  for_each     = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name         = "aks-${var.project_naming_convention}-${each.value.name}-${local.common_naming}01-pub-key-openssh"
  value        = tls_private_key.aks[each.value.name].public_key_openssh
  key_vault_id = azurerm_key_vault.aks.id
  depends_on = [
    azurerm_key_vault_access_policy.azure_devops_service_connection
  ]
}

data "azurerm_kubernetes_service_versions" "current" {
  location = data.azurerm_resource_group.app-primary.location
}

data "azurerm_subnet" "aks" {
  for_each             = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name                 = each.value.azure_subnet_name
  virtual_network_name = each.value.azure_vnet_name
  resource_group_name  = data.terraform_remote_state.infra-primary.outputs.resource_group
}

data "azurerm_application_gateway" "aks" {
  for_each            = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name                = each.value.azure_gateway_name
  resource_group_name = data.terraform_remote_state.infra-primary.outputs.resource_group
}

locals {
  detailed_enabled_aks_cluster = [
    for cluster in local.enabled_aks_cluster :
    merge(cluster,
      {
        long_name                       = "aks-${var.project_naming_convention}-${cluster.name}-${local.common_naming}01"
        aks_version                     = lookup(cluster, "version", data.azurerm_kubernetes_service_versions.current.latest_version)
        sku_tier                        = lookup(cluster, "sku", var.aks_sku)
        private_cluster_enabled         = lookup(cluster, "private_api", var.aks_private_api)
        api_server_authorized_ip_ranges = concat(lookup(cluster, "api_auth_ips", var.aks_api_auth_ips), local.all_authorized_ip_ranges)
        #default_node_pool               = lookup(cluster, "default_node_pool", var.aks_default_node_pool)
        # This way the user can define only the setting that wants to change
        default_node_pool = {
          name                = lookup(cluster, "default_node_pool.name", var.aks_default_node_pool.name)
          vm_size             = lookup(cluster, "default_node_pool.vm_size", var.aks_default_node_pool.vm_size)
          enable_auto_scaling = lookup(cluster, "default_node_pool.enabled_auto_scaling", var.aks_default_node_pool.enable_auto_scaling)
          min_node_count      = lookup(cluster, "default_node_pool.min_node_count", var.aks_default_node_pool.min_node_count)
          max_node_count      = lookup(cluster, "default_node_pool.max_node_count", var.aks_default_node_pool.max_node_count)
          availability_zones  = lookup(cluster, "default_node_pool.zones", var.aks_default_node_pool.availability_zones)
          max_pods            = lookup(cluster, "default_node_pool.max_pods", var.aks_default_node_pool.max_pods)
          os_disk_size_gb     = lookup(cluster, "default_node_pool.os_disk_size_gb", var.aks_default_node_pool.os_disk_size_gb)
          labels              = lookup(cluster, "default_node_pool.labels", var.aks_default_node_pool.labels)
          vnet_subnet_id      = data.azurerm_subnet.aks[cluster.name].id
        }
        #extra_node_pools = lookup(cluster, "extra_node_pools", var.aks_extra_node_pools)
        extra_node_pools = {
          for key, value in lookup(cluster, "extra_node_pools", var.aks_extra_node_pools) : "${cluster.name}-${key}" => value
        }
        rbac                          = lookup(cluster, "rbac", var.aks_rbac)
        aks_automatic_channel_upgrade = lookup(cluster, "automatic_channel_upgrade", var.aks_automatic_channel_upgrade)
        #        node_resource_group           = "aks-${var.project_naming_convention}-${cluster.name}-${var.location}"
        node_resource_group = "MC_${var.project_naming_convention}_aks_${cluster.name}_${var.location}"
      }
    )
  ]
}

resource "azurerm_kubernetes_cluster" "deployment" {
  for_each                = { for aks in local.detailed_enabled_aks_cluster : aks.name => aks }
  name                    = each.value.long_name
  resource_group_name     = data.azurerm_resource_group.app-primary.name
  location                = data.azurerm_resource_group.app-primary.location
  dns_prefix              = each.value.long_name
  kubernetes_version      = each.value.aks_version
  sku_tier                = each.value.sku_tier
  private_cluster_enabled = each.value.private_cluster_enabled
  #  api_server_authorized_ip_ranges = each.value.api_server_authorized_ip_ranges
  node_resource_group = each.value.node_resource_group

  linux_profile {
    admin_username = azurerm_key_vault_secret.aks_node_ssh_admin_user[each.value.name].value
    ssh_key {
      key_data = azurerm_key_vault_secret.aks_node_public_key_openssh[each.value.name].value
    }
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  enable_pod_security_policy = false

  #  default_node_pool {
  #    name                   = "akspool01"
  #    type                   = "VirtualMachineScaleSets"
  #    enable_auto_scaling    = true
  #    min_count              = 3
  #    max_count              = 10
  #    enable_host_encryption = false
  #    enable_node_public_ip  = false
  #    vm_size                = "Standard_DS2_v2"
  #    availability_zones     = ["1", "2", "3", ]
  #    vnet_subnet_id         = each.value.default_node_pool.vnet_subnet_id
  #    orchestrator_version   = each.value.aks_version
  #  }

  default_node_pool {
    name                  = each.value.default_node_pool.name
    vm_size               = each.value.default_node_pool.vm_size
    orchestrator_version  = each.value.aks_version
    type                  = "VirtualMachineScaleSets"
    enable_auto_scaling   = each.value.default_node_pool.enable_auto_scaling
    node_count            = each.value.default_node_pool.enable_auto_scaling ? null : each.value.default_node_pool.max_node_count
    min_count             = each.value.default_node_pool.enable_auto_scaling ? each.value.default_node_pool.min_node_count : null
    max_count             = each.value.default_node_pool.enable_auto_scaling ? each.value.default_node_pool.max_node_count : null
    availability_zones    = each.value.default_node_pool.availability_zones
    max_pods              = each.value.default_node_pool.max_pods > 0 ? each.value.default_node_pool.max_pods : null
    os_disk_size_gb       = each.value.default_node_pool.os_disk_size_gb > 0 ? each.value.default_node_pool.os_disk_size_gb : null
    vnet_subnet_id        = each.value.default_node_pool.vnet_subnet_id
    node_labels           = length(each.value.default_node_pool.labels) > 0 ? each.value.default_node_pool.labels : null
    enable_node_public_ip = false
  }

  #  private_cluster_enabled = true

  identity {
    type = "SystemAssigned"
  }

  role_based_access_control {
    enabled = each.value.rbac

    azure_active_directory {
      managed = true
    }
  }


  addon_profile {
    aci_connector_linux {
      enabled = false
    }

    azure_policy {
      enabled = true
    }

    http_application_routing {
      enabled = false
    }

    ingress_application_gateway {
      enabled    = true
      gateway_id = data.azurerm_application_gateway.aks[each.value.name].id
    }

    oms_agent {
      enabled                    = true
      log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
    }
  }

  lifecycle {
    ignore_changes = [
      tags,
      default_node_pool[0].node_count,
      kubernetes_version,
      default_node_pool[0].orchestrator_version
    ]
  }
}

resource "azurerm_role_assignment" "agic_agw" {
  for_each = { for aks in local.detailed_enabled_aks_cluster : aks.name => aks }
  #  principal_id         = local.gateway_managed_identity_principal_id
  #  principal_id        = "58ac5f70-5077-4d0b-bd61-6bb6b900b418" # gateway_managed_identity_principal_object_id
  # principal_id         = "4a10e8f7-7178-4d66-964a-0367d98fdf31"
  principal_id         = azurerm_kubernetes_cluster.deployment[each.value.name].addon_profile[0].ingress_application_gateway[0].ingress_application_gateway_identity[0].object_id
  role_definition_name = "Contributor"
  scope                = data.azurerm_application_gateway.aks[each.value.name].id
}

resource "azurerm_role_assignment" "agic_apg_rg" {
  for_each = { for aks in local.detailed_enabled_aks_cluster : aks.name => aks }
  #  principal_id         = local.gateway_managed_identity_principal_id
  #principal_id         = "58ac5f70-5077-4d0b-bd61-6bb6b900b418" # gateway_managed_identity_principal_object_id
  #principal_id         = "4a10e8f7-7178-4d66-964a-0367d98fdf31"
  principal_id         = azurerm_kubernetes_cluster.deployment[each.value.name].addon_profile[0].ingress_application_gateway[0].ingress_application_gateway_identity[0].object_id
  role_definition_name = "Reader"
  scope                = data.azurerm_resource_group.infra-primary.id # resource group where the APW is
}

resource "azurerm_role_assignment" "mio" {
  for_each = { for aks in local.detailed_enabled_aks_cluster : aks.name => aks }
  #  principal_id         = local.gateway_managed_identity_principal_id
  #principal_id         = "58ac5f70-5077-4d0b-bd61-6bb6b900b418" # gateway_managed_identity_principal_object_id
  #principal_id         = "4a10e8f7-7178-4d66-964a-0367d98fdf31"
  principal_id         = azurerm_kubernetes_cluster.deployment[each.value.name].addon_profile[0].ingress_application_gateway[0].ingress_application_gateway_identity[0].object_id
  role_definition_name = "Managed Identity Operator"
  scope                = "/subscriptions/3fd0012c-9f2f-4da8-8869-0dbe61384321/resourcegroups/ETN-ES-DERMS-ContainerOrchestration/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-derms-agw-dev-eus-p01"
}

data "azurerm_monitor_diagnostic_categories" "aks_deployment" {
  for_each    = { for aks in local.detailed_enabled_aks_cluster : aks.name => aks }
  resource_id = azurerm_kubernetes_cluster.deployment[each.value.name].id
}

resource "azurerm_monitor_diagnostic_setting" "aks_deployment" {
  for_each                   = { for aks in local.detailed_enabled_aks_cluster : aks.name => aks }
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_kubernetes_cluster.deployment[each.value.name].id
  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.aks_deployment[each.value.name].logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.aks_deployment[each.value.name].metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

locals {
  # this has the content '"${node_name}" = "${node_details} with extra lines"'
  # detailed_extra_node_pools = flatten([
  #   for cluster in local.detailed_enabled_aks_cluster :
  #   { for node_name, node_details in cluster.extra_node_pools : node_name => merge({ for key, value in node_details : key => value },
  #     {
  #       "kubernetes_cluster_id" = azurerm_kubernetes_cluster.deployment[cluster.name].id
  #       "vnet_subnet_id"        = azurerm_kubernetes_cluster.deployment[cluster.name].default_node_pool[0].vnet_subnet_id
  #       "terraform_name"        = "${node_name}"
  #     })
  #   }
  # ])

  # this way we remove the key and the content will be only '"${node_details} with extra lines"'
  detailed_extra_node_pools = flatten([
    for cluster in local.detailed_enabled_aks_cluster :
    [for node_name, node_details in cluster.extra_node_pools : merge({ for key, value in node_details : key => value },
      {
        "kubernetes_cluster_id" = azurerm_kubernetes_cluster.deployment[cluster.name].id
        "vnet_subnet_id"        = azurerm_kubernetes_cluster.deployment[cluster.name].default_node_pool[0].vnet_subnet_id
        "terraform_name"        = "${node_name}"
      })
    ]
  ])
}

resource "azurerm_kubernetes_cluster_node_pool" "deployment" {
  for_each              = { for node in local.detailed_extra_node_pools : node.terraform_name => node }
  kubernetes_cluster_id = each.value.kubernetes_cluster_id
  name                  = each.value.name
  mode                  = length(each.value.mode) > 0 ? each.value.mode : null
  vm_size               = each.value.vm_size
  node_count            = each.value.enable_auto_scaling ? null : each.value.max_node_count
  enable_auto_scaling   = each.value.enable_auto_scaling
  min_count             = each.value.enable_auto_scaling ? each.value.min_node_count : null
  max_count             = each.value.enable_auto_scaling ? each.value.max_node_count : null
  availability_zones    = length(each.value.availability_zones) > 0 ? each.value.availability_zones : null
  max_pods              = each.value.max_pods > 0 ? each.value.max_pods : null
  os_disk_size_gb       = each.value.os_disk_size_gb > 0 ? each.value.os_disk_size_gb : null
  vnet_subnet_id        = each.value.vnet_subnet_id
  node_labels           = (length(each.value.labels) > 0) ? each.value.labels : null
  node_taints           = (length(each.value.taints) > 0) ? each.value.taints : null
  enable_node_public_ip = false
  os_type               = "Linux"

  lifecycle {
    ignore_changes = [
      node_count
    ]
  }
}

##
# Link the Bastion Vnet to the Private DNS Zone generated to resolve the Server IP from the URL in Kubeconfig
##
resource "azurerm_private_dns_zone_virtual_network_link" "link_bastion_cluster" {
  name = "dnslink-bastion-cluster"
  # The Terraform language does not support user-defined functions, and so only the functions built in to the language are available for use.
  # The below code gets the private dns zone name from the fqdn, by slicing the out dns prefix
  private_dns_zone_name = join(".", slice(split(".", azurerm_kubernetes_cluster.deployment["green"].private_fqdn), 1, length(split(".", azurerm_kubernetes_cluster.deployment["green"].private_fqdn))))
  resource_group_name   = "MC_${var.project_naming_convention}_aks_green_${var.location}"
  virtual_network_id    = data.terraform_remote_state.infra-primary.outputs.environment_vnet_id
}

# Big data platform - it's the cold store of all the data for later analytics and future model improvements

#resource "azurerm_eventhub_namespace" "bdp" {
#  name                = "evhns-${var.project_naming_convention}-bdp-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  location            = data.azurerm_resource_group.app-primary.location
#  sku                 = var.bdp_eventhub_namespace_sku
#  capacity            = var.bdp_eventhub_namespace_capacity
#}
#
#data "azurerm_monitor_diagnostic_categories" "evhns_bdp" {
#  resource_id = azurerm_eventhub_namespace.bdp.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "evhns_bdp" {
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_eventhub_namespace.bdp.id
#  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.evhns_bdp.logs
#    content {
#      category = log.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#
#  dynamic "metric" {
#    for_each = data.azurerm_monitor_diagnostic_categories.evhns_bdp.metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}
#
#resource "azurerm_eventhub" "bdp" {
#  name                = "evh-${var.project_naming_convention}-bdp-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  namespace_name      = azurerm_eventhub_namespace.bdp.name
#  partition_count     = var.bdp_eventhub_partition_count
#  message_retention   = var.bdp_eventhub_message_retention
#
#  capture_description {
#    enabled             = true
#    encoding            = "Avro"
#    interval_in_seconds = 900
#    size_limit_in_bytes = 157286400
#    skip_empty_archives = true
#
#    destination {
#      name                = "EventHubArchive.AzureBlockBlob"
#      archive_name_format = "/raw/capture/{Namespace}/eventhub={EventHub}/day={Year}-{Month}-{Day}/hour={Hour}/file_min{Minute}_sec{Second}_part{PartitionId}"
#      blob_container_name = data.terraform_remote_state.data-primary.outputs.bdp_container_name
#      storage_account_id  = data.terraform_remote_state.data-primary.outputs.bdp_account_id
#    }
#  }
#}
#
#resource "azurerm_eventhub_authorization_rule" "bdp" {
#  name                = "evh-${var.project_naming_convention}-bdp-${local.common_naming}01"
#  namespace_name      = azurerm_eventhub_namespace.bdp.name
#  eventhub_name       = azurerm_eventhub.bdp.name
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  listen              = true
#  send                = true
#  manage              = true
#}

#provider "databricks" {
#  alias                       = "bdp"
#  azure_workspace_resource_id = data.terraform_remote_state.data-primary.outputs.bdp_databrick_workspace_id
#}
#
#data "azurerm_storage_account" "bdp" {
#  name                = data.terraform_remote_state.data-primary.outputs.bdp_account_name
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#}
#
#data "azurerm_storage_container" "bdp" {
#  name                 = data.terraform_remote_state.data-primary.outputs.bdp_container_name
#  storage_account_name = data.terraform_remote_state.data-primary.outputs.bdp_account_name
#}

#resource "databricks_notebook" "raw_add_partition" {
#  provider = databricks.bdp
#  #source         = join("/", [path.root, "raw_add_partition_databrick_notebook.scala"])
#  language = "SCALA"
#  content_base64 = base64encode(
#    templatefile(
#      "${path.root}/raw_add_partition_databrick_notebook.scala",
#      {
#        #        EVENTHUB             = azurerm_eventhub.bdp.name,
#        #        EVENTHUBNAMESPACE    = azurerm_eventhub_namespace.bdp.name,
#        STORAGEACCOUNTACCESS = "wasbs://${data.azurerm_storage_container.bdp.name}@${data.azurerm_storage_account.bdp.primary_blob_host}"
#      }
#    )
#  )
#  path = "/Shared/raw_add_partition"
#}

#data "azurerm_key_vault_secret" "pgsql_admin_user" {
#  name         = data.terraform_remote_state.data-primary.outputs.psql_admin_user_key_vault_name
#  key_vault_id = data.terraform_remote_state.data-primary.outputs.key_vault_id
#}
#
#data "azurerm_key_vault_secret" "pgsql_admin_pass" {
#  name         = data.terraform_remote_state.data-primary.outputs.psql_admin_pass_key_vault_name
#  key_vault_id = data.terraform_remote_state.data-primary.outputs.key_vault_id
#}
#
#resource "random_id" "pgsql_random_part_bdp_user" {
#  byte_length = 8
#}
#
#data "azurerm_postgresql_server" "environment" {
#  name                = data.terraform_remote_state.data-primary.outputs.psql_server_name
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#}
#
#locals {
#  pgsql_bdp_db = "bdp"
#}
#
#resource "azurerm_key_vault_secret" "pgsql_bdp_user" {
#  name         = "${data.azurerm_postgresql_server.environment.name}-bdp-user"
#  value        = "${local.pgsql_bdp_db}${random_id.pgsql_random_part_bdp_user.hex}"
#  key_vault_id = data.terraform_remote_state.data-primary.outputs.key_vault_id
#}
#
#resource "azurerm_key_vault_secret" "pgsql_bdp_pass" {
#  name         = "${data.azurerm_postgresql_server.environment.name}-bdp-pass"
#  value        = uuid()
#  key_vault_id = data.terraform_remote_state.data-primary.outputs.key_vault_id
#
#  lifecycle {
#    ignore_changes = [
#      value
#    ]
#  }
#}
#
#resource "azurerm_postgresql_database" "bdp" {
#  name                = local.pgsql_bdp_db
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#  server_name         = data.azurerm_postgresql_server.environment.name
#  charset             = "UTF8"
#  collation           = "English_United States.1252"
#}
#
#provider "postgresql" {
#  alias           = "admin"
#  host            = data.azurerm_postgresql_server.environment.fqdn
#  port            = 5432
#  username        = "${data.azurerm_key_vault_secret.pgsql_admin_user.value}@${data.azurerm_postgresql_server.environment.name}"
#  password        = data.azurerm_key_vault_secret.pgsql_admin_pass.value
#  superuser       = false
#  sslmode         = "require"
#  connect_timeout = 15
#}
#
#resource "postgresql_role" "bdp" {
#  provider        = postgresql.admin
#  name            = azurerm_key_vault_secret.pgsql_bdp_user.value
#  password        = azurerm_key_vault_secret.pgsql_bdp_pass.value
#  login           = true
#  inherit         = true
#  superuser       = false
#  create_database = false
#  create_role     = false
#  replication     = false
#  #connection_limit    = -1
#  # to prevent a REASSIGN OWNED and DROP OWNED to the CURRENT_USER (normally the connected user for the provider)
#  skip_reassign_owned = true
#}

#resource "postgresql_grant" "bdp" {
#  provider    = postgresql.admin
#  database    = azurerm_postgresql_database.bdp.name
#  role        = postgresql_role.bdp.name
#  object_type = "database"
#  # https://www.postgresql.org/docs/13/ddl-priv.html#PRIVILEGE-ABBREVS-TABLE
#  privileges = ["CREATE", "CONNECT", "TEMPORARY"]
#}
#
#provider "postgresql" {
#  alias           = "bdp"
#  host            = data.azurerm_postgresql_server.environment.fqdn
#  port            = 5432
#  database        = azurerm_postgresql_database.bdp.name
#  username        = azurerm_key_vault_secret.pgsql_bdp_user.value
#  password        = azurerm_key_vault_secret.pgsql_bdp_pass.value
#  superuser       = false
#  sslmode         = "require"
#  connect_timeout = 15
#}

#data "azurerm_data_factory" "bdp" {
#  name                = data.terraform_remote_state.data-primary.outputs.bdp_data_factory_name
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#}
#
#resource "azurerm_data_factory_linked_service_azure_databricks" "bdp" {
#  name                       = "${var.project_naming_convention}-bdp-${local.common_naming}01"
#  data_factory_id            = data.azurerm_data_factory.bdp.id
#  resource_group_name        = data.terraform_remote_state.data-primary.outputs.resource_group
#  adb_domain                 = data.terraform_remote_state.data-primary.outputs.bdp_databrick_workspace_url
#  msi_work_space_resource_id = data.terraform_remote_state.data-primary.outputs.bdp_databrick_workspace_id
#
#  new_cluster_config {
#    node_type             = "Standard_DS3_v2"
#    cluster_version       = "6.4.x-esr-scala2.11"
#    min_number_of_workers = 1
#    # despite azure reporting this value as 0 in plan phase, this field can only be [1-10]
#    max_number_of_workers = 1
#
#    spark_config = {
#      "spark.sql.hive.metastore.version"                                                        = "1.2.1"
#      "spark.sql.hive.metastore.jars"                                                           = "builtin"
#      "datanucleus.autoCreateSchema"                                                            = "true"
#      "datanucleus.fixedDatastore"                                                              = "false"
#      "javax.jdo.option.ConnectionURL"                                                          = "jdbc:postgresql://${data.azurerm_postgresql_server.environment.fqdn}:5432/${azurerm_postgresql_database.bdp.name}?sslmode=require"
#      "javax.jdo.option.ConnectionUserName"                                                     = "${azurerm_key_vault_secret.pgsql_bdp_user.value}@${data.azurerm_postgresql_server.environment.name}"
#      "javax.jdo.option.ConnectionPassword"                                                     = azurerm_key_vault_secret.pgsql_bdp_pass.value
#      "javax.jdo.option.ConnectionDriverName"                                                   = "org.postgresql.Driver"
#      "spark.sql.warehouse.dir"                                                                 = "wasbs://${data.azurerm_storage_container.bdp.name}@${data.azurerm_storage_account.bdp.primary_blob_host}/hive"
#      "spark.hadoop.fs.azure.account.key.${data.azurerm_storage_account.bdp.primary_blob_host}" = element(split(";", element(split("AccountKey=", regex("AccountKey=.+;", data.azurerm_storage_account.bdp.primary_connection_string)), 1)), 0)
#    }
#
#    spark_environment_variables = {
#      "PYSPARK_PYTHON" = "/databricks/python3/bin/python3"
#    }
#  }
#
#  lifecycle {
#    ignore_changes = [new_cluster_config[0].max_number_of_workers]
#  }
#
#}
#
#resource "azurerm_data_factory_pipeline" "bdp" {
#  name                = basename(databricks_notebook.raw_add_partition.path)
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#  data_factory_id     = data.azurerm_data_factory.bdp.id
#
#  activities_json = jsonencode([{
#    name      = basename(databricks_notebook.raw_add_partition.path)
#    type      = "DatabricksNotebook"
#    dependsOn = []
#    policy = {
#      timeout                = "7.00:00:00"
#      retry                  = 0
#      retryIntervalInSeconds = 30
#      secureOutput           = false
#      secureInput            = false
#    }
#    userProperties = []
#    typeProperties = {
#      notebookPath = databricks_notebook.raw_add_partition.path
#      baseParameters = {
#        run_date = {
#          value = "@formatDateTime(pipeline().TriggerTime, 'yyyy-MM-dd')"
#          type  = "Expression"
#        }
#      }
#    }
#    linkedServiceName = {
#      referenceName = azurerm_data_factory_linked_service_azure_databricks.bdp.name
#      type          = "LinkedServiceReference"
#    }
#    userProperties = []
#  }])
#
#  depends_on = [
#    azurerm_data_factory_linked_service_azure_databricks.bdp
#  ]
#}
#
#resource "azurerm_data_factory_trigger_schedule" "bdp" {
#  name                = basename(databricks_notebook.raw_add_partition.path)
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#  data_factory_id     = data.azurerm_data_factory.bdp.id
#  pipeline_name       = azurerm_data_factory_pipeline.bdp.name
#  start_time          = "2021-05-18T00:30:00Z"
#  interval            = 1
#  frequency           = "Day"
#
#  lifecycle {
#    ignore_changes = [
#      start_time
#    ]
#  }
#}

# redis

#data "azurerm_redis_cache" "environment" {
#  name                = data.terraform_remote_state.data-primary.outputs.redis_name
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#}

#resource "kubernetes_secret" "redis" {
#  for_each                  = { for aks in local.enabled_aks_cluster : aks.name => aks }
#  provider = "kubernetes.${each.value.name}"
#
#  metadata {
#    name = data.azurerm_redis_cache.environment.name
#  }
#
#  data = {
#    "ENDPOINT"     = data.azurerm_redis_cache.environment.hostname
#    "ENDPOINT_KEY" = data.azurerm_redis_cache.environment.primary_access_key
#  }
#
#  type = "Opaque"
#}

# iothub

#data "azurerm_storage_account" "iot" {
#  name                = data.terraform_remote_state.data-primary.outputs.iot_storage_account_name
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#}
#
#data "azurerm_storage_container" "iot" {
#  name                 = data.terraform_remote_state.data-primary.outputs.iot_storage_container_name
#  storage_account_name = data.azurerm_storage_account.iot.name
#}
#
#resource "azurerm_eventhub_namespace" "iot" {
#  name                = "evhns-${var.project_naming_convention}-iot-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  location            = data.azurerm_resource_group.app-primary.location
#  sku                 = var.iot_eventhub_namespace_sku
#  capacity            = var.iot_eventhub_namespace_capacity
#}
#
#data "azurerm_monitor_diagnostic_categories" "evhns_iot" {
#  resource_id = azurerm_eventhub_namespace.iot.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "evhns_iot" {
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_eventhub_namespace.iot.id
#  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.evhns_iot.logs
#    content {
#      category = log.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#
#  dynamic "metric" {
#    for_each = data.azurerm_monitor_diagnostic_categories.evhns_iot.metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}
#
#resource "azurerm_eventhub" "iot" {
#  name                = "evh-${var.project_naming_convention}-iot-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  namespace_name      = azurerm_eventhub_namespace.iot.name
#  partition_count     = var.iot_eventhub_partition_count
#  message_retention   = var.iot_eventhub_message_retention
#}
#
#data "azurerm_monitor_diagnostic_categories" "evh_iot" {
#  resource_id = azurerm_eventhub_namespace.iot.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "evh_iot" {
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_eventhub_namespace.iot.id
#  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.evh_iot.logs
#    content {
#      category = log.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#
#  dynamic "metric" {
#    for_each = data.azurerm_monitor_diagnostic_categories.evh_iot.metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}
#
#resource "azurerm_eventhub_authorization_rule" "sending" {
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  namespace_name      = azurerm_eventhub_namespace.iot.name
#  eventhub_name       = azurerm_eventhub.iot.name
#  name                = "sending"
#  listen              = false
#  send                = true
#  manage              = false
#}
#
#
#resource "azurerm_iothub" "environment" {
#  name                = "iot-${var.project_naming_convention}-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  location            = data.azurerm_resource_group.app-primary.location
#  sku {
#    name     = var.iot_sku
#    capacity = var.iot_sku_capacity
#  }
#}
#
#data "azurerm_monitor_diagnostic_categories" "iot_environment" {
#  resource_id = azurerm_iothub.environment.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "iot_environment" {
#  name                           = "sent-to-log-analytics"
#  target_resource_id             = azurerm_iothub.environment.id
#  log_analytics_workspace_id     = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#  log_analytics_destination_type = "AzureDiagnostics"
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.iot_environment.logs
#    content {
#      category = log.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#
#  dynamic "metric" {
#    for_each = data.azurerm_monitor_diagnostic_categories.iot_environment.metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}
#
#resource "azurerm_iothub_endpoint_storage_container" "environment" {
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  iothub_name         = azurerm_iothub.environment.name
#  name                = data.azurerm_storage_account.iot.name
#  container_name      = data.azurerm_storage_container.iot.name
#  connection_string   = data.azurerm_storage_account.iot.primary_blob_connection_string
#
#  file_name_format           = "{iothub}/{partition}_{YYYY}_{MM}_{DD}_{HH}_{mm}"
#  batch_frequency_in_seconds = 60
#  max_chunk_size_in_bytes    = 10485760
#  #encoding                   = "Avro"
#  encoding = "JSON"
#}
#
#resource "azurerm_iothub_endpoint_eventhub" "environment" {
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  iothub_id           = azurerm_iothub.environment.id
#  name                = azurerm_eventhub_authorization_rule.sending.name
#  connection_string   = azurerm_eventhub_authorization_rule.sending.primary_connection_string
#}
#
#resource "azurerm_iothub_route" "environment" {
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  iothub_name         = azurerm_iothub.environment.name
#  name                = azurerm_iothub_endpoint_storage_container.environment.name
#  source              = "DeviceMessages"
#  condition           = "true"
#  endpoint_names      = [azurerm_iothub_endpoint_storage_container.environment.name]
#  enabled             = true
#}

# etib-control2

#data "azurerm_storage_account" "etib-control2" {
#  name                = data.terraform_remote_state.data-primary.outputs.etib-control2_storage_account_name
#  resource_group_name = data.terraform_remote_state.data-primary.outputs.resource_group
#}
#
#resource "azurerm_app_service_plan" "ASP-etib-control2" {
#  name                = "plan-${var.project_naming_convention}-control2-${local.common_naming}01"
#  location            = data.azurerm_resource_group.app-primary.location
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  kind                = "FunctionApp"
#
#  sku {
#    tier = "Dynamic"
#    size = "Y1"
#  }
#}
#
#resource "azurerm_application_insights" "timeseries" {
#  name                = "appi-${var.project_naming_convention}-timeseries-${local.common_naming}01"
#  location            = data.azurerm_resource_group.app-primary.location
#  resource_group_name = data.azurerm_resource_group.app-primary.name
#  application_type    = "web"
#}
#
#resource "azurerm_function_app" "etibcontrol2" {
#  name                       = "func-${var.project_naming_convention}-control2-${local.common_naming}01"
#  location                   = data.azurerm_resource_group.app-primary.location
#  resource_group_name        = data.azurerm_resource_group.app-primary.name
#  app_service_plan_id        = azurerm_app_service_plan.ASP-etib-control2.id
#  storage_account_name       = data.azurerm_storage_account.etib-control2.name
#  storage_account_access_key = data.azurerm_storage_account.etib-control2.primary_access_key
#  app_settings = {
#    "WEBSITE_RUN_FROM_PACKAGE"       = "",
#    "FUNCTIONS_WORKER_RUNTIME"       = "node",
#    "APPINSIGHTS_INSTRUMENTATIONKEY" = azurerm_application_insights.timeseries.instrumentation_key,
#  }
#  version = "~3"
#  lifecycle {
#    ignore_changes = [
#      app_settings["WEBSITE_RUN_FROM_PACKAGE"],
#    ]
#  }
#}
