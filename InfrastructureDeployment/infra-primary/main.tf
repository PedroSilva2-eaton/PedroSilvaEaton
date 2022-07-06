provider "azurerm" {
  features {
    # so it doesn't purge them in key vault when deleting it from terraform
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

data "azurerm_resource_group" "infra-primary" {
  name = "ETN-ES-DERMS-ContainerOrchestration"
}

locals {
  common_naming = "${var.environment}-${data.terraform_remote_state.ado-automation.outputs.location_short}-${var.environment_qualifier}"
  tags = {
    "terraform" = "infra"
  }
  all_authorized_ip_ranges = data.terraform_remote_state.ado-automation.outputs.all_authorized_ip_ranges
  log_analytics_solutions = [
    "OMSGallery/ContainerInsights",
    "OMSGallery/AzureAppGatewayAnalytics",
    "OMSGallery/KeyVaultAnalytics"
  ]
  enabled_deployments = [
    for deployment in var.deployments :
    deployment if deployment.enabled
  ]
  enabled_aks_cluster = [
    for deployment in local.enabled_deployments :
    merge({ for key, value in deployment : key => value if !contains(["enabled", "gw_address_space"], key) },
      {
        gateway = {
          name         = "${deployment.name}-gateway",
          abbreviation = "agw-${deployment.name}"
          cidr         = tolist([deployment.gw_address_space])
        }
    })
  ]
  cidr_for_28_mask_bits = cidrsubnet(var.environment_vnet_cidr, 1, 0)
  cidr_for_27_mask_bits = cidrsubnet(var.environment_vnet_cidr, 1, 1)
  gateway_snets = [
    for aks in local.enabled_aks_cluster :
    { for key, value in aks.gateway : key => value
    }
  ]
  vm_snets = [
    {
      name         = "AzureBastionSubnet",
      abbreviation = "bas",
      cidr         = tolist([cidrsubnet(local.cidr_for_27_mask_bits, 2, 0)])
    },
    {
      name         = "virtual_machines",
      abbreviation = "vm",
      cidr         = tolist([cidrsubnet(local.cidr_for_27_mask_bits, 2, 1)])
    }
  ]
  enabled_vm_snets = [
    for vm in local.vm_snets :
    vm if var.create_vm
  ]
  other_snets = [
    {
      name         = "container_registry",
      abbreviation = "cr",
      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 0)])
    },
    #    {
    #      name         = "postgresql",
    #      abbreviation = "psql",
    #      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 1)])
    #    },
    #    {
    #      name         = "redis",
    #      abbreviation = "redis",
    #      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 2)])
    #    },
    {
      name         = "keyvault",
      abbreviation = "kv",
      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 3)])
    },
    {
      name         = "storage_account",
      abbreviation = "st",
      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 4)])
    }
    #    {
    #      name         = "function_app",
    #      abbreviation = "func",
    #      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 5)])
    #    },
    #    {
    #      name         = "app_service_plan",
    #      abbreviation = "plan",
    #      cidr         = tolist([cidrsubnet(local.cidr_for_28_mask_bits, 3, 6)])
    #    }
  ]
  enable_snets = concat(local.gateway_snets, local.vm_snets, local.other_snets)
  gateway_subnet_ids = [
    for gateway in local.gateway_snets :
    azurerm_subnet.environment[gateway.name].id
  ]
  dns_subdomains = [
    for subdomain in var.gateway_https_subdomains : format("%s.%s", subdomain, var.gateway_https_domain)
  ]
  #  databrick_subnets = [
  #    {
  #      name = "pub",
  #      cidr = tolist([cidrsubnet(var.databrick_vnet_cidr, 4, 0)])
  #    },
  #    {
  #      name = "prv",
  #      cidr = tolist([cidrsubnet(var.databrick_vnet_cidr, 4, 7)])
  #    }
  #  ]
}

# log analytics

resource "azurerm_log_analytics_workspace" "environment" {
  name                = "log-${var.project_naming_convention}-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  sku                 = var.log_analytics_workspace_sku
  retention_in_days   = var.log_analytics_workspace_retention
  tags                = local.tags
}

resource "azurerm_log_analytics_solution" "monitor" {
  for_each              = { for solution in local.log_analytics_solutions : solution => solution }
  solution_name         = trimprefix(each.value, "OMSGallery/")
  workspace_resource_id = azurerm_log_analytics_workspace.environment.id
  workspace_name        = azurerm_log_analytics_workspace.environment.name
  location              = azurerm_log_analytics_workspace.environment.location
  resource_group_name   = azurerm_log_analytics_workspace.environment.resource_group_name
  tags                  = local.tags

  plan {
    publisher = "Microsoft"
    product   = each.value
  }
}

# environment vnet and there subnets

resource "azurerm_virtual_network" "environment" {
  name                = "vnet-${var.project_naming_convention}-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  address_space       = tolist([var.environment_vnet_cidr])
  tags                = local.tags

  lifecycle {
    ignore_changes = [
      subnet
    ]
  }
}

data "azurerm_monitor_diagnostic_categories" "vnet_environment" {
  resource_id = azurerm_virtual_network.environment.id
}

resource "azurerm_monitor_diagnostic_setting" "vnet_environment" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_virtual_network.environment.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.vnet_environment.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.vnet_environment.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_subnet" "environment" {
  for_each                                       = { for snet in local.enable_snets : snet.name => snet }
  name                                           = each.value.abbreviation == "bas" ? "AzureBastionSubnet" : "snet-${var.project_naming_convention}-${each.value.abbreviation}-${local.common_naming}01"
  resource_group_name                            = data.azurerm_resource_group.infra-primary.name
  virtual_network_name                           = azurerm_virtual_network.environment.name
  address_prefixes                               = each.value.cidr
  enforce_private_link_endpoint_network_policies = true
}

resource "azurerm_network_security_group" "environment" {
  for_each            = { for snet in local.enable_snets : snet.name => snet }
  name                = "nsg-${var.project_naming_convention}-${each.value.abbreviation}-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  tags                = local.tags

  lifecycle {
    ignore_changes = [
      security_rule
    ]
  }
}

data "azurerm_monitor_diagnostic_categories" "nsg_environment" {
  for_each    = { for snet in local.enable_snets : snet.name => snet }
  resource_id = azurerm_network_security_group.environment[each.value.name].id
}

resource "azurerm_monitor_diagnostic_setting" "nsg_environment" {
  for_each                   = { for snet in local.enable_snets : snet.name => snet }
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_network_security_group.environment[each.value.name].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.nsg_environment[each.value.name].logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.nsg_environment[each.value.name].metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "environment" {
  for_each                  = { for snet in local.enable_snets : snet.name => snet }
  network_security_group_id = azurerm_network_security_group.environment[each.value.name].id
  subnet_id                 = azurerm_subnet.environment[each.value.name].id
}

resource "azurerm_network_security_rule" "inbound_http" {
  for_each                    = { for gateway in local.gateway_snets : gateway.name => gateway }
  name                        = "inbound_http"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_network_security_group.environment[each.value.name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[each.value.name].name
}

resource "azurerm_network_security_rule" "inbound_https" {
  for_each                    = { for gateway in local.gateway_snets : gateway.name => gateway }
  name                        = "inbound_https"
  priority                    = 101
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_network_security_group.environment[each.value.name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[each.value.name].name
}

resource "azurerm_network_security_rule" "required_management_ports" {
  for_each                    = { for gateway in local.gateway_snets : gateway.name => gateway }
  name                        = "required_management_ports"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "65200-65535"
  source_address_prefix       = "GatewayManager"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_network_security_group.environment[each.value.name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[each.value.name].name
}

# private DNS zone

locals {
  st_subresources = ["blob", "table", "queue", "file", "web"]
}

locals {
  resources_private_link = {
    "storage_account"    = [for subresource in local.st_subresources : "privatelink.${subresource}.core.windows.net"]
    "container_registry" = ["privatelink.azurecr.io"]
    #"postgresql"         = ["privatelink.postgres.database.azure.com"]
    #"redis"              = ["privatelink.redis.cache.windows.net"]
    "keyvault" = ["privatelink.vaultcore.azure.net"]
    #"kubernets"          = ["privatelink.${var.location}.azmk8s.io"]
    #    "funtion_app"        = ["privatelink.azurewebsites.net"]
  }
  privatelinks_raw = transpose(local.resources_private_link)
  privatelinks = { for privatelink, value in local.privatelinks_raw :
    replace(replace(replace(replace(replace(replace(replace(privatelink, ".io", ""), ".windows.net", ""), ".azure.com", ""), ".azure.net", ""), ".core", ""), ".database", ""), ".cache", "") => privatelink
    #    replace(replace(replace(replace(replace(replace(replace(replace(privatelink, ".io", ""), ".windows.net", ""), ".azure.com", ""), ".azure.net", ""), ".core", ""), ".database", ""), ".cache", ""), ".net", "") => privatelink
  }
}

resource "azurerm_private_dns_zone" "environment" {
  for_each            = local.privatelinks
  name                = each.value
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  tags                = local.tags

  lifecycle {
    ignore_changes = [
      number_of_record_sets
    ]
  }
}

locals {
  all_vnets = {
    "environment" = azurerm_virtual_network.environment.id
    "aks"         = azurerm_virtual_network.aks.id
    #    "databrick"   = azurerm_virtual_network.databrick.id
  }
  dns_zone_vnet_link = flatten([
    for short_privatelink, privatelink in local.privatelinks : [
      for vnet, vnet_id in local.all_vnets : {
        private_dns_zone       = privatelink
        privatelink_short_name = short_privatelink
        linked_vnet_short_name = vnet
        linked_vnet_id         = vnet_id
      }
    ]
    ]
  )
  map_dns_zone_vnet_link = { for object in local.dns_zone_vnet_link : format("%s-to-%s-vnet", replace(object.privatelink_short_name, ".", "-"), object.linked_vnet_short_name) => object }
}

resource "azurerm_private_dns_zone_virtual_network_link" "environment" {
  for_each              = local.map_dns_zone_vnet_link
  name                  = each.key
  resource_group_name   = data.azurerm_resource_group.infra-primary.name
  private_dns_zone_name = each.value.private_dns_zone
  registration_enabled  = false
  virtual_network_id    = each.value.linked_vnet_id
  tags                  = local.tags
}

# ado resources

data "azurerm_key_vault" "ado" {
  name                = var.azure_devops_pipeline_key_vault
  resource_group_name = data.terraform_remote_state.ado-automation.outputs.state_resource_group
}

data "azurerm_monitor_diagnostic_categories" "kv_ado" {
  resource_id = data.azurerm_key_vault.ado.id
}

resource "azurerm_monitor_diagnostic_setting" "kv_ado" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = data.azurerm_key_vault.ado.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_ado.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_ado.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_private_endpoint" "kv_ado" {
  name                = "pe-${data.azurerm_key_vault.ado.name}"
  location            = data.azurerm_key_vault.ado.location
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  subnet_id           = azurerm_subnet.environment["keyvault"].id
  tags                = local.tags

  private_service_connection {
    name                           = data.azurerm_key_vault.ado.name
    private_connection_resource_id = data.azurerm_key_vault.ado.id
    is_manual_connection           = false
    subresource_names              = ["Vault"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
  }

  private_dns_zone_group {
    name                 = "private-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.environment["privatelink.vaultcore"].id]
  }
}

data "azurerm_resource_group" "ado" {
  name = data.terraform_remote_state.ado-automation.outputs.state_resource_group
}

data "azurerm_storage_account" "ado" {
  name                = data.terraform_remote_state.ado-automation.outputs.state_storage_account
  resource_group_name = data.azurerm_resource_group.ado.name
}

locals {
  ado_pe_subresources = length(var.ado_private_endpoints_subresources_storage_accounts) > 0 ? var.ado_private_endpoints_subresources_storage_accounts : ["Blob"]
}

resource "azurerm_private_endpoint" "st_ado" {
  for_each            = { for subresource in local.ado_pe_subresources : lower(subresource) => subresource }
  name                = "pe-${lower(each.value)}-${data.azurerm_storage_account.ado.name}"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  subnet_id           = azurerm_subnet.environment["storage_account"].id
  tags                = local.tags

  private_service_connection {
    name                           = data.azurerm_storage_account.ado.name
    private_connection_resource_id = data.azurerm_storage_account.ado.id
    is_manual_connection           = false
    subresource_names              = [each.value] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
  }

  private_dns_zone_group {
    name                 = "private-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.environment["privatelink.${lower(each.value)}"].id]
  }
}

# gateway

resource "azurerm_user_assigned_identity" "gateway" {
  name                = "id-${var.project_naming_convention}-agw-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  tags                = local.tags
}

resource "azurerm_key_vault" "gateway" {
  name                       = "kv-${var.project_naming_convention}-agw-${local.common_naming}01"
  resource_group_name        = data.azurerm_resource_group.infra-primary.name
  location                   = data.azurerm_resource_group.infra-primary.location
  tenant_id                  = data.terraform_remote_state.ado-automation.outputs.tenant_id
  soft_delete_retention_days = 90 # The retention period must be kept at 90 days, the default value, as the Application Gateway doesn't support a different retention period yet
  purge_protection_enabled   = true
  sku_name                   = "standard"
  tags                       = local.tags

  network_acls {
    default_action = "Allow"
    #    default_action = "Deny"
    #    ip_rules       = local.all_authorized_ip_ranges
    bypass = "AzureServices"
  }

  lifecycle {
    ignore_changes = [
      access_policy
    ]
  }
}

data "azurerm_monitor_diagnostic_categories" "kv_gateway" {
  resource_id = azurerm_key_vault.gateway.id
}

resource "azurerm_monitor_diagnostic_setting" "kv_gateway" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_key_vault.gateway.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_gateway.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_gateway.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_private_endpoint" "kv_gateway" {
  name                = "pe-${azurerm_key_vault.gateway.name}"
  location            = azurerm_key_vault.gateway.location
  resource_group_name = azurerm_key_vault.gateway.resource_group_name
  subnet_id           = azurerm_subnet.environment["keyvault"].id
  tags                = local.tags

  private_service_connection {
    name                           = azurerm_key_vault.gateway.name
    private_connection_resource_id = azurerm_key_vault.gateway.id
    is_manual_connection           = false
    subresource_names              = ["Vault"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
  }

  private_dns_zone_group {
    name                 = "private-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.environment["privatelink.vaultcore"].id]
  }
}

resource "azurerm_key_vault_access_policy" "azure_devops_service_connection" {
  key_vault_id = azurerm_key_vault.gateway.id
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

resource "azurerm_key_vault_access_policy" "gateway" {
  key_vault_id = azurerm_key_vault.gateway.id
  tenant_id    = data.terraform_remote_state.ado-automation.outputs.tenant_id
  object_id    = azurerm_user_assigned_identity.gateway.principal_id

  secret_permissions = [
    "list",
    "get"
  ]

  certificate_permissions = [
    "list",
    "get"
  ]
}

resource "azurerm_key_vault_certificate" "gateway_self_signed_cert" {
  name         = "self-signed-gateway-cert"
  key_vault_id = azurerm_key_vault.gateway.id
  tags         = local.tags

  certificate_policy {
    issuer_parameters {
      name = "Self"
    }

    key_properties {
      exportable = true
      key_size   = 2048
      key_type   = "RSA"
      reuse_key  = true
    }

    lifetime_action {
      action {
        action_type = "AutoRenew"
      }

      trigger {
        days_before_expiry = 30
      }
    }

    secret_properties {
      content_type = "application/x-pkcs12"
    }

    x509_certificate_properties {
      # Server Authentication = 1.3.6.1.5.5.7.3.1
      # Client Authentication = 1.3.6.1.5.5.7.3.2
      extended_key_usage = ["1.3.6.1.5.5.7.3.1"]

      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]

      subject_alternative_names {
        dns_names = local.dns_subdomains
      }

      subject            = "CN=${var.gateway_https_domain}"
      validity_in_months = 12
    }
  }
}

resource "time_sleep" "wait_for_certificate_creation" {
  depends_on = [
    azurerm_key_vault_certificate.gateway_self_signed_cert,
  ]

  create_duration = "60s"
}

#resource "azurerm_key_vault_certificate" "gateway" {
#  name         = "gateway-certificate-pfx"
#  key_vault_id = azurerm_key_vault.gateway.id
#  tags         = local.tags
#
#  certificate_policy {
#    issuer_parameters {
#      name = "Self"
#    }
#
#    key_properties {
#      exportable = true
#      key_size   = 2048
#      key_type   = "RSA"
#      reuse_key  = true
#    }
#
#    lifetime_action {
#      action {
#        action_type = "AutoRenew"
#      }
#
#      trigger {
#        days_before_expiry = 30
#      }
#    }
#
#    secret_properties {
#      content_type = "application/x-pkcs12"
#    }
#  }
#
#  certificate {
#    contents = filebase64("gateway-${var.environment}-certificate.pfx")
#    password = ""
#  }
#}


resource "azurerm_public_ip" "gateway" {
  for_each            = { for gateway in local.gateway_snets : gateway.name => gateway }
  name                = "pip-${var.project_naming_convention}-${each.value.abbreviation}-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  #domain_name_label   = "pip-${var.project_naming_convention}-${each.value.abbreviation}-${local.common_naming}01"
  domain_name_label = "pip-derms-${each.value.abbreviation}-${local.common_naming}001"
  sku               = "Standard"
  allocation_method = "Static"
  tags              = local.tags
}

data "azurerm_monitor_diagnostic_categories" "pip_gateway" {
  for_each    = { for gateway in local.gateway_snets : gateway.name => gateway }
  resource_id = azurerm_public_ip.gateway[each.value.name].id
}

resource "azurerm_monitor_diagnostic_setting" "pip_gateway" {
  for_each                   = { for gateway in local.gateway_snets : gateway.name => gateway }
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_public_ip.gateway[each.value.name].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.pip_gateway[each.value.name].logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.pip_gateway[each.value.name].metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_application_gateway" "deployment" {
  for_each            = { for gateway in local.gateway_snets : gateway.name => gateway }
  name                = "agw-${var.project_naming_convention}-${each.value.abbreviation}-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  enable_http2        = var.gateway_http2_enabled
  zones               = ["1", "2", "3"]
  tags                = local.tags

  identity {
    identity_ids = [
      azurerm_user_assigned_identity.gateway.id
    ]
    type = "UserAssigned"
  }

  sku {
    name = "WAF_v2"
    tier = "WAF_v2"
  }

  # tonumber(regex("[^/]*$", azurerm_subnet.environment[gateway.name].address_prefix) will extract the network mask
  # to calculate the number of hosts available is 2^(32-Mask)
  # pow (x, y) is equal to x^y
  # we need to reserves five IP addresses in each subnet for internal use: the first four and the last IP addresses
  autoscale_configuration {
    min_capacity = 1
    max_capacity = pow(2, (32 - tonumber(regex("[^/]*$", azurerm_subnet.environment[each.value.name].address_prefix)))) - 5
  }

  waf_configuration {
    enabled          = true
    firewall_mode    = "Prevention"
    rule_set_type    = "OWASP"
    rule_set_version = "3.1"
  }

  ssl_policy {
    policy_name = "AppGwSslPolicy20170401S"
    policy_type = "Predefined"
  }

  gateway_ip_configuration {
    name      = "ip-configuration"
    subnet_id = azurerm_subnet.environment[each.value.name].id
  }

  # frontends

  frontend_ip_configuration {
    name                 = "frontend-public-ip"
    public_ip_address_id = azurerm_public_ip.gateway[each.value.name].id
  }

  frontend_port {
    name = "frontend-http-port"
    port = 80
  }

  frontend_port {
    name = "frontend-https-port"
    port = 443
  }

  http_listener {
    name                           = "listener-http"
    frontend_ip_configuration_name = "frontend-public-ip"
    frontend_port_name             = "frontend-http-port"
    protocol                       = "Http"
    host_name                      = "pip-derms-agw-green-dev-eus-p001.eastus.cloudapp.azure.com"
  }

  http_listener {
    name                           = "listener-https"
    frontend_ip_configuration_name = "frontend-public-ip"
    frontend_port_name             = "frontend-https-port"
    protocol                       = "Https"
    host_name                      = "pip-derms-agw-green-dev-eus-p001.eastus.cloudapp.azure.com"
    require_sni                    = false
    #    ssl_certificate_name           = var.gateway_https_certificate_exists ? azurerm_key_vault_certificate.gateway.name : azurerm_key_vault_certificate.gateway_self_signed.name
    ssl_certificate_name = var.gateway_https_certificate_exists ? azurerm_key_vault_certificate.gateway_self_signed_cert.name : azurerm_key_vault_certificate.gateway_self_signed_cert.name
  }

  ssl_certificate {
    #    name                = var.gateway_https_certificate_exists ? azurerm_key_vault_certificate.gateway.name : azurerm_key_vault_certificate.gateway_self_signed.name
    #    key_vault_secret_id = var.gateway_https_certificate_exists ? azurerm_key_vault_certificate.gateway.secret_id : azurerm_key_vault_certificate.gateway_self_signed.secret_id
    name                = var.gateway_https_certificate_exists ? azurerm_key_vault_certificate.gateway_self_signed_cert.name : azurerm_key_vault_certificate.gateway_self_signed_cert.name
    key_vault_secret_id = var.gateway_https_certificate_exists ? azurerm_key_vault_certificate.gateway_self_signed_cert.secret_id : azurerm_key_vault_certificate.gateway_self_signed_cert.secret_id
  }

  # backend pools

  # required field configured with dummy data as this is going to be managed by AGIC
  backend_address_pool {
    name = "dummy-backend-pool"
  }

  # required field configured with dummy data as this is going to be managed by AGIC
  backend_http_settings {
    name                                = "dummy-backend-http-setting"
    cookie_based_affinity               = "Disabled"
    port                                = 443
    protocol                            = "Https"
    request_timeout                     = 1
    pick_host_name_from_backend_address = false
    host_name                           = "dummy"
  }

  # routing rules

  request_routing_rule {
    name                       = "routing-rule-https"
    rule_type                  = "Basic"
    http_listener_name         = "listener-https"
    backend_address_pool_name  = "dummy-backend-pool"
    backend_http_settings_name = "dummy-backend-http-setting"
  }

  # force redirect from http to https

  redirect_configuration {
    name                 = "permanent-redirect-https"
    redirect_type        = "Permanent"
    include_path         = true
    include_query_string = true
    target_listener_name = "listener-https"
  }

  request_routing_rule {
    name                        = "routing-rule-http"
    rule_type                   = "Basic"
    http_listener_name          = "listener-http"
    redirect_configuration_name = "permanent-redirect-https"
  }

  # Ignore most changes as they will be managed by AGIC
  lifecycle {
    ignore_changes = [
      backend_address_pool,
      backend_http_settings,
      frontend_port,
      probe,
      request_routing_rule,
      url_path_map,
      redirect_configuration,
      autoscale_configuration,
      http_listener,
      tags,
      ssl_certificate
    ]
  }

  depends_on = [
    time_sleep.wait_for_certificate_creation,
    azurerm_network_security_rule.required_management_ports
  ]
}

#data "azurerm_monitor_diagnostic_categories" "agw_deployment" {
#  for_each    = { for gateway in local.gateway_snets : gateway.name => gateway }
#  resource_id = azurerm_application_gateway.deployment[each.value.name].id
#}

#resource "azurerm_monitor_diagnostic_setting" "agw_deployment" {
#  for_each                   = { for gateway in local.gateway_snets : gateway.name => gateway }
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_application_gateway.deployment[each.value.name].id
#  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.agw_deployment[each.value.name].logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.agw_deployment[each.value.name].metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}

# bastion

locals {
  bastion_index = index(local.vm_snets.*.name, "AzureBastionSubnet")
}

#resource "azurerm_public_ip" "bastion" {
#  count               = var.create_vm ? 1 : 0
#  name                = "pip-${var.project_naming_convention}-${local.vm_snets[local.bastion_index].abbreviation}-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.infra-primary.name
#  location            = data.azurerm_resource_group.infra-primary.location
#  domain_name_label   = "pip-${var.project_naming_convention}-${local.vm_snets[local.bastion_index].abbreviation}-${local.common_naming}01"
#  sku                 = "Standard"
#  allocation_method   = "Static"
#  tags                = local.tags
#}

#data "azurerm_monitor_diagnostic_categories" "pip_bastion" {
#  count       = var.create_vm ? 1 : 0
#  resource_id = azurerm_public_ip.bastion[count.index].id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "pip_bastion" {
#  count                      = var.create_vm ? 1 : 0
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_public_ip.bastion[count.index].id
#  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.pip_bastion[count.index].logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.pip_bastion[count.index].metrics
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
## https://docs.microsoft.com/en-us/azure/bastion/bastion-nsg#apply
resource "azurerm_network_security_rule" "bastion_inbound_internet" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-internet-inbound"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = 443
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_inbound_control_plane" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-gateway-manager-inbound"
  priority                    = 130
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = 443
  source_address_prefix       = "GatewayManager"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_inbound_loadbalancer" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-azure-loadbalancer-inbound"
  priority                    = 140
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = 443
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_inbound_data_plane" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-bastion-host-comunication-inbound"
  priority                    = 150
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_ranges     = [8080, 5701]
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "VirtualNetwork"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_outbound_virtual_machine" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-ssh-rdp-outbound"
  priority                    = 100
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_ranges     = [22, 3389]
  source_address_prefix       = "*"
  destination_address_prefix  = "VirtualNetwork"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_outbound_public_endpoints" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-azure-cloud-outbound"
  priority                    = 110
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = 443
  source_address_prefix       = "*"
  destination_address_prefix  = "AzureCloud"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_outbound_data_plane" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-bastion-host-comunication-outbound"
  priority                    = 120
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_ranges     = [8080, 5701]
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = "VirtualNetwork"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

resource "azurerm_network_security_rule" "bastion_outbound_internet" {
  count                       = var.create_vm ? 1 : 0
  name                        = "nsgsr-allow-internet-outbound"
  priority                    = 130
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = 80
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].resource_group_name
  network_security_group_name = azurerm_network_security_group.environment[local.vm_snets[local.bastion_index].name].name
}

##
# Create a Bastion VM
##
resource "azurerm_network_interface" "bastion_nic" {
  name                = "nic-bastion"
  location            = data.azurerm_resource_group.infra-primary.location
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.environment["virtual_machines"].id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "example" {
  name                            = "vm-bastion"
  location                        = data.azurerm_resource_group.infra-primary.location
  resource_group_name             = data.azurerm_resource_group.infra-primary.name
  size                            = "Standard_D2_v2"
  admin_username                  = var.vm_username
  admin_password                  = var.vm_password
  disable_password_authentication = false
  network_interface_ids = [
    azurerm_network_interface.bastion_nic.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

resource "azurerm_public_ip" "pip_azure_bastion" {
  name                = "pip-azure-bastion"
  location            = data.azurerm_resource_group.infra-primary.location
  resource_group_name = data.azurerm_resource_group.infra-primary.name

  allocation_method = "Static"
  sku               = "Standard"
}

resource "azurerm_bastion_host" "bastion" {
  #  for_each            = { for snet in local.enable_snets : snet.name => snet }
  count               = var.create_vm ? 1 : 0
  name                = "bas-${var.project_naming_convention}-${local.common_naming}01"
  location            = data.azurerm_resource_group.infra-primary.location
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  #  sku                 = "Standard"
  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.environment["AzureBastionSubnet"].id
    public_ip_address_id = azurerm_public_ip.pip_azure_bastion.id
  }
}

# aks blue/green deployment

resource "azurerm_virtual_network" "aks" {
  name                = "vnet-${var.project_naming_convention}-aks-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  address_space       = tolist([var.aks_vnet_cidr])
  tags                = local.tags

  lifecycle {
    ignore_changes = [
      subnet
    ]
  }
}

data "azurerm_monitor_diagnostic_categories" "vnet_aks" {
  resource_id = azurerm_virtual_network.aks.id
}

resource "azurerm_monitor_diagnostic_setting" "vnet_aks" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_virtual_network.aks.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.vnet_aks.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.vnet_aks.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_subnet" "aks" {
  for_each                                       = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name                                           = "snet-${var.project_naming_convention}-aks-${each.value.name}-${local.common_naming}01"
  resource_group_name                            = data.azurerm_resource_group.infra-primary.name
  virtual_network_name                           = azurerm_virtual_network.aks.name
  address_prefixes                               = tolist([each.value.aks_address_space])
  service_endpoints                              = ["Microsoft.KeyVault"]
  enforce_private_link_endpoint_network_policies = true
}

locals {
  detailed_enabled_aks_cluster = [
    for cluster in local.enabled_aks_cluster :
    merge({ for key, value in cluster : key => value if !contains(["aks_address_space", "gateway"], key) },
      {
        azure_vnet_name    = azurerm_virtual_network.aks.name
        azure_subnet_name  = azurerm_subnet.aks[cluster.name].name
        azure_gateway_name = "agw-${var.project_naming_convention}-${cluster.gateway.abbreviation}-${local.common_naming}01"
        #        azure_gateway_name = azurerm_application_gateway.deployment[cluster.gateway.name].name
    })
  ]
}

resource "azurerm_network_security_group" "aks" {
  for_each            = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name                = "nsg-${var.project_naming_convention}-aks-${each.value.name}-${local.common_naming}01"
  resource_group_name = data.azurerm_resource_group.infra-primary.name
  location            = data.azurerm_resource_group.infra-primary.location
  tags                = local.tags

  lifecycle {
    ignore_changes = [
      security_rule
    ]
  }
}

data "azurerm_monitor_diagnostic_categories" "nsg_aks" {
  for_each    = { for aks in local.enabled_aks_cluster : aks.name => aks }
  resource_id = azurerm_network_security_group.aks[each.value.name].id
}

resource "azurerm_monitor_diagnostic_setting" "nsg_aks" {
  for_each                   = { for aks in local.enabled_aks_cluster : aks.name => aks }
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_network_security_group.aks[each.value.name].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.nsg_aks[each.value.name].logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.nsg_aks[each.value.name].metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "aks" {
  for_each                  = { for aks in local.enabled_aks_cluster : aks.name => aks }
  network_security_group_id = azurerm_network_security_group.aks[each.value.name].id
  subnet_id                 = azurerm_subnet.aks[each.value.name].id
}

# Databrick resources

#resource "azurerm_virtual_network" "databrick" {
#  name                = "vnet-${var.project_naming_convention}-dbw-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.infra-primary.name
#  location            = data.azurerm_resource_group.infra-primary.location
#  address_space       = tolist([var.databrick_vnet_cidr])
#  tags                = local.tags
#}
#
#data "azurerm_monitor_diagnostic_categories" "vnet_databrick" {
#  resource_id = azurerm_virtual_network.databrick.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "vnet_databrick" {
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_virtual_network.databrick.id
#  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.vnet_databrick.logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.vnet_databrick.metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}

#resource "azurerm_subnet" "databrick" {
#  for_each             = { for subnet in local.databrick_subnets : subnet.name => subnet }
#  name                 = "snet-${var.project_naming_convention}-dbw-${each.value.name}-${local.common_naming}01"
#  resource_group_name  = data.azurerm_resource_group.infra-primary.name
#  virtual_network_name = azurerm_virtual_network.databrick.name
#  address_prefixes     = each.value.cidr
#
#  delegation {
#    name = "databricks-delegation-${each.value.name}-subnet"
#
#    service_delegation {
#      name = "Microsoft.Databricks/workspaces"
#      actions = [
#        "Microsoft.Network/virtualNetworks/subnets/join/action",
#        "Microsoft.Network/virtualNetworks/subnets/prepareNetworkPolicies/action",
#        "Microsoft.Network/virtualNetworks/subnets/unprepareNetworkPolicies/action"
#      ]
#    }
#  }
#}
#
#resource "azurerm_network_security_group" "databrick" {
#  for_each            = { for subnet in local.databrick_subnets : subnet.name => subnet }
#  name                = "nsg-${var.project_naming_convention}-dbw-${each.value.name}-${local.common_naming}01"
#  resource_group_name = data.azurerm_resource_group.infra-primary.name
#  location            = data.azurerm_resource_group.infra-primary.location
#  tags                = local.tags
#
#  lifecycle {
#    ignore_changes = [
#      security_rule
#    ]
#  }
#}
#
#data "azurerm_monitor_diagnostic_categories" "nsg_databrick" {
#  for_each    = { for subnet in local.databrick_subnets : subnet.name => subnet }
#  resource_id = azurerm_network_security_group.databrick[each.value.name].id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "nsg_databrick" {
#  for_each                   = { for subnet in local.databrick_subnets : subnet.name => subnet }
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_network_security_group.databrick[each.value.name].id
#  log_analytics_workspace_id = azurerm_log_analytics_workspace.environment.id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.nsg_databrick[each.value.name].logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.nsg_databrick[each.value.name].metrics
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
#resource "azurerm_subnet_network_security_group_association" "databrick" {
#  for_each                  = { for subnet in local.databrick_subnets : subnet.name => subnet }
#  network_security_group_id = azurerm_network_security_group.databrick[each.value.name].id
#  subnet_id                 = azurerm_subnet.databrick[each.value.name].id
#}

# vnet peering between all networks

#resource "azurerm_virtual_network_peering" "databrick_to_aks" {
#  name                      = "databrick_to_aks"
#  resource_group_name       = data.azurerm_resource_group.infra-primary.name
#  virtual_network_name      = azurerm_virtual_network.databrick.name
#  remote_virtual_network_id = azurerm_virtual_network.aks.id
#}

#resource "azurerm_virtual_network_peering" "databrick_to_environment" {
#  name                      = "databrick_to_environment"
#  resource_group_name       = data.azurerm_resource_group.infra-primary.name
#  virtual_network_name      = azurerm_virtual_network.databrick.name
#  remote_virtual_network_id = azurerm_virtual_network.environment.id
#}

#resource "azurerm_virtual_network_peering" "aks_to_databrick" {
#  name                      = "aks_to_databrick"
#  resource_group_name       = data.azurerm_resource_group.infra-primary.name
#  virtual_network_name      = azurerm_virtual_network.aks.name
#  remote_virtual_network_id = azurerm_virtual_network.databrick.id
#}

resource "azurerm_virtual_network_peering" "aks_to_environment" {
  name                      = "aks_to_environment"
  resource_group_name       = data.azurerm_resource_group.infra-primary.name
  virtual_network_name      = azurerm_virtual_network.aks.name
  remote_virtual_network_id = azurerm_virtual_network.environment.id
}

#resource "azurerm_virtual_network_peering" "environment_to_databrick" {
#  name                      = "environment_to_databrick"
#  resource_group_name       = data.azurerm_resource_group.infra-primary.name
#  virtual_network_name      = azurerm_virtual_network.environment.name
#  remote_virtual_network_id = azurerm_virtual_network.databrick.id
#}

resource "azurerm_virtual_network_peering" "environment_to_aks" {
  name                      = "environment_to_aks"
  resource_group_name       = data.azurerm_resource_group.infra-primary.name
  virtual_network_name      = azurerm_virtual_network.environment.name
  remote_virtual_network_id = azurerm_virtual_network.aks.id
}


# service health alerts

#data "azurerm_subscription" "current" {}

# Create Action Group for email notifications

#resource "azurerm_monitor_action_group" "actiongroup1" {
#  name                = "ag-evci-alert-we-${var.environment}"
#  resource_group_name = data.azurerm_resource_group.infra-primary.name
#  short_name          = "evci-ems-${var.environment}"
#
#  email_receiver {
#    name          = "sendtoadmin"
#    email_address = "helder.lloureiro@eaton.com"
#  }
#}

# Create Service Health Alerts

#resource "azurerm_monitor_activity_log_alert" "servicehealth" {
#  name                = "Service Health Alert-ECVI-${var.environment}"
#  resource_group_name = data.azurerm_resource_group.infra-primary.name
#  scopes              = [data.azurerm_subscription.current.id]
#  description         = "Service Health Alerts for Eaton-ES-EVCI-EMS-${var.environment}."
#
#  criteria {
#    category = "ServiceHealth"
#    service_health {
#      events    = ["Incident", "Maintenance", "Informational", "ActionRequired", "Security"]
#      locations = ["West Europe"]
#      services = ["Application Gateway", "Application Insights", "Azure Active Directory", "Azure Container Registry", "Azure DNS",
#        "Azure Data Lake Storage Gen 1", "Azure Databricks", "Azure IoT Hub", "Azure Kubernetes Service", "Azure Private Link", "Event Hubs",
#      "Functions", "Key Vault", "Load Balancer", "Log Analytics", "Logic Apps", "Network Infrastructure", "Redis Cache", "Storage", "Virtual Networks"]
#    }
#  }
#
#  action {
#    action_group_id = azurerm_monitor_action_group.actiongroup1.id
#  }
#}


# remote state files

locals {
  state_name = "infra-primary"
  terraform_state_config_content = templatefile(
    "../template/remote_state.tf.tpl",
    {
      state_name      = local.state_name
      resource_group  = data.terraform_remote_state.ado-automation.outputs.state_resource_group
      storage_account = data.terraform_remote_state.ado-automation.outputs.state_storage_account
      container_name  = data.terraform_remote_state.ado-automation.outputs.state_container_name
      key             = "${local.state_name}.tfstate"
    }
  )
}

resource "local_file" "remote_state_in_data_primary" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_state_config_content
  filename        = "../data-primary/remote_state_${local.state_name}.tf"
  file_permission = "0644"
}

resource "local_file" "remote_state_in_app_primary" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_state_config_content
  filename        = "../app-primary/remote_state_${local.state_name}.tf"
  file_permission = "0644"
}

resource "azurerm_resource_group" "rg" {
  name     = "ETN-ES-DERMS-RG-DDE"
  location = data.azurerm_resource_group.infra-primary.location
}

resource "azurerm_storage_account" "loadforecastappsa" {
  name                     = "loadforecastsa"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  /* network_rules  {
    default_action             = "Allow"
    virtual_network_subnet_ids = [azurerm_virtual_network.environment.id]
  } */
}

resource "azurerm_app_service_plan" "loadforecastappsp" {
  name                = "loadforecastsp"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "Linux"
  reserved            = true

  sku {
    tier = "Dynamic"
    size = "Y1"
  }

  lifecycle {
    ignore_changes = [
      kind
    ]
  }
}

resource "azurerm_function_app" "loadforecastapm" {
  name                       = "loadforecastapm"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  app_service_plan_id        = azurerm_app_service_plan.loadforecastappsp.id
  storage_account_name       = azurerm_storage_account.loadforecastappsa.name
  storage_account_access_key = azurerm_storage_account.loadforecastappsa.primary_access_key
  os_type                    = "linux"
  version                    = "~4"
  https_only                 = "true"
  
  app_settings = {
    FUNCTIONS_WORKER_RUNTIME = "python"
  }

  site_config {
    linux_fx_version = "python|3.9"
    min_tls_version = "1.2"
  }

  identity = {
    type = "SystemAssigned"
  }
}

resource "azurerm_storage_container" "loadforecastsc" {
  name                  = "loadforecastsc"
  storage_account_name  = azurerm_storage_account.loadforecastappsa.name
  container_access_type = "private"
}

resource "azurerm_storage_table" "loadforecaststperfres" {
  name                 = "perfresults"
  storage_account_name = azurerm_storage_account.loadforecastappsa.name
}

resource "azurerm_storage_table" "loadforecaststtestdatas" {
  name                 = "testdatas"
  storage_account_name = azurerm_storage_account.loadforecastappsa.name
}

resource "azurerm_storage_blob" "loadforecastsboutput" {
  name                   = "algorithmResults.zip"
  storage_account_name   = azurerm_storage_account.loadforecastappsa.name
  storage_container_name = azurerm_storage_container.loadforecastsc.name
  type                   = "Block"
}

resource "azurerm_storage_blob" "loadforecastsbtestdatas" {
  name                   = "testDatas.txt"
  storage_account_name   = azurerm_storage_account.loadforecastappsa.name
  storage_container_name = azurerm_storage_container.loadforecastsc.name
  type                   = "Block"
}

resource "azurerm_cosmosdb_account" "cosmos_db_account_dde" {
  name                = "etn-cosmosdb-account"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  enable_automatic_failover = true
  /* public_network_access_enabled = true
  is_virtual_network_filter_enabled = true

  virtual_network_rule {
    id = azurerm_virtual_network.aks.id
    ignore_missing_vnet_service_endpoint = true
  } */

  consistency_policy {
     consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.rg.location
    failover_priority = 0
  }
}

resource "azurerm_servicebus_namespace" "loadforecastsbn" {
  name                = "etn-servicebus-namespace"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  sku                 = "Standard"

  tags = {
    source = "terraform"
  }
}

resource "azurerm_servicebus_queue" "loadforecastsbq" {
  name         = "etn_servicebus_queue"
  /* namespace_id = azurerm_servicebus_namespace.loadforecastsbn.id */
  resource_group_name = azurerm_resource_group.rg.name
  namespace_name = azurerm_servicebus_namespace.loadforecastsbn.name

  enable_partitioning = true
}

data "azurerm_advisor_recommendations" "ad-recommandations" {
  filter_by_category        = ["HighAvailability", "security", "Performance", "cost", "OperationalExcellence"]
}

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "eaton_dde_keyvault" {
  name                        = "etnddekeyvault"
  location                    = azurerm_resource_group.rg.location
  resource_group_name         = azurerm_resource_group.rg.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = true

  sku_name = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Get",
    ]

    secret_permissions = [
      "Get",
    ]

    storage_permissions = [
      "Get",
    ]
  }
}