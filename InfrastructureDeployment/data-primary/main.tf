provider "azurerm" {
  features {
    # so it doesn't purge them in key vault when deleting it from terraform
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

data "azurerm_resource_group" "data-primary" {
  #  name = "ETN-ES-DERMS-Data-Primary"
  name = "ETN-ES-DERMS-ContainerOrchestration"
}

locals {
  common_naming                   = "${var.environment}-${data.terraform_remote_state.ado-automation.outputs.location_short}-${var.environment_qualifier}"
  infra_primary_resource_group    = data.terraform_remote_state.infra-primary.outputs.resource_group
  all_authorized_ip_ranges        = data.terraform_remote_state.ado-automation.outputs.all_authorized_ip_ranges
  environment_vnet_name           = data.terraform_remote_state.infra-primary.outputs.environment_vnet
  environment_vnet_resource_group = data.terraform_remote_state.infra-primary.outputs.resource_group
  environment_subnets             = data.terraform_remote_state.infra-primary.outputs.environment_subnets
}

data "azurerm_subnet" "environment" {
  for_each             = local.environment_subnets
  name                 = each.value
  virtual_network_name = local.environment_vnet_name
  resource_group_name  = local.environment_vnet_resource_group
}

#data "external" "my_public_ip_address" {
#  program = ["bash", "-c", "curl -s 'https://api.ipify.org?format=json'"]
#}

# Key Vault

resource "azurerm_key_vault" "data-primary" {
  name                       = "kv-${var.project_naming_convention}-data-${local.common_naming}1"
  resource_group_name        = data.azurerm_resource_group.data-primary.name
  location                   = data.azurerm_resource_group.data-primary.location
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

data "azurerm_monitor_diagnostic_categories" "kv_data" {
  resource_id = azurerm_key_vault.data-primary.id
}

resource "azurerm_monitor_diagnostic_setting" "kv_data" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_key_vault.data-primary.id
  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_data.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.kv_data.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_private_endpoint" "kv_data-primary" {
  name                = "pe-${azurerm_key_vault.data-primary.name}"
  location            = var.location
  resource_group_name = local.infra_primary_resource_group
  subnet_id           = data.azurerm_subnet.environment["keyvault"].id

  private_service_connection {
    name                           = azurerm_key_vault.data-primary.name
    private_connection_resource_id = azurerm_key_vault.data-primary.id
    is_manual_connection           = false
    subresource_names              = ["Vault"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
  }
}

resource "azurerm_key_vault_access_policy" "azure_devops_service_connection" {
  key_vault_id = azurerm_key_vault.data-primary.id
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

# Big data platform - it's the cold store of all the data for later analytics and future model improvements

#resource "random_id" "pgsql_random_part_admin_user" {
#  byte_length = 8
#}
#
#locals {
#  pgsql_name = "psql-${var.project_naming_convention}-bdp-${local.common_naming}01"
#}
#
#resource "azurerm_key_vault_secret" "pgsql_admin_user" {
#  name         = "${local.pgsql_name}-admin-user"
#  value        = "${var.project_naming_convention}${random_id.pgsql_random_part_admin_user.hex}"
#  key_vault_id = azurerm_key_vault.data-primary.id
#  depends_on = [
#    azurerm_key_vault_access_policy.azure_devops_service_connection
#  ]
#}
#
#resource "azurerm_key_vault_secret" "pgsql_admin_pass" {
#  name         = "${local.pgsql_name}-admin-pass"
#  value        = uuid()
#  key_vault_id = azurerm_key_vault.data-primary.id
#  depends_on = [
#    azurerm_key_vault_access_policy.azure_devops_service_connection
#  ]
#
#  lifecycle {
#    ignore_changes = [
#      value
#    ]
#  }
#}
#
#resource "azurerm_postgresql_server" "bdp" {
#  name                             = local.pgsql_name
#  resource_group_name              = data.azurerm_resource_group.data-primary.name
#  location                         = data.azurerm_resource_group.data-primary.location
#  sku_name                         = var.postgres_sku_name
#  version                          = var.postgres_version
#  create_mode                      = var.postgres_creation_mode
#  creation_source_server_id        = (var.postgres_creation_mode != "Default") ? var.postgres_creation_source_server_id : null
#  administrator_login              = (var.postgres_creation_mode == "Default") ? azurerm_key_vault_secret.pgsql_admin_user.value : null
#  administrator_login_password     = (var.postgres_creation_mode == "Default") ? azurerm_key_vault_secret.pgsql_admin_pass.value : null
#  backup_retention_days            = var.postgres_backup_retention_days
#  geo_redundant_backup_enabled     = var.postgres_geo_redudant_backup
#  storage_mb                       = var.postgres_storage_mb
#  auto_grow_enabled                = true
#  public_network_access_enabled    = true
#  ssl_enforcement_enabled          = true
#  ssl_minimal_tls_version_enforced = "TLS1_2"
#
#  identity {
#    type = "SystemAssigned"
#  }
#
#  threat_detection_policy {
#    disabled_alerts      = []
#    email_account_admins = false
#    email_addresses      = []
#    enabled              = true
#    retention_days       = 0
#  }
#}
#
#data "azurerm_monitor_diagnostic_categories" "psql_bdp" {
#  resource_id = azurerm_postgresql_server.bdp.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "psql_bdp" {
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_postgresql_server.bdp.id
#  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.psql_bdp.logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.psql_bdp.metrics
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
#resource "azurerm_private_endpoint" "psql_bdp" {
#  name                = "pe-${azurerm_postgresql_server.bdp.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["postgresql"].id
#
#  private_service_connection {
#    name                           = azurerm_postgresql_server.bdp.name
#    private_connection_resource_id = azurerm_postgresql_server.bdp.id
#    is_manual_connection           = false
#    subresource_names              = ["postgresqlServer"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}
#
#resource "azurerm_postgresql_firewall_rule" "allow_azure_services" {
#  name                = "allow-azure-services"
#  resource_group_name = data.azurerm_resource_group.data-primary.name
#  server_name         = azurerm_postgresql_server.bdp.name
#  start_ip_address    = "0.0.0.0"
#  end_ip_address      = "0.0.0.0"
#}

# we will remove this policy when we disable public access
#resource "azurerm_postgresql_firewall_rule" "allow_my_public_ip_address" {
#  name                = "allow-terraform-public-ip-address"
#  resource_group_name = data.azurerm_resource_group.data-primary.name
#  server_name         = azurerm_postgresql_server.bdp.name
#  start_ip_address    = "0.0.0.0"         #data.external.my_public_ip_address.result.ip
#  end_ip_address      = "255.255.255.255" #data.external.my_public_ip_address.result.ip
#}

#resource "azurerm_key_vault_access_policy" "pgsql" {
#  key_vault_id       = azurerm_key_vault.data-primary.id
#  tenant_id          = data.terraform_remote_state.ado-automation.outputs.tenant_id
#  object_id          = azurerm_postgresql_server.bdp.identity[0].principal_id
#  key_permissions    = ["get", "unwrapkey", "wrapkey"]
#  secret_permissions = ["get"]
#}

#resource "azurerm_storage_account" "bdp" {
#  name                     = replace("st-${var.project_naming_convention}-bdp-${local.common_naming}01", "-", "")
#  resource_group_name      = data.azurerm_resource_group.data-primary.name
#  location                 = data.azurerm_resource_group.data-primary.location
#  account_kind             = var.bdp_storage_account_kind
#  account_tier             = var.bdp_storage_account_tier
#  account_replication_type = var.bdp_storage_account_replication
#  access_tier              = ((var.bdp_storage_account_kind == "BlobStorage") || (var.bdp_storage_account_kind == "FileStorage") || (var.bdp_storage_account_kind == "StorageV2")) ? var.bdp_storage_account_access_tier : null
#  min_tls_version          = var.minimum_tls_version
#  is_hns_enabled           = ((var.bdp_storage_account_tier == "Standard") || ((var.bdp_storage_account_tier == "Premium") && (var.bdp_storage_account_kind == "BlockBlobStorage"))) ? var.bdp_storage_datalake_v2 : null
#  tags                     = {}
#}
#
#resource "azurerm_private_endpoint" "st_blob_bdp" {
#  name                = "pe-blob-${azurerm_storage_account.bdp.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["storage_account"].id
#
#  private_service_connection {
#    name                           = azurerm_storage_account.bdp.name
#    private_connection_resource_id = azurerm_storage_account.bdp.id
#    is_manual_connection           = false
#    subresource_names              = ["Blob"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}
#
#resource "azurerm_private_endpoint" "st_table_bdp" {
#  name                = "pe-table-${azurerm_storage_account.bdp.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["storage_account"].id
#
#  private_service_connection {
#    name                           = azurerm_storage_account.bdp.name
#    private_connection_resource_id = azurerm_storage_account.bdp.id
#    is_manual_connection           = false
#    subresource_names              = ["Table"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}
#
#resource "azurerm_private_endpoint" "st_queue_bdp" {
#  name                = "pe-queue-${azurerm_storage_account.bdp.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["storage_account"].id
#
#  private_service_connection {
#    name                           = azurerm_storage_account.bdp.name
#    private_connection_resource_id = azurerm_storage_account.bdp.id
#    is_manual_connection           = false
#    subresource_names              = ["Queue"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}
#
#resource "azurerm_private_endpoint" "st_file_bdp" {
#  name                = "pe-file-${azurerm_storage_account.bdp.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["storage_account"].id
#
#  private_service_connection {
#    name                           = azurerm_storage_account.bdp.name
#    private_connection_resource_id = azurerm_storage_account.bdp.id
#    is_manual_connection           = false
#    subresource_names              = ["File"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}
#
#resource "azurerm_private_endpoint" "st_web_bdp" {
#  name                = "pe-web-${azurerm_storage_account.bdp.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["storage_account"].id
#
#  private_service_connection {
#    name                           = azurerm_storage_account.bdp.name
#    private_connection_resource_id = azurerm_storage_account.bdp.id
#    is_manual_connection           = false
#    subresource_names              = ["Web"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}
#
#resource "azurerm_storage_container" "bdp" {
#  name                  = "bdp"
#  storage_account_name  = azurerm_storage_account.bdp.name
#  container_access_type = "private"
#}

#resource "azurerm_data_factory" "bdp" {
#  name                = "adf-${var.project_naming_convention}-bdp-${local.common_naming}01"
#  location            = data.azurerm_resource_group.data-primary.location
#  resource_group_name = data.azurerm_resource_group.data-primary.name
#
#  identity {
#    type = "SystemAssigned"
#  }
#
#  # We don't need this atm because we are automatizing all using terraform
#  #vsts_configuration {
#  #  account_name = "etn-esb"
#  #  project_name = "EVCI_EMS"
#  #  repository_name = "etib-de-dev-datafactory"
#  #  branch_name = "master"
#  #  root_folder = "/"
#  #  tenant_id = data.azurerm_client_config.current.tenant_id
#  #}
#
#  lifecycle {
#    ignore_changes = [
#      tags
#    ]
#  }
#}
#
#data "azurerm_monitor_diagnostic_categories" "adf_bdp" {
#  resource_id = azurerm_data_factory.bdp.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "adf_bdp" {
#  name                           = "sent-to-log-analytics"
#  target_resource_id             = azurerm_data_factory.bdp.id
#  log_analytics_workspace_id     = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#  log_analytics_destination_type = "AzureDiagnostics" # https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_diagnostic_setting#log_analytics_destination_type
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.adf_bdp.logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.adf_bdp.metrics
#    content {
#      category = metric.value
#      retention_policy {
#        days    = 0
#        enabled = false
#      }
#    }
#  }
#}

#resource "azurerm_databricks_workspace" "bdp" {
#  name                        = "dbw-${var.project_naming_convention}-bdp-${local.common_naming}01"
#  location                    = data.azurerm_resource_group.data-primary.location
#  resource_group_name         = data.azurerm_resource_group.data-primary.name
#  sku                         = var.bdp_databrick_workspace_sku
#  managed_resource_group_name = "dbw-${var.project_naming_convention}-bdp-${var.location}"
#
#  custom_parameters {
#    virtual_network_id                                   = data.terraform_remote_state.infra-primary.outputs.databrick_vnet_id
#    storage_account_name                                 = replace("st-${var.project_naming_convention}-dbw-${local.common_naming}01", "-", "")
#    public_subnet_name                                   = data.terraform_remote_state.infra-primary.outputs.databrick_public_snet
#    public_subnet_network_security_group_association_id  = data.terraform_remote_state.infra-primary.outputs.databrick_public_snet_nsg_association_id
#    private_subnet_name                                  = data.terraform_remote_state.infra-primary.outputs.databrick_private_snet
#    private_subnet_network_security_group_association_id = data.terraform_remote_state.infra-primary.outputs.databrick_private_snet_nsg_association_id
#  }
#}

#resource "azurerm_role_assignment" "bdp" {
#  scope                = azurerm_databricks_workspace.bdp.id
#  role_definition_name = "Contributor"
#  principal_id         = azurerm_data_factory.bdp.identity[0].principal_id
#}

#locals {
#  databrick_url = "https://${azurerm_databricks_workspace.bdp.workspace_url}"
#}
#
#
#resource "null_resource" "databricks_token" {
#  triggers = {
#    workspace = azurerm_databricks_workspace.bdp.id
#  }
#  provisioner "local-exec" {
#    command = "chmod +x ${path.root}/generate-databrick-token.sh && ${path.root}/generate-databrick-token.sh"
#    environment = {
#      DATABRICKS_ENDPOINT              = local.databrick_url
#      DATABRICKS_WORKSPACE_RESOURCE_ID = azurerm_databricks_workspace.bdp.id
#      KEY_VAULT                        = azurerm_key_vault.data-primary.name
#      SECRET_NAME                      = "databrick-token"
#    }
#  }
#  depends_on = [
#    azurerm_key_vault_access_policy.azure_devops_service_connection
#  ]
#}

# redis

#resource "azurerm_redis_cache" "environment" {
#  name                          = "redis-${var.project_naming_convention}-${local.common_naming}01"
#  resource_group_name           = data.azurerm_resource_group.data-primary.name
#  location                      = data.azurerm_resource_group.data-primary.location
#  capacity                      = var.redis_capacity
#  family                        = var.redis_family
#  sku_name                      = var.redis_sku
#  enable_non_ssl_port           = var.redis_enable_non_ssl_port
#  public_network_access_enabled = false
#  subnet_id                     = (var.redis_sku == "Premium") ? data.azurerm_subnet.environment["redis"].id : null # This Subnet must only contain Azure Cache for Redis instances without any other type of resources.
#
#  minimum_tls_version = "1.2"
#  redis_version       = 6
#  redis_configuration {
#  }
#}
#
#data "azurerm_monitor_diagnostic_categories" "redis" {
#  resource_id = azurerm_redis_cache.environment.id
#}
#
#resource "azurerm_monitor_diagnostic_setting" "redis" {
#  name                       = "sent-to-log-analytics"
#  target_resource_id         = azurerm_redis_cache.environment.id
#  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id
#
#  dynamic "log" {
#    for_each = data.azurerm_monitor_diagnostic_categories.redis.logs
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
#    for_each = data.azurerm_monitor_diagnostic_categories.redis.metrics
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
#resource "azurerm_private_endpoint" "redis_environment" {
#  name                = "pe-${azurerm_redis_cache.environment.name}"
#  location            = var.location
#  resource_group_name = local.infra_primary_resource_group
#  subnet_id           = data.azurerm_subnet.environment["redis"].id
#
#  private_service_connection {
#    name                           = azurerm_redis_cache.environment.name
#    private_connection_resource_id = azurerm_redis_cache.environment.id
#    is_manual_connection           = false
#    subresource_names              = ["redisCache"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
#  }
#}

# container registry

resource "azurerm_container_registry" "environment" {
  name                          = replace("cr-${var.project_naming_convention}-${local.common_naming}01", "-", "")
  resource_group_name           = data.azurerm_resource_group.data-primary.name
  location                      = data.azurerm_resource_group.data-primary.location
  sku                           = var.acr_sku
  admin_enabled                 = var.acr_admin_enabled
  public_network_access_enabled = var.acr_public_access_enabled
  zone_redundancy_enabled       = var.acr_zone_redundancy_enabled

  identity {
    type = "SystemAssigned"
  }
}

data "azurerm_monitor_diagnostic_categories" "cr" {
  resource_id = azurerm_container_registry.environment.id
}

resource "azurerm_monitor_diagnostic_setting" "cr" {
  name                       = "sent-to-log-analytics"
  target_resource_id         = azurerm_container_registry.environment.id
  log_analytics_workspace_id = data.terraform_remote_state.infra-primary.outputs.log_analytics_workspace_id

  dynamic "log" {
    for_each = data.azurerm_monitor_diagnostic_categories.cr.logs
    content {
      category = log.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = data.azurerm_monitor_diagnostic_categories.cr.metrics
    content {
      category = metric.value
      retention_policy {
        days    = 0
        enabled = false
      }
    }
  }
}

resource "azurerm_private_endpoint" "cr_environment" {
  count               = var.acr_sku == "Premium" ? 1 : 0
  name                = "pe-${azurerm_container_registry.environment.name}"
  location            = var.location
  resource_group_name = local.infra_primary_resource_group
  subnet_id           = data.azurerm_subnet.environment["container_registry"].id

  private_service_connection {
    name                           = azurerm_container_registry.environment.name
    private_connection_resource_id = azurerm_container_registry.environment.id
    is_manual_connection           = false
    subresource_names              = ["registry"] # https://docs.microsoft.com/en-us/azure/private-link/private-endpoint-overview#private-link-resource
  }
}

resource "azurerm_key_vault_secret" "cr_admin_user" {
  count        = var.acr_admin_enabled ? 1 : 0
  name         = "${azurerm_container_registry.environment.name}-admin-user"
  value        = azurerm_container_registry.environment.admin_username
  key_vault_id = azurerm_key_vault.data-primary.id
  depends_on = [
    azurerm_key_vault_access_policy.azure_devops_service_connection
  ]
}

resource "azurerm_key_vault_secret" "cr_admin_pass" {
  count        = var.acr_admin_enabled ? 1 : 0
  name         = "${azurerm_container_registry.environment.name}-admin-pass"
  value        = azurerm_container_registry.environment.admin_password
  key_vault_id = azurerm_key_vault.data-primary.id
  depends_on = [
    azurerm_key_vault_access_policy.azure_devops_service_connection
  ]
}

# iot hub

#resource "azurerm_storage_account" "iot" {
#  name                     = replace("st-${var.project_naming_convention}-iot-${local.common_naming}01", "-", "")
#  resource_group_name      = data.azurerm_resource_group.data-primary.name
#  location                 = data.azurerm_resource_group.data-primary.location
#  account_kind             = var.iot_storage_account_kind
#  account_tier             = var.iot_storage_account_tier
#  account_replication_type = var.iot_storage_account_replication
#  access_tier              = ((var.iot_storage_account_kind == "BlobStorage") || (var.iot_storage_account_kind == "FileStorage") || (var.iot_storage_account_kind == "StorageV2")) ? var.iot_storage_account_access_tier : null
#  min_tls_version          = var.minimum_tls_version
#  tags                     = {}
#}
#
#resource "azurerm_storage_container" "iot" {
#  name                  = "iot"
#  storage_account_name  = azurerm_storage_account.iot.name
#  container_access_type = "private"
#}

# Storage account test etib-control2

#resource "azurerm_storage_account" "etib-control2" {
#  name                     = replace("st-${var.project_naming_convention}-control2-${local.common_naming}01", "-", "")
#  resource_group_name      = data.azurerm_resource_group.data-primary.name
#  location                 = data.azurerm_resource_group.data-primary.location
#  account_kind             = var.etib_control2_storage_account_kind
#  account_tier             = var.etib_control2_storage_account_tier
#  account_replication_type = var.etib_control2_storage_account_replication
#  access_tier              = ((var.etib_control2_storage_account_kind == "BlobStorage") || (var.etib_control2_storage_account_kind == "FileStorage") || (var.etib_control2_storage_account_kind == "Storage")) ? var.etib_control2_storage_account_access_tier : null
#  min_tls_version          = var.minimum_tls_version
#  tags                     = {}
#}

# remote state files

locals {
  state_name = "data-primary"
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

#resource "local_file" "remote_state_in_infra_primary" {
#  count           = var.local_terraform_state ? 0 : 1
#  content         = local.terraform_state_config_content
#  filename        = "../infra-primary/remote_state_${local.state_name}.tf"
#  file_permission = "0644"
#}

#resource "local_file" "remote_state_in_data_primary" {
#  count           = var.local_terraform_state ? 0 : 1
#  content         = local.terraform_state_config_content
#  filename        = "../data-primary/remote_state_${local.state_name}.tf"
#  file_permission = "0644"
#}

resource "local_file" "remote_state_in_app_primary" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_state_config_content
  filename        = "../app-primary/remote_state_${local.state_name}.tf"
  file_permission = "0644"
}
