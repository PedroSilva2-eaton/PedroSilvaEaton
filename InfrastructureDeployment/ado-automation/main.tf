provider "azurerm" {
  features {
    # so it doesn't purge them in key vault when deleting it from terraform
    key_vault {
      purge_soft_delete_on_destroy = false
    }
  }
}

data "azurerm_subscription" "current" {}

data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "terraform_state" {
  name = var.terraform_state_resource_group
}

data "azurerm_storage_account" "terraform_state" {
  name                = var.terraform_state_storage_account
  resource_group_name = data.azurerm_resource_group.terraform_state.name
}

data "azurerm_storage_container" "terraform_state" {
  name                 = var.terraform_state_container
  storage_account_name = data.azurerm_storage_account.terraform_state.name
}

data "azurerm_key_vault" "azure_devops_pipeline" {
  name                = var.azure_devops_pipeline_key_vault
  resource_group_name = data.azurerm_resource_group.terraform_state.name
}

# autorized ips

data "dns_a_record_set" "ubiwhere" {
  host = "server.ubiwhere.com"
}

resource "null_resource" "chmod" {
  triggers = {
    always_run = "${timestamp()}"
  }
  provisioner "local-exec" {
    command = "chmod +x ${path.root}/retrieve_authorized_ip_ranges.sh"
  }
}


data "external" "retrieve_authorized_ip_ranges" {
  program = ["bash", "-c", "${path.root}/retrieve_authorized_ip_ranges.sh"]
}

locals {
  azure                    = split("\n", data.external.retrieve_authorized_ip_ranges.result.azure)
  zscaler                  = split("\n", data.external.retrieve_authorized_ip_ranges.result.zscaler)
  all_authorized_ip_ranges = concat(local.azure, local.zscaler, data.dns_a_record_set.ubiwhere.addrs, var.environment_extra_auth_ips, )
}

# local backend

locals {
  # Azure region mapping between standard format and it's short format for resource naming purpose
  regions = {
    "eastus" = "eus"
  }
  terraform_provider_config_content = templatefile(
    "../template/backend.tf.tpl",
    {
      terraform_fixed_version         = var.terraform_fixed_version
      azurerm_provider_fixed_version  = var.azurerm_provider_fixed_version
      local_provider_fixed_version    = var.local_provider_fixed_version
      template_provider_fixed_version = var.template_provider_fixed_version
      null_provider_fixed_version     = var.null_provider_fixed_version
      random_provider_fixed_version   = var.random_provider_fixed_version
      time_provider_fixed_version     = var.time_provider_fixed_version
      dns_provider_fixed_version      = var.dns_provider_fixed_version
      external_provider_fixed_version = var.external_provider_fixed_version
      resource_group                  = data.azurerm_resource_group.terraform_state.name
      storage_account                 = data.azurerm_storage_account.terraform_state.name
      container_name                  = data.azurerm_storage_container.terraform_state.name
      key                             = "ado-automation.tfstate"
      subscription_id                 = data.azurerm_subscription.current.subscription_id
      tenant_id                       = data.azurerm_client_config.current.tenant_id
    }
  )
}

resource "local_file" "terraform_backend_config" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_provider_config_content
  filename        = "backend.tf"
  file_permission = "0644"
}

# infra-primary backend

locals {
  terraform_infra_primary_backend_config_content = templatefile(
    "../template/backend.tf.tpl",
    {
      terraform_fixed_version         = var.terraform_fixed_version
      azurerm_provider_fixed_version  = var.azurerm_provider_fixed_version
      local_provider_fixed_version    = var.local_provider_fixed_version
      template_provider_fixed_version = var.template_provider_fixed_version
      null_provider_fixed_version     = var.null_provider_fixed_version
      random_provider_fixed_version   = var.random_provider_fixed_version
      time_provider_fixed_version     = var.time_provider_fixed_version
      dns_provider_fixed_version      = var.dns_provider_fixed_version
      external_provider_fixed_version = var.external_provider_fixed_version
      resource_group                  = data.azurerm_resource_group.terraform_state.name
      storage_account                 = data.azurerm_storage_account.terraform_state.name
      container_name                  = data.azurerm_storage_container.terraform_state.name
      key                             = "infra-primary.tfstate"
      subscription_id                 = data.azurerm_subscription.current.subscription_id
      tenant_id                       = data.azurerm_client_config.current.tenant_id
    }
  )
}

resource "local_file" "terraform_infra_primary_backend_config" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_infra_primary_backend_config_content
  filename        = "../infra-primary/backend.tf"
  file_permission = "0644"
}

# data-primary backend

locals {
  terraform_data_primary_backend_config_content = templatefile(
    "../template/backend.tf.tpl",
    {
      terraform_fixed_version         = var.terraform_fixed_version
      azurerm_provider_fixed_version  = var.azurerm_provider_fixed_version
      local_provider_fixed_version    = var.local_provider_fixed_version
      template_provider_fixed_version = var.template_provider_fixed_version
      null_provider_fixed_version     = var.null_provider_fixed_version
      random_provider_fixed_version   = var.random_provider_fixed_version
      time_provider_fixed_version     = var.time_provider_fixed_version
      dns_provider_fixed_version      = var.dns_provider_fixed_version
      external_provider_fixed_version = var.external_provider_fixed_version
      resource_group                  = data.azurerm_resource_group.terraform_state.name
      storage_account                 = data.azurerm_storage_account.terraform_state.name
      container_name                  = data.azurerm_storage_container.terraform_state.name
      key                             = "data-primary.tfstate"
      subscription_id                 = data.azurerm_subscription.current.subscription_id
      tenant_id                       = data.azurerm_client_config.current.tenant_id
    }
  )
}

resource "local_file" "terraform_data_primary_backend_config" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_data_primary_backend_config_content
  filename        = "../data-primary/backend.tf"
  file_permission = "0644"
}

# app-primary backend

locals {
  terraform_app_primary_backend_config_content = templatefile(
    "../template/backend-extra-providers.tf.tpl",
    {
      terraform_fixed_version           = var.terraform_fixed_version
      azurerm_provider_fixed_version    = var.azurerm_provider_fixed_version
      local_provider_fixed_version      = var.local_provider_fixed_version
      template_provider_fixed_version   = var.template_provider_fixed_version
      null_provider_fixed_version       = var.null_provider_fixed_version
      random_provider_fixed_version     = var.random_provider_fixed_version
      time_provider_fixed_version       = var.time_provider_fixed_version
      dns_provider_fixed_version        = var.dns_provider_fixed_version
      external_provider_fixed_version   = var.external_provider_fixed_version
      databrick_provider_fixed_version  = var.databrick_provider_fixed_version
      postgresql_provider_fixed_version = var.postgresql_provider_fixed_version
      tls_provider_fixed_version        = var.tls_provider_fixed_version
      resource_group                    = data.azurerm_resource_group.terraform_state.name
      storage_account                   = data.azurerm_storage_account.terraform_state.name
      container_name                    = data.azurerm_storage_container.terraform_state.name
      key                               = "app-primary.tfstate"
      subscription_id                   = data.azurerm_subscription.current.subscription_id
      tenant_id                         = data.azurerm_client_config.current.tenant_id
    }
  )
}

resource "local_file" "terraform_app_primary_backend_config" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_app_primary_backend_config_content
  filename        = "../app-primary/backend.tf"
  file_permission = "0644"
}

# remote state files

locals {
  terraform_state_config_content = templatefile(
    "../template/remote_state.tf.tpl",
    {
      state_name      = "ado-automation"
      resource_group  = data.azurerm_resource_group.terraform_state.name
      storage_account = data.azurerm_storage_account.terraform_state.name
      container_name  = data.azurerm_storage_container.terraform_state.name
      key             = "ado-automation.tfstate"
    }
  )
}

resource "local_file" "remote_state_in_infra_primary" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_state_config_content
  filename        = "../infra-primary/remote_state_ado_automation.tf"
  file_permission = "0644"
}

resource "local_file" "remote_state_in_data_primary" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_state_config_content
  filename        = "../data-primary/remote_state_ado_automation.tf"
  file_permission = "0644"
}

resource "local_file" "remote_state_in_app_primary" {
  count           = var.local_terraform_state ? 0 : 1
  content         = local.terraform_state_config_content
  filename        = "../app-primary/remote_state_ado_automation.tf"
  file_permission = "0644"
}

