terraform {
  required_version = ">= ${terraform_fixed_version}"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= ${azurerm_provider_fixed_version}"
    }
    local = {
      source  = "hashicorp/local"
      version = "= ${local_provider_fixed_version}"
    }
    template = {
      source  = "hashicorp/template"
      version = "= ${template_provider_fixed_version}"
    }
    null = {
      source  = "hashicorp/null"
      version = "= ${null_provider_fixed_version}"
    }
    random = {
      source  = "hashicorp/random"
      version = "= ${random_provider_fixed_version}"
    }
    time = {
      source  = "hashicorp/time"
      version = "= ${time_provider_fixed_version}"
    }
    dns = {
      source  = "hashicorp/dns"
      version = "= ${dns_provider_fixed_version}"
    }
    external = {
      source  = "hashicorp/external"
      version = "= ${external_provider_fixed_version}"
    }
    databricks = {
      source  = "databrickslabs/databricks"
      version = "= ${databrick_provider_fixed_version}"
      configuration_aliases = [
        databricks.bdp
      ]
    }
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "= ${postgresql_provider_fixed_version}"
      configuration_aliases = [
        postgresql.admin,
        postgresql.bdp
      ]
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= ${tls_provider_fixed_version}"
    }
  }

  backend "azurerm" {
    resource_group_name  = "${resource_group}"
    storage_account_name = "${storage_account}"
    container_name       = "${container_name}"
    key                  = "${key}"
    subscription_id      = "${subscription_id}"
    tenant_id            = "${tenant_id}"
  }
}
