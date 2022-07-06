terraform {
  required_version = ">= 1.1.3"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 2.90.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "= 2.1.0"
    }
    template = {
      source  = "hashicorp/template"
      version = "= 2.2.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "= 3.1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.1.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "= 0.7.2"
    }
    dns = {
      source  = "hashicorp/dns"
      version = "= 3.2.1"
    }
    external = {
      source  = "hashicorp/external"
      version = "= 2.2.0"
    }
    databricks = {
      source  = "databrickslabs/databricks"
      version = "= 0.4.7"
      configuration_aliases = [
        databricks.bdp
      ]
    }
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "= 1.12.1"
      configuration_aliases = [
        postgresql.admin,
        postgresql.bdp
      ]
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= 3.1.0"
    }
  }

  backend "azurerm" {
    resource_group_name  = "DevOps-Automation"
    storage_account_name = "stetndermsdotfrsdev"
    container_name       = "remotestate"
    key                  = "app-primary.tfstate"
    subscription_id      = "3fd0012c-9f2f-4da8-8869-0dbe61384321"
    tenant_id            = "d6525c95-b906-431a-b926-e9b51ba43cc4"
  }
}
