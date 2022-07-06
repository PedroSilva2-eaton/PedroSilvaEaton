data "terraform_remote_state" "infra-primary" {
  backend = "azurerm"
  config = {
    resource_group_name  = "DevOps-Automation"
    storage_account_name = "stetndermsdotfrsdev"
    container_name       = "remotestate"
    key                  = "infra-primary.tfstate"
  }
}
