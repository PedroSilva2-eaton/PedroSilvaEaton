data "terraform_remote_state" "data-primary" {
  backend = "azurerm"
  config = {
    resource_group_name  = "DevOps-Automation"
    storage_account_name = "stetndermsdotfrsdev"
    container_name       = "remotestate"
    key                  = "data-primary.tfstate"
  }
}
