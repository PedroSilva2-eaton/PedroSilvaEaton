data "terraform_remote_state" "ado-automation" {
  backend = "azurerm"
  config = {
    resource_group_name  = "DevOps-Automation"
    storage_account_name = "stetndermsdotfrsdev"
    container_name       = "remotestate"
    key                  = "ado-automation.tfstate"
  }
}
