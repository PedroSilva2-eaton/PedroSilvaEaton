data "terraform_remote_state" "${state_name}" {
  backend = "azurerm"
  config = {
    resource_group_name  = "${resource_group}"
    storage_account_name = "${storage_account}"
    container_name       = "${container_name}"
    key                  = "${key}"
  }
}
