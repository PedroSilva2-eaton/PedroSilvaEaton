data "external" "retrieve_environment_config_${state_name}" {
  program = [
    "jq",
    "-n",
    "-R",
    "-f",
    "../program-environment-data-remote-state-config.jq",
    "$${var.environment}-data-remote-state-config.hcl"
  ]
}

data "terraform_remote_state" "${state_name}" {
  backend = "azurerm"
  config = merge(
    data.external.retrieve_environment_config_${state_name}.result,
    {
      key = "${key}"
    }
  )
}
