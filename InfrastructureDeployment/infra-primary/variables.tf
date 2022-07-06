variable "aks_vnet_cidr" {
  description = "The IPv4 network adress prefix, in CIDR notation, defined for AKS clusters"
  type        = string
}

variable "databrick_vnet_cidr" {
  description = "The IPv4 network adress prefix, in CIDR notation, defined for Databrick"
  type        = string
}

variable "environment_vnet_cidr" {
  description = "The IPv4 primary network adress prefix, in CIDR notaion, defined for this subscription"
}

variable "log_analytics_workspace_sku" {
  description = "SKU of the Log Analytics Workspace.  allowed values:  Free, PerNode, Premium, Standard, Standalone, Unlimited, and PerGB2018 (new Sku as of 2018-04-03)"
  type        = string
  #default     = "PerGB2018"
}

variable "log_analytics_workspace_retention" {
  # https://azure.microsoft.com/en-us/pricing/details/log-analytics/
  description = "Retention (in days) of logs.  allowed values: Possible values are either 7 (Free Tier only) or range between 30 and 730.(>31 will incur additional charges)"
  type        = number
  #default     = 31
}

variable "gateway_https_domain" {
  description = "The root domain (common name) configured in https certificate"
  type        = string
}

variable "gateway_https_subdomains" {
  description = "The list of all dns subdomains used in subject alternative names in https certificate"
  type        = list(string)
}

variable "gateway_https_certificate_exists" {
  description = "If it exists the gateway https certificate file in the git repository. The file should be named 'gateway-certificate.pfx'"
  type        = bool
}

variable "gateway_http2_enabled" {
  description = "If HTTP2 needs to be enabled on gateway"
  type        = bool
  default     = false
}

variable "ado_private_endpoints_subresources_storage_accounts" {
  description = "List of private endpoints subsresources names that we are going to apply to ado storage account. This list can only have Blob, Table, Queue, File and Web"
  type        = list(string)
  default     = []
}

variable "vm_password" {
  description = "password to virtual machine"
  type        = string
}

variable "vm_username" {
  description = "username to virtual machine"
  type        = string
}
