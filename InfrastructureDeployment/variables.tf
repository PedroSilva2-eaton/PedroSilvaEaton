variable "local_terraform_state" {
  type        = bool
  description = "whether to create the local terraform state because we are creating the resources from scratch"
  default     = false
}

variable "terraform_fixed_version" {
  type        = string
  description = "Required terraform version"
  default     = "1.1.3"
}

# https://github.com/hashicorp/terraform-provider-azurerm/releases
# https://releases.hashicorp.com/terraform-provider-azurerm/
variable "azurerm_provider_fixed_version" {
  type        = string
  description = "Required azurerm provider version"
  default     = "2.90.0"
}

# https://github.com/hashicorp/terraform-provider-local/releases
# https://releases.hashicorp.com/terraform-provider-local/
variable "local_provider_fixed_version" {
  type        = string
  description = "Required local provider version"
  default     = "2.1.0"
}

# https://github.com/hashicorp/terraform-provider-template/releases
# https://releases.hashicorp.com/terraform-provider-template/
variable "template_provider_fixed_version" {
  type        = string
  description = "Required template provider version"
  default     = "2.2.0"
}

# https://github.com/hashicorp/terraform-provider-null/releases
# https://releases.hashicorp.com/terraform-provider-null/
variable "null_provider_fixed_version" {
  type        = string
  description = "Required null provider version"
  default     = "3.1.0"
}

# https://github.com/hashicorp/terraform-provider-random/releases
# https://releases.hashicorp.com/terraform-provider-random/
variable "random_provider_fixed_version" {
  type        = string
  description = "Required random provider version"
  default     = "3.1.0"
}

# https://github.com/hashicorp/terraform-provider-time/releases
# https://releases.hashicorp.com/terraform-provider-time/
variable "time_provider_fixed_version" {
  type        = string
  description = "Required time provider version"
  default     = "0.7.2"
}

# https://docs.microsoft.com/en-us/azure/databricks/dev-tools/terraform/
# https://github.com/databrickslabs/terraform-provider-databricks/releases
variable "databrick_provider_fixed_version" {
  type        = string
  description = "Required databrick provider version"
  default     = "0.4.7"
}

# https://github.com/cyrilgdn/terraform-provider-postgresql
# https://registry.terraform.io/providers/cyrilgdn/postgresql
variable "postgresql_provider_fixed_version" {
  type        = string
  description = "Required postgresql provider version"
  default     = "1.12.1"
}

# https://github.com/hashicorp/terraform-provider-tls/releases
# https://releases.hashicorp.com/terraform-provider-tls/
variable "tls_provider_fixed_version" {
  type        = string
  description = "Required tls provider version"
  default     = "3.1.0"
}

# https://github.com/hashicorp/terraform-provider-dns/releases
# https://releases.hashicorp.com/terraform-provider-dns/
variable "dns_provider_fixed_version" {
  type        = string
  description = "Required dns provider version"
  default     = "3.2.1"
}

# https://github.com/hashicorp/terraform-provider-external/releases
# https://releases.hashicorp.com/terraform-provider-external/
variable "external_provider_fixed_version" {
  type        = string
  description = "Required external provider version"
  default     = "2.2.0"
}

# https://github.com/hashicorp/terraform-provider-kubernetes/releases
# https://releases.hashicorp.com/terraform-provider-kubernetes/
variable "kubernetes_provider_fixed_version" {
  type        = string
  description = "Required kubernets provider version"
  default     = "2.7.1"
}

# https://github.com/hashicorp/terraform-provider-azuread/releases
# https://releases.hashicorp.com/terraform-provider-azuread/
variable "azuread_provider_fixed_version" {
  type        = string
  description = "Required azuread provider version"
  default     = "2.16.0"
}

variable "terraform_state_resource_group" {
  description = "name of the resource group where the storage account for Terraform remote state file resides. In this case, it should be 'DevOps-Automation'"
  type        = string
}

variable "terraform_state_storage_account" {
  description = "name of the storage account where Terraform remote state key state files resides"
  type        = string
}

variable "terraform_state_container" {
  description = "name of the container, inside the storage account, where  Terraform remote key state files resides. Normally the default name 'remotestate' is usually adopted."
  type        = string
}

variable "azure_devops_pipeline_key_vault" {
  description = "name of the key vault that is going to store the secrets that are going to be used by Azure DevOps pipelines"
  type        = string
}

variable "azure_devops_service_principal_object_id" {
  description = "The object id of the service principal that is used in azure devops project service connection"
  type        = string
}

variable "location" {
  description = "Azure location to store all deployment"
  type        = string
}

variable "environment" {
  description = "type of environment that could be dev, qa or prod"
  type        = string
}

variable "environment_qualifier" {
  description = " denote primary or secondary instances. Values: p for primary or s for secondary"
  type        = string
}

variable "project_naming_convention" {
  description = "project name used in project section of the naming convention used in all resource names"
  type        = string
  default     = "derms"
}

variable "minimum_tls_version" {
  description = "Minimum version of TLS that must be used to connect to the storage account"
  type        = string
  default     = "TLS1_2"
}

variable "create_vm" {
  description = "Create virtual machines and related resources"
  type        = bool
  #default     = false
}

variable "deployments" {
  description = "Definition of Green and/or Blue deployments"
  type = list(object({
    name              = string
    enabled           = bool
    aks_address_space = string
    gw_address_space  = string
  }))
  #default = [
  #  {
  #    name              = "green"
  #    enabled           = true
  #    aks_address_space = "10.11.0.0/20"
  #    gw_address_space  = "10.201.65.192/27"
  #  },
  #  {
  #    name              = "blue"
  #    enabled           = false
  #    aks_address_space = "10.11.112.0/20"
  #    gw_address_space  = "10.201.65.224/27"
  #  }
  #]
}

variable "environment_extra_auth_ips" {
  description = "List of extra IP addresses that are going to be added to all the environmnet resources that have firewall enabled"
  type        = list(string)
  default     = ["37.228.241.0/24", "20.122.195.0/24", "20.37.158.0/23"]
}

# the ip of ado agent vm will not be usaged  because each stage will be run by a diferent agent (if using the microsoft public agent pools)
# we will need to use self hosted agent, and we we use it, we dont need to add its ip to authorized list because it will be using vnet authorization
# trying to use the variable in plan and override it in deploy
variable "environment_terraform_agent_ip" {
  description = "String with the ip address of the Azure DevOps vm agent. This value should always be empty as this is calculated in Azure DevOps pipeline"
  type        = string
  default     = ""
}

variable "environment_terraform_agent_ip_netmask" {
  description = "String with the ip address, and its netmask, of the Azure DevOps vm agent. This value should always be empty as this is calculated in Azure DevOps pipeline"
  type        = string
  default     = ""
}
