variable "bdp_eventhub_namespace_sku" {
  description = "Defines which tier to use. Valid options are Basic and Standard."
  type        = string
  default     = "Standard"
}

variable "bdp_eventhub_namespace_capacity" {
  description = "Specifies the Capacity / Throughput Units for a Standard SKU namespace. Valid values range from 1 - 20"
  type        = number
  default     = 1
}

variable "bdp_eventhub_partition_count" {
  description = "Specifies the current number of shards on the Event Hub. Changing this forces a new resource to be created."
  type        = number
  default     = 2
}

variable "bdp_eventhub_message_retention" {
  description = "Specifies the number of days to retain the events for this Event Hub."
  type        = number
  default     = 1
}

variable "deployment_bdp" {
  description = "Deploy Data Factory and Databrick"
  type        = bool
  default     = true
}

variable "aks_sku" {
  description = "The SKU Tier that should be used for k8s cluster. Possible values are Free and Paid (which includes the Uptime SLA)"
  type        = string
  default     = "Paid"
}

variable "aks_private_api" {
  description = "Deploy green k8s without a public accessible API control plane endpoint"
  type        = bool
  default     = true
}

variable "aks_api_auth_ips" {
  description = "List of IP addresses that are allowed to access the k8s control plane API"
  type        = list(string)
  default     = []
}

# default pool is a system pool and the minimum size is 1
# az vm list-sizes --location westeurope -o table
# az vm list-skus -l westeurope -o table
variable "aks_default_node_pool" {
  description = "The object to configure the green k8s default node pool. If cluster_auto_scalling is false then the number of the nodes will be equal to cluster_max_node_count"
  type = object({
    name                = string
    vm_size             = string
    enable_auto_scaling = bool
    min_node_count      = number
    max_node_count      = number
    max_pods            = number
    os_disk_size_gb     = number
    availability_zones  = list(string)
    labels              = map(string)
  })
  default = {
    name                = "default"
    vm_size             = "Standard_B2s"
    enable_auto_scaling = true
    min_node_count      = 1
    max_node_count      = 2
    max_pods            = 30
    os_disk_size_gb     = 32
    availability_zones  = ["1", "2", "3"]
    labels = {
      "default_node_pool" = "true"
    }
  }
}

variable "aks_rbac" {
  description = "enable Role-based access control in k8s deployment"
  type        = bool
  default     = true
}

# https://docs.microsoft.com/en-us/azure/aks/upgrade-cluster#set-auto-upgrade-channel-preview
variable "aks_automatic_channel_upgrade" {
  description = "The upgrade channel for the k8s deployment. Possible values are patch, rapid, node-image and stable. Omitting this field sets this value to none."
  type        = string
  default     = "patch"
}

variable "aks_extra_node_pools" {
  description = "The map object to configure one, or several, additional k8s node pools. If cluster_auto_scalling is false then the number of the nodes will be equal to cluster_max_node_count"
  type = map(object({
    name                = string
    vm_size             = string
    mode                = string
    enable_auto_scaling = bool
    min_node_count      = number
    max_node_count      = number
    max_pods            = number
    os_disk_size_gb     = number
    availability_zones  = list(string)
    labels              = map(string)
    taints              = list(string)
  }))
  default = {
    "1" = {
      name                = "usercompute1"
      vm_size             = "Standard_F2s_v2"
      mode                = "User"
      enable_auto_scaling = true
      min_node_count      = 1
      max_node_count      = 3
      max_pods            = 30
      os_disk_size_gb     = 32
      availability_zones  = ["1", "2", "3"]
      labels = {
        "sku"               = "Standard_F2s_v2"
        "default_node_pool" = "false"
      }
      taints = []
    }
  }
}

variable "iot_eventhub_namespace_sku" {
  description = "Defines which tier to use. Valid options are Basic and Standard."
  type        = string
  default     = "Standard"
}

variable "iot_eventhub_namespace_capacity" {
  description = "Specifies the Capacity / Throughput Units for a Standard SKU namespace. Valid values range from 1 - 20"
  type        = number
  default     = 1
}

variable "iot_eventhub_partition_count" {
  description = "Specifies the current number of shards on the Event Hub. Changing this forces a new resource to be created."
  type        = number
  default     = 2
}

variable "iot_eventhub_message_retention" {
  description = "Specifies the number of days to retain the events for this Event Hub."
  type        = number
  default     = 1
}

variable "iot_sku" {
  description = "The name of the sku. Possible values are B1, B2, B3, F1, S1, S2, and S3."
  type        = string
  default     = "S1"
}

variable "iot_sku_capacity" {
  description = "The number of provisioned IoT Hub units"
  type        = string
  default     = "1"
}
