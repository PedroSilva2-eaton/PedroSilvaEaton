variable "bdp_storage_account_kind" {
  description = "Defines the Kind of account. Valid options are BlobStorage, BlockBlobStorage, FileStorage, Storage and StorageV2. Changing this forces a new resource to be created. Defaults to StorageV2."
  type        = string
  default     = "StorageV2"
}

variable "bdp_storage_account_tier" {
  description = "Defines the Tier to use for this storage account. Valid options are Standard and Premium. For BlockBlobStorage and FileStorage accounts only Premium is valid. Changing this forces a new resource to be created."
  type        = string
  default     = "Standard"
}

variable "bdp_storage_account_replication" {
  description = "account_replication_type - (Required) Defines the type of replication to use for this storage account. Valid options are LRS, GRS, RAGRS, ZRS, GZRS and RAGZRS"
  type        = string
  default     = "RAGRS"
}

variable "bdp_storage_account_access_tier" {
  description = "Defines the access tier for BlobStorage, FileStorage and StorageV2 accounts. Valid options are Hot and Cool, defaults to Hot."
  type        = string
  default     = "Hot"
}

variable "bdp_storage_datalake_v2" {
  description = "Enabled Hierarchical name space for Data Lake Storage gen 2"
  type        = bool
  default     = false
}

variable "bdp_databrick_workspace_sku" {
  description = "The sku to use for the Databricks Workspace. Possible values are standard, premium, or trial. "
  type        = string
  default     = "standard"
}

## az postgres server list-skus --location westeurope -o table
variable "postgres_sku_name" {
  description = "The name of the SKU, follows the tier + family + cores pattern (e.g. B_Gen4_1, GP_Gen5_8)"
  type        = string
  default     = "GP_Gen5_2"
}

variable "postgres_version" {
  description = "Postgresql version. Valid values are 9.5, 9.6, 10, 10.0, and 11"
  type        = number
  default     = 11
}

variable "postgres_creation_mode" {
  description = "Postgresql creation mode. Can be used to restore or replicate existing servers. Possible values are Default, Replica, GeoRestore, and PointInTimeRestore"
  type        = string
  default     = "Default"
}

variable "postgres_creation_source_server_id" {
  description = "For creation modes other then default, the source Postgresql server ID to use"
  type        = string
  default     = ""
}

variable "postgres_storage_mb" {
  description = "Max storage allowed for Postgresql server. Possible values are between 5120 MB(5GB) and 1048576 MB(1TB) for the Basic SKU and between 5120 MB(5GB) and 4194304 MB(4TB) for General Purpose/Memory Optimized SKUs."
  type        = number
  default     = 5120
}

variable "postgres_backup_retention_days" {
  description = "minimum of days that a Postgresql exists. possible values are between 7 and 35 days"
  type        = number
  default     = 7
}

variable "postgres_geo_redudant_backup" {
  description = "Turn Geo-redundant server backups on/off. This allows you to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. This is not support for the Basic tier."
  type        = bool
  default     = false
}

variable "redis_sku" {
  description = "The SKU of Redis to use. Possible values are Basic, Standard and Premium."
  type        = string
  default     = "Basic"
}

variable "redis_family" {
  description = "The SKU family/pricing group to use. Valid values are C (for Basic/Standard SKU family) and P (for Premium)"
  type        = string
  default     = "C"
}

variable "redis_capacity" {
  description = "The size of the Redis cache to deploy. Valid values for a SKU family of C are 0, 1, 2, 3, 4, 5, 6, and for P family are 1, 2, 3, 4."
  type        = number
  default     = 1
}

variable "redis_enable_non_ssl_port" {
  description = "Enable the non-SSL port (6379)"
  type        = bool
  default     = false
}

variable "acr_sku" {
  description = "SKU of the container registry.  allowed values: Basic, Standard and Premium"
  type        = string
  default     = "Standard"
}

variable "acr_admin_enabled" {
  description = "Specifies whether the admin user is enabled for the container registry"
  type        = bool
  default     = true
}

variable "acr_public_access_enabled" {
  description = "Whether public network access is allowed for the container registry"
  type        = bool
  default     = true
}

variable "acr_zone_redundancy_enabled" {
  description = "Whether zone redundancy is enabled for this Container Registry. Changing this forces a new resource to be created."
  type        = bool
  default     = false
}

variable "iot_storage_account_kind" {
  description = "Defines the Kind of account. Valid options are BlobStorage, BlockBlobStorage, FileStorage, Storage and StorageV2. Changing this forces a new resource to be created. Defaults to StorageV2."
  type        = string
  default     = "StorageV2"
}

variable "iot_storage_account_tier" {
  description = "Defines the Tier to use for this storage account. Valid options are Standard and Premium. For BlockBlobStorage and FileStorage accounts only Premium is valid. Changing this forces a new resource to be created."
  type        = string
  default     = "Standard"
}

variable "iot_storage_account_replication" {
  description = "account_replication_type - (Required) Defines the type of replication to use for this storage account. Valid options are LRS, GRS, RAGRS, ZRS, GZRS and RAGZRS"
  type        = string
  default     = "RAGRS"
}

variable "iot_storage_account_access_tier" {
  description = "Defines the access tier for BlobStorage, FileStorage and StorageV2 accounts. Valid options are Hot and Cool, defaults to Hot."
  type        = string
  default     = "Hot"
}

variable "etib_control2_storage_account_kind" {
  description = "Defines the Kind of account. Valid options are BlobStorage, BlockBlobStorage, FileStorage, Storage and StorageV2. Changing this forces a new resource to be created. Defaults to StorageV2."
  type        = string
  default     = "StorageV2"
}

variable "etib_control2_storage_account_tier" {
  description = "Defines the Tier to use for this storage account. Valid options are Standard and Premium. For BlockBlobStorage and FileStorage accounts only Premium is valid. Changing this forces a new resource to be created."
  type        = string
  default     = "Standard"
}

variable "etib_control2_storage_account_replication" {
  description = "account_replication_type - (Required) Defines the type of replication to use for this storage account. Valid options are LRS, GRS, RAGRS, ZRS, GZRS and RAGZRS"
  type        = string
  default     = "RAGRS"
}

variable "etib_control2_storage_account_access_tier" {
  description = "Defines the access tier for BlobStorage, FileStorage and StorageV2 accounts. Valid options are Hot and Cool, defaults to Hot."
  type        = string
  default     = "Hot"
}
