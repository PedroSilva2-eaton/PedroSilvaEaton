# Introduction

This repository will be used by [Azure DevOps (ADO)](https://dev.azure.com/etn-esb/EVCI_EMS) to deploy, using [Terraform](https://www.terraform.io/), all the Azure infrastructure used by our environments
> Until we transfer all the [development resources](https://dev.azure.com/etn-esb/EVCI_EMS/_git/infrastructure-deployment-dev) to this repository, we are using this repository only for QA and PROD environments

[[_TOC_]]

# Getting Started

Before you can use Terraform to create all the needed resources, you need:
1. Azure CLI tool
1. Terraform CLI tool
1. Service Principal to be used by Terraform
> All commands blocks bellow will be in using bash shell scripting

## Azure CLI
> Don't need to follow these instructions if you are going to use Azure Bash cloud shell

You can install using [azure instructions](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest) or use one of the following alternatives that already have the CLI installed:
* docker image [azure-cli](https://hub.docker.com/r/microsoft/azure-cli/)
* Azure Cloud shell available
After that, you need to confirm that you are using the correct account
```bash
az logout
az account clear
az login
```

## Install Terraform CLI
> Don't need to follow these instructions if you are going to use Azure Bash cloud shell
> You shouldn't install the latest version if the variable terraform_fixed_version is defined in variables.tf!
You can follow Hashicorp install [instructions](https://www.terraform.io/intro/getting-started/install.html) or use the following ones
```bash
$ TF_VERSION=$(curl -s https://checkpoint-api.hashicorp.com/v1/check/terraform | jq -r -M '.current_version')
$ wget https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip
$ unzip terraform_${TF_VERSION}_linux_amd64.zip
$ rm terraform_${TF_VERSION}_linux_amd64.zip
$ echo $PATH
/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$ sudo mv terraform /usr/local/bin/
$ terraform --version
```

## Service Principal to be used by Terraform
> Only follow this instruction if you do not have this information available in your subscription DevOps-Automation Key Vault

Currently, EATON standard is to have one subscription for each environment, therefore, a service principal (SP) must be created for each subscription.
Because the SP needs to be able to create, modify, and destroy resources in the subscription, it shall be granted with "Contributor" role at the subscription level.
You need to follow this [instructions](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/guides/service_principal_client_secret) to create the SP in the usually EATON format "etn-cicdsvc-{project_name}-{env}".

# Required Resources for ADO Automation
> Normally this is already created when you get your subscription access but follow these instructions if that is not the case

To correctly maintain the state of your Terraform deployments, you will need to have a few resources created before being able to execute terraform:
* 'DevOps-Automation' Resource Group in WestEurope location
* Storage Account to hold all Terraform deployment state - Eaton recommendation is to use the format of "st{project}dotfrs{environment}" where {project} is identifier
of project, 'dotfrs' stands for "DevOps Terraform remote state" and {env} is identifier of environment such as 'prd', 'tst', 'qa', 'dev'.
* Key Vault to store deployment secrets - Eaton recomendation is bassed on [microsoft naming](https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming) which results in "{resource type abreviature}-{project}-{service}-{environment}-{region}-{p/s and instance number}"
* Service Connection for your projects in ADO

For the first 3 points, you can use these commands
> The following commands instruction use az, jq, date and xargs cli tool

```bash
$ export subscription="Eaton ES EVCI EMS Dev"
$ export subscriptionId=$(az account list | jq -r ".[] | select ( .name == \"${subscription}\" ) | .id")
$ export location="westeurope"
$ export resourceGroup="DevOps-Automation"
$ export storageAccount="stevciemsdotfrsdevwep01"
$ export storageContainer="remotestate"
$ export keyVault="kv-evciems-ado-dev-we-p01"
$ export expirationDate=$(date -u -d "3 year" '+%Y-%m-%dT%H:%MZ')
$ az group create -n ${resourceGroup} -l ${location} -o none
$ az storage account create -n ${storageAccount} -g ${resourceGroup} -l ${location} --kind StorageV2 --sku Standard_GRS --allow-blob-public-access false --min-tls-version TLS1_2 --https-only true --default-action Deny -o none
$ az lock create -n ${storageAccount} --lock-type CanNotDelete -g ${resourceGroup} --resource-type Microsoft.Storage/storageAccounts --resource ${storageAccount}
$ az storage blob service-properties delete-policy update --account-name ${storageAccount} --days-retained 365 --enable true -o none
$ az storage container create -n ${storageContainer} --account-name ${storageAccount} --public-access off -o none
$ az keyvault create -n ${keyVault} -g ${resourceGroup} -l ${location} --enabled-for-disk-encryption -o none
$ az lock create -n ${keyVault} --lock-type CanNotDelete -g ${resourceGroup} --resource-type Microsoft.KeyVault/vaults --resource ${keyVault}
$ az storage container generate-sas --account-name ${storageAccount} --expiry ${expirationDate} --name tfstate --permissions dlrw -o json | xargs az keyvault secret set --vault-name ${keyVault} --name tf-sas-token --value
```
Now you need the SP to access to key vault
```bash
servicePrincipalId=e5a61294-b987-40fc-81e5-78a9f056cbfa
az keyvault set-policy --name ${keyVault} --object-id ${servicePrincipalId} --key-permissions backup create decrypt delete encrypt get import list purge recover restore sign unwrapKey update verify wrapKey --secret-permissions backup delete get list purge recover restore set  --certificate-permissions backup create delete get import list purge recover restore update  --storage-permissions backup delete deletesas get getsas list listsas purge recover regeneratekey restore set setsas update
```

# First execution of Terraform apply (with no remote state in Storage Account)
> Only follow these instructions if you don't already have a working azurerm backend in your azure provider or if you need to recreate from zero!!!

```bash
$ sed -i '/local_terraform_state/,/default/s/true/false/' variables.tf
$ cd ado-automation
$ terraform init
$ export TF_VAR_terraform_state_resource_group="DevOps-Automation"
$ export TF_VAR_terraform_state_storage_account="stevciemstfstatedevwep01"
$ export TF_VAR_azure_devops_pipeline_key_vault="kv-evciems-ado-dev-we-p01"
$ export TF_VAR_terraform_state_container="remotestate"
$ export TF_VAR_location=westeurope
$ export TF_VAR_environment=dev
$ export TF_VAR_environment_qualifier=p
$ export TF_VAR_aks_vnet_cidr=10.11.0.0/16
$ export TF_VAR_databrick_vnet_cidr=10.10.0.0/16
$ export TF_VAR_environment_vnet_cidr="10.201.65.0/24"
$ export TF_VAR_create_vm=1
$ export TF_VAR_deployments='[{ name = "green", enabled = true, aks_address_space = "10.11.0.0/20", gw_address_space = "10.201.65.192/27" },{ name = "blue", enabled = false, aks_address_space = "10.11.112.0/20", gw_address_space = "10.201.65.224/27" }]'
$ export TF_VAR_log_analytics_workspace_sku="PerGB2018"
$ export TF_VAR_log_analytics_workspace_retention=31
$ export TF_VAR_gateway_https_domain=brightlayer-bems-dev.eaton.com
$ export TF_VAR_gateway_https_subdomains='["connect", "api", "admin", "tech", "www"]'
$ export TF_VAR_gateway_https_certificate_exists=0
$ export ARM_CLIENT_ID=********-****-****-****-************
$ export ARM_CLIENT_SECRET=*************************************
$ export ARM_SUBSCRIPTION_ID=********-****-****-****-************
$ export ARM_TENANT_ID=********-****-****-****-************
$ terraform plan
$ terraform apply -auto-approve
```

Now that terraform has created a new file backend.tf (with information regarding azurerm backend), you need to force terraform to move the local state to the remote azurerm backend

```bash
$ terraform init -force-copy
...
Successfully configured the backend "azurerm"! Terraform will automatically
use this backend unless the backend configuration changes.
...
```

As Terraform will now operate remotely with azurerm backend, we need to remove older terraform.tfstate and push the new changes for the git repository

```bash
$ rm terraform.tfstate*
$ git add --all
$ git commit -m "terraform is using azurerm remote backend"
$ git push
```

>>>
If for any reason you deleted your local git clone, or the .terraform folder, you only need to do the following commands to be able to reuse Terraform with the existing environment
```bash
$ terraform init
$ cd ado-automation
$ terraform state list
```
You will still need to use that export all the needed variables when you did the first execution of terraform
>>>

# CI/CD workflow

Todo

# ADO pipeline

To be able to use the pipeline defined in azure-pipelines.yml, we need to do the following steps:
1. Create Service Connection for the project in ADO
1. Define Azure Key vault as variable group
1. configure YAML pipeline with azure-pipelines.yml file

## ADO Service Connection
> Normally this is already created when you get your subscription access but follow these instructions if that is not the case

The user who is going to create a service connection in ADO needs to have the following items ready before creating the service connection in ADO:
* The application (client) ID of the service principal mentioned in the earlier section.
* The client secret (key, password) of the service principal mentioned in the earlier section.
* The name and ID of the target subscription.
* The tenant ID of Azure Active Directory that provides identity management.
The steps to create a service connection in ADO to your subscription are as follow:
1. Open your Azure DevOps organization. Then open the project that needs the connection and click "Project settings" at the bottom left.
1. Click "Service connections" in the section of Pipelines. Then click "New service connection" in the top right corner.
1. Click "Azure Resource Manager", click "Next", click "Service principal (manual)" then click "Next"
1. In the "Environment" drop-down menu choose the correct one according to your case and in the "Scope Level" choose "Subscription". Fill the required fields "Subscription Id", "Service Principal Id", "Service principal key" and "Tenant ID" with the info available in the Key vault that exists in "DevOps-Automation" resource group. Regarding the field "Subscription Name" you can collect the name from [here](https://portal.azure.com/#blade/Microsoft_Azure_Billing/SubscriptionsBlade). Then click the "Verify" button. If the information you provide is correct, the verification shall pass.
1. Before you close the dialog in "Verify and save", don’t forget to tick the check box of “Allow all pipelines to use this connection” if you are creating a service connection for other pipelines to use.

## Azure Key Vault as variable group

> You will need to repeat this process for all the environments (the following instructions are only for the DEV environment)

1. For the pipelines to read the secrets in key vaults, click "Library" under "Pipelines", then click "+ Variable group" button on the top
1. Then on the variable group "Properties" window, enter the name "ADO-DEV-Group" as the variable group to indicate where it comes from, provide some description for information, then click the "Link secrets from an Azure key vault as variables" switch button
1. In "Azure subscription" drop-down menu, choose the Service Connection that was created earlier at the "Project Settings" section. Then in "Key vault name" drop-down menu, choose the key vault name from where the secrets are being extracted.
1. Click the "+Add" button at the bottom, then choose the secrets you would like to import from the key vault to the pipeline library
1. Click "Ok" button, then click "Save" button on the top menu.

> If you add new secrets to the key vault that are need in your pipelines, dont forget those secrets to the corresponding variable group

## azure-pipelines.yml

To create the pipeline, for this git repository, you need to go to this [URL](https://dev.azure.com/etn-esb/EVCI_EMS/_build) and follow this instructions:

1. New pipeline
1. Connect to Azure Repos Git
1. Select this git repository
1. Review your pipeline YAML
1. Save

> You will need to repeat this process for all the environments (the following instructions are only for the DEV environment)
After that you need to configure 'approvals and checks'. You should open this [URL](https://dev.azure.com/etn-esb/EVCI_EMS/_environments) and follow this instructions to create the corresponding environment used in pipeline yaml:

1. New environment
   - Name: terraform-dev
   - resource: None
1. create

Now go to 'Approvals and checks' and follow the next instructions:

1. click on the + (plus) button
1. select Approvals
   - Approvers: add all the need usernames and groups
1. create

> In the first execution, you will need to allow access from the pipeline to the variables group and the corresponding environment defined above!
> You can check the permision on "variable group" on the "pipeline permissions"
> You can check the permision on environment in "security" menu and the "pipeline permissions"

# Destroying all the environment

Before we can destroy all AWS resources, we need to first migrate the remote backend state to a local one.
The first step is to force the deletion of the file backend.tf that as the information regarding S3 backend

```bash
$ sed -i '/local_terraform_state/,/default/s/false/true/' variables.tf
$ cd ado-automation
$ terraform init
$ export TF_VAR_terraform_state_resource_group="DevOps-Automation"
$ export TF_VAR_terraform_state_storage_account=""
$ export TF_VAR_azure_devops_pipeline_key_vault="kv-evciems-ado-dev-we-p01"
$ export TF_VAR_terraform_state_container="remotestate"
$ export TF_VAR_location=westeurope
$ export TF_VAR_environment=dev
$ export TF_VAR_environment_qualifier=p
$ export TF_VAR_aks_vnet_cidr=10.11.0.0/16
$ export TF_VAR_databrick_vnet_cidr=10.10.0.0/16
$ export TF_VAR_environment_vnet_cidr="10.201.65.0/24"
$ export TF_VAR_create_vm=1
$ export TF_VAR_deployments='[{ name = "green", enabled = true, aks_address_space = "10.11.0.0/20", gw_address_space = "10.201.65.192/27" },{ name = "blue", enabled = false, aks_address_space = "10.11.112.0/20", gw_address_space = "10.201.65.224/27" }]'
$ export TF_VAR_log_analytics_workspace_sku="PerGB2018"
$ export TF_VAR_log_analytics_workspace_retention=31
$ export TF_VAR_gateway_https_domain=brightlayer-bems-dev.eaton.com
$ export TF_VAR_gateway_https_subdomains='["connect", "api", "admin", "tech", "www"]'
$ export TF_VAR_gateway_https_certificate_exists=0
$ export ARM_CLIENT_ID=********-****-****-****-************
$ export ARM_CLIENT_SECRET=*************************************
$ export ARM_SUBSCRIPTION_ID=********-****-****-****-************
$ export ARM_TENANT_ID=********-****-****-****-************
$ terraform plan
$ terraform apply -auto-approve
```

Now that the file was deleted, we need to inform terraform to move the terraform state from azurerm to local files

```bash
$ terraform init -force-copy
...
Successfully unset the backend "azurerm". Terraform will now operate locally.
...
```

As Terraform will now operate locally, we can force terraform to plan to delete all resources

```bash
$ cd ..
$ for folder in app-primary data-primary infra-primary ado-automation; do cd ${folder}; terraform plan -destroy; cd ..; done
```
and if everything is ok, delete them

```bash
$ for folder in app-primary data-primary infra-primary ado-automation; do cd ${folder}; terraform apply -destroy -auto-approve; cd ..; done
```

Now don't forget to commit the changes to this repository

```bash
$ git add --all
$ git commit -m "destroyed all resources in Azure"
$ git push
```
## Generate PFX certificate

Previous - Generate CSR certificate 

```bash
openssl req \
  -new \
  -nodes \
  -newkey rsa:2048 \
  -subj "/C=US/ST=OH/L=Beachwood/O=Eaton/CN=brightlayer-bems-qa.eaton.com" \
  -reqexts SAN \
  -config <( cat /etc/ssl/openssl.cnf \
    <(printf "[SAN]\nsubjectAltName='DNS.1:connect.brightlayer-bems-qa.eaton.com,DNS.2:api.brightlayer-bems-qa.eaton.com,DNS.3:admin.brightlayer-bems-qa.eaton.com,DNS.4:tech.brightlayer-bems-qa.eaton.com,DNS.5:www.brightlayer-bems-qa.eaton.com'")) \
  -keyout brightlayer_bems_qa_private.key \
  -out brightlayer_bems_qa_public.csr
```

After sent this to the EATON team they forward 4 certs:

- 668676058.crt;
- AAACertificateServices.crt;
- TrustedSecureCertificateAuthorityDV.crt;
- USERTrustRSAAAACA.crt;

Combine the above crt files into a bundle (the order matters, here):

`cat 668676058.crt TrustedSecureCertificateAuthorityDV.crt USERTrustRSAAAACA.crt AAACertificateServices.crt > eaton_bundle.crt`

Next we have to create pfx cert from certificate (eaton_bundle.crt) and private key

You will need to use openssl.

`openssl pkcs12 -export -out gateway-certificate.pfx -inkey brightlayer_bems_qa_private.key -in eaton_bundle.crt`




