#!/bin/sh

# Bash strict mode, stop on any error
#set -euo pipefail
set -eu

# Ensure all required environment variables are present
test -n "$DATABRICKS_ENDPOINT"
test -n "$DATABRICKS_WORKSPACE_RESOURCE_ID"
test -n "$KEY_VAULT"
test -n "$SECRET_NAME"
test -n "$ARM_CLIENT_ID"
test -n "$ARM_CLIENT_SECRET"
test -n "$ARM_TENANT_ID"

# Login
az login --service-principal -u "$ARM_CLIENT_ID" -p "$ARM_CLIENT_SECRET" -t "$ARM_TENANT_ID"

# Get a token for the global Databricks application.
# The resource name is fixed and never changes.
token_response=$(az account get-access-token --resource 2ff814a6-3304-4ab8-85cb-cd0e6f879c1d)
token=$(echo "$token_response" | jq -r '.accessToken')
if [ "${token}" = "" ]; then
  echo "The token for the global databrick application isn't defined!"
  exit 1
fi

# Get a token for the Azure management API
token_response=$(az account get-access-token --resource https://management.core.windows.net/)
azToken=$(echo "$token_response" | jq -r '.accessToken')
if [ "${azToken}" = "" ]; then
  echo "The token for the Azure managment API isn't defined!"
  exit 1
fi

# Generate a PAT token. Note the quota limit of 600 tokens.
api_response=$(curl -sf "${DATABRICKS_ENDPOINT}"/api/2.0/token/create \
  -H "Authorization: Bearer $token" \
  -H "X-Databricks-Azure-SP-Management-Token:$azToken" \
  -H "X-Databricks-Azure-Workspace-Resource-Id:$DATABRICKS_WORKSPACE_RESOURCE_ID" \
  -d '{ "comment": "Terraform-generated token" }')
pat_token=$(echo "$api_response" | jq -r '.token_value')
if [ "${pat_token}" = "" ]; then
  echo "The PAT token isn't defined!"
  exit 1
fi

az keyvault secret set --vault-name "$KEY_VAULT" -n "$SECRET_NAME" --value "$pat_token"
