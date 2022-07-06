#!/bin/sh

# Bash strict mode, stop on any error
#set -euo pipefail
set -eu

# Azure Devops
WEEKLY_MICROSOFT_IP_RANGES_URL="https://www.microsoft.com/en-gb/download/confirmation.aspx?id=56519"
WEEKLY_MICROSOFT_IP_RANGES_URL_FINAL=$(curl -sS ${WEEKLY_MICROSOFT_IP_RANGES_URL} | egrep -o 'https://download.*?\.json' | grep -wv "script" | uniq)
AZURE_DEVOPS_RANGES=$(curl -sL ${WEEKLY_MICROSOFT_IP_RANGES_URL_FINAL} | jq -r '.values | .[] | select (.properties.systemService == "AzureDevOps") | select (.name | test(".*US.*")) | .properties | .addressPrefixes[]')

#Zscaler
ZSCALER_IP_RANGES_JSON="https://api.config.zscaler.com/zscaler.net/cenr/jsonip"
XSCALER_RANGES=$(curl -s ${ZSCALER_IP_RANGES_JSON} | jq -r '.Geo_regions | .[] | .[] | .[] | select(.notes | (length == 0 or (.[] | contains("Not Ready for Use") | not ))) | .cidr | sub("\t"; "") ' | sort | uniq)

jq -n --arg azure "${AZURE_DEVOPS_RANGES}" --arg zscaler "${XSCALER_RANGES}" '{"azure":$azure, "zscaler":$zscaler}'
