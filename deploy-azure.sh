#!/usr/bin/env bash
#
# Deploy PcapExplorer to Azure Container Apps.
#
# Why Container Apps: it scales to zero (idle costs nothing), includes a monthly
# free grant (180,000 vCPU-seconds + 360,000 GiB-seconds + 2M requests), and
# hands you a free HTTPS URL (https://<app>.<region>.azurecontainerapps.io) with
# no custom domain required.
#
# The image is built in the cloud from the local source via `--source .`, so you
# do NOT need Docker installed locally. Because the build uses the local build
# context, the git-ignored data/GeoLite2-City.mmdb is included (see .dockerignore)
# and baked into the image so the map works.
#
# Prerequisites:
#   1. Azure CLI installed:  https://learn.microsoft.com/cli/azure/install-azure-cli
#   2. Logged in:            az login   (and: az account set --subscription "<name-or-id>")
#   3. Run from the repo root:  ./deploy-azure.sh
#
# Override any of these with environment variables if you like:
set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-pcap-explorer-rg}"
LOCATION="${LOCATION:-westus2}"
ENVIRONMENT="${ENVIRONMENT:-pcap-explorer-env}"
APP_NAME="${APP_NAME:-pcap-explorer}"

echo ">> Using resource group '$RESOURCE_GROUP' in '$LOCATION' (app: '$APP_NAME')"

# One-time setup: install the Container Apps CLI extension and register providers.
echo ">> Ensuring Container Apps extension + resource providers are ready..."
az extension add --name containerapp --upgrade --only-show-errors -y
az provider register --namespace Microsoft.App --wait
az provider register --namespace Microsoft.OperationalInsights --wait

# Resource group (idempotent).
echo ">> Creating resource group (if it doesn't exist)..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none

# Build from local source (cloud build, no local Docker) and deploy.
# --target-port 5432 matches the server's default listen port.
echo ">> Building image in the cloud and deploying (this takes a few minutes)..."
az containerapp up \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --location "$LOCATION" \
  --environment "$ENVIRONMENT" \
  --source . \
  --target-port 5432 \
  --ingress external

# Ensure scale-to-zero for lowest cost (0 = pay nothing while idle).
echo ">> Setting scale-to-zero (min 0, max 3 replicas)..."
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --min-replicas 0 \
  --max-replicas 3 \
  --output none

FQDN="$(az containerapp show -n "$APP_NAME" -g "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv)"

echo
echo "============================================================"
echo " Deployed. Your app is live at:"
echo "   https://$FQDN"
echo "============================================================"
echo
echo "Link this on your website with a normal <a href> — no domain needed."
echo "To tear everything down later:  az group delete --name $RESOURCE_GROUP --yes"
