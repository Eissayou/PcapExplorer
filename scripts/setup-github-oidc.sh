#!/usr/bin/env bash
#
# One-time setup: let GitHub Actions deploy to your Azure subscription WITHOUT
# storing any long-lived Azure password. It creates an Azure AD app with an
# OIDC federated credential trusted only for this repo's main branch, grants it
# permission to deploy, and prints the four GitHub secrets you need to add.
#
# Run this ONCE, locally, after `az login`:
#   ./scripts/setup-github-oidc.sh
#
set -euo pipefail

GITHUB_ORG="${GITHUB_ORG:-Eissayou}"
GITHUB_REPO="${GITHUB_REPO:-PcapExplorer}"
BRANCH="${BRANCH:-main}"
APP_NAME="${APP_NAME:-pcap-explorer-github-oidc}"

echo ">> Reading current subscription/tenant..."
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"
echo "   subscription: $SUBSCRIPTION_ID"

echo ">> Creating (or reusing) Azure AD app '$APP_NAME'..."
APP_ID="$(az ad app list --display-name "$APP_NAME" --query '[0].appId' -o tsv)"
if [ -z "$APP_ID" ]; then
  APP_ID="$(az ad app create --display-name "$APP_NAME" --query appId -o tsv)"
fi
az ad sp create --id "$APP_ID" >/dev/null 2>&1 || true
echo "   appId: $APP_ID"

echo ">> Adding federated credential for repo:${GITHUB_ORG}/${GITHUB_REPO} (branch ${BRANCH})..."
az ad app federated-credential create --id "$APP_ID" --parameters "{
  \"name\": \"github-${GITHUB_REPO}-${BRANCH}\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${GITHUB_ORG}/${GITHUB_REPO}:ref:refs/heads/${BRANCH}\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}" >/dev/null 2>&1 || echo "   (federated credential already exists — skipping)"

echo ">> Granting the app Contributor on the subscription (needed to create resources)..."
az role assignment create \
  --assignee "$APP_ID" \
  --role Contributor \
  --scope "/subscriptions/${SUBSCRIPTION_ID}" >/dev/null 2>&1 || echo "   (role already assigned — skipping)"

cat <<EOF

============================================================
 Done. Add these as GitHub repo secrets:
   GitHub > your repo > Settings > Secrets and variables > Actions > New repository secret

   AZURE_CLIENT_ID       = $APP_ID
   AZURE_TENANT_ID       = $TENANT_ID
   AZURE_SUBSCRIPTION_ID = $SUBSCRIPTION_ID
   MAXMIND_LICENSE_KEY   = <maxmind.com > Account > Manage License Keys > Generate new key>

 Then push to main (or run the workflow manually from the Actions tab) and it
 will build + deploy. The workflow prints your live URL at the end.
============================================================
EOF
