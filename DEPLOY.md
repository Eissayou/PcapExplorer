# Deploying PcapExplorer

Target: **Azure Container Apps** — scales to zero (idle = $0), has a monthly free
grant (180,000 vCPU-seconds + 360,000 GiB-seconds + 2M requests), and gives a free
HTTPS URL like `https://pcap-explorer.<region>.azurecontainerapps.io`. No custom
domain required — just link that URL from your site.

## Option A — GitHub Actions (auto-deploy on push to `main`)

The workflow at `.github/workflows/deploy.yml` builds the image in Azure's cloud
and deploys on every push to `main`. It downloads the GeoLite2 database at build
time (it's git-ignored — MaxMind's license forbids committing it to a public
repo), so nothing sensitive lives in the repo.

**One-time setup:**

1. Install the Azure CLI and sign in:
   ```bash
   az login
   az account set --subscription "<your-subscription-name-or-id>"
   ```
2. Wire GitHub to Azure with OIDC (no stored passwords):
   ```bash
   ./scripts/setup-github-oidc.sh
   ```
   It prints three `AZURE_*` values.
3. Get a MaxMind license key: <https://www.maxmind.com> → Account → Manage License Keys → Generate new key.
4. Add all four as GitHub repo secrets (repo → Settings → Secrets and variables → Actions):
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `MAXMIND_LICENSE_KEY`.

**Deploy:** push to `main`, or trigger it manually from the repo's **Actions** tab
(Deploy to Azure Container Apps → Run workflow). The run prints your live URL at
the end. Every later push redeploys automatically.

## Option B — Manual, from your machine (one-off)

You already have `data/GeoLite2-City.mmdb` locally, so no license key is needed here.

```bash
az login
az account set --subscription "<your-subscription-name-or-id>"
./deploy-azure.sh
```

`deploy-azure.sh` builds the image in the cloud (no local Docker needed), bakes in
your local `.mmdb`, deploys, and prints the live `https://…azurecontainerapps.io`
URL. Re-run it any time to redeploy.

## Cost & teardown

With scale-to-zero, an idle app costs nothing and light demo traffic stays inside
the free monthly grant. To remove everything:

```bash
az group delete --name pcap-explorer-rg --yes
```

## Notes

- The server listens on port `5432` by default; the deploy wires ingress to it.
- `GEOIP_MAX_LOOKUPS` and `GEOIP_DATABASE_PATH` can be set as container env vars
  (see the README Configuration table); the defaults are fine.
- OIDC federation is scoped to `main`. To deploy from another branch, add a
  federated credential for it (re-run the setup script with `BRANCH=<name>`).
