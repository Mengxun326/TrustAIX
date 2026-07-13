# Deployment guide

For a single host, copy the private access configuration, set the required environment variables, then run `docker compose -f compose.production.yaml up -d`. Caddy terminates HTTPS automatically after `TRUSTAIX_DOMAIN` resolves to the host.

For Kubernetes, create a secret with `openai-api-key` and `access.yaml`, then install `deploy/helm/trustaix`. The chart runs non-root, drops Linux capabilities, uses read-only application storage and has liveness/readiness checks. Replace the `emptyDir` audit volume with a managed database or encrypted persistent volume before production use.

`python -m trustaix.backup /data/trustaix.db /backups/trustaix-$(date +%F).db` creates a SQLite-consistent backup. Schedule it and call the retention API from an admin automation according to your compliance policy.
