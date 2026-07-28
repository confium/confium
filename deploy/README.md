# Confium Deployment Templates

Production-ready deployment artifacts for Confium.

## Contents

| Directory | What it provides |
| --- | --- |
| `docker/` | Docker Compose for local development. One command: `docker compose up`. |
| `helm/confium/` | Helm chart for Kubernetes. `helm install confium ./deploy/helm/confium`. |
| `.github/workflows-templates/` | Drop-in GitHub Actions for threshold-signed releases. |
| `grafana/` | Pre-built Grafana dashboard JSON for coordinator monitoring. |

## Quick start (Docker Compose)

```sh
cd deploy/docker
docker compose up
```

Brings up: 1 coordinator + 3 signers (2-of-3 threshold) + 1 transparency log + 1 witness.

## Kubernetes (Helm)

```sh
helm install confium ./deploy/helm/confium \
  --set signers.count=5 \
  --set signers.threshold=3
```

## GitHub Actions

Copy `deploy/.github/workflows-templates/threshold-sign.yml` to your repo's
`.github/workflows/` directory. Configure the required secrets:
`CONFIUM_COORDINATOR_URL`, `CONFIUM_SIGNER_ID`, `CONFIUM_SIGNER_TOKEN`.

## Grafana

Import `deploy/grafana/confium-coordinator.json` into your Grafana instance.
Requires Prometheus scraping the coordinator's `/metrics` endpoint.
