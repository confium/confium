# Confium Production Deployment Guide

This guide walks through deploying Confium on Kubernetes for production use. For local dev see [docker-compose full-stack](../docker-compose/full-stack.yml).

## Prerequisites

- Kubernetes 1.27+
- `kubectl` configured
- TLS certificates (we recommend [cert-manager](https://cert-manager.io/))
- A storage class for persistent volumes
- An HSM or KMS for share storage (or `kubernetes-secret` for dev)

## Quick start

```sh
# Apply the full production stack
kubectl apply -f deploy/k8s/production/

# Watch it come up
kubectl -n confium-system get pods -w
```

This brings up:

- 1 coordinator (single replica, holds session state)
- 3 signerd replicas (one share each, 2-of-3 CMP20)
- 1 log-server
- ConfigMaps, PVCs, Services, NetworkPolicies, PDBs, HPAs

## What's in the manifest

### Security

- **`runAsNonRoot: true`** on every pod (distroless base images match)
- **`readOnlyRootFilesystem: true`** so writes go only to mounted volumes
- **`allowPrivilegeEscalation: false`**; capabilities dropped
- **`seccompProfile: RuntimeDefault`** for syscall filtering
- **NetworkPolicies** restricting signerd ingress/egress to just the coordinator

### Reliability

- **StatefulSet for signerd** with PVC per replica (share storage)
- **PDB** keeping at least 2 signerd replicas available (preserves quorum)
- **HPA** scaling signerd from 3 to 10 replicas on CPU >70%
- **Readiness + liveness probes** on coordinator

### Observability

- **Prometheus annotations** on all pods (`prometheus.io/scrape: "true"`)
- **Metrics path**: `/metrics` on each service
- **Pre-built Grafana dashboards** in `deploy/grafana/`:
  - `confium-coordinator.json`
  - `confium-signerd.json`
  - `confium-log-server.json`

## DKG ceremony

After the cluster is up, run a DKG to generate the initial shares:

```sh
# Exec into one of the signerd pods
kubectl -n confium-system exec -it confium-signerd-0 -- bash

# Inside the pod, run a 2-of-3 DKG
confium threshold dkg \
    --threshold 2 \
    --parties 3 \
    --scheme cmp20 \
    --out /tmp/shares.json

# Distribute shares to the other 2 pods (or via kubectl cp)
# In production, use the operator-driven flow instead.
```

For a fully operator-driven flow, install the [bundle](../k8s/bundle.yaml) which adds the Confium operator. Then:

```sh
kubectl apply -f - <<EOF
apiVersion: confium.org/v1
kind: ThresholdKey
metadata:
  name: my-key
  namespace: confium-system
spec:
  threshold: 2
  party_count: 3
  scheme: cmp20
EOF
```

The operator runs the DKG and distributes shares to the signerd pods automatically.

## TLS

The manifest references `confium-coordinator-tls` secret for the coordinator's TLS cert. Provision it via cert-manager:

```sh
# cert-manager issuer (if not already installed)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml

# Self-signed issuer for dev (use Let's Encrypt / internal CA for prod)
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: self-signed
  namespace: confium-system
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: confium-coordinator-tls
  namespace: confium-system
spec:
  secretName: confium-coordinator-tls
  dnsNames: [confium-coordinator, confium-coordinator.confium-system.svc]
  issuerRef:
    name: self-signed
EOF
```

## Monitoring

1. Install Prometheus + Grafana (via [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack)).
2. Import dashboards:
   ```sh
   kubectl -n monitoring create cm confium-dashboards \
       --from-file=deploy/grafana/
   kubectl -n monitoring label cm confium-dashboards grafana_dashboard=1
   ```
3. Open Grafana → "Confium" folder → dashboards appear.

## Upgrading

```sh
# Pull latest images
kubectl -n confium-system set image statefulset/confium-signerd \
    signerd=ghcr.io/confium/signerd:v0.4.0
kubectl -n confium-system rollout status statefulset/confium-signerd

# Roll back if anything fails
kubectl -n confium-system rollout undo statefulset/confium-signerd
```

The PDB ensures 2 signerd replicas stay available during the rollout.

## Backup

- **Coordinator state:** PVC `confium-coordinator-data` — snapshot daily.
- **Signerd shares:** PVC per replica — snapshot daily; rotate via Herzberg refresh quarterly.
- **Log server:** PVC `confium-log-server-data` — append-only; snapshot weekly. Backup of OTS proofs is critical.

See [backup-shares.mdx](../cookbook/backup-shares.mdx).

## See also

- [Terraform modules](https://github.com/confium/terraform-confium)
- [K8s bundle (operator-only)](../k8s/bundle.yaml)
- [Helm chart](../helm/confium/)
- [Threat model](../../docs/security/threat-model.mdx)
