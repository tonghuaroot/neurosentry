# NeuroSentry Helm Chart

Deploys NeuroSentry as a privileged per-node **DaemonSet** — eBPF runtime
protection for AI inference on every node in the cluster.

## Install

```bash
helm install neurosentry deploy/helm/neurosentry \
  --namespace neurosentry --create-namespace \
  --set image.repository=<registry>/neurosentry \
  --set image.tag=<version>
```

## What it deploys

- DaemonSet (privileged; `hostPID`/`hostNetwork`; `BPF`, `NET_ADMIN`,
  `SYS_ADMIN` caps) mounting `/sys/kernel/debug`, `/sys/fs/bpf`, and
  `/sys/kernel/btf` (read-only, for CO-RE).
- ServiceAccount + ClusterRole/Binding (pods/nodes read, quarantine).
- ConfigMap rendered from `values.yaml` (`protection.*`, `agent.*`).
- Service exposing `metrics` (2112) and `web` (8080); optional `ServiceMonitor`.

## Health gating

Kubernetes probes hit the **web** listener, not the metrics port:

| Probe | Path | Meaning |
|---|---|---|
| liveness | `/healthz` | process up → restart on failure |
| readiness | `/readyz` | components started **and** kernel support adequate → gates rollout/traffic |

`/readyz` returns `503` until the agent is ready, and reflects the Phase 1
kernel-capability assessment (`support: supported / degraded / unsupported`).

## Fail-safe

By default the agent **refuses to start** if `enforce_mode` is on but the node
kernel lacks BPF LSM (it would otherwise silently monitor-only). Set
`allowDegraded: true` to opt individual nodes into monitor-only instead.

Never set `--skip-bpf` in production (there is no value for it); that flag is for
non-Linux development only.

## Key values

See `values.yaml`. Common overrides: `image.*`, `resources`, `protection.*`,
`allowDegraded`, `serviceMonitor.enabled`, `updateStrategy.rollingUpdate.maxUnavailable`.
