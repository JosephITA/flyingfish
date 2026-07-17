# FlyingFish 🐟✈️

> *The flying fish lives in two worlds at once — it gathers speed beneath the waves, breaks the surface, and glides through open air as if the border between sea and sky were never there. Liquid computing makes the same promise to your workloads: pods that swim in one cluster and soar into another, without ever noticing the boundary. **FlyingFish is the instrument that tells you why the glide fails** — whether the fish never left the water, hit a wall in the wind, or landed in a sea it doesn't recognize.*

**FlyingFish** is a single-binary diagnostic CLI for [Liqo](https://liqo.io) inter-cluster connectivity. When two peered Kubernetes clusters can't talk — peering stuck, tunnel down, some pods reachable and others not, DNS resolving into the void — `flyingfish check` walks every layer the connection depends on and points at the **first broken link**, with evidence and a concrete fix.

```
 ENVIRONMENT
  ✓ ENV-01   Liqo core components healthy
  ✓ ENV-03   Liqo CRD groups served

 GATEWAY EXPOSURE
  ✗ GW-02    Gateway server service exposed
      gateway server service is not (or not usefully) exposed
      · liqo-tenant-milan/gw-milan: LoadBalancer stuck <pending>
      ⚑ LoadBalancer pending → no LB controller, or your cloud LB cannot do UDP

 diagnosis ✗ GW-02 [GATEWAY EXPOSURE]: gateway server service is not exposed
```

## Why

Liqo's network fabric is a chain: **control plane** (consumer → provider API server) → **gateway exposure** (a UDP service the peer can reach) → **WireGuard tunnel** (gateway ↔ gateway) → **Geneve overlay** (every node ↔ its gateway) → **CIDR remapping** (IPAM/NAT for overlapping networks) → **reflection** (services & endpoints translated across clusters). A failure anywhere in the chain surfaces as a confusing symptom somewhere else. FlyingFish encodes the whole chain — and its classic failure modes — as an ordered, dependency-aware check suite.

## Install

```bash
go install github.com/JosephITA/flyingfish/cmd/flyingfish@latest
```

or build from source:

```bash
git clone https://github.com/JosephITA/flyingfish && cd flyingfish
go build -o bin/flyingfish ./cmd/flyingfish
```

## Usage

```bash
# Diagnose from one side (everything observable with a single kubeconfig)
flyingfish check

# Full cross-cluster diagnosis: correlates both sides — e.g. detects a
# GatewayClient dialing an endpoint the GatewayServer no longer advertises
flyingfish check --kubeconfig consumer.yaml --remote-kubeconfig provider.yaml

# Focus on one peering, machine-readable output, CI-friendly exit codes
flyingfish check --peer milan -o json
```

| Exit code | Meaning |
|---|---|
| `0` | all checks passed |
| `1` | warnings only |
| `2` | at least one failure (the `diagnosis` field names the culprit) |
| `3` | tool error (bad kubeconfig, no cluster access) |

## What it checks

| Layer | Checks | Catches |
|---|---|---|
| Environment | Liqo components, CRDs, versions, kernel ≥ 5.10, stale peering debris | broken/partial installs, unsupported version mixes |
| Control plane | ForeignCluster module conditions, **peering age & per-module condition duration**, provider API reachability, in-band proxy, identity certificate expiry | auth failures that masquerade as network failures; how long a module has actually been unhealthy vs. how old the peering is |
| Gateway exposure | gateway pods, LoadBalancer/NodePort exposure, advertised vs. actual endpoint, client↔server endpoint match, live UDP probe of the endpoint | `<pending>` LBs, UDP-less cloud LBs, private-only NodePorts, stale endpoints, actively-refused UDP |
| Tunnel | Connection state, live WireGuard handshake age (via `wg show` in the gateway pod), **tunnel/gateway-pod uptime and real traffic byte counters**, tunnel interface MTU (compared across clusters in dual mode), latency | blocked UDP ports, stale keys after re-peering, expired NAT mappings, MTU mismatches, a tunnel that's "Connected" but has never moved a byte |
| Fabric | per-node fabric agent, InternalNode wiring, firewall configs incl. MSS clamping | "pods on node X work, node Y doesn't", MTU-style hangs |
| IPAM | remapped peer CIDRs vs. local pod/node networks, IP allocations | remap collisions that silently blackhole traffic |
| CNI | Calico interface autodetection, Cilium kube-proxy replacement, NetworkPolicies vs. remapped CIDRs | CNI features that bypass or drop Liqo's traffic |
| Reflection | reflected EndpointSlice reachability, virtual node readiness, **virtual node age & actual scheduled/running workload count** | DNS that resolves to unreachable endpoints; a peering that's technically Ready but has nothing running on it |

Passive by default — FlyingFish only **reads** cluster state (plus `wg show` inside existing gateway pods and harmless UDP probe packets toward the gateway endpoint). It never modifies Liqo resources.

If a live peering exists, the report also includes a **peering resource dump** — ForeignClusters (role, age), ResourceSlices (CPU/memory/pod quotas requested vs. accepted), Identities, Tenants, NamespaceOffloadings, and virtual node capacity — as plain markdown tables.

Every report ends with a **manual test cheat sheet** (the concrete IPs, ports, CIDRs and MTU it discovered, each with a ready-to-paste command like `curl`, `nc`, `ping -M do`) and an **"All Checks — Summary" table**: every check, its status, and a one-line result, in a single markdown table you can screenshot or paste straight into a chat with another developer.

## Roadmap

- **Active probes** (`--active` / `flyingfish probe`): UDP echo through the gateway path, pod-to-pod per-node reachability matrix, path-MTU sweep, guided tcpdump hop localization.
- **`flyingfish watch`**: live re-checking dashboard.
- **`flyingfish report`**: self-contained markdown/HTML incident report.

The full design document — Liqo networking architecture, the failure-mode catalog, and the complete check contract — lives in [`LIQO_CONNECTIVITY_DIAGNOSTICS.md`](LIQO_CONNECTIVITY_DIAGNOSTICS.md).

## License

Copyright 2026 the FlyingFish authors.

Licensed under the [Apache License, Version 2.0](LICENSE).

*FlyingFish is an independent diagnostic tool for Liqo and is not affiliated with the Liqo project.*
