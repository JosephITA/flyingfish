# Liqo Inter-Cluster Connectivity — Diagnostic Tool Specification

> **Status:** v2 — reviewed and fact-checked against the Liqo v1.2.0 repo (Helm chart +
> templates) and the v1.2.0 documentation. This document is the implementation brief
> for a CLI diagnostic tool that identifies connectivity problems between two Liqo-peered
> Kubernetes clusters. It is written so that a junior engineer (or a smaller AI model) can
> implement the tool without re-reading the Liqo documentation.

---

## 1. Background: what Liqo is and why connectivity matters

Liqo (https://liqo.io) enables dynamic multi-cluster Kubernetes topologies. A **consumer**
cluster offloads pods to a **provider** cluster, which appears locally as a *virtual node*.
For this to work, Liqo builds a **network fabric** that extends pod-to-pod and pod-to-service
connectivity across clusters. Every Liqo feature (offloading, service reflection, storage
fabric) sits on top of two connectivity dependencies:

1. **Control plane**: the consumer cluster must reach the provider's Kubernetes API server
   (directly, or through Liqo's API-server proxy over the tunnel when using in-band peering).
2. **Data plane**: a WireGuard UDP tunnel between one gateway pod per side, plus a Geneve
   overlay inside each cluster connecting every node to that gateway.

If either path degrades, symptoms range from "peering never completes" to subtle ones like
"DNS resolves but connections hang" (MTU) or "some pods reachable, some not" (per-node
overlay issues). The diagnostic tool's job is to walk these layers in order and point at the
exact broken link.

---

## 2. Liqo v1.x networking architecture (facts the tool relies on)

### 2.1 Components

| Component | Runs as | Role |
|---|---|---|
| `liqo-controller-manager` | Deployment, ns `liqo` | Creates/reconciles network CRDs during peering; computes NAT/remapping rules |
| `liqo-ipam` | Deployment, ns `liqo` | IP address management; allocates remapped CIDRs and IPs |
| `liqo-crd-replicator` | Deployment, ns `liqo` | Replicates CRs between peered clusters (Configuration/PublicKey exchange etc.); if it's down, peering negotiation silently stalls |
| `liqo-webhook` | Deployment, ns `liqo` | Admission webhooks for Liqo resources |
| Gateway pod (`gw-<cluster-id>`) | Deployment in tenant ns `liqo-tenant-<cluster-id>` | One per peer, per side. Containers: `gateway` (control), `wireguard` (tunnel), `geneve` (overlay termination). Populates routes and nftables NAT rules |
| `liqo-fabric` | DaemonSet, ns `liqo` | Runs on every node; creates Geneve tunnels node ↔ gateway pod, installs routes/firewall rules |
| `liqo-proxy` | Deployment, ns `liqo` (port 8118) | HTTP CONNECT passthrough to the local API server, used by in-band peering |
| Virtual node | Node object on consumer | Represents provider capacity; not a network component but its `Ready` condition depends on API reachability |

### 2.2 Custom resources (all namespaced in the tenant namespace unless noted)

| CRD (group) | Meaning | What its status tells a diagnostic |
|---|---|---|
| `ForeignCluster` (core.liqo.io, cluster-scoped) | One per peer; aggregates modules | Conditions for networking / authentication / offloading health |
| `Configuration` (networking.liqo.io) | Remote cluster's declared Pod/External CIDRs and how they are **remapped locally** | Wrong/missing CIDRs → broken remapping |
| `GatewayServer` (networking.liqo.io) | Server side of the tunnel; owns the exposed Service | `.status.endpoint` (IP/port actually exposed); unset → exposure problem |
| `GatewayClient` (networking.liqo.io) | Client side; holds the server endpoint to dial | Wrong endpoint → tunnel never comes up |
| `PublicKey` (networking.liqo.io) | Peer's WireGuard public key | Missing/mismatched → handshake failure |
| `Connection` (networking.liqo.io) | Tunnel state | `.status.value` = `Connected` / `Not Connected`; also carries latency info from inter-gateway pings |
| `InternalNode` / `InternalFabric` / `RouteConfiguration` / `FirewallConfiguration` (networking.liqo.io) | Per-node overlay wiring (Geneve), routes, nftables rules | Missing entries for a node → that node's pods can't cross the tunnel |
| `Network`, `IP` (ipam.liqo.io) | CIDR allocations and single-IP remappings (e.g., API-server proxy address) | Conflicting/failed allocations |
| `Identity`, `ResourceSlice`, `Tenant` (authentication.liqo.io) | Control-plane auth | Auth failures that masquerade as "networking" issues |

### 2.3 Data path (consumer pod → provider pod)

```
pod (node A, consumer)
  → CNI to node A
  → Geneve tunnel (UDP 6091) node A → gateway pod gw-<provider>
  → nftables SNAT/DNAT (CIDR remapping, if overlap)
  → WireGuard tunnel (UDP, service port default 51840) → provider gateway pod
  → reverse remapping (nftables)
  → Geneve tunnel gateway → destination node
  → CNI to destination pod
```

### 2.4 Addressing and remapping (critical to get right in the tool)

- Each cluster declares `podCIDR`, `serviceCIDR`, an `externalCIDR` (typically
  `10.70.0.0/16`) and an `internalCIDR` (typically `10.80.0.0/16`, used for fabric-internal
  addressing). In v1.2.0 the Helm values default to empty and the CIDRs are auto-managed —
  **read the effective values from the cluster-scoped `Network` CRs (ipam.liqo.io), never
  assume defaults.**
- If the two clusters' CIDRs **overlap** (very common: two clusters with the default
  `10.244.0.0/16`), the local IPAM allocates a **remapped CIDR** for the remote cluster and
  gateways translate with nftables. Communication is NAT-less only when nothing overlaps.
- The remapped values are visible in each cluster's `Configuration` resource
  (`kubectl get configuration -A` shows `REMAPPED POD CIDR` etc.).
- To reach remote pod `10.244.1.7` when its cluster was remapped to `10.71.0.0/16`, a local
  pod must dial `10.71.1.7` — same host bits, remapped prefix. Reflected EndpointSlices
  already contain translated IPs; humans doing manual pings must translate by hand.
- `externalCIDR` covers non-pod endpoints (API-server proxy, external hosts remapped via
  `IP` CRDs). Same prefix-substitution logic applies.
- Reserved subnets: the operator can reserve subnets that IPAM must not hand out; local pod
  and service CIDRs are reserved automatically. A remote cluster remapped **onto a subnet
  that the local infra actually uses** (e.g., node network) silently blackholes traffic —
  worth an explicit check.

### 2.5 Ports & protocols matrix

| Flow | Proto/Port | Direction | Notes |
|---|---|---|---|
| K8s API server | TCP 6443/443 | consumer → provider | Skipped if in-band peering (goes through tunnel via liqo-proxy TCP 8118) |
| WireGuard tunnel | UDP, service port **51840** by default (`liqoctl` flag `--gw-server-service-port`) | gateway client → gateway server (one direction only — client initiates, NAT on client side is fine) | Exposed as LoadBalancer (default) or NodePort |
| Geneve overlay | UDP **6091** (Helm `networking.genevePort`; standard Geneve is 6081 — Liqo deliberately uses 6091) | node ↔ gateway pod, **intra-cluster** | Node-level firewalls between nodes must allow it |
| Gateway metrics/probes | TCP 8081/8082 (fabric health/metrics) | intra-cluster | Only relevant for observability |

Other facts: minimum kernel **5.10** (nftables features); WireGuard runs in `kernel` or
`userspace` mode (Helm `...wireguard.implementation`); tunnel MTU default **1340**
(WireGuard overhead: 60 B IPv4 / 80 B IPv6) and **must match on both sides**
(`--mtu` on `liqoctl network connect` / `liqoctl peer`); TCP MSS clamping is enabled by
default, but UDP datagrams with DF that exceed the tunnel MTU are dropped; Liqo versions
must match between peers (mixed versions unsupported).

### 2.6 How peering is established (so the tool knows what "healthy" looks like)

`liqoctl peer` (needs both kubeconfigs) = three modules:
1. **Networking** — equivalent to `liqoctl network connect`: exchange `Configuration`s,
   deploy GatewayServer (provider) + GatewayClient (consumer), exchange `PublicKey`s,
   create `Connection`s.
2. **Authentication** — consumer gets an `Identity` (kubeconfig restricted to Liqo APIs).
3. **Offloading** — consumer creates `ResourceSlice`; virtual node appears.

Health can be read with `liqoctl info` and `liqoctl info peer <cluster-id>` (supports
`-o json` — the diagnostic tool can shell out or reimplement via CRD reads; **prefer
reading CRDs directly with client-go** so the tool doesn't depend on liqoctl).

---

## 3. Failure-mode catalog

Ordered roughly by frequency in the field. Each entry: **Symptom → Causes → How to detect**.
The check IDs refer to §5.

### F1. Gateway server not reachable (the #1 killer)
- **Symptom:** `Connection` stuck `Not Connected`; `liqoctl peer/network connect` hangs on "waiting for connection".
- **Causes:**
  - LoadBalancer Service stuck `<pending>` (no LB controller, quota, or cloud LB that can't do **UDP** — e.g., DigitalOcean's LB health checks don't support UDP and mark the service down).
  - NodePort chosen but node IPs are private / firewalled from the other cluster.
  - Perimeter firewall / security group dropping the UDP port (51840 or custom).
  - `GatewayServer.status.endpoint` advertises an address the client can't route to (LB private IP, wrong `--gw-server-service-loadbalancerip`).
  - Double NAT rewriting source ports unpredictably (client side is usually fine — WireGuard client initiates — but a stateful firewall timing out UDP mappings kills idle tunnels).
- **Detect:** GW-01…GW-05, TUN-02, PROBE-UDP.

### F2. WireGuard handshake fails despite reachability
- **Symptom:** UDP reaches the server (packet counters increase) but `Connection` stays down; `wg show` shows no `latest handshake`.
- **Causes:** `PublicKey` CRs missing/stale after re-peering (keys regenerate when gateways are recreated); endpoint IP:port mismatch between `GatewayClient` spec and the server's actual exposure; clock skew is *not* an issue for WG, but MTU < 1280-ish can break handshakes in extreme cases.
- **Detect:** TUN-01, TUN-03, TUN-04.

### F3. MTU / fragmentation blackhole
- **Symptom:** ping works, small HTTP requests work, large responses / TLS handshakes / `kubectl logs` through in-band proxy hang. Classic PMTUD blackhole.
- **Causes:** underlay path MTU < 1340 + WG overhead (common on cloud VPNs, PPPoE, double encapsulation e.g. WG over VXLAN networks); MTU set differently on the two sides; ICMP "frag needed" filtered; UDP-with-DF apps.
- **Detect:** MTU-01 (config equality), PROBE-MTU (active sweep with `ping -M do` at decreasing sizes through the tunnel).

### F4. CIDR conflicts / broken remapping
- **Symptom:** tunnel `Connected` but pod→pod traffic vanishes; or traffic reaches remote cluster with unroutable source.
- **Causes:** remote cluster remapped onto a subnet used locally (node network, VPN, corporate ranges) because it wasn't in `reservedSubnets`; `Configuration` CIDRs don't match what the remote cluster actually uses (cluster reinstalled with new CIDRs, stale Configuration); same `externalCIDR` on both sides is normal (translation handles it) but a *wrong* Configuration is not; overlapping `internalCIDR` with real infrastructure.
- **Detect:** IPAM-01…IPAM-04.

### F5. Intra-cluster overlay (Geneve) broken on some nodes
- **Symptom:** pods on node X reach remote pods, pods on node Y don't (partial, node-dependent failures — highly characteristic).
- **Causes:** node firewall (or cloud SG between nodes) blocking UDP 6091 toward the node hosting the gateway pod; `liqo-fabric` DaemonSet pod not running/crashing on the node; missing `InternalNode`/route for a recently added node; kernel too old for nftables rules.
- **Detect:** FAB-01…FAB-04, PROBE-PP run from multiple nodes.

### F6. CNI interference
- **Symptom:** anything from broken overlay to gateway pod networking flaps.
- **Causes:**
  - **Calico**: BGP IP autodetection grabbing Liqo-created interfaces (`liqo*` tunnel/Geneve devices) — must be excluded via `skipInterface` regex.
  - **Cilium** in kube-proxy-replacement/eBPF mode: eBPF programs can bypass the nftables rules Liqo installs; socket-LB translating service IPs before Liqo sees them.
  - NetworkPolicies (or CNI-level policies) dropping traffic from remapped remote pod CIDRs — remote pods have IPs outside the local pod CIDR, so "allow from pods" policies don't match them.
  - CNI masquerading cross-node traffic that Liqo expects unmasqueraded.
- **Detect:** CNI-01 (detect CNI + known-issue heuristics), CNI-02 (NetworkPolicy scan for policies in offloaded namespaces that don't cover remapped CIDRs), plus PROBE results pattern.

### F7. Control-plane reachability / auth (often mistaken for network fabric issues)
- **Symptom:** virtual node `NotReady`, offloaded pods stuck, but `Connection` is `Connected`.
- **Causes:** consumer can't reach provider API server (endpoint in the Identity kubeconfig unreachable, cert not valid for the address used); in-band peering: liqo-proxy down or its remapped `IP` CR wrong; expired/revoked Identity.
- **Detect:** API-01…API-03, FC-01.

### F8. Service reflection / DNS anomalies
- **Symptom:** cross-cluster DNS name resolves but connection fails, or resolves to nothing.
- **Causes:** EndpointSlice reflection produced IPs that aren't reachable (remapping config changed after reflection); service reflected but endpoints empty (remote pods not ready); CoreDNS caching stale IPs after re-peering.
- **Detect:** REF-01, REF-02, PROBE-DNS, PROBE-SVC.

### F9. Version / install-state mismatches
- **Symptom:** subtle CRD reconcile errors, features half-working.
- **Causes:** different Liqo versions on the two clusters (unsupported); leftover resources from a previous peering (force-unpeer remnants); upgrade performed without unpeering (unsupported path).
- **Detect:** ENV-02, ENV-03, ENV-04.

### F10. Gateway pod health / restarts
- **Symptom:** tunnel flaps; latency spikes in `Connection` status.
- **Causes:** OOM/crashloop of gateway containers; node pressure; HA not configured (Helm default `gatewayTemplates.replicas: 1` — a single-replica gateway is a SPOF; during node drain the tunnel drops); UDP conntrack entries lost on restart.
- **Detect:** GW-06, TUN-05 (flap history via restart counts + Connection transitions).

---

## 4. The tool: product decision

**Form: a single-binary CLI written in Go with a rich TUI**, named **FlyingFish**
(binary `flyingfish`, no cluster-side install required). Rationale:

- Go: same ecosystem as Liqo/Kubernetes; `client-go` gives typed access; single static
  binary; easy `kubectl exec` streaming for in-pod probes; cross-compiles.
- TUI: `bubbletea` + `lipgloss` for a live checklist view (spinner per running check,
  ✅/⚠️/❌ per result, expandable failure details), falling back automatically to plain
  sequential output when stdout is not a TTY. `cobra` for the command surface.
- Read-only by default; active probes (which create pods) behind an explicit flag.
- Machine-readable output (`--output json|yaml|markdown`) so it can run in CI or be consumed
  by another agent.

### Command surface

```
flyingfish check   --kubeconfig A [--remote-kubeconfig B] [--peer <cluster-id>] [--active] [--level quick|standard|deep]
flyingfish probe   mtu|udp|pod-to-pod|service|dns  (individual active probes)
flyingfish watch   (re-runs passive checks on interval, live TUI dashboard)
flyingfish report  (runs `check --level deep`, emits self-contained markdown/HTML report)
flyingfish version
```

- **Dual-cluster mode** (both kubeconfigs): full matrix, can correlate both sides
  (e.g., compare the two `Configuration`s, both `Connection`s, run probes in both directions).
- **Single-cluster mode**: everything observable from one side + clear "cannot verify
  remotely, ask peer admin to run X" messages.
- `--peer` selects the ForeignCluster when several exist; interactive picker in TUI mode.
- Exit codes: `0` all pass, `1` warnings only, `2` at least one failure, `3` tool error
  (bad kubeconfig etc.).

### Engine design

```go
type CheckResult struct {
    ID, Name    string
    Layer       string        // env|api|gateway|tunnel|fabric|ipam|cni|reflection|probe
    Status      Status        // Pass|Warn|Fail|Skip
    Detail      string        // human explanation of what was observed
    Remediation string        // concrete next step, may embed kubectl commands
    Evidence    []string      // raw observations (endpoint values, counters, CIDRs)
    DependsOn   []string      // check IDs
}
```

- Checks form a DAG; a failed dependency marks dependents `Skip` with reason (don't drown
  the user in cascade failures — the tool's core value is pointing at the *first* broken layer).
- Layers run in order: env → api → gateway → tunnel → fabric → ipam → cni → reflection → probes.
- Every check has a timeout (default 10 s passive, 60 s active) and runs concurrently within
  its layer.
- All Liqo CRDs are read via the dynamic client with the GVRs listed in §2.2 (avoid importing
  Liqo's Go types — keeps the tool decoupled from Liqo releases; parse with `unstructured`).

---

## 5. Check catalog (the implementation contract)

Legend: **[1]** = works in single-cluster mode; **[2]** = needs both kubeconfigs;
**[A]** = active (creates resources; requires `--active`; everything it creates goes in a
dedicated namespace `flyingfish-probe` with a common label, and is torn down on exit,
including on Ctrl-C — use a deferred cleanup + ownerRef on the namespace).

### Layer 0 — Environment (ENV)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| ENV-01 [1] | Liqo installed & healthy | Deployments in ns `liqo` (`liqo-controller-manager`, `liqo-ipam`, `liqo-fabric` DS, webhook) all Ready | Fail lists the unhealthy workloads and last container error |
| ENV-02 [2] | Version match | Read Liqo version (controller-manager image tag / `liqo-version` labels) on both sides | Fail if different (unsupported by Liqo) |
| ENV-03 [1] | CRDs present | All GVRs of §2.2 exist in discovery | Fail → broken/partial install |
| ENV-04 [1] | Stale peering debris | Tenant namespaces / ForeignClusters with deletion timestamps stuck, orphaned gateways | Warn with cleanup hints (`liqoctl network reset`, force-unpeer docs) |
| ENV-05 [1] | Node kernels ≥ 5.10 | `.status.nodeInfo.kernelVersion` of all nodes | Warn per offending node (nftables requirement) |

### Layer 1 — Control plane (API / FC)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| FC-01 [1] | ForeignCluster module conditions | Read `ForeignCluster` status conditions (networking/authentication/offloading) | Direct map to which module is unhappy — drives which later layers matter |
| API-01 [1] | Provider API reachable from consumer | From the Identity kubeconfig stored in tenant ns secrets: extract server URL; TCP+TLS dial from the tool *and* (better) from inside the cluster via an [A] probe pod running `curl -k` | Distinguish "reachable from operator laptop but not from cluster" |
| API-02 [1] | In-band proxy path | If in-band: liqo-proxy Deployment ready; `IP` CR for proxy exists with remapped address; remapped address falls inside remote-side remapped externalCIDR | |
| API-03 [1] | Identity validity | Client-cert expiry dates in Identity kubeconfig; attempt a `SelfSubjectReview`-style call in dual mode | Warn < 30 days to expiry |

### Layer 2 — Gateway exposure (GW)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| GW-01 [1] | Gateway pods running | `gw-*` pods in tenant ns Ready, all 3 containers | Include restart counts |
| GW-02 [1] | Server Service sane | On server side: Service exists; if LoadBalancer → has ingress IP/hostname (Fail `<pending>` with cloud-specific hints, incl. DigitalOcean UDP caveat); if NodePort → collect node addresses and Warn if all are private RFC1918 while the peer is a different site |
| GW-03 [1] | Advertised endpoint consistency | `GatewayServer.status.endpoint` == actual Service exposure (IP + port) | Catches stale endpoints after Service changes |
| GW-04 [2] | Client dials the right place | `GatewayClient.spec` endpoint on consumer == `GatewayServer.status.endpoint` on provider | The single most valuable dual-mode check |
| GW-05 [1] | UDP port open from outside | From the tool's host: send WireGuard-shaped UDP packet(s) to endpoint, look for any ICMP unreachable (open UDP ports are silent — document that "no response" is *inconclusive*, only ICMP-refused is a hard Fail); complement with PROBE-UDP for a definitive answer |
| GW-06 [1] | Gateway stability | Restart counts + recent `Connection` condition transitions | Warn on flapping |

### Layer 3 — Tunnel (TUN)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| TUN-01 [1] | Connection CR state | `Connection.status.value == "Connected"` (both directions in dual mode) | The headline check |
| TUN-02 [1] | WG handshake freshness | `kubectl exec` into gateway pod: `wg show liqo-tunnel latest-handshakes` (interface name: discover via `wg show interfaces`) | Fail if no handshake or > 3 min old |
| TUN-03 [1] | WG traffic counters move | `wg show ... transfer` sampled twice, 2 s apart, while Connection pinger runs | rx=0 with tx>0 → outbound-only = classic firewall/endpoint issue |
| TUN-04 [2] | Key symmetry | `PublicKey` CR on each side == `wg show ... public-key` of the peer's gateway | Catches stale keys after gateway recreation |
| TUN-05 [1] | Tunnel latency | Read latency from `Connection` status (inter-gateway pinger; v1.2.0 defaults: ping every 2 s, connection declared lost after 5 consecutive losses, status refreshed every 10 s — so `Connection` reacts to real outages within ~10–20 s) | Warn above threshold (default 200 ms), informational otherwise |

### Layer 4 — Intra-cluster fabric (FAB)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| FAB-01 [1] | fabric DaemonSet coverage | desired == ready, list missing nodes | Node-partial failures |
| FAB-02 [1] | InternalNode per node | Every schedulable node has an `InternalNode`; `InternalFabric`/`RouteConfiguration`s present for the peering | |
| FAB-03 [1] | Geneve reachability node→gateway | [A] probe: hostNetwork pod (or `kubectl debug node`) sending UDP 6091 to the gateway pod's node; passive fallback: parse fabric pod logs for Geneve errors | |
| FAB-04 [1] | FirewallConfiguration applied | `FirewallConfiguration` CRs exist and report applied condition; fabric/gateway logs free of nftables errors. Note: MSS clamping itself is installed as a `FirewallConfiguration` named like `*-mssclamp` — its absence/failure directly explains MTU-symptom cases (F3) | Catches kernel/nftables issues concretely |

### Layer 5 — IPAM / remapping (IPAM)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| IPAM-01 [2] | Configurations are truthful | Consumer's `Configuration` for the peer: declared remote pod/external CIDR == what the remote cluster actually reports (its own `Network` CRs / install values); and vice versa | Stale config after cluster reinstall |
| IPAM-02 [1] | Remap collision with local infra | Remapped CIDRs (pod/external of the peer) vs: local pod CIDR, service CIDR, node addresses, internalCIDR, `reservedSubnets` | Fail on overlap, print the exact colliding ranges |
| IPAM-03 [2] | Overlap requiring NAT detected & handled | If the raw CIDRs overlap, confirm remapping is active (remapped ≠ original); if the CIDRs overlap but the Configuration shows original == remapped → Fail | |
| IPAM-04 [1] | IP CRs healthy | All `IP` CRs have allocated status addresses | For proxy/external-host remaps |

### Layer 6 — CNI interactions (CNI)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| CNI-01 [1] | Detect CNI & known caveats | Fingerprint from DaemonSets (calico-node, cilium, flannel, …). Calico → check `IP_AUTODETECTION_METHOD` excludes `liqo*` interfaces (Warn otherwise, with exact env value to set). Cilium → Warn if kube-proxy replacement/socket-LB detected, link to caveat | Heuristic Warns, not Fails |
| CNI-02 [1] | NetworkPolicy interference | In offloaded namespaces (those with `NamespaceOffloading`), find NetworkPolicies whose ipBlocks/podSelectors cannot match the peer's **remapped** pod CIDR | Warn listing policies |

### Layer 7 — Reflection (REF)
| ID | What | Method | Pass / Fail |
|---|---|---|---|
| REF-01 [1] | Reflected EndpointSlices sane | For reflected Services: endpoint IPs fall inside the peer's remapped pod/external CIDR and are non-empty | Empty or out-of-range → reflection vs remapping drift |
| REF-02 [1] | Virtual node Ready | Virtual node conditions | Ties back to API layer if NotReady |

### Layer 8 — Active end-to-end probes (PROBE) — all [A]
| ID | What | Method |
|---|---|---|
| PROBE-UDP [2] | Prove UDP path outside WireGuard | Deploy `ghcr.io/liqotech/udpecho` behind a Service of the same type/port family as the gateway on the server cluster; from a client-cluster pod (and from the tool host) send/expect echo. Mirrors the official FAQ procedure |
| PROBE-PP [2] | Pod→pod through the fabric | nginx/agnhost pods in a namespace on both sides; compute the remapped IP of the remote pod (host bits + remapped prefix, per §2.4); ping + TCP connect from source pods **on at least 2 different nodes** (catches F5); report per-node matrix |
| PROBE-SVC [2] | Pod→reflected service | Offload a namespace (or use `--namespace` of an existing offloaded one), curl the reflected service by cluster-local DNS name |
| PROBE-DNS [1] | DNS for reflected services | From a probe pod: resolve `svc.ns.svc.cluster.local` of a reflected service; compare against Service clusterIP |
| PROBE-MTU [2] | Path MTU sweep | From probe pod: `ping -M do -s <size>` toward remote (remapped) pod IP, binary-search sizes between 1200 and 1500; report largest passing payload; compare with configured tunnel MTU (1340). Also compare MTU value on both `Connection`/gateway specs |
| PROBE-TCPDUMP [1] | Guided capture (deep level only) | `kubectl exec` tcpdump in gateway pod (`tcpdump -tnl -i any icmp`) while PROBE-PP pings, report whether packets arrive at gw-local, leave tunnel, arrive gw-remote — localizes the drop point to one of the 4 hops of §2.3 |

**Probe hygiene:** everything labeled `app.kubernetes.io/managed-by=flyingfish`; namespace
deleted on exit; `--keep-probes` to retain for manual inspection; never modify Liqo CRs.

---

## 6. Output design

- **TUI (default on TTY):** layered checklist with live spinners; failures expand inline with
  Detail → Evidence → Remediation; final summary panel: "Diagnosis: <one-line root cause>"
  choosing the *first failing layer* as the primary finding.
- **`--output json`:** array of CheckResult + top-level `diagnosis` object — this is the
  contract for other tools/AI agents.
- **`report` command:** markdown with the §2.3 path diagram annotated (✓/✗ per hop), the full
  matrix, and copy-pasteable remediation commands.
- Every Fail must ship a Remediation string. Write them against the catalog in §3 (e.g.,
  GW-02 LB pending on DigitalOcean → suggest NodePort + firewall rule; TUN-04 → recreate
  PublicKey CRs / re-run `liqoctl network connect`).

## 7. Implementation plan (milestones)

1. **M1 – skeleton:** cobra CLI, kubeconfig loading (×2), dynamic client, CheckResult engine
   with DAG + layer scheduler, plain output, JSON output, exit codes. ENV + FC + TUN-01
   checks. *(Already usable.)*
2. **M2 – passive coverage:** all GW/TUN/FAB/IPAM/CNI/REF checks (pure reads + `exec` into
   existing Liqo pods for `wg show`). Dual-mode correlation (GW-04, TUN-04, IPAM-01/03).
3. **M3 – TUI:** bubbletea live view, peer picker, `watch` mode.
4. **M4 – active probes:** probe namespace lifecycle, PROBE-UDP/PP/DNS/SVC/MTU, per-node
   matrix, `probe` subcommands.
5. **M5 – polish:** `report` command, remediation text review against §3, CI (kind + liqo
   two-cluster e2e using `liqoctl peer` on kind, then break things deliberately: drop the UDP
   port with a NetworkPolicy/iptables rule, scale gateway to 0, corrupt PublicKey — assert
   the tool blames the right layer).

## 8. Facts to re-verify during implementation (do not skip)

Already verified against the v1.2.0 repo (`deployments/liqo/values.yaml` + templates):
`liqo-fabric` DaemonSet exists; `liqo-crd-replicator` and `liqo-webhook` are real components;
Geneve port 6091; WireGuard `kernel|userspace` implementation option with
`preserveClientEndpoint: true` (server keeps the discovered client endpoint across PublicKey
reconciliations — relevant when interpreting TUN-04); gateway replicas default 1; Connection
pinger defaults (2 s interval, loss threshold 5, status update 10 s); liqo-proxy port 8118;
MSS clamping shipped as a `FirewallConfiguration`; `externalCIDR`/`internalCIDR` Helm values
empty by default (auto-managed — read effective values from `Network` CRs).

Still to confirm on a live v1.2.0 install (or deeper source dive) during implementation:

1. Exact CRD names/GVRs (§2.2) — `kubectl api-resources | grep liqo` on a live v1.2.0 install.
2. WireGuard interface name inside the gateway pod (assumed `liqo-tunnel`) — use
   `wg show interfaces` instead of hardcoding.
3. `Connection` status field paths (`.status.value`, latency fields) — inspect a live CR.
4. Tenant namespace naming pattern (`liqo-tenant-<cluster-id>`) and gateway pod naming (`gw-<cluster-id>`).
5. Default gateway service port 51840 (per v1.2.0 docs; older versions used 5871) — the tool
   must read it from the Service/GatewayServer status rather than assume it.
6. In-band peering flag/behavior on `liqoctl peer` v1.2.0 and the proxy `IP` CR name.

Ground truth sources: Liqo docs v1.2.0 (features/network-fabric, advanced/peering/
inter-cluster-network, installation/requirements, FAQ network section, advanced/
external-ip-remapping, advanced/k8s-api-server-proxy) and the Helm chart
`deployments/liqo/values.yaml` in github.com/liqotech/liqo.
