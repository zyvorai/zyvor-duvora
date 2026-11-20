# Product and implementation plan

## Product decision

Build one standalone DPU operating platform. Customers install one control plane and operate one console. PacketWolf, Zeus OS, Gryvia, and Atlas can consume the API later, but none is required to run this project.

Working name: **Duvora**. Repository suggestion: `zyvorai/duvora`; CLI: `duvoractl`. Naming availability has not been checked.

Primary buyer: infrastructure/platform teams operating BlueField-enabled private clouds and GPU infrastructure. Initial problem: fragmented device inventory, unsafe lifecycle workflows, and unclear policy/telemetry evidence. Sell supported device operations only after hardware qualification; avoid claiming universal acceleration from a dashboard.

## Phase 1 — runnable evaluation release (implemented)

- Standard-library Python HTTP control plane with SQLite persistence.
- Eight console workspaces with light/dark themes and responsive layout.
- Role-separated access keys and host-bound inventory agents.
- Reviewed, expiring, actor-bound plans with device revision validation.
- Simulation workflows for service deployment, isolation, release, upgrades, and rollback.
- Policy verdict evaluation, metrics endpoint, audit export, CLI.
- Linux PCI discovery and NVIDIA DPF read-only import.
- Container/Kubernetes templates, CI, backend tests, browser suite.

Acceptance: source runs without hardware; simulator operations never claim physical success; backend workflow and HTTP tests pass. Browser visual acceptance is still pending in the creating environment.

## Phase 2 — qualified BlueField provisioning

Create a DPF mutation adapter, pinned to a selected DPF release and hardware matrix. Map Zyvor plans to vendor objects only after validating schemas with a real cluster. Implement inventory identity using device serial and DPF UID, signed BFB artifact metadata, compatibility checks, explicit maintenance windows, host effects, provisioning receipts, status watches, and recovery runbooks.

Acceptance: provision a physical DPU, interrupt control-plane connectivity, resume reconciliation, and prove recovery. Record host/DPU OS, NIC firmware, DPF/DOCA versions, management topology, and downtime. Do not equate accepted Kubernetes intent with hardware readiness.

## Phase 3 — physical networking and isolation

Implement one supported policy backend first. Map tenant boundaries to actual VFs, representors, VRFs/VLANs or vendor service constructs as supported. Define fail-open/fail-closed semantics per operation. Keep management access reachable independently of tenant policy.

Acceptance: two real tenants, positive and negative traffic tests, no cross-tenant leakage, IPv4/IPv6 coverage, reboot persistence, adapter failure handling, management-path survival, and policy drift detection. Process attribution still requires a host-side sensor.

## Phase 4 — service lifecycle and telemetry

Deploy immutable DPU service artifacts, validate signatures and architecture, record image provenance, reconcile rollout health, collect vendor hardware counters, and retain time-series telemetry. Add canary upgrades, observation-based rollback triggers, durable retry budgets, and failed-job recovery.

Acceptance: actual DPU containers run and stop, observed readiness matches behavior, counter units are verified, missing counters remain unknown, and canary failure leaves healthy devices intact.

## Phase 5 — storage and GPU integrations

Qualify one storage path such as a supported DOCA SNAP/NVMe-oF deployment. Integrate network health and tenant policy evidence into Gryvia scheduling and diagnostics through the API. Add Atlas integration once a storage backend is proven.

Acceptance: documented throughput/latency/CPU measurements with baseline, device specifications, concurrency, queue depth, and failure cases. Validate RDMA/storage isolation separately from ordinary TCP policy.

## Phase 6 — enterprise fleet operations

Replace SQLite with transactional PostgreSQL before horizontal HA. Add OIDC/SSO, tenant-scoped authorization, service accounts, key rotation, external audit retention, secrets management, API rate limits, multi-site agents, backup automation, GitOps intent, support bundles, upgrade tooling, and billing hooks.

Acceptance: HA failover without duplicate hardware execution, tenant authorization tests, disaster recovery rehearsal, and independently reviewed security boundaries.

## UX contract

- Each page answers one operator question.
- Observed, simulated, desired, and unsupported states remain distinguishable.
- Hardware mutations use preview → explicit approval → observed receipt.
- Unknown metrics are never zeros or invented success states.
- Failed requests keep the last known view with an error notice.
- Keyboard access, visible focus, reduced-motion support, mobile navigation.
- Avoid implementation jargon where it does not help an operational decision.

## Commercial packaging proposal

Use one product with optional capabilities rather than a separate application per function. The evaluation build can provide read-only inventory and local simulation. A future supported enterprise edition can include qualified provisioning, isolation, fleet upgrades, SSO, HA, and audit retention. Price hardware operations per managed physical DPU, with support tiers after measuring deployment effort. No pricing or production-support commitment is established by this release.
