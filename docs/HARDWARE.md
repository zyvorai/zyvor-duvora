# Hardware integrations

## Linux PCI agent

`python -m duvora.agent` reads `/sys/bus/pci/devices`. NVIDIA/Mellanox vendor `0x15b3` and recognized BlueField device IDs create stable host/PCI-derived inventory identities. PCI presence does not prove DPU mode, Arm OS health, firmware compatibility, or offload availability. These values remain unknown. No root privileges or device writes are required for readable sysfs.

The agent reports only recognized PCI functions and interface names. It does not collect payloads, process command lines, secrets, or fabricated hardware counters. Multiple PCI functions may represent one physical card; serial-based physical-card deduplication is follow-up work. Do not use PCI IDs alone as a support qualification matrix.

Device reports use a principal `agent:<hostname>`. The report hostname must match that principal. A Linux observation cannot overwrite simulator or DPF inventory identities.

## NVIDIA DPF bridge

The bridge performs only:

```bash
kubectl --context CONTEXT --namespace NAMESPACE --request-timeout=15s \
  get dpus.provisioning.dpu.nvidia.com -o json
```

It imports object UIDs and observed readiness, using DPF `status.phase` (`Ready`/`Error`) or a Ready condition fallback. It does not fabricate firmware or hardware measurements. UID-based identity is stable across repeated reads but changes when a DPF object is recreated.

The bridge's hostname denotes the reporting bridge, not the physical server hosting the DPU. Mapping DPF node references and physical serial numbers to server topology is follow-up work. The bridge is one-shot: run it periodically with a scheduler, or invoke it through your existing agent framework. Physical observations older than 120 seconds appear stale in the console.

Use the namespace-scoped `get/list` role in `deploy/dpf-readonly-role.yaml`. Bind it to a dedicated Kubernetes identity. Authentication and TLS are handled by kubectl's existing context. The control plane itself does not need Kubernetes credentials.

## Reference sources inspected

- [NVIDIA DPF repository](https://github.com/NVIDIA/doca-platform), `public-main`.
- [DPU types](https://github.com/NVIDIA/doca-platform/blob/public-main/api/provisioning/v1alpha1/dpu_types.go), blob `487785f92710a3febe5f8f189b71aaf6346401d5`.
- [Provisioning API group](https://github.com/NVIDIA/doca-platform/blob/public-main/api/provisioning/v1alpha1/groupversion_info.go), blob `2d3949439837cb6c0b3e4097ea27b16b8b709c33`.
- [Canonical/BlueField OS explanation](https://canonical.com/blog/ubuntu-and-nvidia-bluefield-3).
- [Netra UX reference](https://github.com/zyvorai/zyvor-netra/blob/main/web/src/styles.css), inspected for product direction only; source not incorporated.

The bridge is fixture-tested. Live DPF compatibility, hardware provisioning, firmware safety, and policy offload remain unverified. Pin a qualified vendor release before implementing mutating adapters.
