<div align="center">

# Duvora

**Plans, isolation, evidence. In your control.**

[![License](https://img.shields.io/badge/License-Apache%202.0-0071e3?style=flat-square&labelColor=1d1d1f)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-0071e3?style=flat-square&labelColor=1d1d1f&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-Vite-0071e3?style=flat-square&labelColor=1d1d1f&logo=react&logoColor=white)](web/)
[![Helm](https://img.shields.io/badge/Helm-k3s-0071e3?style=flat-square&labelColor=1d1d1f&logo=helm&logoColor=white)](helm/duvora)
[![eBPF](https://img.shields.io/badge/eBPF-TCX%20%C2%B7%20libbpf-0071e3?style=flat-square&labelColor=1d1d1f)](bpf)

[![Book a demo](https://img.shields.io/badge/Book_a_demo-0071e3?style=for-the-badge)](https://zyvor.dev/schedule?utm_source=github&utm_medium=duvora&utm_campaign=readme_hero)
[![30-day PoC](https://img.shields.io/badge/30--day_PoC-000000?style=for-the-badge)](https://zyvor.dev/poc?utm_source=github&utm_medium=duvora&utm_campaign=readme_hero)
[![Live site](https://img.shields.io/badge/Live_site-30d5c8?style=for-the-badge)](https://zyvorai.github.io/zyvor-duvora/)

<img src="docs/social/duvora-hero-dark.jpg" alt="Duvora - Plans, isolation, evidence. In your control." width="100%">

<img src="docs/ux/anim/hero.gif" alt="Duvora console: steering, AI traffic, threats and the shift briefing" width="100%">

**One server, one API, one CLI and one console for DPU inventory, traffic steering, AI security and change evidence.**
Run the whole workflow on four simulated BlueField DPUs before the hardware arrives.

**Zero runtime dependencies** · **Shadow before enforce** · **Native eBPF agent** · **Revision-guarded rollback** · **Apache-2.0**

[**Quickstart**](#quickstart) · [**Live site**](https://zyvorai.github.io/zyvor-duvora/) · [**Steering**](docs/STEERING.md) · [**AI**](docs/AI.md) · [**API**](docs/API.md) · [**Operations**](docs/OPERATIONS.md)

</div>

---

## Why teams pick Duvora

| When this happens… | Duvora gives you… |
|---|---|
| The DPU lab is not ready, but the workflow has to be designed now | Four simulated BlueField devices with persistent service, isolation, upgrade and rollback workflows |
| A change goes out and nobody can say who approved what | Plans bound to their creator, expiring in five minutes, with idempotent apply and a JSON evidence trail |
| A rollback would overwrite someone else's later change | Snapshots with a revision guard: rollback refuses to clobber newer state |
| You need node isolation but cannot risk cutting off SSH | Shadow first, leased enforce, a kill switch, an agent fail-safe and a local override file |
| Kernel telemetry means another vendor's agent on every node | Duvora's own TCX and tracepoint programs, loaded through libbpf |
| Prompts, keys and customer data flow to LLM APIs unnoticed | LLM traffic inspection, shadow-AI discovery, artifact scans and an AI posture score |

![Capabilities at a glance: Inventory, Change, eBPF, Govern, Steering, AI security](docs/ux/readme-capabilities.jpg)

---

## Steer every flow, safely

<img src="docs/ux/anim/steering-flow.svg" alt="Animated traffic steering: packets matched against ordered rules and routed to bypass, allow, inspect or drop" width="100%">

Ordered 5-tuple rules end in **bypass**, **allow**, **inspect** or **drop**. A steer plan replays recent flows against the new set first. Shadow counts would-drops per rule, enforce is leased and falls back to shadow on its own, SSH and the control plane are always exempt, and rollback restores the previous set. Runs in the host kernel as `duvora_steer` (TCX), or in simulation. [Steering guide →](docs/STEERING.md)

## See what talks to models

<img src="docs/ux/anim/ai-inspect.svg" alt="Animated AI security: an LLM request is inspected, prompt injection and secrets are flagged and redacted" width="100%">

Inspect samples the start of each flow and flags prompt injection, secrets and personal data with redacted snippets. Around it: shadow-AI discovery, image and model scans that can gate deploys, threat-intel feeds, and playbooks that **draft** the block plan while a human applies it. [AI guide →](docs/AI.md)

## One API, one audit trail

<img src="docs/ux/anim/architecture.svg" alt="Animated architecture: console, CLI, bridges and agents talk to one authenticated API backed by SQLite state and audit" width="100%">

Observations stay separate from simulated desired state. Physical reports cannot overwrite simulator identities or grant enforcement. Job progress survives restart.

---

## Duvora vs NVIDIA DPF

Duvora is not a DPF replacement: it reads DPF's DPU objects and adds the operator workflow around them.

| | **Duvora** | **NVIDIA DPF** |
|---|---|---|
| Role | Operator workspace: inventory, plans, isolation, incidents, evidence | Provisioning and orchestration of BlueField DPUs and services |
| Try it without hardware | Yes, four simulated devices | Needs BlueField DPUs |
| Change control | Expiring actor-bound plans, typed confirmations, revision-guarded rollback | Kubernetes resources and controllers |
| DPU provisioning and firmware | Not implemented | Yes |
| **Choose DPF when** | | You provision BlueField DPUs and run DPU services in production |

## The console

<table>
<tr>
<td width="50%"><img src="docs/ux/console-overview.jpg" alt="Overview: fleet pulse, DPU fleet and active incidents"><br><sub><b>Overview</b>: fleet pulse, devices, incidents</sub></td>
<td width="50%"><img src="docs/ux/console-steering.jpg" alt="Steering: rule sets, shadow verdicts and a rule test"><br><sub><b>Steering</b>: shadow verdicts, "which rule wins?"</sub></td>
</tr>
<tr>
<td><img src="docs/ux/console-ai-traffic.jpg" alt="AI traffic: LLM endpoints and findings"><br><sub><b>AI traffic</b>: endpoints, findings, coverage</sub></td>
<td><img src="docs/ux/console-report.jpg" alt="Report: shift briefing with AI posture"><br><sub><b>Report</b>: shift briefing and AI posture</sub></td>
</tr>
</table>

## Quickstart

```bash
git clone https://github.com/zyvorai/zyvor-duvora.git && cd zyvor-duvora
make web && python3 -m duvora.server --demo
```

Open **http://127.0.0.1:8787** and sign in as **admin / Admin@321**. Four simulated BlueField devices appear. Deploy to k3s with `./scripts/deploy-remote.sh user@host`, or see [Operations](docs/OPERATIONS.md), the [CLI and API](docs/API.md), [hardware integration](docs/HARDWARE.md) and [eBPF](docs/EBPF.md).

## What it is, and is not

0.5.0 is a runnable evaluation release: simulation workflows, read-only PCI and DPF inventory, native eBPF telemetry and node isolation, host-kernel traffic steering and LLM traffic inspection. It does **not** flash firmware, provision physical DPUs, run DPU containers or offload to DPU hardware. Isolation and steering are host-kernel enforcement on the node. Full matrix: [docs/STATUS.md](docs/STATUS.md) · history: [CHANGELOG.md](CHANGELOG.md).

## Part of the Zyvor stack

**[Netra](https://github.com/zyvorai/zyvor-netra)** eBPF network observability · **[Gryvia](https://github.com/zyvorai/zyvor-gryvia)** Kubernetes GPU platform · **[Rivora](https://github.com/zyvorai/zyvor-rivora)** eBPF L4 load balancer · [zyvor.dev](https://zyvor.dev)

## License and support

Free and open source under [Apache-2.0](LICENSE) (see [NOTICE](NOTICE)). **Zyvor Enterprise** adds supported releases, upgrade guidance, priority incident triage, a named technical contact and 24x7 critical intake: [plans](docs/SUBSCRIPTION-MODEL.md) · [pricing](https://zyvor.dev/pricing?utm_source=github&utm_medium=duvora&utm_campaign=readme_license) · [sales@zyvor.dev](mailto:sales@zyvor.dev) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

<div align="center">

### Run your DPU fleet workflow before the hardware arrives

[![Book a demo](https://img.shields.io/badge/Book_a_demo-0071e3?style=for-the-badge)](https://zyvor.dev/schedule?utm_source=github&utm_medium=duvora&utm_campaign=readme_footer)
[![30-day PoC](https://img.shields.io/badge/Start_a_30--day_PoC-000000?style=for-the-badge)](https://zyvor.dev/poc?utm_source=github&utm_medium=duvora&utm_campaign=readme_footer)
[![Pricing](https://img.shields.io/badge/Pricing-1d1d1f?style=for-the-badge)](https://zyvor.dev/pricing?utm_source=github&utm_medium=duvora&utm_campaign=readme_footer)
[![Star on GitHub](https://img.shields.io/github/stars/zyvorai/zyvor-duvora?style=for-the-badge&logo=github&label=Star&color=2997ff)](https://github.com/zyvorai/zyvor-duvora)

</div>
