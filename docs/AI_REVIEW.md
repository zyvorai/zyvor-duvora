# AI code review (duvora)

_Generated 2026-10-20 by claude-opus-5-5 from a snapshot of tracked sources; verify before acting._

# Code review: Duvora (0.5.0)

## Summary

Duvora is a simulation-first "DPU fleet control plane." It is a standard-library Python HTTP server with SQLite storage, a CLI (`duvoractl`), and a React/Vite console. A host agent does read-only PCI/DPF inventory and can load Duvora's own eBPF programs (TCX counters, drop reasons, TCP events, node isolation, `duvora_steer`) through ctypes/libbpf. Packaging includes Helm, Compose and Kubernetes manifests, plus a marketing site and README card generators. Most of the server core (`core.py`, `server.py`, `cli.py`, `steering.py`, `runtime.py`) is not in the provided excerpt, so findings there are limited.

## Bugs and correctness risks

**Python backend**

- **`duvora/budget.py`: `budget()` and `budget_blockers()` can raise `KeyError`.**
  - When a device reports a partial `capacity` dict (e.g. only `arm_cores`), `device_capacity()` returns it as-is.
  - `budget()` then iterates all `RESOURCES` and indexes `cap[k]`.
  - `budget_blockers()` indexes `cap[k]` for every requested key.
  - Either path likely produces a 500 instead of a `Problem`.
- **Helm agent with TLS off will probably fail.**
  - In `helm/duvora/templates/agent.yaml`, the default `DUVORA_URL` is `http://<svc>.<ns>.svc:8787` when `tls.enabled=false`, which is the default.
  - `tests/test_http.py::test_remote_http_blocked_in_client` shows `cli.request` raises `ValueError('…HTTPS…')` for non-loopback HTTP.
  - `Credential.current()` and `EbpfAgent` calls in `duvora/agent.py` only catch `OSError`. The agent would likely crash or loop on every report.
  - Uncertain: I can't see whether `request` special-cases cluster hostnames. Worth verifying.
- **`duvora/agent.py`: fragile and inconsistent error handling.**
  - `Credential.current()` classifies errors with `"404" in str(exc)`, which is brittle; it should check `HTTPError.code`.
  - `ebpf.step()` in the main loop is unguarded, so one exception kills the agent.
  - A `Steering` load failure is swallowed even with `--ebpf required`. `NodeIsolation` failures do exit in that mode.
- **`duvora/siem.py` `flush()` silently loses events on failure.**
  - On send failure, the batch is re-queued truncated to free space: `batch[:maxlen-len(queue)]`.
  - The discarded remainder is not added to `stats["dropped"]`, so data loss is invisible.
  - A failure also stops the loop until the next flush, with no backoff.
- **`duvora/identity.py`: unsynchronised state and possibly uncommitted writes.**
  - `identity_touched` is read and written outside `self.lock` from threaded handlers.
  - `agent_token_user` issues an `UPDATE` under `self.lock` but not inside `self.transaction()`. Whether it commits depends on connection settings, which are not visible here.
- **`duvora/bpf/steer.py` `drain_flows`/`drain_payloads` lose samples.**
  - They read all entries, then delete them.
  - Increments that land between the read and the delete are lost.
  - This is acceptable for sampling, but undocumented.

**eBPF programs**

- **`bpf/duvora_bpf.h` `dv_parse` does not walk IPv6 extension headers or detect IPv6 fragments.** In `duvora_nodeiso.c` enforce mode, `iso_always_passes()` then sees `protocol` = HBH/Fragment, not ICMPv6, so the packet is judged and dropped unless allowed. Affected traffic includes:
  - MLD reports, which carry Hop-by-Hop Router Alert.
  - Fragmented IPv6 UDP.

  The docs claim "ICMPv6 … non-first fragments always pass," which is not true for IPv6.
- **`bpf/duvora_bpf.h`: TCP `doff` is not validated (≥5).** `payload_off` can point inside the TCP header for malformed packets, which affects inspected payload capture.
- **License mismatch in `bpf/*.c`.** The files declare `SPDX-License-Identifier: Apache-2.0` but set `LICENSE[] = "GPL"`. This is a licensing contradiction; it should probably be dual-licensed and documented.

**Web console**

- **`web/src/components/Copilot.tsx` `review()` mishandles steer plans.**
  - It casts every drafted action to `'isolate' | 'release'`.
  - The CHANGELOG says `draft_plan` now covers `steer`/`unsteer`.
  - Such drafts open the plan dialog with no `ruleset` preset, so the copilot's draft is lost.
- **`web/src/pages/Devices.tsx`: the source filter is incomplete and can crash.**
  - `SOURCES` omits `duvora-ebpf` and `netra-ebpf`, which `format.ts` knows about, so eBPF-discovered devices can't be filtered.
  - `.toLowerCase()` on `x.model`/`x.site` throws if either is ever null.
- **`web/src/api.ts` `download()`/`saveJSON()` may
