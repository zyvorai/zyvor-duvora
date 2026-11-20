# Contributing

Run `make check` before submitting changes. Keep observed hardware state separate from simulated desired state. New hardware mutation adapters require a capability declaration, preview semantics, recovery procedure, and hardware acceptance evidence. Add tests for permission boundaries, stale plans, and failure paths when modifying orchestration.

Use small reviewable pull requests. Document behavioral changes in CHANGELOG.md and capability changes in docs/STATUS.md. Do not commit access keys, database files, packet payloads, or customer inventory.
