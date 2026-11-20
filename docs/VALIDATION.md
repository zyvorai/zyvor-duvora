# Validation record

## Executed in the creating environment

- Python 3.12.14: **40 unit and HTTP integration tests passed**.
- Python module compilation passed.
- JavaScript parser check passed for the console module.
- Loopback HTTP integration server served authenticated API requests.
- Python wheel build and isolated target installation passed; all four bundled console assets and installed CLI entry point were verified.

Coverage includes role checks, agent host binding, simulator identity protection, unknown-field rejection, non-finite measurements, IPv4/IPv6 policy evaluation, partial release, policy restoration, immutable image references, upgrade steps, rollback conflict detection, expired/stale plans, concurrent/idempotent apply, overlapping-job prevention, persisted restart recovery, simulation opt-in after restart, fixed static routes, security headers, HTTP content types, and evidence/metrics endpoints.

## Included but not executed here

- Browser workflow suite (`tests/e2e.cjs`): login, plan/apply, verdict evaluation, rollback, page navigation, theme, mobile overflow, viewer permissions.
- Docker build/runtime and Kubernetes deployment.
- NVIDIA DPF live cluster import and physical Linux BlueField discovery.
- Physical firmware/BFB provisioning, hardware policy enforcement, service execution, offload/performance benchmarks: not implemented.

A Chromium installation was attempted; the environment's download returned an invalid archive. No screenshot or browser-pass claim is made. GitHub Actions includes browser and container jobs for an environment with working dependency downloads.

## Reproduce

```bash
make check
python3 -m pip install --no-deps .
duvoractl --help
```

Browser suite (fresh database):

```bash
npm install --no-save playwright@1.62.1
npx playwright install chromium
export DUVORA_KEYS='{"admin":{"role":"admin","token":"local-test-admin-key-1234567890"},"viewer":{"role":"viewer","token":"local-test-viewer-key-1234567890"}}'
python3 -m duvora.server --demo --db /tmp/browser.db
# In another terminal:
node tests/e2e.cjs
```

The displayed test keys are local fixtures, never production credentials. Browser screenshots are written into ignored `test-results/` when the suite runs.
