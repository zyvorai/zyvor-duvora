# Security

Report vulnerabilities privately to the repository maintainer using GitHub private vulnerability reporting when enabled. Do not post access keys or customer inventory in public issues.

This release is a local/evaluation control plane. Configure unique keys for each principal, terminate TLS before remote access, and restrict network ingress. Administrator keys have fleet-wide authority; tenant labels are not a tenant RBAC boundary. Agent keys are bound to one host or bridge identity. Viewer keys cannot mutate state.

The console holds keys in memory; signing out clears them. API calls require a bearer key and mutations require JSON. Public routes only serve fixed console assets and health. The runtime does not execute shell input or fetch service images. Hardware writes are unavailable.

SQLite audit history is persistent but not tamper-proof. Protect the database volume and export evidence to a controlled destination. The HTTP server is not hardened for an untrusted public Internet deployment: external rate limiting, TLS, SSO, and centralized audit retention are follow-up work.
