# Backend deployment readiness

**Autonomous activation: BLOCKED.** This is a source review, not evidence of a
live deployment or authorization. The inbox now refuses startup when either
execution flag is exactly `true`. Do not bypass this hold: its existing runner
does not provide a filesystem or network jail, CPU/memory quotas, or a verified
hostile-code boundary. Do not enable Jackboy autonomous mode.

## Existing components and limits

- The root Dockerfile builds the Go inbox, link client and shell helper; Railway
  can terminate HTTPS at ingress. A read-only Railway status on 2026-11-12
  showed the `Evolution` production environment with online `Omni`,
  `jackboy-dev-control` and `orbiting-minds-mothership` services, and an
  `omni-data` volume listed with `Omni`. This checkout is not linked to that
  project and has no Railway-specific configuration. Status alone does not
  verify the deployed revision, TLS behavior, volume contents or safety flags.
- `/healthz`, bearer-authenticated legacy handshake/job/status, and signed
  scoped dispatch v2/v3 are implemented. The legacy bearer lane does not bind
  requests to an owner/project grant. Dispatch v2 records quarantined receipts;
  v3 binds signed scope and payload but relies on Jackboy to validate the
  current grant and send cancellation upon revocation.
- Private file-backed records, audit, replay protection, restart quarantine,
  signed callbacks and v3 cancellation exist. V3 has a single runner per data
  directory; streaming output, a verified multi-session executor and an OMNI
  emergency-stop control are not established. The existing output is bounded
  terminal result output, not live streaming.
- The separate `omni-link` client targets Jackboy's scoped link protocol and
  fixed self-test, not arbitrary CODE. CLI Dock support and the browser
  terminal preview are not an execution service. MFA, passkeys, owner approvals
  and device pairing belong to their existing systems and are not changed here.
- The Mothership's `omni.workspace/v1` contract describes a separate sandbox
  with approved command steps and polled output, not this inbox's dispatch
  API. Its documentation describes a reference service tested on Lovable's
  build machine, not a verified deployed sandbox. `omni.dock/v1` is a distinct
  device protocol for scoped status, held proposals and stop controls. Do not
  treat an inbox handshake as proof of workspace or docking compatibility.

## Required gates before any separately authorized deployment

- [ ] Identify the actual Railway project, service, environment, source branch,
  deploy triggers, ingress TLS, persistent volume and running revision; do not
  infer them from this checkout.
- [ ] Back up persistent data; review the inbox storage and replay-nonce
  migration notes, retention and rollback procedure in `inbox/README.md`.
  No new database migration is introduced by this safety hold. Jackboy's v3
  documentation describes `0062_omni_dispatch_v3.sql` and subsequent related
  migrations and reconciliation; verify actual schema and migration history
  before separately authorizing changes. Mothership documentation also describes
  migrations `0047` and `0048`; their deployed state is unverified.
- [ ] Keep dispatch, worker, shell and Jackboy autonomous execution disabled.
  Verify effective settings without disclosing values; protect ingress and
  preserve existing authentication, MFA, passkeys and pairing.
- [ ] On an isolated staging system, test authenticated HTTPS, handshake and
  rejection of bad, replayed, expired and wrong-scope signatures; verify grants
  and revocation against the actual Jackboy and Mothership integrations.
- [ ] Design, implement and independently verify an isolated executor with
  host-secret exclusion, filesystem and network isolation, CPU/memory/process
  and time limits, and reliable termination. Diagnostics and proposals must not
  authorize execution; approval must be owner/project/job-bound and current.
- [ ] Verify a separately approved isolated `printf` job, job ID, bounded
  streaming, concurrent session isolation, persistent audit/status, cancellation,
  timeout, emergency stop and restart recovery; reject unapproved jobs. Test
  failure, race and security cases, including no Jackboy activation.
- [ ] Confirm deployed revision, TLS, durable storage, callback compatibility,
  live controls, budget enforcement and explicit owner authorization before
  considering any production execution. Never use a diagnostic or handshake as
  execution approval.

## Configuration names

Inbox: `PORT`, `OMNI_DATA_DIR`, `OMNI_API_KEY`, `OMNI_CALLBACK_SECRET`,
`OMNI_ALLOWED_REPOS`, `JACKBOY_CALLBACK_URL`, `OMNI_GIT_TOKEN`,
`OMNI_WORKER_ENABLED`, `OMNI_SHELL_ENABLED`.

Scoped dispatch: `OMNI_DISPATCH_ENABLED`, `OMNI_DISPATCH_CLIENT_ID`,
`OMNI_DISPATCH_HMAC_SECRET`, `JACKBOY_DISPATCH_CALLBACK_URL`,
`OMNI_DISPATCH_CALLBACK_CLIENT_ID`, `OMNI_DISPATCH_CALLBACK_SECRET`.

Scoped link: `JACKBOY_LINK_ORIGIN`, `OMNI_LINK_CLIENT_ID`,
`OMNI_LINK_PROJECT_ID`, `OMNI_LINK_BOOTSTRAP_KEY`, `OMNI_LINK_HMAC_SECRET`,
`OMNI_LINK_AUDIT_DIR`. These are repository configuration names, not an
inventory of values configured on Railway.

Mothership workspace integration: `OMNI_SANDBOX_ORIGIN`,
`OMNI_SANDBOX_CLIENT_ID`, `OMNI_SANDBOX_HMAC_SECRET`, `OMNI_SANDBOX_ENABLED`.
Jackboy v3 sender: `JACKBOY_DISPATCH_V3_ENABLED`, `OMNI_DISPATCH_ORIGIN`,
`OMNI_DISPATCH_CLIENT_ID`, `OMNI_DISPATCH_HMAC_SECRET`, `OMNI_DISPATCH_CA_FILE`.
