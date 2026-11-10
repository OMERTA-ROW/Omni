# OMNI job inbox and worker

Receives jobs from Jackboy, works on them in a throwaway checkout, and reports real results back. Standard library only.

## What it does
- `POST /jackboy/handshake`: needs the bearer token. Answers with `HMAC(OMNI_CALLBACK_SECRET, challenge)`, which proves OMNI holds both shared keys. Jackboy turns "OMNI verified" on only when this proof matches.
- `POST /jackboy/jobs`: needs the bearer token. Accepts `omni.job/v1`. `Idempotency-Key` must equal `jobId`, and the repo must be listed in `OMNI_ALLOWED_REPOS`. Jobs are saved as JSON files and survive restarts.
- `GET /jackboy/jobs/{id}`: needs the bearer token. Returns the job's status.
- `shell` jobs are disabled unless `OMNI_SHELL_ENABLED=true`. When enabled, they accept a command, an optional allowlisted repo checkout, and an optional timeout of 1–3600 seconds (default 60). Results include the exit code, separate stdout/stderr, duration, timeout state, and truncation state.
- Worker:
  1. Makes a shallow clone into a temporary folder.
  2. Runs `git apply --check` and then applies the supplied patch.
  3. Runs `go test ./...` in every Go module it finds.
  4. Posts a signed `omni.job-result/v1` to `JACKBOY_CALLBACK_URL`.
  - Headers: `X-Omni-Timestamp`, `X-Omni-Nonce`, `X-Omni-Signature: sha256=HMAC(secret, ts.nonce.body)`.
- Execution is **off by default**. Only `OMNI_WORKER_ENABLED=true` starts the
  worker; other values (including `TRUE` and `1`) do not. Authentication,
  handshake and status routes remain available. Submission still records jobs;
  this flag is an execution gate, not a separate acceptance gate.
- On every store open, historical `queued` and `running` jobs become
  `quarantined`, even if execution is enabled. Completed/failed results remain
  available. Neither restart nor retrying the same idempotency key releases
  quarantine. After explicit owner re-approval, submit a fresh job ID; the old
  record remains quarantined. No automatic resume endpoint is provided.

## What it does not do
- It never pushes, merges or deploys. It sends back job results only.
- It can't write code from plain-text instructions yet. A `code` job with no patch fails and says so.
- Shell jobs run `/bin/sh -c` from a fresh temporary directory as the separate non-root `omni-sandbox` account. The inbox remains `omni`; its restricted Docker helper transfers only the job workspace and launches the command with a scrubbed environment. Output is capped at 64 KiB per stream and the workspace is removed after execution.
- Code/test jobs use that same unchanged privilege helper, process containment,
  timeout and output limits. All modules share one 60-second default deadline
  (`TestTimeout` can override it for isolated tests). Each Go invocation receives
  only `PATH`, job-local `HOME`, `LANG`, job-local `GOPATH`/`GOCACHE`,
  `GOFLAGS=-mod=readonly`, and `TERM=dumb`. No service environment is inherited
  by `go test`. Trusted clone/patch preparation still runs in the service;
  optional clone credentials are not passed to the test process.
- This reuses the shell runner's existing boundaries; it does not add a network
  namespace, filesystem jail, CPU/memory quota or separate container. Do not
  treat it as a complete hostile-code sandbox.

## Run
```
OMNI_API_KEY=... OMNI_CALLBACK_SECRET=... OMNI_ALLOWED_REPOS=OMERTA-ROW/Omni go run ./cmd/omni-inbox
```
The host needs Linux, `git` and `go`. The Docker image creates the `omni-sandbox`
account and installs the restricted privilege helper required for execution.
Only set `OMNI_WORKER_ENABLED=true` after separately authorizing execution.
`OMNI_SHELL_ENABLED=true` remains the additional, unchanged shell opt-in.
The service stays on its normal `omni` account and test jobs fail closed if the
sandbox identity/helper is unavailable. The values of `OMNI_API_KEY` and
`OMNI_CALLBACK_SECRET` must match Jackboy's secrets. Jackboy's `OMNI_API_URL` is
the public HTTPS address of this service.

### Persistent state and rollout

Mount persistent storage at `/data`. The image sets `OMNI_DATA_DIR=/data`; with
no override, startup requires `/data` to exist. It never silently falls back to
the container filesystem or creates a replacement `/data` when the mount is
missing. An explicit normalized absolute `OMNI_DATA_DIR` may name a new child
directory of an existing parent. Symlinks and `/` are rejected.

The root entrypoint creates explicit child directories as needed, sets the
directory to `10001:10001` mode `0700`, then drops privileges. The store verifies
service ownership and actual writability before opening records, and logs only
the effective path (not configuration secrets). Records are `0600`; writes use
private temporary files, file sync, atomic rename and directory sync.
Malformed/linked historical records or a failed quarantine write abort startup.

Before any separately approved rollout, keep the worker disabled, back up and
inspect historical state, and place regular service-readable records in the
approved persistent directory. Startup quarantines pending records without
executing them. Confirm status and quarantine before authorizing any fresh
submission. Do not manually reset quarantined records to `queued`.

Rollback to the previous image is not execution-safe: it starts its worker and
requeues interrupted work without this gate. Do not restart an old image against
the historical queue; use an owner-reviewed recovery plan instead.

## Test
Run `go vet ./...` and `go test -race ./...` from `inbox/` on Linux.
The worker tests need `git` and `go` on PATH. The Linux Docker image additionally
tests the real helper as service UID 10001, with tests executing as UID 10002.
`docker/tests/entrypoint_test.sh` runs as root in a disposable Linux container.

## OMNI-initiated secure link (separate opt-in)

See [SECURE-LINK.md](SECURE-LINK.md) for the scoped, time-limited Jackboy handshake and fixed protocol-test job client. This does not activate the legacy worker above. A throwaway checkout alone is not a security sandbox for untrusted repository code.
