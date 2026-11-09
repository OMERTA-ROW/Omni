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

## What it does not do
- It never pushes, merges or deploys. It sends back job results only.
- It can't write code from plain-text instructions yet. A `code` job with no patch fails and says so.
- Shell jobs run `/bin/sh -c` from a fresh temporary directory as the separate non-root `omni-sandbox` account. The inbox remains `omni`; its restricted Docker helper transfers only the job workspace and launches the command with a scrubbed environment. Output is capped at 64 KiB per stream and the workspace is removed after execution.

## Run
```
OMNI_API_KEY=... OMNI_CALLBACK_SECRET=... OMNI_ALLOWED_REPOS=OMERTA-ROW/Omni go run ./cmd/omni-inbox
```
The host needs `git` and `go`. The Docker image creates the `omni-sandbox` account and installs the restricted privilege helper required for shell execution. Set `OMNI_SHELL_ENABLED=true` to opt in; the service stays on its normal `omni` account and a shell job fails closed if the helper cannot drop privileges. A custom `OMNI_DATA_DIR` must remain writable by `omni`. The values of `OMNI_API_KEY` and `OMNI_CALLBACK_SECRET` must match Jackboy's secrets. Jackboy's `OMNI_API_URL` is the public HTTPS address of this service.

## Test
`go test ./...`. The worker tests need `git` and `go` on PATH.

## OMNI-initiated secure link (separate opt-in)

See [SECURE-LINK.md](SECURE-LINK.md) for the scoped, time-limited Jackboy handshake and fixed protocol-test job client. This does not activate the legacy worker above. A throwaway checkout alone is not a security sandbox for untrusted repository code.
