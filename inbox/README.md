# OMNI job inbox and worker

Receives jobs from Jackboy, works on them in a throwaway checkout, and reports real results back. Standard library only.

## What it does
- `POST /jackboy/handshake`: needs the bearer token. Answers with `HMAC(OMNI_CALLBACK_SECRET, challenge)`, which proves OMNI holds both shared keys. Jackboy turns "OMNI verified" on only when this proof matches.
- `POST /jackboy/jobs`: needs the bearer token. Accepts `omni.job/v1`. `Idempotency-Key` must equal `jobId`, and the repo must be listed in `OMNI_ALLOWED_REPOS`. Jobs are saved as JSON files and survive restarts.
- `GET /jackboy/jobs/{id}`: needs the bearer token. Returns the job's status.
- Worker:
  1. Makes a shallow clone into a temporary folder.
  2. Runs `git apply --check` and then applies the supplied patch.
  3. Runs `go test ./...` in every Go module it finds.
  4. Posts a signed `omni.job-result/v1` to `JACKBOY_CALLBACK_URL`.
  - Headers: `X-Omni-Timestamp`, `X-Omni-Nonce`, `X-Omni-Signature: sha256=HMAC(secret, ts.nonce.body)`.

## What it does not do
- It never pushes, merges or deploys. It sends back only the diff summary and test output.
- It can't write code from plain-text instructions yet. A `code` job with no patch fails and says so.

## Run
```
OMNI_API_KEY=... OMNI_CALLBACK_SECRET=... OMNI_ALLOWED_REPOS=OMERTA-ROW/Omni go run ./cmd/omni-inbox
```
The host needs `git` and `go`. The values of `OMNI_API_KEY` and `OMNI_CALLBACK_SECRET` must match Jackboy's secrets. Jackboy's `OMNI_API_URL` is the public HTTPS address of this service.

## Test
`go test ./...`. The worker tests need `git` and `go` on PATH.

## OMNI-initiated secure link (separate opt-in)

See [SECURE-LINK.md](SECURE-LINK.md) for the scoped, time-limited Jackboy handshake and fixed protocol-test job client. This does not activate the legacy worker above. A throwaway checkout alone is not a security sandbox for untrusted repository code.
