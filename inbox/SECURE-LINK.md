# OMNI-initiated Jackboy link

The new `omni-link` command reuses the inbox HMAC implementation and initiates `omni.link/v2` sessions with Jackboy. It is an explicit, one-shot client. It does not start `omni-inbox`, execute repository tests, modify the existing `omni` shortcut, or use GitHub credentials.

## Owner setup

Review Jackboy's matching `docs/OMNI-SECURE-LINK.md` first. Its migration, dedicated Node HTTPS host, new scoped secrets, project approval and activation require owner permission. This branch provisions none of them. Jackboy's Cloudflare web build cannot run the fixed subprocess; use the approved Node-hosted link origin.

Provide these values using the host's managed secret/config store:

- `JACKBOY_LINK_ORIGIN`: exact HTTPS origin with valid certificate; no path/query/user info.
- `OMNI_LINK_CLIENT_ID`, `OMNI_LINK_PROJECT_ID`: exactly the identity and project approved at Jackboy.
- `OMNI_LINK_BOOTSTRAP_KEY`, `OMNI_LINK_HMAC_SECRET`: new independent random 32-byte hex secrets, matching Jackboy's scoped link only. Never reuse legacy keys or GitHub App/installation/CODE credentials.
- `OMNI_LINK_AUDIT_DIR`: existing absolute directory, private mode 0700. Events append to mode-0600 `link.jsonl`; do not use a shared or symlink directory. `handshake-state.json` stores only the opaque handshake ID and expiry, with a cross-process file lock and atomic replacement; the bearer session token is memory-only. Events contain timestamps, fixed state names and job UUIDs, never keys, signatures, request bodies or session tokens.

The root Docker image builds and includes `omni-link` at `/usr/local/bin/omni-link` alongside `omni-inbox`. The image's default command remains `omni-inbox`; invoke `omni-link` only as an explicit owner-approved one-off command (for example, through the host's one-off run feature). Do not set it as the service's automatic startup command: it is a one-shot CLI, not a daemon.

For a standalone build from `inbox/`, use `go build -o <absolute-staging-path>/omni-link ./cmd/omni-link` with Go 1.25+. No binary is installed on PATH outside the Docker image.

After separate owner activation approval:

```text
omni-link handshake
omni-link safety
omni-link submit <new-lowercase-job-uuid>
omni-link run <same-job-uuid>
omni-link status <same-job-uuid>
omni-link cancel <same-job-uuid>
```

`safety` performs the signed Step 9 handshake when needed, then reads Jackboy's
fresh `omni.safety/v1` snapshot. It reports the System Kill Switch, CODE
Emergency Stop, CODE setting, OMNI authorization and permit count independently;
it never changes a control or issues, renews or releases a permit. Expired or
incomplete snapshots are rejected, as are `checkedAt` timestamps more than
60 seconds in the future (Jackboy's protocol clock-skew bound). The read-only snapshot is not an execution
approval and cannot release the existing OMNI worker startup hold. Jackboy owns
the passkey ceremony and OMNI authorization; this client does not create either.
Jackboy refuses a new handshake while the System Kill Switch is on, so this
one-shot command cannot fetch a snapshot in that state and must fail closed.

The client sends a persisted UUIDv4 `handshakeId` on handshake and reuses it
across invocations. Jackboy's matching idempotent-handshake endpoint maps a
repeated ID to the same live session and answers an expired/conflicting ID with
a nonce-bound proof and
`{"contract":"omni.link/v2","requestNonce":"...","error":"handshake_id_expired_or_conflict"}`
under HTTP 409. Only that authenticated conflict rotates the ID. Generic
transport, audit, unsigned-conflict or storage failures never trigger a fresh
handshake.
This requires Jackboy's matching endpoint and migration `0071_omni_idempotent_handshake.sql`;
local companion tests do not establish that either is installed in production.
The lock and state files are both opened relative to the same `os.Root`, so
replacing the audit directory's pathname cannot separate the lock from its state.

`submit` only queues `protocol.self-test`; `run` explicitly requests that fixed trusted test. Use one UUID through retries and reconciliation. A failed/cancelled/timed-out job never restarts; replacement work needs a new intentional submission. No command accepts a shell string, patch, repository, task prompt or privileged action. General CODE tasks still use Jackboy's existing owner-approved CODE workflow.

## Authentication and recovery

HTTPS and HMAC bind the method, path, timestamp, random nonce, bearer hash and raw body. A response proof binds the request nonce and exact response; unproven success is rejected. TLS verification stays on, and redirects are refused. Bootstrap credentials obtain a project/approval-bound session lasting at most five minutes. Session tokens remain in process memory; only hashes live on Jackboy. OMNI checks the returned capability list and records authenticated/disconnected/job state events.

Each operation revalidates project ownership, owner role, grant expiry and global pause on Jackboy. The client serializes use of its session, retries transient job calls at most three times using the same job ID, and reconnects if a session expires. A handshake failure is returned for explicit retry. No new identity or scope is inferred from retry. Audit failure prevents requests; failure after a server response is an uncertain outcome that must be reconciled by status.

Queued/running jobs expire after 60 seconds (or earlier grant expiry), materialized on subsequent requests. Jackboy atomically claims one run, caps active jobs at two and live sessions at eight, and preserves terminal states. Cancellation is cooperative within the fixed subprocess's three-second time limit; a 100 ms monitor observes revocation/cancel. A disconnected/crashed process is not automatically rerun.

## Tests and boundaries

From `inbox/`, `go test -race ./internal/link ./cmd/omni-link ./internal/inbox`
and `go vet ./internal/link ./cmd/omni-link ./internal/inbox` cover the client and
inbox contracts. `GOOS=linux GOARCH=amd64 go build ./...` checks the deployment
target. Full native `go test ./...` and `go vet ./...` currently fail on macOS
because the Linux-only `cmd/omni-shell-exec` references `syscall.SYS_PRCTL`;
this is independent of the link client.

`TestCrossLanguage` is run by Jackboy's integration suite with `OMNI_INBOX_DIR` set to this checkout's `inbox/`. It drives this real Go client against Jackboy's actual HTTPS adapter, SQL migration and fixed subprocess using a local trusted certificate. A standalone Go run skips only this cross-repository test when its test server variables are absent.

The existing `internal/inbox.Worker` is unchanged and **not** activated. Its temporary checkout does not isolate untrusted repository code from its host. The new self-test accepts no caller code and uses Node permission restrictions; those are not a malicious-code sandbox. Adding arbitrary tasks requires a separately approved execution boundary. Nothing here merges, deploys, changes production credentials or grants autonomous execution.
