# OMNI-initiated Jackboy link

The new `omni-link` command reuses the inbox HMAC implementation and initiates `omni.link/v2` sessions with Jackboy. It is an explicit, one-shot client. It does not start `omni-inbox`, execute repository tests, modify the existing `omni` shortcut, or use GitHub credentials.

## Owner setup

Review Jackboy's matching `docs/OMNI-SECURE-LINK.md` first. Its migration, dedicated Node HTTPS host, new scoped secrets, project approval and activation require owner permission. This branch provisions none of them. Jackboy's Cloudflare web build cannot run the fixed subprocess; use the approved Node-hosted link origin.

Provide these values using the host's managed secret/config store:

- `JACKBOY_LINK_ORIGIN`: exact HTTPS origin with valid certificate; no path/query/user info.
- `OMNI_LINK_CLIENT_ID`, `OMNI_LINK_PROJECT_ID`: exactly the identity and project approved at Jackboy.
- `OMNI_LINK_BOOTSTRAP_KEY`, `OMNI_LINK_HMAC_SECRET`: new independent random 32-byte hex secrets, matching Jackboy's scoped link only. Never reuse legacy keys or GitHub App/installation/CODE credentials.
- `OMNI_LINK_AUDIT_DIR`: existing absolute directory, private mode 0700. Events append to mode-0600 `link.jsonl`; do not use a shared or symlink directory. Events contain timestamps, fixed state names and job UUIDs, never keys, signatures, request bodies or session tokens.

Build from `inbox/`: `go build -o <absolute-staging-path>/omni-link ./cmd/omni-link` using Go 1.25+. No binary is installed on PATH.

After separate owner activation approval:

```text
omni-link handshake
omni-link submit <new-lowercase-job-uuid>
omni-link run <same-job-uuid>
omni-link status <same-job-uuid>
omni-link cancel <same-job-uuid>
```

`submit` only queues `protocol.self-test`; `run` explicitly requests that fixed trusted test. Use one UUID through retries and reconciliation. A failed/cancelled/timed-out job never restarts; replacement work needs a new intentional submission. No command accepts a shell string, patch, repository, task prompt or privileged action. General CODE tasks still use Jackboy's existing owner-approved CODE workflow.

## Authentication and recovery

HTTPS and HMAC bind the method, path, timestamp, random nonce, bearer hash and raw body. A response proof binds the request nonce and exact response; unproven success is rejected. TLS verification stays on, and redirects are refused. Bootstrap credentials obtain a project/approval-bound session lasting at most five minutes. Session tokens remain in process memory; only hashes live on Jackboy. OMNI checks the returned capability list and records authenticated/disconnected/job state events.

Each operation revalidates project ownership, owner role, grant expiry and global pause on Jackboy. The client serializes use of its session, retries transient job calls at most three times using the same job ID, and reconnects if a session expires. A handshake failure is returned for explicit retry. No new identity or scope is inferred from retry. Audit failure prevents requests; failure after a server response is an uncertain outcome that must be reconciled by status.

Queued/running jobs expire after 60 seconds (or earlier grant expiry), materialized on subsequent requests. Jackboy atomically claims one run, caps active jobs at two and live sessions at eight, and preserves terminal states. Cancellation is cooperative within the fixed subprocess's three-second time limit; a 100 ms monitor observes revocation/cancel. A disconnected/crashed process is not automatically rerun.

## Tests and boundaries

`go test -race ./...` and `go vet ./...` cover the existing inbox plus client contracts, TLS origin rules, HMAC verification, response rejection, retries/reconnects, no redirect following and fail-closed audit behavior.

`TestCrossLanguage` is run by Jackboy's integration suite with `OMNI_INBOX_DIR` set to this checkout's `inbox/`. It drives this real Go client against Jackboy's actual HTTPS adapter, SQL migration and fixed subprocess using a local trusted certificate. A standalone Go run skips only this cross-repository test when its test server variables are absent.

The existing `internal/inbox.Worker` is unchanged and **not** activated. Its temporary checkout does not isolate untrusted repository code from its host. The new self-test accepts no caller code and uses Node permission restrictions; those are not a malicious-code sandbox. Adding arbitrary tasks requires a separately approved execution boundary. Nothing here merges, deploys, changes production credentials or grants autonomous execution.
