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

## Jackboy scoped dispatch v2 (receipt-only, off by default)

`POST /api/public/jackboy/dispatch` implements `jackboy.dispatch/v2`, matching
Jackboy's `src/lib/omni-dispatch-client.server.ts` and
`src/lib/omni-dispatch-callback.server.ts` at
`f86d0932c3ca46d319958f8bffe85df763efedec`. This is a separate signed lane:
the legacy `/jackboy/*` routes, bearer authentication, handshake and sandbox
are unchanged. Do **not** enable `OMNI_WORKER_ENABLED` for this protocol.

| Environment variable | Purpose |
|---|---|
| `OMNI_DISPATCH_ENABLED` | Only the exact value `true` enables dispatch; otherwise requests receive 503. Default off. |
| `OMNI_DISPATCH_CLIENT_ID` | Expected `x-jackboy-client`; 1–64 ASCII letters, digits, `_` or `-`. |
| `OMNI_DISPATCH_HMAC_SECRET` | Request signing/response proof key, at least 32 characters; match Jackboy's dispatch client configuration. |
| `JACKBOY_DISPATCH_CALLBACK_URL` | Explicit HTTPS URL ending exactly in `/api/public/omni/callback`; no credentials, query, fragment or redirects. |
| `OMNI_DISPATCH_CALLBACK_CLIENT_ID` | Outgoing `x-omni-client`; match Jackboy's callback receiver setting of the same name. |
| `OMNI_DISPATCH_CALLBACK_SECRET` | Separate callback signing/proof key, at least 32 characters; match Jackboy's receiver. |
| `OMNI_DATA_DIR` | Existing private persistent storage root (default `/data`); dispatch uses its own `dispatch-v2/` directory. |
| `OMNI_ALLOWED_REPOS` | Existing exact repository allowlist, also required for submit, status and cancel. |

All dispatch/callback settings must be valid when dispatch is enabled; invalid
enabled configuration aborts startup. The receiver on Jackboy independently
requires its own `OMNI_DISPATCH_CALLBACK_ENABLED=true` and current live grants.
Nothing in this implementation changes that setting or grants approval.

### Wire authentication and scope

The request body is at most 8192 bytes and contains exactly `contract`, `action`
(`submit`, `status`, `cancel`), UUID `ownerId`, `projectId`, `grantId`, `jobId`,
allowlisted `repo`, `kind` (`build`, `test`) and lowercase 64-hex `payloadDigest`.
Unknown/duplicate/case-folded fields, non-string values, invalid UTF-8 and
trailing JSON are rejected. The body contains no instructions, patch or command.

Headers are `x-jackboy-client`, 10-digit `x-jackboy-timestamp` (within 60 seconds),
32-lowercase-hex `x-jackboy-nonce`, and lowercase-hex `x-jackboy-signature`.
The signature is HMAC-SHA256 of these newline-separated bytes, with no trailing
newline:

```
jackboy.dispatch/v2
POST
/api/public/jackboy/dispatch
{client}
{timestamp}
{nonce}
{raw body}
```

Jackboy must validate the current owner/project/grant before sending. OMNI
authenticates Jackboy and binds every operation to the entire immutable scope;
it does not independently query Jackboy's grant database or grant execution.
Configure the public origin with HTTPS at the ingress (Railway terminates TLS);
the callback client always verifies HTTPS certificates.

Every authenticated nonce is durably consumed before schema/action processing,
including authenticated requests that later fail. Nonces and receipts share a
synced, atomically replaced state file. File locks serialize reopened processes,
and callback ordering uses the same transaction lock. Nonces survive restarts,
store their signed request timestamp, and are pruned on each state write once
older than five minutes. Requests outside the 60-second timestamp window are
rejected before storage access, so pruning cannot admit a stale signed replay.
Legacy boolean `true` entries are conservatively timestamped at migration time
and persisted in the new numeric format on the next write. Preserve this persistent directory
across restarts and key rotation; deleting it discards replay protection.

`submit` returns 202 and records only `quarantined`; a matching retry with a
**fresh nonce** is idempotent. Any different owner/project/grant/repo/kind/digest
for an existing job ID returns 409. `status` returns 200; `cancel` returns 200
and permanently sets `cancelled`. A later submit cannot undo cancellation.
Unknown jobs return 404 for status/cancel. These receipts are never stored in
the legacy executable queue and never wake the worker, even if an operator
independently enables that worker.

Success bodies contain exactly `contract`, `requestNonce`, and
`job: {id, status}`. The `x-jackboy-proof` is HMAC-SHA256 over
`jackboy.dispatch/v2\nresponse\n{nonce}\n{HTTP status}\n{raw response body}`.
Error responses do not confer a successful receipt.

### Signed callbacks and audit

Submit/cancel (including idempotent retries) send the persisted receipt to the
configured callback; status is read-only apart from nonce consumption/audit.
The callback contains exactly `contract: "jackboy.dispatch-callback/v2"`,
`ownerId`, `projectId`, `grantId`, `jobId`, `repo`, `payloadDigest`, and
`status` (`quarantined` or `cancelled`). Headers are `x-omni-contract`,
`x-omni-client`, fresh `x-omni-timestamp`/`x-omni-nonce`, and `x-omni-signature`.
The signature canonical string is:

```
jackboy.dispatch-callback/v2
POST
/api/public/omni/callback
{client}
{timestamp}
{nonce}
{raw body}
```

Callbacks have a five-second timeout, an 8192-byte response cap, verified TLS,
and no redirect following. Only HTTP 200 with a valid `x-omni-proof` over
`jackboy.dispatch-callback/v2\nresponse\n{nonce}\n200\n{raw response body}`
and the matching strict `{contract, requestNonce, status}` acknowledgement
counts as delivery. A failed callback returns 503 to dispatch but retains the
quarantined/cancelled receipt. Retry the original action with the same scope
and a fresh nonce; there is no background delivery worker or execution retry.

`dispatch-v2/audit.jsonl` records every authenticated request, dispatch outcome, callback
attempt and callback outcome. It logs fixed event names, HTTP outcome and
validated job ID/status only, never raw bodies, signatures, keys or tokens.
Audit/state files are service-owned `0600` under a `0700` directory. Symlinked,
hard-linked, nonprivate or corrupt files fail closed. Audit failure never
produces a successful response; a receipt already persisted before failure
remains held and can be inspected with a fresh authenticated status request.
If the audit device itself is unavailable, the service emits a fixed stderr
error and returns 503 rather than silently dropping the audit requirement.
Requests rejected before successful signature verification (including disabled
dispatch, invalid credentials/timestamps/nonces/signatures and oversized bodies)
perform no audit/state writes or fsyncs and retain their normal error codes.

No deployment, variable changes, worker activation or live job submission is
part of this feature. Before any separately approved rollout, back up persistent
state, keep both execution and dispatch off, configure the separate keys and
callback receiver, and validate with isolated fixtures first. Monitor nonce/audit
storage growth; do not delete replay history as a routine log-rotation step.

## Scoped dispatch v3 execution (additional, never enabled automatically)

The same `POST /api/public/jackboy/dispatch` also accepts
`contract: "jackboy.dispatch/v3"`. V2 remains its unchanged quarantine-only
protocol. V3 uses the same keys, client, 60-second timestamp window, five-minute
persisted nonce retention, exact-byte HMAC/proof formats and 8192-byte request
limit, replacing only the contract prefix in those canonical strings.
All requests remain disabled unless `OMNI_DISPATCH_ENABLED=true`.

A v3 submit has the v2 scope fields plus **exactly**:
- `payload`: a UTF-8 string of at most 6144 bytes. For `test` it is the signed
  instruction text (never interpreted as a shell command); for `build` it is
  the patch to apply before testing.
- `expiresAt`: an integer Unix timestamp in seconds, strictly in the future
  and no more than 30 minutes from receipt.

The digest is still the lowercase SHA-256 of Jackboy's exact
`src/lib/omni-dispatch-digest.ts` serialization: `JSON.stringify` of the ordered
keys `contract: "jackboy.dispatch-payload/v2"`, `ownerId`, `projectId`,
`grantId`, `jobId`, `repo`, `kind`, `instructions: payload`. This includes the
wire kind `build`, not the legacy kind `code`. A mismatched digest, expiry,
extra field or changed immutable scope/payload/expiry is rejected.
V3 `status` and `cancel` send only the original scope fields, with no payload
or expiry. Signed success responses retain `{contract,requestNonce,job:{id,status}}`
with the v3 response proof.

### Execution states and cancellation

V3 state, payloads, results and callback outbox are private persistent files under
`OMNI_DATA_DIR/dispatch-v3`, separate from both v2 receipts and legacy jobs.
The states are:

| State | Meaning |
|---|---|
| `approved` | A new, digest-verified v3 submit was received with `OMNI_WORKER_ENABLED` exactly `true`. |
| `quarantined` | Worker was off at submission, or startup interrupted a historical approval/run. Turning the worker on never releases it. |
| `running` | The single v3 runner claimed a current, unexpired approval. |
| `completed` | Sandbox tests passed. |
| `failed` | Clone, patch or tests failed; a bounded result is retained. |
| `expired` | Approval expired before claim or during execution; it cannot run again. |
| `cancelled` | Cancellation permanently prevents queued execution or stops the running context/process group. |

Only v3 `approved` jobs can be claimed, only while the worker gate is on, and
only while expiry and the repository allowlist are still valid. Quarantined
jobs require a fresh owner-approved grant/job submission; no release endpoint
is provided. Restart quarantines historical `approved`/`running` records instead
of resuming them. Completed/failed/cancelled/expired records and callback retries
survive restart. There is one runner owner per persistent directory; use one
inbox service replica for this deployment.

`cancel` is idempotent for a held/running/cancelled job and never overwrites an
already completed/failed/expired result. Persist cancellation before signalling
the active context; the runner also polls persisted state to observe cancellation
from another inbox process. Completion cannot overwrite persisted cancellation.
Grant expiry bounds the entire clone/apply/test execution context; the existing
test sandbox retains its own default 60-second test deadline and output limits.

Execution calls the existing sandboxed `Worker.Process`: `test` clones and runs
Go tests; `build` applies the signed patch then tests. It uses the unchanged
scrubbed Go environment, `omni-sandbox` identity, helper, process cleanup and
limits. No shell dispatch kind, caller-selected command, push, merge, PR creation
or deployment is introduced. This is not a new hostile-code isolation boundary;
the existing filesystem/network/CPU/memory limitations still apply.

### V3 results and durable delivery

Callbacks use `contract`/`x-omni-contract: "jackboy.dispatch-callback/v3"` and the
same signature, HTTPS/no-redirect, timeout, response-size and proof checks as v2.
The acknowledgement is the matching strict `{contract,requestNonce,status}`
object with `x-omni-proof`. A compatible **v3** Jackboy receiver is required;
the currently referenced v2 receiver is not assumed to accept v3.

Callback statuses are `quarantined`, `cancelled`, `running`, `completed`,
`failed` and `expired` (`approved` is only a dispatch response state).
For `completed`/`failed`, add:

```
"result": {
  "passed": true,
  "summary": "bounded, redacted summary",
  "output": "bounded, redacted test output",
  "truncated": false
}
```

Summary is at most 500 Unicode characters; output at most 6144 UTF-8 bytes.
Redaction happens before persistence and again before transmission: configured
secret/token/key/password values, credential assignments, bearer strings,
common token/JWT/private-key formats, credential URLs and long opaque token-like
strings are replaced. Heuristic redaction cannot guarantee removal of arbitrary
encoded or fragmented secrets; tests must still run without credentials.
Output can be shortened further when JSON escaping would exceed the 8192-byte
callback envelope; `truncated` is then true. Raw output is never audit-logged.

Transitions enqueue ordered persistent callback snapshots. Failed delivery or
bad proof retains the event and result; retries use fresh timestamp/nonce/signature
with exponential backoff from two seconds up to 256 seconds. Successful verified
ack removes only that outbox event, not the stored job/result. There is no retry
limit or automatic result deletion. Delivery is ordered, so a failed earlier
callback can delay later callbacks; monitor the outbox and disk use. The delivery
loop works with execution off, but dispatch itself must remain enabled.

The v3 runner and callbacks do not confer owner authorization: Jackboy must
validate its current grant before signing; revocation must send signed cancel.
No live runtime flag, secret, deployment, migration or worker activation is
performed by adding this code. Before separately approving deployment, require
a compatible v3 receiver, isolated grant/cancel/expiry and sandbox evidence, and
keep both dispatch and execution off until explicitly authorized.
