# OMNI isolated workspace sandbox

This is a separate `omni.workspace/v1` service. It does not replace the inbox,
change Mothership authentication, create owner approvals, or enable Jackboy
autonomy. The inbox execution startup hold remains in force.

Execution is disabled by default, the durable Emergency Stop latch starts
engaged, and every new service process re-engages it before accepting work.
Commands require the existing Mothership-signed `command.run` request, a
session with `run_commands`, and the corresponding signed `step.decide`
approval. `autonomous: true` does not approve a command. Repository checkout,
GitHub operations, providers, and agent autonomy are unsupported.

## Containment design

- Each session gets a separate bubblewrap user, PID, network, IPC, UTS, and
  mount namespace and a separate supervisor process. Nested user namespaces
  are disabled. The host/container root is not mounted into the job namespace.
- `/usr`, `/bin`, and required libraries are read-only; `/etc` exposes only
  `passwd`, `group`, and `nsswitch.conf`. `/proc` and `/dev` are namespace
  local. `/data`, service environment variables, host mounts, and the Docker
  socket are not available to commands.
- `/workspace` and `/tmp` are separate size- and inode-limited tmpfs mounts.
  The command process receives a clean, fixed environment, a non-root
  namespace UID, process/file/address-space limits, CPU-time and wall-clock
  limits, bounded combined output, and process-group cancellation.
- Durable job events and status use atomic file replacement under `/data`.
  A restart never resumes a command and always re-engages Emergency Stop.
  Signed Emergency Stop controls use a separate HMAC key; an `engage` request
  latches the stop and terminates active/starting sessions.

These are implementation properties, not proof of containment. Kernel,
container-runtime, Railway, and Mothership interoperability tests must pass in
an isolated Linux staging environment before any live sandbox test. `RLIMIT_AS`
limits per-process virtual address space; it is not a substitute for an outer
container/cgroup memory ceiling. Configure hard container CPU, memory, and PID
limits too.

## Configuration names

Required integration settings:

- `OMNI_SANDBOX_CLIENT_ID`
- `OMNI_SANDBOX_HMAC_SECRET`
- `OMNI_SANDBOX_PROJECT_ID`
- `OMNI_SANDBOX_CONTROL_SECRET` (required when execution is enabled; distinct
  from the workspace HMAC secret)
- `OMNI_SANDBOX_ENABLED`
- `OMNI_SANDBOX_DATA_DIR`

Optional limits and executable paths:

- `PORT`
- `OMNI_SANDBOX_COMMAND_TIMEOUT_SEC`
- `OMNI_SANDBOX_CPU_SEC`
- `OMNI_SANDBOX_MEMORY_MB`
- `OMNI_SANDBOX_MAX_PROCESSES`
- `OMNI_SANDBOX_FILE_MB`
- `OMNI_SANDBOX_OUTPUT_CAP_BYTES`
- `OMNI_SANDBOX_MAX_SESSIONS`
- `OMNI_SANDBOX_WORKSPACE_MB`
- `OMNI_SANDBOX_WORKSPACE_INODES`
- `OMNI_SANDBOX_BWRAP`
- `OMNI_SANDBOX_SUPERVISOR`

Keep values in the authorized platform secret/configuration store. Do not put
secret values in deployment commands, logs, images, or job environments.

## Build and local tests

From the repository root:

```sh
docker build -f sandbox/Dockerfile -t omni-isolated-sandbox:staging .
node --test sandbox/server.test.mjs sandbox/containment.test.mjs
```

The Node unit tests use a fake executor. The real containment suite is opt-in
and skips by default. Run it only on a disposable, isolated Linux staging
runtime with user namespaces and bubblewrap available:

```sh
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --cpus 2 --pids-limit 512 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=10001,gid=65534 \
  --user 10001:65534 \
  --env OMNI_SANDBOX_CONTAINMENT=1 \
  --entrypoint node omni-isolated-sandbox:staging \
  --test /app/containment.test.mjs
```

The suite exercises the real bubblewrap/supervisor path: signed handshake and
approval flow, service-file/network isolation probes, per-session workspace
separation, tmpfs quota, CPU/address-space/process limits, cancellation, and
safe restart recovery. A skipped suite is not a containment pass. If the
runtime blocks user namespaces or mount operations, stop; do not grant broad
privileges or weaken the container profile as a workaround.

## Staging deployment and verification

1. Build and scan the image from the reviewed branch. Deploy only to a separate
   staging service with no production Mothership URL, production credentials,
   or host filesystem mounts. Do not mount the Docker socket. Use a dedicated
   persistent volume mounted only at `/data`, hard outer CPU/memory/PID limits,
   owned by UID `10001`/GID `65534`, ingress TLS, and the platform's non-root/
   runtime hardening controls. If the platform cannot provide that volume
   ownership without running the service as root, stop rather than weakening
   the image's privilege boundary.
2. Set `OMNI_SANDBOX_ENABLED=false`. Keep the separate Emergency Stop engaged;
   do not issue the signed `clear` action as part of deployment or health
   checks. Supply only staging integration credentials through the secret
   store. The service must fail closed if its real startup probe cannot verify
   network isolation, positive namespace UID, and the clean environment.
3. Verify `/healthz`, signed `health.check`, correct staging project/client
   binding, rejection of wrong client/project, invalid signature, replay, and
   stale timestamp. Confirm no request can start a session while disabled.
4. After separate owner authorization for a staging execution test, enable
   only the staging service and clear its Emergency Stop with the separately
   controlled staging key. Verify an owner-approved `printf
   'OMNI_EXECUTOR_OK\n'` output and job ID through the actual Mothership
   integration, then test invalid approval, filesystem/network probes, CPU and
   memory exhaustion, process/file/workspace limits, bounded output,
   cancellation, Emergency Stop, concurrent sessions, and restart recovery.
   The test suite supplements but does not replace Mothership end-to-end checks.
5. Re-engage the staging stop, disable execution, preserve audit output, and
   report test evidence. Do not connect this service to production, change
   production secrets, merge, or activate autonomous execution without
   separate owner authorization.

## Current verification boundary

No live staging or deployed test is implied by these instructions. Until the
Linux containment suite and the signed Mothership end-to-end test pass, this
service is not approved for a live sandbox test. Existing migrations are not
modified; the service uses its own versioned JSON state file and needs a
dedicated persistent `/data` volume.
