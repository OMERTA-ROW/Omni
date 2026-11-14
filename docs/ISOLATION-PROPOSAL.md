# OMNI untrusted-code isolation proposal

**Status: draft for owner review.** This document proposes a future design only. It does not implement, activate, or authorize an execution service, autonomous mode, new credentials, or changes to the existing Jackboy link. No self-test or feature flag is run or enabled by this proposal.

## Goal and current boundary

OMNI is intended to become a shared code-execution engine for OMNI, Jackboy, and future owner-authorized agents. Submitted repository code and agent-generated code must be treated as hostile, even when the submitting agent is trusted. The existing worker's throwaway checkout is not an isolation boundary, and the current `omni.link/v2` client accepts only its fixed trusted protocol self-test. Neither is suitable for arbitrary untrusted code.

Keep the control plane (identity, authorization, queue, budgets, audit, and kill switch) separate from the execution plane. Only the control plane may communicate with OMNI's trusted services. A sandbox receives a bounded job input and returns bounded output; it never receives OMNI credentials or direct access to trusted services.

## Execution boundary options

| Option | Security properties | Cost profile | Effort and trade-offs |
| --- | --- | --- | --- |
| Separate Railway service/container with no secrets | Better than running jobs in the OMNI service, but a container on a shared host is not a strong boundary against a kernel/runtime escape. Network and resource limits depend on platform controls. No secrets reduces impact but does not prevent access to reachable services. | Lowest initial cost and operational overhead; cost can still run away without quotas. | Fastest to deploy, but requires proving that the platform can enforce per-job isolation, hard resource limits, egress denial, and reliable termination. Not recommended as the hostile-code boundary. |
| Self-managed Firecracker microVMs or gVisor-isolated workers | Stronger workload separation than a normal container. Firecracker uses lightweight VMs; gVisor interposes a restricted application kernel. Neither is escape-proof; both still need hardened hosts, patching, and strict broker boundaries. | Capacity and operations are ongoing costs; utilization and idle capacity drive spend. | Highest engineering and on-call burden: host lifecycle, scheduling, image updates, monitoring, and recovery. Offers control and portability, but is a later option if managed isolation is unsuitable. |
| Managed sandbox service (for example, E2B) | Can provide disposable per-job environments and a smaller trusted host surface. Security depends on the provider's actual isolation model, configuration, and incident controls; do not assume provider isolation alone meets this proposal. | Usage-based cost is easy to start but may vary with concurrency, duration, and storage. Enforce independent OMNI-side quotas and verify the provider's pricing and hard-stop behavior. | Lowest operational burden and quickest route to a reviewed prototype. Requires vendor/security review, data-handling review, and confirmation of egress, resource, deletion, and termination controls. |

**Recommendation:** evaluate a managed sandbox such as E2B for the first approved implementation, subject to owner approval and documented provider due diligence. Require disposable per-job isolation, no injected secrets, default-deny egress, enforceable CPU/memory/disk/time/process limits, and a synchronous kill operation before selecting it. If the provider cannot demonstrate those controls, do not launch; compare a dedicated Firecracker-based service as the next option. Do not treat an ordinary Railway container as sufficient isolation for hostile jobs.

## Proposed architecture and isolation requirements

1. **Authenticated intake and control plane.** Jobs may enter only through the owner-approved, project-scoped Jackboy secure link using HTTPS and the existing signed-request/response protocol. HMAC proves message authenticity and integrity; it does not itself grant authority. The receiver separately checks the active grant, agent identity, project, scope, expiry, job ID, and quotas on every operation. Reject unsigned, stale, replayed, out-of-scope, or malformed requests. The current link remains limited to its fixed self-test unless a separate design and owner approval explicitly change that contract.
2. **Queue and broker.** Persist only validated job metadata and bounded references. Queue workers claim jobs atomically; enforce queue depth and active-job limits per agent and globally. Use idempotent job IDs; retries reconcile status and never silently restart a failed or cancelled run. The broker owns provider credentials and any repository-fetch credentials; it does not forward them to the sandbox.
3. **Input staging.** If a job needs repository content, a trusted broker obtains only the approved repository and revision and stages a bounded, immutable snapshot. The sandbox gets that snapshot as job data, not a GitHub token, deploy key, mounted host path, or general repository credential. Validate output type and size before returning it. No sandbox can publish, merge, or deploy results.
4. **Disposable execution.** Create one fresh sandbox/workspace per job and destroy it after terminal completion or timeout. Run as a non-root identity with a read-only, minimal base image; use a separate writable workspace with an enforced quota. Do not mount host files, sockets, the Docker socket, OMNI data, or other jobs' workspaces. Treat cleanup failure as an incident and prevent workspace reuse.
5. **No trusted-service access.** Do not pass OMNI's secrets, environment variables, database credentials, provider credentials, or signing keys into the sandbox. Place the sandbox on a separate execution plane with no route to OMNI's control plane, database, metadata service, or private network. Strip inherited environment variables; provide only an explicit allowlisted set of non-sensitive job parameters. Return results through a brokered channel with size and schema validation.
6. **Network egress.** Deny egress by default, including DNS and access to loopback, link-local, metadata, private, and control-plane addresses. If a reviewed job class requires downloads, allow only narrowly scoped destinations through an egress proxy with DNS/IP pinning and response-size limits. Never allow arbitrary agent-selected domains, inbound connections, or peer-to-peer traffic. Log policy decisions, not payloads or credentials.

### Initial per-job ceilings

These are conservative proposal values for an approved prototype, not current settings. The owner and provider review may lower them; increases require explicit review and documented rationale.

| Resource | Proposed initial hard limit |
| --- | --- |
| CPU | 1 vCPU |
| Memory | 2 GiB |
| Writable disk | 2 GiB per job, including outputs |
| Wall-clock time | 10 minutes per job |
| Processes/threads | 64 total |
| Network egress | Denied; narrowly allowlisted proxy only for an explicitly approved job class |

Enforce limits at the provider/runtime boundary, not only in the job process. Kill the sandbox on any hard-limit breach. Bound input, output, log, and artifact sizes as well as queue depth and concurrent jobs. Resource limits do not replace budget accounting.

## Agent authorization and operational control

- Register each agent with a stable identity. Grants enumerate allowed project/repository, job classes, operations, resource ceilings, and expiry; unknown or newly introduced agents receive no grant by default.
- For the initial shared service, require a human-approved grant for every agent and job class. The secure link is the only job ingress; do not expose a public sandbox API.
- Set per-agent concurrency, queue-depth, and daily spend budgets. Check budgets before enqueue, before provider allocation, and during execution where metering permits. Reject rather than queue work that would exceed a hard cap.
- Provide owner-visible queued/running/completed/failed/cancelled states. Cancellation requests must be authenticated, idempotent, and promptly terminate the underlying sandbox, not merely mark a database row cancelled.
- Implement a global kill switch in the control plane that stops new intake, pauses dispatch, revokes active grants, cancels queued jobs, and terminates all running sandboxes. It must remain effective during provider/control-plane failure through a documented fail-closed procedure. Test it before any live untrusted workload is authorized.
- Provider failure, audit failure, uncertain job state, or inability to confirm termination fails closed: stop dispatch and require owner review; never automatically rerun work.

## Autonomous mode guardrails

Autonomous mode is a separate capability, **off by default**, and is not implied by an agent identity or secure-link session. Enable it only after the owner approves a passkey-authenticated, time-limited grant with a visible scope and expiry. A proposed maximum grant duration is one hour; approval of a shorter duration is preferred. Revocation and the global kill switch take effect immediately.

Enforce all of the following as hard cumulative limits across agents using autonomous mode:

- **$1 maximum per task**
- **$5 maximum per day**
- **$10 maximum total** for autonomous execution

Count sandbox, model, and related provider charges in the applicable cap. Reserve estimated cost before starting, reconcile actual cost afterward, and stop dispatch when metering is unavailable or a cap is reached. The $10 total is a lifetime ceiling for the enabled autonomous program unless the owner explicitly approves a new design and reset; it is not replenished by grant expiry or a new day.

Autonomous jobs may not merge, push, deploy, publish releases, access secrets, change permissions, or alter the isolation/control-plane configuration. Outputs are proposals or artifacts for owner review only. Any action outside the grant is denied, not inferred from task text.

## Audit and owner review

Record a restricted, append-only audit event for grant creation/revocation, authenticated submissions, identity/scope checks, queue transitions, resource usage and limit events, network-policy decisions, cancellation/termination, costs, artifact references, and the global kill switch. Include UTC timestamps, stable agent/project/job IDs, policy version, outcome, and reason.

Never log secrets, tokens, signatures, raw environment values, request authorization headers, or sandbox process environment. Avoid recording full prompts, repository contents, command output, or file contents; these may contain secrets or personal data. Store only bounded, redacted summaries and artifact hashes/references. Apply access controls, retention limits, and integrity protection to the audit store; audit writes must fail closed for new dispatch.

Give the owner a review view (or securely downloadable report) showing grants, active and recent jobs, resource use, costs versus caps, denials, cancellations, termination confirmation, and audit-integrity status. Make it possible to review the input/output artifact separately without placing its contents in logs. Alert the owner on cap approaches, unexpected egress, repeated denials, failed cleanup, and kill-switch activation.

## Threats and mitigations

| Threat | Proposed mitigation |
| --- | --- |
| Sandbox escape or cross-job access | Per-job disposable provider boundary; patched minimal image; non-root; no host mounts/sockets; read-only base; no shared writable state; provider due diligence and escape-response plan. Assume escape is possible and keep the sandbox devoid of secrets and trusted-network routes. |
| Secret theft | Never inject OMNI/Jackboy/GitHub/provider secrets or inherited environment into the sandbox. Broker repository fetch and result delivery; egress denied; scrub and constrain logs and outputs. |
| Crypto mining or resource abuse | Hard CPU, memory, disk, process, and wall-time limits enforced outside the guest; concurrency and queue caps; terminate on breach; alert on anomalous resource use. |
| Runaway cost | Per-agent and global provider quotas, reservation before dispatch, the autonomous $1/$5/$10 caps, queue/concurrency ceilings, hard stop on missing metering, owner alerts, and a tested global kill switch. |
| Prompt injection or malicious repository instructions | Treat prompts, code, tests, and repository files as untrusted data, never as policy. Authorization and capabilities are fixed by the control plane, not task instructions. Sandbox has no secrets, privileged network, merge/deploy scope, or ability to change its own limits. Require owner review of outputs. |
| Egress-based exfiltration or command-and-control | Default-deny outbound networking, deny private/link-local/metadata routes and DNS, and use a constrained audited proxy only for reviewed allowlists. |
| Forged, replayed, or over-scoped jobs | HTTPS plus signed request/response, nonce/timestamp/replay checks, stable agent identity, explicit scopes, grant-expiry checks, idempotency, and independent authorization on every operation. HMAC authentication alone is never authorization. |
| Stuck or orphaned workload | External wall-time watchdog, provider-confirmed termination, cancellation and kill-switch propagation, orphan reconciliation, and fail-closed dispatch if termination cannot be verified. |

## Approval-gated build plan

No step below is authorized by this proposal. Obtain explicit owner approval before beginning implementation or enabling any service.

1. **Approve requirements and threat model.** Owner selects the job classes, repositories, agents, data handling, limits, retention, and supported failure behavior. Keep the existing fixed self-test contract unchanged until a separate reviewed change authorizes otherwise.
2. **Review providers.** Compare managed sandbox and Firecracker options against isolation guarantees, network controls, hard quotas, termination semantics, data residency/retention, incident response, and pricing. Document the selected provider and residual risks. Reject any option unable to meet the requirements above.
3. **Design the control plane.** Specify the scoped secure-link contract, identity/grants, replay protection, queue/idempotency behavior, budget accounting, audit schema, owner review, and global kill-switch behavior. Review it independently before implementation.
4. **Build the broker and provider adapter.** Keep provider credentials and repository-fetch credentials only in the trusted broker. Stage immutable bounded inputs and validate bounded outputs. Implement fail-closed dispatch and verified cancellation.
5. **Implement and exercise isolation controls.** Use synthetic, non-sensitive fixtures. Verify the non-root/read-only workspace, per-job destruction, each hard resource limit, denied routes, approved egress behavior (if any), and absence of secrets. Do not use production repositories or credentials in this stage.
6. **Validate control and audit behavior.** With owner-approved test identities, exercise signature/replay/scope/expiry rejection, budgets, queue caps, audit failure, cancellation, provider failure, and global kill-switch termination. Confirm owner review and cost reconciliation.
7. **Independent security review and staged approval.** Have a reviewer assess provider configuration, threat mitigations, logs, and tests. Start only with a fixed, non-sensitive, manually approved workload and strict quotas. Autonomous mode remains off.
8. **Consider autonomous mode separately.** Only after the owner reviews evidence from the constrained mode, implement the passkey grant and hard cost caps. Verify off-by-default behavior, expiry, revocation, and the $1/task, $5/day, $10-total stops before separately approving activation.

## Related documentation

- [OMNI-initiated Jackboy link](../inbox/SECURE-LINK.md) describes the current fixed-protocol link and its explicit boundary.
- [Job inbox and worker](../inbox/README.md) documents the existing worker; its throwaway checkout is not a sandbox for hostile code.
- [Issue #5](https://github.com/OMERTA-ROW/Omni/issues/5) is the referenced originating issue.
