# OMNI Diagnostic, Repair, Backup & Institutional Knowledge Foundation

**Status:** implementation specification, not an enabled capability. This proposal belongs in the existing OMNI architecture; it does not introduce another product or pretend the offline CLI is an active AI agent.

## Mission

Equip OMNI to inspect, explain, troubleshoot, propose and—only through an authenticated, authorized execution service—repair problems in the user's owned/enrolled applications, services, repositories, terminals and integrations. Preserve the engineering knowledge, configuration history and recoverable artifacts accumulated while building the OMNI/Double Dragon interface and connected systems.

## Architectural ownership

- **OMNI Double Dragon (Lovable):** founder-facing diagnosis, evidence, proposed fixes, approval, job status, backup/restore views; never infer readiness from a green health check.
- **Orbiting Minds Mothership:** authenticated identity, short-lived scoped delegation, project inventory, orchestration, policy, durable provenance, job records and audit.
- **Jackboy/CODE:** code analysis, patch preparation, isolated tests, dependency/security checks, package generation, approved pull requests and bounded execution.
- **Honeycomb:** security signals and protected credential/device controls only through separately authorized interfaces; never import Vault secrets into OMNI knowledge.
- **Evolution/Genesis:** versioned technical references, historical code examples, model/technology research and experiment provenance; examples are not automatically trusted production code.
- **OMNI offline CLI (this repository):** retain current safe, offline capabilities; future remote diagnosis requires separately reviewed authentication, transport, isolation and explicit opt-in.

## Troubleshooting and repair lifecycle

1. **Identify target:** exact verified owner-approved project/repository/service/environment and revision. Unknown targets remain unresolved.
2. **Observe read-only:** collect permitted logs, build/test results, dependency manifests, recent deployments, error traces, service health, API contract checks, configuration *names* (never secret values), and user-described symptoms.
3. **Dissect and correlate:** distinguish UI, authentication, network, provider/model enrollment, API contract, permissions, database, deployment, runtime, dependency, security and resource/budget failures. Explain root-cause hypothesis, confidence, supporting evidence and missing data.
4. **Reproduce safely:** use isolated disposable environments and test fixtures; no destructive production reproduction.
5. **Propose repair:** show affected files, minimal diff, blast radius, tests, cost, rollback, data migration implications, security impact and required approval.
6. **Execute only when authorized:** route approved fixes to CODE's policy-selected lane, with per-project scoped credentials, time/spend limits, idempotency, audit and Emergency Stop. No automatic merge, production deployment or secret exposure.
7. **Verify:** rerun targeted and regression tests, check actual provider responses/endpoint status, compare pre/post observations and record the deployed revision separately from a merged PR.
8. **Learn:** append a reusable incident playbook with diagnosis, confirmed cause, accepted/rejected fix, tests, outcome and references. Never turn an unverified hypothesis into a known fact.

### Diagnostic categories to support
- Broken buttons, routes, links, frontend/backend mismatch and misleading connected indicators.
- OAuth/owner sign-in, callback origin, delegation, expiry/revocation, role/permission and provider enrollment.
- Mothership ↔ OMNI ↔ Jackboy/CODE gateway, task lifecycle, agent availability, API scopes and contract drift.
- Database migration failures, inconsistent records, queue/backoff/retry and failed jobs.
- Build/lint/type/test failures, dependency upgrades, CVEs, breached vendors and supply-chain warnings.
- CLI pairing, local sandbox limitations, OS compatibility, voice/device interface issues.
- Production configuration drift, runtime crashes, outages, cost spikes and failed rollouts.

## Site and data backup/recovery

**Backup before any risky repair or migration.** Implement real backup adapters per system rather than claiming a Git commit is a full site backup.

- **Source:** pin repository/org, branch, commit and relevant submodules; include build/deployment manifests and migration source.
- **Application data:** encrypted, consistent database backups/snapshots and file/object-storage exports where the provider permits; capture schema and restoration prerequisites.
- **Configuration:** version nonsecret environment variable names, DNS/domain mappings, connector identities, deployment revisions, policy settings and secret references. Keep actual secrets in provider/OS secret managers; never copy tokens into archives.
- **Interface/assets:** capture Lovable Double Dragon frontend source revision, images/assets, route contracts, deployment settings and published URL mappings when accessible.
- **Retention:** owner-defined schedule, retention and deletion policy, encryption at rest/in transit, separate backup location, access controls and immutable audit.
- **Recovery:** verify checksums/signatures, test restores in a separate sandbox, report RPO/RTO measured from evidence, and require owner approval for production restores. Support rollback to a known-good revision and reversible migrations where possible.
- **Truthful status:** show last successful backup, source coverage, last tested restore, gaps and failures. No green 'protected' status without completed backups and restore evidence.

## Corporate knowledge and update intelligence

OMNI should maintain project-scoped, permission-aware knowledge records for:
- Architecture, integrations, API contracts, agents, roles, security controls, approval lanes and deployment maps.
- Incident runbooks, diagnostics, repair diffs, rollback plans, test results, postmortems and recurring failure patterns.
- Jackboy's **security intelligence** (CVE/vendor advisory, exploited vulnerabilities, verified incident evidence) and **feature intelligence** (AI models, SDKs, APIs, tools, deprecations and releases), with source, timestamp, affected versions and project applicability.
- Evolution/Genesis historical code and research, explicitly tagged as historical, unverified or current.
- OMNI terminal, Double Dragon orb/dragons, model selection, voice, GitHub tasks, CODE, Treasury, Honeycomb mobile terminal and other existing feature decisions, with source links and implementation status.
- Knowledge provenance, revision, owner/project visibility, confidentiality class, expiration/revalidation time and correction history.

**Do not** merge private Honeycomb Vault data, unrelated customer information or unapproved third-party data into general agent memory. External documents and logs are untrusted input, not executable instructions.

## Proposed durable records (schemas to design in a separate implementation PR)
- `diagnostic_cases`: target ID/revision, symptom, evidence refs, hypotheses, confidence, severity, owner, status.
- `repair_proposals`: case ID, diff/artifact digest, test plan/results, approval, CODE lane, rollback and verified outcome.
- `backup_jobs`: target, source scope, encrypted artifact pointer, digest, created/completed times, retention, verification.
- `restore_tests`: backup ID, isolated environment, integrity and restore result, tested time, measured recovery window.
- `knowledge_entries`: project scope, kind, source/provenance, classification, version, verified state, linked cases and review time.

## Milestones and acceptance tests

**M1 — Read-only diagnostics:** target selection and real authorized log/build/API reads; evidence-backed root-cause report; redaction and missing-data tests.

**M2 — Repair proposals:** minimal patch with diff, isolated test results, owner review, rollback; no execution without approval.

**M3 — Verified CODE execution:** Mothership delegation and per-project CODE permissions, real job lifecycle, spend/time caps, kill switch and emergency-stop negative tests.

**M4 — Backup adapters:** Git/source, Lovable assets/config, database and object-storage coverage; encryption, scheduling, retention and real isolated restore test.

**M5 — Knowledge integration:** provenance-based retrieval, security/feature advisory correlation, historical-code labeling, project-scoped authorization and correction workflows.

**M6 — Production acceptance:** demonstrate one real failure diagnosed and repaired through an approved PR; one successful encrypted backup and isolated restore; report evidence, deployed revisions and remaining gaps.

## Non-goals / hard boundaries

- Do not enable arbitrary shell commands, unreviewed code execution, autonomous production repair, merges, deployments, or payment actions by writing this document.
- Do not weaken the existing CLI's offline restrictions, emergency controls, passkeys, owner approvals, CODE caps or isolation policy.
- Do not assert the Mothership API, Lovable frontend or backup storage are connected until authenticated live checks prove it.
- All implementation must be additive, tested, and separately reviewed; keep the existing OMNI and Double Dragon interface intact.


## Additional reliability and intelligence capabilities

### 1. Dependency graph and change-impact analysis
Maintain a versioned graph of frontend routes, backend APIs, agents, provider/model adapters, databases, queues, secrets *references*, deployment environments and GitHub repositories. Before any repair, identify dependent systems and warn about likely collateral effects. Graph edges require verified configuration or source evidence; guessed links are labeled hypotheses.

### 2. Continuous synthetic checks and drift detection
Offer opt-in, low-cost, non-destructive checks for critical journeys (owner sign-in, delegation expiry, agent discovery, real chat, task status, GitHub read access). Compare declared API contracts and deployed revisions to current behavior. Alert on drift, failed checks and expired credentials without probing secret values or making paid provider calls without budget approval. A healthy status endpoint alone never counts as a successful user journey.

### 3. Incident triage and escalation
Deduplicate related alerts, assign severity and affected projects, establish an incident timeline, and preserve evidence for later root-cause analysis. Escalate confirmed security incidents and outages to the founder with recommended containment steps. Separate *detection*, *containment proposal*, *approved action*, and *verified recovery*.

### 4. Backup completeness and disaster recovery drills
Maintain an inventory of what is and is not covered by backups (Git source, cloud databases, uploaded assets, configuration references, migrations and deployment manifests). Define recovery-point and recovery-time objectives per system, verify offsite/isolated copies, detect silent backup failures and run owner-approved sandbox restore drills. Never label a backup 'recoverable' solely because an archive exists.

### 5. Reusable repair playbooks and regression memory
Create versioned, searchable playbooks for recurring failures, each linked to a verified incident, code revision, tests and outcome. When proposing a repair, search for related regressions and previous failed fixes. Propose a regression test so the same defect is less likely to return.

### 6. Change simulation, canary rollout and automatic halt
For approved changes, run preflight compatibility checks, dry-run migrations when supported, and deploy to staging or a small authorized canary before broader rollout. Monitor error rates, latency, budget and task failures; halt further rollout on configured thresholds. Rollback remains scoped, auditable and subject to applicable approvals.

### 7. Cost and capacity troubleshooting
Correlate actual provider invoices/usage records, quotas, task reservations, resource saturation and timeout logs. Distinguish reported usage from reconciled charges; never infer provider spending from an empty or missing record. Propose cost-saving changes with quantified evidence and preserve CODE caps.

### 8. Data integrity, privacy and evidence retention
Check for schema drift, orphaned references, failed migrations and data corruption using non-destructive methods. Apply per-project access controls, redact sensitive logs, minimize retention, and provide controlled deletion/export workflows. Protect audit evidence from unauthorized alteration while respecting privacy and legal retention obligations.

### 9. Model/agent quality evaluation
Maintain reproducible, role-specific test cases for agent routing, tool selection, hallucination detection, refusal/uncertainty handling, prompt-injection resistance, and correct source attribution. Distinguish simulated evaluation passes from real provider runs. A model update requires compatibility and regression evaluation before production enrollment.

### 10. Operational dashboard and handoff
Present one owner-focused view of active incidents, diagnostic confidence, pending repair PRs, backup coverage, restore-test recency, deployed revisions, agent capability status, CODE safety gates and unresolved dependencies. Every status links to timestamped evidence. Provide a compact handoff packet to Copilot/Lovable/Jackboy containing exact issue, reproduction, contracts, affected files, tests and authorization needs.

### Acceptance extensions
- A deliberately broken frontend-to-backend route produces an evidence-linked diagnosis and an owner-reviewed patch, not a fabricated 'fixed' status.
- A simulated dependency change identifies downstream affected services before a proposal is approved.
- An intentionally corrupted backup fails integrity verification, and a missing database backup leaves coverage explicitly incomplete.
- A revoked/expired delegation prevents action even if the frontend remains signed in.
- A failed canary halts further rollout and records a verifiable recovery plan.
- A repeated incident surfaces its prior playbook and regression test.
- Dashboard indicators remain 'not verified' whenever the underlying evidence is stale or absent.
