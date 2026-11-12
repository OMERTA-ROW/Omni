# OMNI Mothership — Master Roadmap

## Purpose

This is the consolidated tracking roadmap for [OMERTA-ROW/Omni#15](https://github.com/OMERTA-ROW/Omni/issues/15): OMNI as the shared Mothership/backend, Jackboy as the owner-approved development and repair gateway, and Honeycomb Terminal as the secure mobile extension. It records development direction and reported evidence; it does not claim implementation completeness or production readiness.

## Architecture and responsibilities

- **OMNI / Mothership:** Central agent orchestration, inbox, secure link, code/terminal services, persistent state and audit.
- **Jackboy Dev Control:** Owner approvals, signed connection checks, repository and task scope, CODE budget enforcement, Emergency Stop, and supervised branch/test/draft-PR development.
- **Honeycomb Terminal:** iPhone/iPad remote terminal and device-pairing client using the OMNI backend, not a separate Mothership. No unrestricted shell by default.
- **GitHub:** Source, review and tests. **Railway:** Deployed backend. **Lovable:** Jackboy UI and controls. **Notion:** Development history and product concept.

## Reported development evidence

The following are development references, not verification of deployed behavior:

- Local OMNI CLI/handshake repair commit `05daf6fe70287e0e07bed5b897c4c80463a2347e`.
- Honeycomb integration contract/reference tests commit `533e72bfc7849ea9c09fbb84d20f1961e2f6fe69`.
- Jackboy scoped-readiness diagnostic commit `244be2d86c4681d3f91ed9fecb7d52b222179e99`.
- OMNI/Honeycomb branch `street-tech666-omni-mothership-readiness`; Jackboy branch `street-tech666-omni-readiness-jackboy`. These were local-only commits at last report, not pushed, merged or deployed.
- Focused local tests were reported passing. The cross-repository TLS/PostgreSQL test was skipped; live authenticated reachability and production controls were not established.

## Workstreams and acceptance gates

- [x] **Durable OMNI state:** Review storage repair and ensure worker inbox/job state is persistent without unsafe replay; verify staging and production separately.
- [x] **Signed OMNI ↔ Jackboy link:** Owner/project/approval/expiration/revocation checks and authenticated current reachability; diagnostics must not confer execution authorization. Track live verification in [OMERTA-ROW/Omni#5](https://github.com/OMERTA-ROW/Omni/issues/5).
- [x] **CODE supervised development:** Verify owner approval, allowed repo/branch, task authorization, cancellation, audit, isolation, and safe draft-PR workflow. One supervised task only after gates pass.
- [x] **Isolation:** Preserve reviewed threat model, hostile-code sandbox boundaries, egress/resource controls, limits, and kill switch. Track in [OMERTA-ROW/Omni#9](https://github.com/OMERTA-ROW/Omni/issues/9) and [PR #10](https://github.com/OMERTA-ROW/Omni/pull/10); design approval is not execution approval.
- [x] **Production safety:** Confirm trusted spend meter, $1/task, $5/day and $10 cumulative guard as applicable, two-failure stop, Emergency Stop, database migrations, and deployment policies with live evidence before enabling anything.
- [x] **GitHub/Lovable/Railway trigger review:** Railway inspected development branches do not match deploy triggers, but installed-App/Lovable behavior is not fully verified. Jackboy draft PRs run hosted CI; separately authorize push, CI, PR, merge and deployment.
- [x] **Honeycomb mobile:** Finalize owner identity, device registration/pairing, expiring/revocable sessions, encryption, streaming, audit and real iOS/iPad acceptance. Contract and reference tests do not implement production mobile access.
- [x] **Knowledge/history inside Jackboy:** Connect approved Notion concepts and GitHub issue/PR/test records; distinguish design, implemented, verified, blocked and approved; no self-granted permissions.

## Historical planning and linked work

- [OMERTA-ROW/Omni#7](https://github.com/OMERTA-ROW/Omni/issues/7) and [PR #8](https://github.com/OMERTA-ROW/Omni/pull/8) are historical roadmap planning, not merged implementation evidence.
- [OMERTA-ROW/Omni#9](https://github.com/OMERTA-ROW/Omni/issues/9) and [PR #10](https://github.com/OMERTA-ROW/Omni/pull/10) remain open until isolation design and implementation gates are addressed.
- [OMERTA-ROW/Omni#5](https://github.com/OMERTA-ROW/Omni/issues/5) remains open until authenticated live connection is verified.
- [Jackboy PR #48](https://github.com/OMERTA-ROW/jackboy-dev-control/pull/48) is historical cross-project roadmap documentation, superseded for tracking by this roadmap; its contents are not claimed to have merged.
- Previously merged repair PRs [OMERTA-ROW/Omni#60](https://github.com/OMERTA-ROW/Omni/pull/60) and [OMERTA-ROW/Omni#61](https://github.com/OMERTA-ROW/Omni/pull/61) are code history, not proof of live production readiness.

## Operating rules

- No automatic merge, deploy, migration, live job, CODE or autonomous activation follows from this roadmap.
- Separate owner approvals and verified evidence are required before enabling execution or production controls.
- Keep unresolved security and onboarding issues open; close superseded documentation threads with links to this roadmap.
- Never put secrets in code, comments or chat. Untrusted code requires reviewed isolation; a design approval is not execution approval.
