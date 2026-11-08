# OMNI Roadmap

## Roles

- **Evolution (Mothership)** is the home base and dashboard (Lovable: Orbiting Minds Mothership).
- **OMNI** is the shared sandboxed code-execution engine and coding agent for OMNI, Jackboy, and future agents. It has its own chat and terminal, like Claude Code or Codex. This repository is deployed on Railway.
- **Jackboy Dev Control** is the dispatcher and gatekeeper for approvals, passkeys, and spend limits ([OMERTA-ROW/jackboy-dev-control](https://github.com/OMERTA-ROW/jackboy-dev-control)).
- **Honeycomb Terminal** is its own branded mobile app, powered by OMNI over the secure link.

## Current state

- Railway deploys OMNI from `main`. The image builds `omni-inbox` by default and includes `omni-link` for owner-approved one-off runs only.
- All `OMNI_LINK_*` values are set on Railway and Jackboy. Approval expires approximately every 24 hours.
- The full self-test is blocked: live Jackboy cannot run the runner, and the Railway Jackboy copy cannot reach Jackboy data. A fix is being planned.

## Operating rules

- Lovable owns `main` for Jackboy. Copilot works on branches and opens PRs only.
- Never put secrets in code, comments, or chat.
- Untrusted code runs only in a separately reviewed, isolated sandbox. Nothing autonomous is enabled by default.
- Spend caps: **$1 per task, $5 per day, and $10 total**.

## Roadmap

1. Complete the handshake test, fix the full self-test blocker, run the full test, and close [OMERTA-ROW/Omni#5](https://github.com/OMERTA-ROW/Omni/issues/5).
2. Write an isolation design document (docs only) and submit it for owner review.
3. Build the sandbox runner with agent IDs, per-agent budgets, a job queue, an audit log, and a kill switch.
4. Add OMNI chat, terminal, and an agents view to Mothership, plus an autonomous switch protected by a passkey and configured to auto-expire.
5. Connect Honeycomb to OMNI with passkey access, auto-lock, shared sessions, and mobile approvals.

Refs OMERTA-ROW/Omni#5
