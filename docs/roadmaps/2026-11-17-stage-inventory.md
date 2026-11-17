# OMNI Terminal — comprehensive capability map and staged implementation

Status: requirements and design backlog; no unverified capability is represented as live.

## Experience and orchestration
- Premium black/gold terminal with rotating Earth orb, agent labels, side conversations, voice/text input and optional purple accent.
- One interface for multiple model providers (OpenAI, Claude, Gemini, Grok, Copilot, Perplexity, DeepSeek) using authorized credentials and per-provider capabilities.
- CODE workspace: code creation, diagnostics, testing, repairs, source control and owner-reviewed pull requests.
- Individual agents with role-specific tools, intelligence profiles, provenance, uncertainty reporting, handoffs and durable context.

## Specialized terminal workspaces
- Finance/taxes: records, reconciliation, research and draft calculations with provenance; professional review for regulated advice.
- Law/compliance: jurisdiction-aware research, citations, document drafting and licensed professional escalation.
- Creative studio: original music composition/production assistance, audio enhancement, editing, video and graphic workflows.
- Game development: worldbuilding, NPC behavior, simulations, scripting, assets, gameplay systems and QA.
- Research/education: mathematics, scientific/technical investigation, historical code lineage, reproducible experiments.
- Business/product: project planning, publishing, marketing, analytics and documentation.

## Stages and separate acceptance gates
1. Inventory existing CLI and web terminal behavior, identify simulation vs real executor.
2. Authenticate: passkey/MFA QR, device pairing, owner approvals, provider-key vault.
3. Integrate agents/providers with scoped tools, cost metering and provenance.
4. Enable specialized workspaces via adapters with test fixtures and safe defaults.
5. Validate real isolated execution, permissions, error handling, logs and session reuse.
6. Staged production autonomy with owner-reviewed permissions, signed permits, stop/rollback and monitoring.

## Known historical troubleshooting to reverify
- CLI pairing returned 403 code_invalid / unsupported arguments; verify current protocol and expiration.
- Authenticator enrollment lacked a clear QR workflow; validate setup and recovery.
- Browser terminal simulation must not be presented as host command execution.
- Deployment and backend readiness must be checked against live SHA, not screenshots.
- Preserve test output, root causes, fixes and independent acceptance per stage.

## Merge policy
This is a roadmap-only PR. Merging does not enable agents, connect APIs, deploy software or certify tests.
