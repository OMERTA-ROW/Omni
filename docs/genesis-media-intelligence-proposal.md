# Genesis Media Intelligence for OMNI — implementation proposal

Status: design-only, no runtime media processing enabled.

## Goal
Make OMNI a controlled upload-and-review workspace for film/video, audio, and music. Genesis supplies a shared temporal/context model for continuity; specialized analyzers detect issues, explain evidence, and suggest non-destructive edits.

## Video pipeline
1. User uploads an authorized video to a private, scoped workspace.
2. Inspect container, codecs, duration, FPS, audio streams; calculate checksum.
3. Decode sampled frames and inspect all frames near detected cuts for isolated dark/black flashes, dropped/duplicate frames, abrupt luminance shifts, and rendering artifacts. Avoid false positives for intentional fades, cuts to black, and artistic effects.
4. Compare adjacent shots for object/wardrobe/lighting continuity; label uncertain observations as suggestions, not confirmed errors.
5. Report timecode, frame range, confidence, thumbnails, cause hypotheses, and previewable fixes.
6. Generate a **separate** candidate edit; never overwrite source. Require explicit approval before rendering/export.

## Audio and music pipeline
1. Analyze sample rate, channels, peaks, loudness, clipping, silence, noise, and alignment.
2. Detect abrupt cuts, clicks/pops, phase issues and timing problems.
3. Offer beat-aware transitions, crossfades, loudness-matched blends and optional stem-based transitions where licensed and available.
4. Preview A/B with clear controls; user chooses transition duration, style and final export. No unauthorized music reuse or automatic publishing.

## Shared Genesis layer
Maintain a media timeline and provenance graph: shot/segment IDs, entities, temporal events, continuity constraints, analyzer outputs, confidence, edits and user decisions. This is a simulation/context framework, **not** a claim of actual consciousness.

## OMNI integration
- Terminal commands (proposed): `omni media inspect <file>`, `omni media analyze <file> --video|--audio`, `omni media report <job-id>`, `omni media preview <job-id>`.
- Mobile Honeycomb client can submit jobs and review results using the same permissioned API later; do not grant mobile execution by default.
- Async worker jobs isolated from agent/terminal execution; job state queued/running/review/failed/completed.
- No autonomous filesystem writes, network uploads, or publication without explicit scoped authorization.
- Enforce file size/duration limits, content-type verification, sandboxed decoding, malware checks, quotas, encryption, retention/deletion policy, and audit logs.
- Never silently send private media to third-party model providers; require provider disclosure and opt-in.

## First deliverable / acceptance tests
- Small CLI or service prototype using FFmpeg/ffprobe and a deterministic flash detector.
- Fixture: known 1-frame black flash at a cut is flagged with exact timestamp; intentional fade is not falsely flagged.
- Fixture: clean video returns no critical findings.
- Fixture: audio with inserted click is flagged with timestamp; clean audio is not.
- Produce JSON report plus human-readable review; no edits to original.
- Tests cover malformed files, unsupported codecs, cancellation, privacy, resource limits, and failure recovery.

## Delivery phases
1. Video flash/technical QC MVP.
2. Audio QC and user-controlled music blending.
3. Scene/character continuity and optional Genesis world-state reasoning.
4. Optional editing/rendering integrations after explicit review.

## Scope boundaries
This PR documents the implementation contract only. It does not implement analyzers, modify deployment, enable autonomous agents, or establish that the current OMNI CLI accepts uploads.

## Genesis game ecosystem enhancement (proposed)
- Accept authorized game source projects or documented engine plugins; distinguish these from opaque compiled binaries and never promise universal executable patching.
- Inventory game engine, versions, dependencies, NPC behavior trees/state machines, physics, combat, economy, ecology, and save-game schema.
- Produce a behavior baseline: aggression triggers, idle/social routines, player proximity responses, animal needs, world simulation and non-player-to-non-player interactions.
- Genesis proposes constrained world rules and NPC state models (needs, memory, goals, threat assessment, social relationships), with adjustable probabilities rather than default hostility.
- Preserve authored story/combat design; provide explicit developer controls for behavior changes and measurable acceptance criteria.
- OMNI generates isolated source changes or engine plugin patches on a review branch, with rollback and migration plans. Jackboy may run authorized static checks, unit/integration tests, simulation regression and performance benchmarks; it must not autonomously publish updates.
- Measure NPC aggression rates, neutral interactions, persistence, frame time, memory use, save compatibility and deterministic replay across seeded simulations.
- Start with an owned prototype such as Rise of the Kings, not third-party commercial games without permission.
- Phase 1: read-only behavior audit. Phase 2: sample NPC natural-law plugin. Phase 3: controlled code patch and tests. Phase 4: developer-approved packaging and distribution.
- A responsive game world does not establish sentience; Genesis is a simulation framework, not a consciousness claim.
