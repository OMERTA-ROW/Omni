# Genesis Civilization Engine — persistent experiential memory

Status: design proposal only. No runtime implementation or claims of sentience.

## Principle
Simulated agents, wildlife, and institutions retain consequential history so future behavior depends on experience, environment, relationships, and context—not solely player-triggered scripts. Memory is modeled state, not subjective consciousness.

## Memory model
- Entity identity, species/type, lifespan stage, location, needs, temperament, and baseline behavior.
- Event records: timestamp, participants, place, stimulus, observed outcome, severity, confidence, source and provenance.
- Episodic memories (what happened), learned associations (what to approach/avoid), social knowledge (who communicated what), and institutional records (citations, court cases, transfers, news).
- Memory persistence, decay, reinforcement, generalization, misinformation, and bounded retrieval; distinguish firsthand observation from rumor.
- An injured shark may learn to avoid a particular vessel or stimulus; other sharks do not automatically share that memory. Responses can vary with hunger, fear, age, injury, and habitat. Model biological plausibility without asserting human emotions or consciousness.

## Decision cycle
Perception -> retrieve relevant memory -> evaluate needs, risk, laws and social context -> choose action -> record outcome -> update memory. Choices include ignore, investigate, flee, seek help, negotiate, defend, or attack. Avoid a universal auto-aggression trigger.

## Civilization integration
Persistent world events link traffic, policing, courts, prisons, businesses, healthcare, ecology, and generated in-game reporting. Systems continue in coarse background simulation when the player is absent; detail increases only near relevant actors/events. News must be traceable to actual simulated events or explicitly marked authored fiction. Prewritten stories can seed canonical historical records.

## OMNI / Jackboy delivery
OMNI coordinates authorized project inspection and proposes engine-specific changes. Genesis supplies simulation schemas and behavior policies. Jackboy runs deterministic tests, performance budgets, rollback checks, and review gates. No third-party game modification without rights and appropriate source/SDK access.

## First playable vertical slice
1. One district, a small NPC population, a traffic officer, a garage, and a local news feed.
2. NPC violates a traffic rule; officer may issue citation; record persists; fine/payment or court response influences finances.
3. Separate wildlife test: curiosity -> injury/negative encounter -> later cautious avoidance, with controlled comparison against an uninjured animal.
4. Restart simulation and verify memories and case records persist; run same seeded scenario twice to ensure reproducibility.
5. Validate no-player world progression, performance at increasing population sizes, memory retention/privacy, and non-destructive rollback.

## Acceptance gates
Documented engine integration target; memory persistence across reloads; causal provenance for decisions; no fabricated case evidence; stable frame-time budget; graceful low-detail simulation; automated tests and explicit owner approval before production deployment.

This specification extends Genesis Media Intelligence PR #25. Merging documentation alone does not activate any engine or make OMNI ready for personal use.
