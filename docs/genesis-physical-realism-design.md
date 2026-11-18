# Genesis physical realism — Rise of the Kings

Status: design-only proposal, not implemented.

## Goal
Improve character impact, loss-of-balance, knockout and fall animation with believable mass, inertia, joint limits, muscle tone and ground contact. Avoid both rigid mannequin motion and overly limp ragdoll folding. UFC-style fighting games are a qualitative reference, not a request to copy assets or animation.

## Approach
- Blend authored animations and active ragdoll physics using pose matching and per-joint drive strengths.
- Vary post-impact muscle tone, balance recovery, bracing and protective reflexes by hit severity, direction, stance and awareness.
- Respect anatomical joint ranges, body proportions, momentum, collision surfaces and friction.
- Simulate believable transitions from standing to stumbling, partial collapse or full loss of balance; avoid deterministic one-size-fits-all knockouts.
- Provide tunable realism and accessibility/gameplay settings; do not claim medically accurate injury prediction.
- Use deterministic seeds and recorded impact inputs for reproducible tests.

## Acceptance tests
1. Side-by-side footage for standing knockdown, backward fall, forward fall and uneven-ground collision.
2. No major clipping, unnatural joint hyperextension, explosive impulses or persistent animation/physics desync.
3. Stable frame-time and graceful fallback at crowded NPC counts.
4. Developer approval before integration or deployment.

## Architecture
Genesis specifies realism constraints and scenarios; OMNI coordinates authorized engine-specific implementation; Jackboy validates tests and rollback. Initial showcase: Rise of the Kings. This does not modify Grand Theft Auto or any third-party title.

## Locomotion, gait and posture realism
- Adapt step length, cadence, foot placement, pelvis motion, balance and torso posture to speed, slope, surface friction, obstacles, fatigue, injuries and character state.
- Use motion matching or responsive locomotion blending with foot IK and grounded contacts to reduce foot sliding and repetitive gait loops.
- Preserve continuity when transitioning between idle, walking, running, turning, stopping and interacting; account for inertia and body weight.

## Reaching, grasping and vehicle contact
- For vehicle doors, vents, latches and other interactive objects, align hands to the actual moving contact target using inverse kinematics and procedural reach correction rather than a generic canned grab animation.
- Model approach distance, shoulder/elbow/wrist limits, finger closure, grip orientation, object collision and contact constraints. The hand should visibly meet the latch before the object moves.
- Animate grasp, force application, latch release, door/vent movement and letting go as one continuous interaction with believable resistance and momentum.
- Support different character heights, handedness, vehicle geometry and obstructed approaches without clipping or hand teleportation.
- Keep tactile animation distinct from actual physics: use authored motion plus contact-aware procedural correction; avoid promising perfect realism for all props.

## Additional acceptance tests
5. Compare walking, turning, stopping, stairs, slopes and injury/fatigue variants for foot sliding, posture discontinuity and collision clipping.
6. Open/close vehicle doors and operate a latch from multiple approach angles and character sizes; confirm hand-target alignment, grip timing, physical contact and no object movement before contact.
7. Verify frame-time budgets and scalable fallback for crowded scenes, with reproducible capture clips for review.
