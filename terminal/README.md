# OMNI Mothership Terminal

A dependency-free, local browser interface for owner review of the future Mothership launcher. It reuses the current Evolution homepage artwork, with metallic gold lettering, an image fixed behind an independently scrolling command transcript, session selection, history recall and local interface logs.

## Open the preview

From the repository root:

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory terminal
```

Open http://127.0.0.1:8765. Stop the server with Ctrl-C. The directory can also be opened directly via `terminal/index.html`; no build, account, external font or provider request is required. Serve only this static directory, not your home or repository root.

## What works

- `help`, `status`, `agents`, `sessions`, `history`, `logs`, `clear`: local interface commands.
- Up/down history with restoration of unfinished input.
- Up to eight isolated local preview sessions, each with its own input draft, history and log.
- Up to 200 records per collection; older records roll off. Reload clears all data.
- Desktop and narrow-screen layout, keyboard focus, labeled controls, status announcements, and no animated background.
- Unrecognized input is displayed as text and explicitly rejected; it is never evaluated.

These are browser sessions, not running agents or shell processes. No runtime is queried. The interface reports no connected agents, not that all agents everywhere are stopped. Logs record UI events only. The heuristic credential omission is a convenience, not a secret detector: do not enter credentials.

## Architecture and compatibility

The OMNI repository contains the offline Go companion under `cli/`. The existing `omni` zsh function changes directory and sets a prompt; it is not a graphical terminal launcher. This change does not touch shell profiles, CLI commands, ANSI branding, installation, permissions or Go code. Existing commands continue to run in the user's terminal.

The separate Evolution web repository (`OMERTA-ROW/orbiting-minds-mothership`, inspected at `99007f6ca7f95ccd551f91d17963f8253d080f87`) uses TanStack Start/React. Its public `/omni` route hosts Razul and the OMNI demo; private agent routes have their own authorization. Its `MothershipBackground` loads the asset documented in `ASSET-PROVENANCE.md`. This standalone view is deliberately added to the CLI repository for launcher design review, without modifying those web routes or connecting their APIs.

The future launcher can host this static view in a browser or webview. Integrating real shell/agent transports is separate work: it needs authenticated session lifecycle and actual execution events. A session tab or a successful UI command must never set an agent to running. No transport has been implemented or enabled by this design. macOS Terminal is not expected to render website backgrounds.

## Browser checks

Use a separately installed Playwright package and an existing Chrome binary. No dependency is required to use the preview. Start the static server above, then:

```sh
NODE_PATH=/absolute/path/to/playwright/node_modules \
SCREENSHOT_DIR=/absolute/existing/output/directory \
node terminal/tests/browser.cjs
```

Optionally set `CHROME_PATH` to an existing Chrome executable. Tests cover history recall, draft restoration, session isolation, disconnected status, input escaping, credential omission, log/history views, bounded session count, independent scrolling, mobile overflow, reload clearing, and absence of external requests and browser errors. Screenshots are written to `SCREENSHOT_DIR`. The default test URL is http://127.0.0.1:8765.

No deployment, merge, agent activation, shell bridge or security-permission change is included.
