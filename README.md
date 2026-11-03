# OMNI

OMNI is the terminal companion initiative within Evolution, designed to help coordinate AI agents and coding workflows.

## Current status

This repository contains the existing **unreleased offline Evolution CLI source**, copied from the Orbiting Minds Mothership Lovable project. The executable is currently named `evolution`; the optional `omni` alias does not enable AI functionality.

Basic offline commands, local project targeting, fixed local test tasks, and release-manifest utilities are implemented in the source. AI/model connections, autonomous agents, authentication, remote sandbox isolation, and signed public installers are not available in this CLI.

## Developer setup

See [the CLI build guide](cli/README.md) for prerequisites and source-development commands, and [security notes](cli/SECURITY.md) for limitations. Go 1.25+ is required. No package-manager installer or signed download is offered.

This copy has not yet been independently built or tested after transfer. Historical checks described in the CLI guide were reported from the Lovable development sandbox.

## License

No open-source license has been selected. Public visibility does not grant an open-source license.

## Terminal appearance

The source now includes a black-and-gold OMNI banner for interactive help/startup. Actual colors depend on terminal ANSI support. Set `OMNI_ANIMATE=1` to opt into a brief orbit animation; it is off by default. Set `NO_COLOR` to disable branding. Redirected output, JSON, and TERM=dumb stay plain. The terminal's global theme is unchanged.

This presentation change has not been compiled or runtime-tested here because a Go toolchain is unavailable. It does not enable the planned AI features.

## Mothership launcher design preview

Open the local [OMNI Terminal preview](terminal/README.md) for the original Evolution artwork, gold command deck, per-session history and interface logs. This additive browser view does not change `omni`, install a launcher, or connect agents or a shell. See [artwork provenance](terminal/ASSET-PROVENANCE.md).
