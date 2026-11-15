# Changelog

This file records repository modernization work from the current baseline. Existing versioned releases remain available through Git tags and GitHub Releases.

## Unreleased

### Added

- Professional project README and documentation index.
- Architecture, packet-flow, policy, lifecycle, build, testing, user, configuration, troubleshooting, security and ADR documentation.
- Contributor and security policies.
- Licensing assessment that does not invent a project license.

### Changed

- Documentation now distinguishes Native WFP User Mode Policy from the WinDivert packet backend and from the unimplemented kernel callout engine.
- Release automation is being separated from ordinary branch verification.

### Security

- Runtime startup no longer needs to install the project's self-signed build certificate into Windows trust stores. The optional certificate remains build/signing metadata only.

## Historical releases

See `git tag` and the GitHub Releases page for prior release notes. The repository currently has no project-level `LICENSE`; owner approval is required before adding one.
