# Release process

Releases are intended for explicit semantic-version tags (`vMAJOR.MINOR.PATCH`) or a manually dispatched workflow. Documentation and ordinary pushes must not publish a release automatically.

A release build should:

1. Run Linux pure-Go and native C checks.
2. Run Windows vet/tests/build on a Windows runner.
3. Rebuild the embedded Windows executable.
4. Verify the public certificate fingerprint is unchanged.
5. Sign only when the repository owner supplies the release PFX secrets.
6. Package the executable, required license notices and SHA256 checksums.
7. Publish release notes that state whether the binary is signed and that no kernel WFP driver is included.

Never put `internal/tlscert/key.pem`, a PFX password, WireGuard profiles or private keys in artifacts. Authenticode signing does not sign WinDivert or create a Microsoft kernel-driver signature.
