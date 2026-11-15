# Code signing

`internal/tlscert/cert.pem` is a tracked public certificate used by the optional build signing flow. `internal/tlscert/key.pem` is ignored and must remain outside Git and release artifacts.

Authenticode signing identifies the EXE signer. It does not make the certificate a trusted public CA, sign a kernel driver, or prove that external WinDivert/Wintun files are authentic. Release workflows should verify native asset provenance and publish checksums separately.

AionWG no longer needs to install its self-signed leaf certificate into the Windows Root or TrustedPublisher stores at application startup. Trust-store changes must be an explicit administrator action outside normal runtime.
