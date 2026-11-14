#requires -Version 5.1
# Signs an EXE with the AionWG code-signing certificate (Authenticode, SHA-256).
# The PFX password comes from the AIONWG_PFX_PW environment variable. The
# certificate never expires, so no timestamp server is used.
param(
    [Parameter(Mandatory)][string]$Exe,
    [Parameter(Mandatory)][string]$Pfx
)
$ErrorActionPreference = 'Stop'
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Pfx, $env:AIONWG_PFX_PW)
$r = Set-AuthenticodeSignature -FilePath $Exe -Certificate $cert -HashAlgorithm SHA256
# Status is NotTrusted until the certificate is installed as a root; what matters
# here is that the signature exists and was made by this certificate.
if (-not $r.SignerCertificate -or $r.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
    throw "Signing failed: $($r.StatusMessage)"
}
$v = Get-AuthenticodeSignature -FilePath $Exe
Write-Host ("Signed {0}: {1} thumbprint={2} status={3}" -f (Split-Path $Exe -Leaf), $v.SignerCertificate.Subject, $v.SignerCertificate.Thumbprint, $v.Status)
