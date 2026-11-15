#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $root 'build-aionwg-windows.ps1') @args
exit $LASTEXITCODE
