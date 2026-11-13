#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    foreach ($file in @('WinDivert.dll','WinDivert64.sys','wintun.dll','WinDivert-LICENSE.txt','third_party/wireguard-go/LICENSE')) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing embedding input: $file" }
    }
    $cc = Get-Command x86_64-w64-mingw32-gcc,gcc -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cc) {
        $target = & $cc.Source -dumpmachine
        if ($LASTEXITCODE -ne 0 -or $target -notmatch '^x86_64-.*mingw32$') { throw 'Compiler must target Windows x64.' }
        & $cc.Source -shared -O2 -Wall -Wextra -Werror -static-libgcc '-Wl,--nxcompat,--dynamicbase,--high-entropy-va' -o shugo-compat.dll native/shugo-compat.c
        if ($LASTEXITCODE -ne 0) { throw 'Compatibility DLL build failed.' }
    } elseif (Test-Path -LiteralPath shugo-compat.dll -PathType Leaf) {
        Write-Warning 'MinGW-w64 not found: embedding the existing shugo-compat.dll (not rebuilt from native/shugo-compat.c).'
    } else {
        throw 'MinGW-w64 gcc or a prebuilt shugo-compat.dll is required.'
    }
    # Reuse the self-signed certificate in internal/tlscert (-new rotates it).
    go run ./internal/tlscert/gen
    if ($LASTEXITCODE -ne 0) { throw 'Certificate generation failed.' }
    $oldOS, $oldArch, $oldCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
    try {
        $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
        New-Item -ItemType Directory -Force dist/standalone | Out-Null
        go build -tags embedded -trimpath -ldflags '-s -w' -o dist/standalone/AionWG.exe .
        if ($LASTEXITCODE -ne 0) { throw 'AionWG embedded build failed.' }
    } finally {
        $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldOS, $oldArch, $oldCGO
    }
    # Dependencies are embedded in the EXE (runtime_embedded_windows.go); the zip carries
    # only the EXE and the license notices for the bundled code.
    Copy-Item -LiteralPath WinDivert-LICENSE.txt dist/standalone/ -Force
    Copy-Item -LiteralPath third_party/wireguard-go/LICENSE dist/standalone/WireGuard-go-LICENSE.txt -Force
    $files = @('dist/standalone/AionWG.exe','dist/standalone/WinDivert-LICENSE.txt','dist/standalone/WireGuard-go-LICENSE.txt')
    Compress-Archive -LiteralPath $files -DestinationPath dist/AionWG-standalone-windows-x64.zip -Force
    Write-Host 'Built dist/standalone/AionWG.exe and dist/AionWG-standalone-windows-x64.zip'
} finally { Pop-Location }
