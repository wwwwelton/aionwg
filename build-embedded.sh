#!/usr/bin/env bash
# One standalone Windows x64 EXE; native dependencies are extracted automatically.
set -euo pipefail
cd "$(dirname "$0")"
for tool in go x86_64-w64-mingw32-gcc zip; do
  command -v "$tool" >/dev/null || { echo "Required build tool: $tool" >&2; exit 1; }
done
for file in internal/app/WinDivert.dll internal/app/WinDivert64.sys internal/app/wintun.dll WinDivert-LICENSE.txt third_party/wireguard-go/LICENSE; do
  [[ -s "$file" ]] || { echo "Missing embedding input: $file" >&2; exit 1; }
done
x86_64-w64-mingw32-gcc -shared -O2 -Wall -Wextra -Werror -static-libgcc \
  -Wl,--nxcompat,--dynamicbase,--high-entropy-va \
  -o internal/app/shugo-compat.dll native/shugo-compat.c
# Reuse the self-signed certificate in internal/tlscert (-new rotates it).
go run ./internal/tlscert/gen
mkdir -p dist/standalone
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
tmp="dist/standalone/.AionWG.exe"
go build -trimpath -ldflags='-s -w' -o "$tmp" ./cmd/aionwg
mv -f "$tmp" dist/standalone/AionWG.exe
# Sign with the long-lived certificate when its private key is present (the key
# is never in git or in the EXE). Without it the EXE is built unsigned.
if [[ -s internal/tlscert/key.pem ]] && command -v powershell.exe >/dev/null && command -v wslpath >/dev/null; then
  pfx="dist/.sign.pfx"
  pw="$(openssl rand -hex 16)"
  trap 'rm -f "$pfx"' EXIT
  openssl pkcs12 -export -inkey internal/tlscert/key.pem -in internal/tlscert/cert.pem -out "$pfx" \
    -passout "pass:$pw" -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1
  AIONWG_PFX_PW="$pw" WSLENV=AIONWG_PFX_PW powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File "$(wslpath -w sign-exe.ps1)" -Exe "$(wslpath -w dist/standalone/AionWG.exe)" -Pfx "$(wslpath -w "$pfx")"
  rm -f "$pfx"
else
  echo "WARNING: EXE not signed (needs internal/tlscert/key.pem and Windows PowerShell through WSL)" >&2
fi
# Dependencies are embedded in the EXE (runtime_embedded_windows.go); the zip carries
# only the EXE and the license notices for the bundled code.
cp WinDivert-LICENSE.txt dist/standalone/
cp third_party/wireguard-go/LICENSE dist/standalone/WireGuard-go-LICENSE.txt
bundle=(AionWG.exe WinDivert-LICENSE.txt WireGuard-go-LICENSE.txt)
rm -f dist/AionWG-standalone-windows-x64.zip
(cd dist/standalone && zip -q ../AionWG-standalone-windows-x64.zip "${bundle[@]}")
printf 'Built dist/standalone/AionWG.exe and dist/AionWG-standalone-windows-x64.zip\n'
