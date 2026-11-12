#!/usr/bin/env bash
# One standalone Windows x64 EXE; native dependencies are extracted automatically.
set -euo pipefail
cd "$(dirname "$0")"
for tool in go x86_64-w64-mingw32-gcc zip; do
  command -v "$tool" >/dev/null || { echo "Required build tool: $tool" >&2; exit 1; }
done
for file in WinDivert.dll WinDivert64.sys wintun.dll; do
  [[ -s "$file" ]] || { echo "Missing embedding input: $file" >&2; exit 1; }
done
x86_64-w64-mingw32-gcc -shared -O2 -Wall -Wextra -Werror -static-libgcc \
  -Wl,--nxcompat,--dynamicbase,--high-entropy-va \
  -o shugo-compat.dll native/shugo-compat.c
# Reuse the self-signed certificate in internal/tlscert (-new rotates it).
go run ./internal/tlscert/gen
mkdir -p dist/standalone
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
tmp="dist/standalone/.AionWG.exe"
go build -tags embedded -trimpath -ldflags='-s -w' -o "$tmp" .
mv -f "$tmp" dist/standalone/AionWG.exe
[[ ! -f WinDivert-LICENSE.txt ]] || cp WinDivert-LICENSE.txt dist/standalone/
rm -f dist/AionWG-standalone-windows-x64.zip
(cd dist/standalone && zip -q ../AionWG-standalone-windows-x64.zip AionWG.exe)
if [[ -f dist/standalone/WinDivert-LICENSE.txt ]]; then
  (cd dist/standalone && zip -q ../AionWG-standalone-windows-x64.zip WinDivert-LICENSE.txt)
fi
printf 'Built dist/standalone/AionWG.exe and dist/AionWG-standalone-windows-x64.zip\n'
