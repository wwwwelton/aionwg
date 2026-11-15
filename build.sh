#!/usr/bin/env bash
# Compila AionWG.exe (Windows x64) a partir do Linux (cross-compile).
# Uso: ./build.sh
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f go.mod ]; then
  echo "ERRO: go.mod não encontrado em $(pwd)." >&2
  echo "Extraia o código-fonte (AionWG-codigo-fonte.zip) nesta pasta e rode de novo." >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "ERRO: 'go' não encontrado no PATH. Instale o Go e tente de novo." >&2
  exit 1
fi

export GOPROXY=direct
export GOSUMDB=off
export GOFLAGS=-mod=mod
export GOTOOLCHAIN=local
export GOOS=windows
export GOARCH=amd64
export CGO_ENABLED=0

mkdir -p dist

echo "==> Go: $(go version)"
echo "==> Compilando dist/AionWG.exe ..."
go build -trimpath -ldflags "-s -w" -o dist/AionWG.exe ./cmd/aionwg

echo "==> Verificando DLLs ao lado do executável ..."
for f in WinDivert.dll WinDivert64.sys; do
  if [ -f "internal/app/$f" ]; then
    echo "    ok: $f"
  else
    echo "    AVISO: internal/app/$f não encontrado (copie do pacote WinDivert 2.2.2)"
  fi
done
if [ -f internal/app/wintun.dll ]; then
  echo "    ok: wintun.dll"
else
  echo "    AVISO: internal/app/wintun.dll não encontrado (baixe wintun-0.14.1.zip em wintun.net)"
fi

echo "==> Pronto: $(pwd)/dist/AionWG.exe"
ls -lh dist/AionWG.exe
sha256sum dist/AionWG.exe
