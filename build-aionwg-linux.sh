#!/usr/bin/env bash
# Linux -> Windows x64 (Go puro, CGO=0), com ZIP opcional e sem configs privadas.
set -Eeuo pipefail

usage() {
  cat <<'HELP'
Uso:
  ./build-aionwg-linux.sh [--source DIR] [--assets-dir DIR | --assets-zip ZIP]
                          [--unverified-modules] [--no-package]

Exemplos (fonte no seu Linux/CachyOS):
  cd /home/avatar/aionwg && ./build-aionwg-linux.sh --source /home/avatar/aionwg --no-package
  ./build-aionwg-linux.sh --source /home/avatar/aionwg --assets-dir /home/avatar/aionwg
  ./build-aionwg-linux.sh --source /home/avatar/aionwg --assets-zip '/caminho/AionWG-windows-x64.zip'

Opções:
  --source DIR          Pasta com go.mod (padrão: diretório atual, ou /home/avatar/aionwg)
  --assets-dir DIR      DLLs/driver (diretório pode conter subpastas)
  --assets-zip ZIP      ZIP com DLLs/driver, mesmo em subpastas
  --no-package          Gerar somente dist/AionWG.exe (sem requerer DLLs/ZIP)
  --unverified-modules  GOPROXY=direct GOSUMDB=off (desativa verificação de módulos)
  -h, --help            Ajuda

Saídas:
  <source>/dist/AionWG.exe
  <source>/dist/AionWG-windows-x64.zip (exceto --no-package)

IMPORTANTE: exige código-fonte. Não recompila EXE pronto, não inclui *.conf/chaves.
HELP
}
fail() { printf 'ERRO: %s\n' "$*" >&2; exit 1; }
info() { printf '[AionWG] %s\n' "$*"; }

SOURCE_DIR="$PWD"
if [[ ! -f "$PWD/go.mod" && -f '/home/avatar/aionwg/go.mod' ]]; then
  SOURCE_DIR='/home/avatar/aionwg'
fi
ASSETS_DIR=''
ASSETS_ZIP=''
UNVERIFIED=0
PACKAGE=1
while (($#)); do
  case "$1" in
    --source|--assets-dir|--assets-zip)
      (($# >= 2)) || fail "falta valor para $1"
      case "$1" in
        --source) SOURCE_DIR="$2" ;;
        --assets-dir) ASSETS_DIR="$2" ;;
        --assets-zip) ASSETS_ZIP="$2" ;;
      esac
      shift 2 ;;
    --unverified-modules) UNVERIFIED=1; shift ;;
    --no-package) PACKAGE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "argumento desconhecido: $1 (use --help)" ;;
  esac
done

[[ -z "$ASSETS_DIR" || -z "$ASSETS_ZIP" ]] || fail 'use --assets-dir OU --assets-zip'
command -v go >/dev/null || fail 'Go não está instalado no Linux (veja https://go.dev/dl/)'
[[ -d "$SOURCE_DIR" ]] || fail "pasta inexistente: $SOURCE_DIR"
SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd -P)"
[[ -f "$SOURCE_DIR/go.mod" ]] || fail "go.mod não encontrado em $SOURCE_DIR; obtenha o código-fonte, não apenas o EXE"
if ((PACKAGE)); then
  [[ -z "$ASSETS_DIR" || -d "$ASSETS_DIR" ]] || fail "--assets-dir inexistente: $ASSETS_DIR"
  [[ -z "$ASSETS_ZIP" || -f "$ASSETS_ZIP" ]] || fail "ZIP de assets inexistente: $ASSETS_ZIP. Use --no-package ou --assets-dir."
  if [[ -n "$ASSETS_ZIP" ]]; then command -v unzip >/dev/null || fail 'instale unzip'; fi
  command -v zip >/dev/null || fail 'instale zip ou use --no-package'
else
  if [[ -n "$ASSETS_DIR" || -n "$ASSETS_ZIP" ]]; then info 'AVISO: --no-package ignora as opções de assets'; fi
fi

cd "$SOURCE_DIR"
info "Fonte: $SOURCE_DIR"
info "Go: $(go version)"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=mod
if ((UNVERIFIED)); then
  export GOPROXY=direct GOSUMDB=off
  info 'AVISO: GOSUMDB=off; checksums de dependências não serão verificados.'
fi
PKG_NAME="$(go list -f '{{.Name}}' .)" || fail 'go list falhou'
[[ "$PKG_NAME" == 'main' ]] || fail "pacote raiz '$PKG_NAME' não é main"
mkdir -p dist
TMP_EXE="$(mktemp "$SOURCE_DIR/dist/.AionWG.XXXXXXXX.exe")"
STAGE_DIR=''
cleanup() {
  [[ -z "$TMP_EXE" ]] || rm -f "$TMP_EXE"
  [[ -z "$STAGE_DIR" ]] || rm -rf "$STAGE_DIR"
}
trap cleanup EXIT
info 'Compilando: GOOS=windows GOARCH=amd64 CGO_ENABLED=0...'
go build -trimpath -ldflags='-s -w' -o "$TMP_EXE" .
[[ -s "$TMP_EXE" ]] || fail 'o go build não gerou executável válido'
mv -f "$TMP_EXE" dist/AionWG.exe
TMP_EXE=''
info "EXE: $SOURCE_DIR/dist/AionWG.exe"
if ((!PACKAGE)); then
  info 'Concluído: somente EXE (--no-package).'
  exit 0
fi

STAGE_DIR="$(mktemp -d)"
mkdir -p "$STAGE_DIR/AionWG-windows-x64"
cp dist/AionWG.exe "$STAGE_DIR/AionWG-windows-x64/"
for f in WinDivert.dll WinDivert64.sys wintun.dll WinDivert-LICENSE.txt shugo-compat.dll; do
  out="$STAGE_DIR/AionWG-windows-x64/$f"
  # Prioridade: ZIP explícito -> assets-dir -> fonte/dist/pasta do script
  if [[ -n "$ASSETS_ZIP" ]]; then
    entry="$(unzip -Z -1 "$ASSETS_ZIP" | awk -F/ -v name="$f" '$NF == name { print; exit }')"
    if [[ -n "$entry" ]]; then
      unzip -p "$ASSETS_ZIP" "$entry" > "$out"
      continue
    fi
  fi
  if [[ -n "$ASSETS_DIR" ]]; then
    candidate="$(find "$ASSETS_DIR" -maxdepth 5 -type f -name "$f" -print -quit)"
    if [[ -n "$candidate" ]]; then cp "$candidate" "$out"; continue; fi
  fi
  for folder in "$SOURCE_DIR" "$SOURCE_DIR/dist" "$(dirname "$(readlink -f "$0")")"; do
    if [[ -f "$folder/$f" ]]; then cp "$folder/$f" "$out"; break; fi
  done
done
cat > "$STAGE_DIR/AionWG-windows-x64/LEIA-ME-BUILD.txt" <<'README'
AionWG - compilação Linux -> Windows x64

AionWG.exe requer execução no Windows x64.
Mantenha WinDivert.dll e WinDivert64.sys na mesma pasta do EXE.
wintun.dll pode ser necessária ao adaptador Wintun, conforme a funcionalidade.
Execute elevado para utilizar WinDivert.
Com [m] ligado, shugo-compat.dll (ao lado do EXE) faz o Shugo enxergar o relay.
Nenhum arquivo .conf/chave privada é incluído no ZIP.
A build não valida automaticamente captura, roteamento, driver ou anti-cheat.
README
for f in WinDivert.dll WinDivert64.sys; do
  [[ -f "$STAGE_DIR/AionWG-windows-x64/$f" ]] || info "AVISO: $f ausente; pacote pode não executar. Use --assets-dir/--assets-zip."
done
rm -f dist/AionWG-windows-x64.zip
(cd "$STAGE_DIR" && zip -q -r "$SOURCE_DIR/dist/AionWG-windows-x64.zip" AionWG-windows-x64)
info "ZIP: $SOURCE_DIR/dist/AionWG-windows-x64.zip"
info 'Concluído. Teste no Windows real.'
