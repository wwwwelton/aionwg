# AionWG — correção do travamento DNS → Mirror (M)

## Problema identificado no código original

Na TUI (`tui_windows.go`), a tecla `m` chamava `Engine.SetMirror()` diretamente
na função `Update`. Em `tunnel_windows.go`, `SetMirror(true)` chamava `openMeter()`:

- `openMeter()` fazia chamadas síncronas a `WintunOpenAdapter`/`WintunCreateAdapter`
  e `WintunStartSession`, que podem demorar ou bloquear o loop da interface.
- `openMeter()` também chamava `e.logf()` no mesmo fluxo de execução.
- O callback do log chamava `program.Send(...)`, que pode aguardar a TUI processar
  a mensagem. Como a TUI ainda estava dentro de `Update`, isso podia provocar
  **deadlock**. A tecla `n` (DNS) apenas alterna um `atomic.Bool`; a sequência
  DNS → M expunha o problema ao ativar o espelho.

## Alterações implementadas

1. Inicialização do Wintun em goroutine (`requestMeter`/`openMeterAsync`), sem
   executar chamadas do driver no `Update` da TUI.
2. Uma inicialização por vez (`meterOpening` protegido por `meterMu`).
3. Operações de driver e callbacks de log executadas sem manter `meterMu`.
4. Descarte seguro do adaptador que terminar de abrir depois de desligar o
   espelho ou encerrar o motor.
5. Logs passam por fila limitada (256 eventos) e goroutine despachante;
   callbacks não bloqueiam o loop da TUI. Logs excedentes são descartados.
6. Três testes de regressão (Windows): DNS → M com abertura lenta, callback de
   log bloqueante e fila de logs cheia.

## Instalar no Windows 11 / PowerShell 7

1. Faça backup da pasta original `C:\aionwg` e pare o AionWG antigo.
2. Extraia este ZIP diretamente em `C:\`, para atualizar os fontes corrigidos em `C:\aionwg`.
3. Abra o PowerShell 7 nessa pasta:

```powershell
cd 'C:\aionwg'
go version
go test ./...
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir (Get-Location).Path -NoPackage
```

`go.mod` exige Go >= 1.24.2 (toolchain go1.24.7). A versão atual do Go
instalada no Windows deve atender esse requisito.

O EXE será criado em `C:\aionwg\dist\AionWG.exe`.

### Empacotar com WinDivert/Wintun

Se os arquivos `WinDivert.dll`, `WinDivert64.sys` e `wintun.dll` estiverem
em `C:\aionwg`:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir (Get-Location).Path -AssetsDir 'C:\aionwg'
```

Se só tiver o ZIP de runtime antigo, localize seu nome real:

```powershell
Get-ChildItem "$HOME\Downloads" -Filter '*AionWG*.zip' | Select-Object Name,FullName
```

E use `-AssetsZip 'C:\caminho\nome-real.zip'` em vez de `-AssetsDir`.
O ZIP final de execução ficará em `dist\AionWG-windows-x64.zip`.

## Teste manual de regressão no Windows

1. Abra o AionWG como Administrador e conecte o túnel.
2. Pressione `n` (DNS) e, logo depois, `m` (Mirror).
3. A TUI deve continuar respondendo, mesmo enquanto o adaptador Wintun inicia.
4. Acompanhe `Espelho DPS`: enquanto inicializa, mostra
   `inicializando AionWG-Meter…`; depois, adaptador pronto ou erro legível.
5. Repita `m` rapidamente, teste `n` novamente e desconecte.
6. Confira o funcionamento do NotMeter/AbyssDPSMeter e as rotas do jogo.

## Correção adicional — `TestSteamMigration` no Windows

O teste original definia somente `HOME` e `XDG_CONFIG_HOME`, mas o Go usa
`%APPDATA%` para `os.UserConfigDir()` no Windows. Isso fazia o teste acessar
`%APPDATA%\AionWG\settings.json` real. O teste agora define também
`APPDATA` para uma pasta temporária e **confere o caminho antes de ler/gravar**,
impedindo acesso acidental às configurações reais. Não modifica o código de
produção nem as configurações WireGuard.

## Validação realizada nesta entrega

- `gofmt` dos arquivos alterados: OK.
- Testes do espelho TCP independente de plataforma com `go test -race`: OK.
- Três testes de regressão de lógica assíncrona executados com stubs e
  `go test -race` em Linux: OK (50 repetições).
- **Não foi possível executar o build completo de Windows neste ambiente**:
  Go disponível aqui é 1.23.2, mas o projeto exige >=1.24.2, e não há acesso
  para baixar o toolchain e as dependências. A integração real com o driver
  Wintun e WinDivert ainda precisa ser validada no Windows.

O ZIP contém o código-fonte e o script de build; **não contém um novo EXE**,
nem configurações WireGuard `.conf`. Nenhuma chave de túnel existente é alterada.
