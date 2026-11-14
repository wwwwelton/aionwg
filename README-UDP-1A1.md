# AionWG — duplicação UDP 1:1 em worker separado

## O que foi implementado

O AionWG continua encaminhando os pacotes originais do **AION 2** via WireGuard.
Quando a opção experimental **[u] UDP 1:1** está ativa, cada datagrama **UDP de saída do jogo** aceito no túnel pode gerar **uma cópia idêntica** pelo túnel WireGuard (mesmo IP público do original).

- O envio principal é **prioritário**: o pacote do jogo é submetido primeiro à fila WireGuard.
- A cópia é encaminhada por **uma goroutine vinculada a um thread do Windows de prioridade reduzida**.
- A fila é limitada a 256 itens; quando cheia, **descarta a cópia**, não o pacote principal.
- Só duplica UDP da classe jogo; **não duplica TCP, Steam, DNS (porta 53), nem tráfego no modo sistema inteiro**.
- Ativa/desativa em tempo real com `[u]` e salva a escolha em `%APPDATA%\AionWG\settings.json` (`"udp_duplicate": true/false`). **Padrão: OFF.**
- Painel indica cópias enviadas, descartadas e erros.

## Roteamento real e limitações

```text
AION2.exe -> WinDivert -> pacote original -> WireGuard -> VPS -> servidor
                         
                         +-> cópia -> fila não bloqueante -> thread separado
                                   -> WinDivertSend(outbound) -> rota do Windows -> servidor
```

O segundo caminho passa pelo **roteamento normal do Windows**. Não significa uma segunda interface física garantida: no layer NETWORK, o `IfIdx` de pacotes de saída é ignorado pelo WinDivert. Se outra VPN estiver alterando a rota padrão, a saída direta poderá não ser independente. Para redundância multipath real com dois ISPs/VPSs e escolha do pacote mais rápido, seria necessário um protocolo com **deduplicação e sessão no destino**, não apenas a reinjeção local.

**Não há garantia de ping menor, igual ou melhora do jogo.** A cópia pode usar banda/CPU, chegar depois, ser descartada pelo servidor ou causar duplicação de comandos/respostas. Há riscos de incompatibilidade com anticheat/regras do jogo. Teste primeiro fora de partidas competitivas e desative `[u]` se notar desconexões, instabilidade ou aumento de jitter. **Não use a duplicação como configuração padrão.**

## Instalação via PowerShell 7 (ZIP completo)

Feche o AionWG e faça backup de `C:\aionwg`. Extraia em `C:\`, preservando a pasta `aionwg`:

```powershell
Expand-Archive -LiteralPath "$HOME\Downloads\AionWG-UDP-1a1-codigo-completo.zip" -DestinationPath 'C:\' -Force; Set-Location 'C:\aionwg'; go test ./...; if ($LASTEXITCODE -ne 0) { throw 'Testes falharam' }; pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir 'C:\aionwg' -AssetsDir 'C:\aionwg'
```

Para aplicar o **patch menor** aos fontes já existentes em `C:\aionwg`:

```powershell
Expand-Archive -LiteralPath "$HOME\Downloads\AionWG-UDP-1a1-patch.zip" -DestinationPath 'C:\aionwg' -Force; Set-Location 'C:\aionwg'; go test ./...; if ($LASTEXITCODE -ne 0) { throw 'Testes falharam' }; pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir 'C:\aionwg' -AssetsDir 'C:\aionwg'
```

Arquivos executáveis gerados em `C:\aionwg\dist`.

## Testes executados nesta entrega

- 30 passagens do `udpdup_test.go` com detector de corrida (`-race`), em módulo isolado com `packet.go`: **OK**.
- `go vet` desses arquivos isolados: **OK**.
- `gofmt`: **OK**.
- A suíte completa e a compilação do aplicativo Windows **não puderam ser executadas aqui**, pois este ambiente contém Go 1.23.2, enquanto o projeto exige Go 1.24.7 e o download do toolchain está indisponível.
- WinDivert/driver e comportamento real do servidor **não foram testados no Windows**.
