# AionWG — UDP múltiplo e prioridade ao último pacote

Esta edição mantém as correções anteriores de DNS/Mirror e estende a cópia experimental de UDP.

## Comandos na TUI

| Tecla | Função | Padrão |
|---|---|---|
| `U` | Liga/desliga cópias adicionais UDP do jogo pelo túnel WireGuard | Desligado |
| `R` | Escolhe de **1 a 8 cópias extras por original** (`1:1`, `2:1`… `8:1`) | `1:1` |
| `F` | Força **cópias UDP extras** também para destinos do jogo fora de `AllowedIPs` (o original segue pela rota normal do Windows; só as cópias vão pelo túnel, então o servidor pode ver dois IPs públicos) | Desligado |
| `O` | Reorganização do **envio UDP principal**, mais recente primeiro | Desligado |
| `A` | Reorganização da **chegada UDP principal**, mais recente primeiro | Desligado |

**Interpretação de proporção:** `1:1` = 1 datagrama UDP original + 1 cópia pelo túnel; `2:1` = 1 original + 2 cópias; `8:1` = 1 original + 8 cópias. Todas as cópias extras usam a fila secundária, fora da goroutine de captura.

**Forçar UDP não converte TCP em UDP.** Apenas tenta gerar cópias adicionais do UDP dos executáveis classificados como **jogo**, mesmo se o destino não estiver em `AllowedIPs`. Exclui DNS (porta 53), LAN, multicast, endpoint VPN e modo sistema inteiro. Para ter efeito, `U` deve estar ligado. Pode revelar o IP público do cliente ao destino e provocar rejeição de sessão.

## Último pacote sempre primeiro (LIFO)

As filas de saída e entrada são separadas (cada uma com worker e limite de 128 datagramas pendentes). Quando habilitadas, **o último pacote enfileirado é selecionado primeiro**. Em caso de saturação, a fila remove o pacote pendente mais antigo. Um envio já em andamento **não pode ser interrompido**; a prioridade vale para itens aguardando processamento.

A fila das **cópias adicionais** usa a mesma política LIFO, sempre que `U` está ativado (256 cópias pendentes no máximo); a rota principal **continua sem reordenação** enquanto `O` e `A` estiverem desativados.

A ordem de chegada dos datagramas UDP do jogo pode ser importante para o protocolo. As opções `O` e `A` modificam a ordem entregue ao jogo, podem descartar pacotes sob carga, causar instabilidade ou **aumentar** latência. Foram deixadas desligadas por padrão. TCP, DNS, ICMP, WireGuard e os demais processos não passam por essas filas.

## Prioridade de teste

1. Conecte com `O` e `A` desligados.
2. Ative `U` e use `R` para deixar `1:1` (apenas se necessário).
3. Compare ping, jitter, perda e funcionamento do jogo.
4. Só experimente `O` ou `A` separadamente; desative se houver desincronização, perdas ou aumento do ping.
5. `F` só é útil para UDP do jogo fora de `AllowedIPs`; normalmente mantenha desligado.

### Compilar no Windows (PowerShell 7)

Feche o AionWG antes de compilar e execute dentro de `C:\aionwg`:

```powershell
Set-Location C:\aionwg; go test ./...; if ($LASTEXITCODE -ne 0) { throw 'Testes falharam' }; pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir 'C:\aionwg' -AssetsDir 'C:\aionwg'
```

O EXE será gerado em `C:\aionwg\dist\AionWG.exe` se a compilação for bem-sucedida.

**Validação limitada:** testes isolados da fila, das razões de cópia e da persistência passaram com `go test -race` no Linux, mas a compilação integral, os drivers e a latência em Windows/AION 2 **não foram verificados neste ambiente**. O pacote ZIP entrega código-fonte, não binário.
