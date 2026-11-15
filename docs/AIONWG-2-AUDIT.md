# AionWG 2.0 — auditoria e compatibilidade

## Escopo e baseline

Auditoria realizada no repositório existente, sem substituir a implementação atual. Baseline executada antes desta evolução:

- `GOOS=windows go vet .` — aprovado.
- `GOOS=windows go test -count=1 .` — aprovado (`69.965s`).
- `go test -count=1 ./...` — aprovado.
- `./build-aionwg-linux.sh --source /mnt/c/aionwg --no-package` — aprovado; gerou `dist/AionWG.exe`.

O projeto atual é Go para Windows, com Bubble Tea, wireguard-go vendorizado, WinDivert embutido e Wintun usado pelo medidor. Não há código-fonte de driver WFP, projeto WDK, INF ou solução Visual Studio para um callout kernel-mode nativo.

## Caminho de dados atual

1. `main_windows.go` prepara runtime, eleva o processo e inicia `runTUI()`.
2. `runtime_embedded_windows.go` extrai `WinDivert.dll`, `WinDivert64.sys`, `wintun.dll` e compatibilidade Shugo verificadas.
3. `StartEngine` resolve o perfil WireGuard, cria o dispositivo wireguard-go e abre WinDivert NETWORK.
4. `divertLoop` recebe pacotes, `capture` classifica por processo/fluxo, aplica bypass/AllowedIPs/NAT/MSS e envia o tráfego ao split TUN e ao WireGuard.
5. `handleInbound` desfaz NAT, trata ICMP/diagnóstico e reinjeta pacotes no WinDivert.
6. `startWFPMonitor` usa WinDivert SOCKET para observação ALE e, quando necessário, tabelas IP Helper; isso não é captura de pacotes por um callout WFP nativo.
7. Wintun é usado pelo medidor `AionWG-Meter`, não como caminho principal do túnel.
8. WARP alternativo usa sessões UDP adicionais. Multipath passou a ser opt-in; o padrão é uma sessão.

### Conclusão técnica

- **Legacy WinDivert:** caminho de dados real e operacional.
- **Hybrid atual:** classificação/observação SOCKET baseada em WFP ALE + captura/reinjeção NETWORK via WinDivert. É híbrido funcional, mas não substitui o driver de dados.
- **Native WFP:** não implementado. Declarar esse estado como ativo sem driver, filtros, instalação e validação no Windows seria incorreto.

## Inventário de atalhos atuais

| Tecla | Implementação atual | Configuração/efeito preservado |
|---|---|---|
| `Enter` / `c` | conectar ou desconectar | perfil selecionado |
| `↑` / `↓`, `k` / `j` | navegar | seleção da TUI |
| `i` | importar perfil | armazenamento atômico de `.conf` |
| `p` | editar processos | lista persistida |
| `w` | alternar WFP | `WFP`, com fallback disponível |
| `l` | selecionar apps WFP | `WFPApps` |
| `s` | túnel de sistema | `FullTunnel` |
| `n` | DNS do túnel | `NoDNS` |
| `b` | melhor rota | `BestEndpoint` |
| `v` | trocar endpoint | seletor/medição de endpoints |
| `m` | espelho DPS | `Mirror` |
| `u` | duplicação UDP | `UDPDuplicate` |
| `r` | proporção de duplicação | `UDPDuplicateRatio` |
| `f` | forçar UDP | `UDPForce` |
| `o` | priorizar envio recente | `UDPPrioritizeOut` |
| `a` | priorizar chegada recente | `UDPPrioritizeIn` |
| `x` | autoteste | diagnóstico de conectividade |
| `g` | diagnóstico | relatório operacional |
| `e` | exportar WireGuard oficial | exportação sem expor chave na TUI |
| `t` | alvo do ping | `PingTarget` |
| `d` | remover perfil | confirmação antes de apagar |
| `h` | multipath WARP | `WarpMultipath`, opt-in |
| `q` / `Ctrl+C` | sair | encerramento do engine |

A nova navegação deve ser aditiva: F1–F10, `Ctrl+K`, `/`, `?`, `Esc`, `Tab` e `Shift+Tab` não podem consumir nem mudar a semântica dos atalhos acima.

## Configuração e hardcodes

- `store.go` persiste processos, alvo de ping, perfil, Mirror, controles UDP, NoDNS, FullTunnel, WFP, WFPApps, BestEndpoint, multipath e CWB.
- Os nomes padrão atuais (`Aion2.exe`, variantes de `Aion2-Win64-Shipping.exe`, `steam.exe` e `steamwebhelper.exe`) são defaults de migração, não devem ser usados como única classificação.
- A classificação de processos, herança para filhos e fallback de ownership IP Helper ficam em `wfp.go` e `owner_windows.go`.
- Exclusões do próprio transporte, endpoints WireGuard/WARP, multicast e redes locais são proteções internas do caminho de dados e devem permanecer fora da seleção do usuário.
- Faixas Cloudflare e portas WARP em `geo.go`/`paths.go` representam endpoints suportados pelo projeto; não são rotas internas arbitrárias da Cloudflare.

## Riscos observados

1. A captura WinDivert NETWORK permanece o ponto único de encaminhamento; removê-la antes de um backend nativo validado quebra o tráfego.
2. `Stats()` consulta IPC WireGuard durante o tick da TUI; essa coleta deve ser desacoplada para não bloquear renderização.
3. O split TUN usa filas internas finitas; filas cheias descartam pacotes e precisam de métricas explícitas.
4. O monitor de processos/socket e os loops de divert têm encerramento concorrente; toda nova integração deve fechar handles, filas e goroutines sem deixar filtros ativos.
5. O multipath WARP abre até quatro sessões quando habilitado. O padrão seguro continua sendo uma sessão.
6. O fluxo de elevação reconstrói argumentos com `strings.Join`; argumentos com espaços podem perder quoting.

## Plano de implementação seguro

### Fase A — compatibilidade da TUI

Adicionar navegação por módulos, ajuda, paleta e dashboard usando somente métricas e estados existentes. Exibir o backend real como `Legacy WinDivert` ou `Hybrid (WFP SOCKET + WinDivert)`, nunca como Native WFP por aparência visual.

### Fase B — políticas de processo

Evoluir a tela existente de processos para regras explícitas `TUNNEL`, `BYPASS`, `BLOCK` e `DEFAULT`, persistidas e auditáveis. Manter a exclusão interna do transporte do AionWG. Aplicar a regra no classificador comum, não em cada loop de captura.

### Fase C — estado operacional

Separar configuração persistida, intenção solicitada, aplicação efetiva e estado observado para driver, interceptação, interface, handshake, rotas e conectividade. Atualizar métricas em goroutines próprias, com cancelamento e limites de fila.

### Fase D — backend nativo real

Somente após fornecer código de callout WFP, projeto WDK, INF/cat, processo de instalação/rollback, assinatura adequada e testes em Windows 11 x64. O backend deve ter contratos explícitos para classificação, reinjeção, proteção contra loop e encerramento. Até lá, Legacy e Hybrid continuam sendo os únicos backends honestamente suportados.

## Não escopo desta etapa

- Não gerar um driver kernel fictício.
- Não remover WinDivert do caminho de dados atual.
- Não alterar globalmente MTU para 1280.
- Não tornar multipath WARP padrão.
- Não apresentar valores ilustrativos como métricas reais.
- Não expor chaves privadas em tela, logs ou diagnósticos.

## Critério para cada incremento

Cada etapa deve preservar os atalhos acima, manter os testes existentes, ter uma verificação específica e só declarar como disponível o backend que foi executado e medido no Windows.
