# Scripts para compilar AionWG.exe

## Pré-requisito importante

O ZIP `AionWG-windows-x64 (0990)xxxx.zip` contém um executável compilado, bibliotecas e arquivos `.conf`, **mas não inclui o código-fonte Go**. Não é possível reconstruir ou alterar o programa a partir desse pacote. Obtenha a pasta original do projeto (ex.: `/home/claude/aionwg`) com `go.mod`, arquivos `.go` e `third_party/wireguard-go` antes de executar.

## Linux -> Windows x64 (reproduzir cross-compilation)

```bash
chmod +x build-aionwg-linux.sh
./build-aionwg-linux.sh --source /home/claude/aionwg \
  --assets-zip '/caminho/AionWG-windows-x64 (0990)xxxx.zip'
```

Se seu ambiente exigir **exatamente** as variáveis antigas de proxy (desabilita a verificação do Go SumDB):

```bash
./build-aionwg-linux.sh --source /home/claude/aionwg --unverified-modules \
  --assets-zip '/caminho/AionWG-windows-x64 (0990)xxxx.zip'
```

Preferir a configuração Go padrão, com verificação de módulos, quando possível.

## Windows PowerShell 7

Sem o ZIP de dependências:

Comando supremo:
```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir "C:\aionwg" -AssetsDir "C:\aionwg"
```

Somente o executável, sem DLLs ou ZIP:
```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir "C:\aionwg" -NoPackage
```

Compilar e empacotar com as DLLs existentes:
```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir "C:\aionwg" -AssetsDir "C:\aionwg"
```

Instalar Go, se estiver ausente, e compilar:
```bash
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -InstallGo -SourceDir "C:\aionwg" -NoPackage
```

```bash
./build-aionwg-linux.sh --source /home/claude/aionwg --no-package
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir 'C:\src\aionwg' -AssetsZip 'C:\Downloads\AionWG-windows-x64 (0990)xxxx.zip'
```

Se a pasta atual já for a pasta do projeto:

```powershell
.\build-aionwg-windows.ps1 -AssetsDir 'C:\Downloads\AionWG-windows-x64 (0990)'
```

O Windows precisa ter `go` instalado no PATH. As dependências Go devem estar disponíveis em rede ou cache.

## Resultados

- `<fonte>/dist/AionWG.exe`
- `<fonte>/dist/AionWG-windows-x64.zip` (se não usar `--no-package` / `-NoPackage`)

O ZIP final contém apenas `AionWG.exe`, as DLLs/driver/licença disponíveis e uma nota de execução. Por segurança, **não** copia configs `.conf`, IPs privados, chaves WireGuard ou logs. Você deve configurar o aplicativo separadamente.

**Importante:** construir não significa que a aplicação foi testada. Verifique drivers WinDivert/Wintun, elevação e captura em um Windows real. O anti-cheat do jogo pode bloquear ferramentas de interceptação de pacotes.

## Relay para Shugo (ligado ao `[m]`)

O espelho `[m]` agora também age como relay para o Shugo.gg: enquanto ligado, o
AionWG carrega `shugo-compat.dll` somente no Shugo (que então enxerga a conexão
do jogo como o par loopback do espelho) e restaura a API original ao desligar
`[m]` ou sair. Não há EXE separado, driver novo ou alteração no AION2.

`./build-embedded.sh` compila a DLL (`shugo-compat.dll`, MinGW-w64) e o EXE.
No build tradicional, mantenha `shugo-compat.dll` ao lado do `AionWG.exe`.
Se a DLL faltar, o log do AionWG avisa e o resto funciona normalmente.

Regressão do pareamento, sem Windows ou acesso à rede:

```sh
cc -std=c11 -Wall -Wextra -Werror native/shugo-compat-test.c -o /tmp/shugo-check
/tmp/shugo-check
```

## EXEs com dependências embutidas

Linux: `./build-embedded.sh`. Windows: `.\build-embedded.ps1`.
Requer Go, MinGW-w64 e os inputs `WinDivert.dll`, `WinDivert64.sys` e
`wintun.dll` na raiz do código-fonte. O ZIP Linux também exige `zip`.

Saídas: `dist/standalone/AionWG.exe` e
`dist/AionWG-standalone-windows-x64.zip`.
Os EXEs não precisam de DLLs ou SYS ao lado. Ao iniciar como Administrador,
extraem seus próprios arquivos para uma pasta versionada pelo conteúdo em
`C:\Program Files\AionWG-Runtime`. Conteúdo já extraído é conferido antes do uso;
arquivos modificados causam erro, sem substituição silenciosa.
O Npcap continua sendo instalado separadamente. Nenhum `.conf` é embutido.

Na validação Windows deste build, o AionWG carregou as DLLs embutidas e abriu
WinDivert com filtro sem tráfego. A integração do relay Shugo embutida ainda não foi
validada no Windows (o helper separado foi bloqueado pelo Defender).

## Ajustes de latência no cliente Windows

- `PersistentKeepalive` omitido usa 15 segundos por peer. Valores explícitos,
  inclusive `0` e `off`, continuam sendo respeitados; o `.conf` não é regravado.
- O logger WireGuard já descarta mensagens verbosas e conserva os erros.
- Os sockets UDP externos (RIO e fallback padrão) usam buffers de envio e
  recepção de 4 MiB e `SIO_UDP_CONNRESET` desativado.
- DSCP EF 46 é solicitado por destino via qWAVE (`QOSSetOutgoingDSCPValue`),
  sem shaping nem sondagem adaptativa. Não usa `IP_TOS`, sem suporte adequado
  no Windows. Exige elevação e qWAVE disponível; falhas são retornadas ao
  WireGuard, não ocultadas como sucesso. Loopback não recebe marcação.
  O roteador/ISP pode ignorar ou reescrever DSCP; isso não garante prioridade.
- O processo elevado usa `HIGH_PRIORITY_CLASS` e GC 400. O limite **suave** de
  memória Go é o menor entre 512 MiB e 25% da RAM disponível ao iniciar.
  `GOMEMLIMIT` explícito é preservado. DLLs, buffers RIO e drivers ficam fora
  desse limite, e o runtime pode ultrapassá-lo. Prioridade alta pode prejudicar
  outros processos; GC 400 não garante menor jitter.
- MTU, DNS e `GOMAXPROCS` permanecem inalterados. Não foram adicionados ajustes
  Linux nem alterações no TCP dos aplicativos encaminhados.

Referência da API:
https://learn.microsoft.com/en-us/windows/win32/api/qos2/nf-qos2-qossetflow

Os testes Windows de tuning consultam a prioridade, o GC, os buffers e a
marcação DSCP no sistema. Para o teste DSCP IPv6, defina
`AIONWG_TEST_IPV6_ENDPOINT` como um destino IPv6 alcançável (`[endereço%zona]:porta`);
endereços da própria máquina não são aceitos pelo qWAVE neste ambiente.
Esses testes não comprovam ausência de fragmentação ou melhoria de jitter:
isso exige medir o túnel real sob carga no link do usuário.
