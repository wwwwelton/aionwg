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
