# AionWG — scripts de compilação atualizados

Estes scripts compilam o **código-fonte Go** e geram `dist/AionWG.exe` para Windows x64. Não é possível recompilar o projeto usando apenas um executável pronto; é necessário `go.mod` e o pacote Go `main`.

## Windows 11 (PowerShell 7)

Abra o PowerShell em `C:\aionwg` com o script `build-aionwg-windows.ps1`.

### Somente o executável (sem ZIP de assets)

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir "C:\aionwg" -NoPackage
```

### Compilar e usar DLLs disponíveis em C:\aionwg

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir "C:\aionwg" -AssetsDir "C:\aionwg"
```

### Compilar e reaproveitar as DLLs do ZIP existente

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir "C:\aionwg" -AssetsZip "C:\CAMINHO\ZIP-REAL.zip"
```

**Nunca use nomes de ZIP fictícios**. Localize o arquivo correto:

```powershell
Get-ChildItem "$HOME\Downloads" -Filter '*AionWG*.zip' | Select-Object Name,FullName
```

### Atualizar o código pelo CachyOS/WSL

O script procura `/home/avatar/aionwg` na distribuição `CachyOS` e, sem `-SourceDir`, copia os fontes para `~/source/aionwg` no Windows.

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -RefreshFromWSL -NoPackage
```

Para copiar a fonte diretamente para `C:\aionwg`:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -RefreshFromWSL -SourceDir "C:\aionwg" -AssetsDir "C:\aionwg"
```

### Instalar Go pelo próprio script, se estiver ausente

Rode o PowerShell como **Administrador** e use `-InstallGo`. O script consulta a versão estável publicada em `go.dev`, verifica o SHA256 oficial e instala o MSI via `msiexec`:

```powershell
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -InstallGo -SourceDir "C:\aionwg" -NoPackage
```

Instalar Go altera o sistema; sem `-InstallGo`, o script não instala nada. Se Go já estiver instalado, ele é utilizado diretamente (inclusive em `C:\Program Files\Go\bin\go.exe`, mesmo antes de atualizar o PATH).

## Linux (em /home/avatar/aionwg)

```bash
cd /home/avatar/aionwg
chmod +x build-aionwg-linux.sh
./build-aionwg-linux.sh --source /home/avatar/aionwg --no-package
```

Com empacotamento de DLLs:

```bash
./build-aionwg-linux.sh --source /home/avatar/aionwg --assets-dir /home/avatar/aionwg
```

Ou usando um ZIP já existente:

```bash
./build-aionwg-linux.sh --source /home/avatar/aionwg --assets-zip '/caminho/ZIP-REAL.zip'
```

## Saídas

- **Somente EXE:** `<SourceDir>/dist/AionWG.exe`.
- **Com empacotamento:** `<SourceDir>/dist/AionWG-windows-x64.zip`, contendo AionWG.exe e DLLs/driver encontrados.

Os scripts nunca adicionam configurações WireGuard nem chaves privadas ao pacote. Sem DLLs ou driver necessários, o pacote pode não executar corretamente; alertas indicam os arquivos ausentes.

**Notas de segurança:** `-UnverifiedModules`/`--unverified-modules` são opcionais e desativam a verificação de checksums Go; não use por padrão. Execute o AionWG elevado no Windows para recursos WinDivert. O build não comprova a operação do driver nem a eficácia das rotas.
