#requires -Version 5.1
<#
.SYNOPSIS
    Instala Go opcionalmente e compila o AionWG.exe no Windows x64.
.DESCRIPTION
    Compila o codigo-fonte Go, sem usar um EXE antigo. Pode copiar a fonte de
    /home/avatar/aionwg (CachyOS/WSL) e empacotar WinDivert/Wintun.
    Por padrao: compila a pasta atual e cria dist/AionWG.exe.
.EXAMPLE
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir 'C:\aionwg' -NoPackage
.EXAMPLE
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -SourceDir 'C:\aionwg' -AssetsDir 'C:\aionwg'
.EXAMPLE
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -RefreshFromWSL -NoPackage
.EXAMPLE
    pwsh.exe -NoProfile -ExecutionPolicy Bypass -File .\build-aionwg-windows.ps1 -InstallGo -SourceDir 'C:\aionwg' -AssetsZip "$HOME\Downloads\AionWG-windows-x64.zip"
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$AssetsDir,
    [string]$AssetsZip,
    [switch]$NoPackage,
    [switch]$RefreshFromWSL,
    [string]$WSLDistro = 'CachyOS',
    [string]$WSLSource = '/home/avatar/aionwg',
    [switch]$InstallGo,
    [switch]$UnverifiedModules
)
$ErrorActionPreference = 'Stop'
# Robocopy retorna 1..7 em operacoes bem-sucedidas; PowerShell 7 nao deve lancar erro nativo nesses casos.
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest

function Info([string]$Message) { Write-Host "[AionWG] $Message" }
function Find-Go {
    $command = Get-Command 'go.exe' -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $goProgramFiles = Join-Path $env:ProgramFiles 'Go\bin\go.exe'
    if (Test-Path -LiteralPath $goProgramFiles -PathType Leaf) { return $goProgramFiles }
    return $null
}
function Install-GoOfficial {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Para instalar Go, abra o PowerShell como Administrador. Ou instale Go manualmente em https://go.dev/dl/.'
    }
    Info 'Consultando o catalogo oficial https://go.dev/dl/?mode=json ...'
    $releases = @(Invoke-RestMethod -Uri 'https://go.dev/dl/?mode=json' -ErrorAction Stop)
    $release = $releases | Where-Object { $_.stable -eq $true } | Select-Object -First 1
    if (-not $release) { throw 'Nenhuma versao estavel de Go encontrada no catalogo oficial.' }
    $msi = $release.files | Where-Object { $_.filename -match '^go[0-9]+\.[0-9]+(\.[0-9]+)?\.windows-amd64\.msi$' } | Select-Object -First 1
    if (-not $msi -or -not $msi.sha256) { throw 'MSI windows-amd64 com SHA256 nao encontrado no catalogo.' }
    $tempMsi = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '.msi')
    try {
        Info "Baixando $($msi.filename) diretamente do go.dev..."
        Invoke-WebRequest -Uri ('https://go.dev/dl/' + $msi.filename) -OutFile $tempMsi -ErrorAction Stop
        $actual = (Get-FileHash -LiteralPath $tempMsi -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne ([string]$msi.sha256).ToLowerInvariant()) { throw 'SHA256 do instalador Go nao confere. Instalacao cancelada.' }
        Info 'SHA256 validado; instalando Go via MSI...'
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('"' + $tempMsi + '"'), '/passive', '/norestart') -PassThru -Wait
        if ($process.ExitCode -notin @(0, 3010)) { throw "Instalacao MSI falhou: codigo $($process.ExitCode)." }
        Info 'Go instalado. Reinicie seu terminal posteriormente para atualizar o PATH, se necessario.'
    } finally {
        Remove-Item -LiteralPath $tempMsi -Force -ErrorAction SilentlyContinue
    }
}
function Copy-SourceFromWSL([string]$Destination) {
    if (-not (Get-Command 'wsl.exe' -ErrorAction SilentlyContinue)) { throw 'wsl.exe nao encontrado. Instale/ative WSL ou use -SourceDir com fonte local.' }
    if (-not (Get-Command 'robocopy.exe' -ErrorAction SilentlyContinue)) { throw 'robocopy.exe nao encontrado no Windows.' }
    $relative = $WSLSource.TrimStart('/') -replace '/', '\'
    $unc = "\\wsl.localhost\$WSLDistro\$relative"
    Info "Fonte WSL: $unc"
    & wsl.exe -d $WSLDistro --exec /usr/bin/true
    if ($LASTEXITCODE -ne 0) { throw "Nao foi possivel iniciar a distribuicao WSL $WSLDistro." }
    if (-not (Test-Path -LiteralPath (Join-Path $unc 'go.mod') -PathType Leaf)) {
        throw "go.mod nao encontrado no WSL: $unc. Confirme -WSLDistro e -WSLSource."
    }
    New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    Info "Copiando fonte para $Destination (sem .git, dist nem arquivos de configuracao)..."
    # Robocopy: 0..7 sao sucesso/avisos; 8+ indicam falha. Nao usamos /MIR, evitando exclusoes na pasta de destino.
    & robocopy.exe $unc $Destination /E /R:2 /W:1 /NFL /NDL /NP /NJH /NJS /XD .git dist node_modules .venv /XF '*.conf' '*.key' '*.pem' '.env'
    $exit = $LASTEXITCODE
    if ($exit -ge 8) { throw "Falha ao copiar arquivos WSL usando Robocopy (codigo $exit)." }
    Info "Fonte copiada (Robocopy: $exit)."
}
function Resolve-AssetPath([string]$Name, [string[]]$Folders) {
    foreach ($folder in $Folders) {
        if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
        $file = Join-Path $folder $Name
        if (Test-Path -LiteralPath $file -PathType Leaf) { return $file }
    }
    return $null
}

if ($AssetsDir -and $AssetsZip) { throw 'Escolha -AssetsDir OU -AssetsZip, nunca ambos.' }
if (-not $SourceDir) {
    if ($RefreshFromWSL) { $SourceDir = Join-Path $HOME 'source\aionwg' }
    else { $SourceDir = (Get-Location).Path }
}
$SourceDir = [IO.Path]::GetFullPath($SourceDir)
if ($RefreshFromWSL) { Copy-SourceFromWSL -Destination $SourceDir }
if (-not (Test-Path -LiteralPath (Join-Path $SourceDir 'go.mod') -PathType Leaf)) {
    throw "go.mod nao encontrado em '$SourceDir'. Use -SourceDir 'C:\aionwg' ou -RefreshFromWSL para copiar o codigo-fonte."
}
if ($NoPackage -and ($AssetsDir -or $AssetsZip)) {
    Write-Warning '-NoPackage: -AssetsDir e -AssetsZip serao ignorados (somente EXE).'
    $AssetsDir = $null; $AssetsZip = $null
}
if (-not $NoPackage) {
    if ($AssetsDir -and -not (Test-Path -LiteralPath $AssetsDir -PathType Container)) { throw "Pasta de assets inexistente: $AssetsDir" }
    if ($AssetsZip -and -not (Test-Path -LiteralPath $AssetsZip -PathType Leaf)) {
        throw "ZIP de assets inexistente: $AssetsZip`nUse -NoPackage para gerar so o EXE ou -AssetsDir 'C:\aionwg' se as DLLs estiverem nessa pasta."
    }
    if ($AssetsDir) { $AssetsDir = (Resolve-Path -LiteralPath $AssetsDir).Path }
    if ($AssetsZip) { $AssetsZip = (Resolve-Path -LiteralPath $AssetsZip).Path }
}
$goExe = Find-Go
if (-not $goExe -and $InstallGo) { Install-GoOfficial; $goExe = Find-Go }
if (-not $goExe) { throw "Go nao encontrado. Execute o script novamente com -InstallGo (PowerShell Admin) ou instale em https://go.dev/dl/." }

$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
$env:GOTOOLCHAIN = 'local'
$env:GOFLAGS = '-mod=mod'
if ($UnverifiedModules) {
    $env:GOPROXY = 'direct'
    $env:GOSUMDB = 'off'
    Write-Warning 'GOSUMDB=off: integridade de dependencias nao sera verificada. Use somente se estritamente necessario.'
}

Push-Location -LiteralPath $SourceDir
try {
    Info "Codigo-fonte: $SourceDir"
    & $goExe version
    if ($LASTEXITCODE -ne 0) { throw 'go version falhou.' }
    $package = & $goExe list -f '{{.Name}}' .
    if ($LASTEXITCODE -ne 0 -or (($package -join '').Trim() -ne 'main')) { throw 'Pacote raiz Go nao e main (ou go list falhou). Confira go.mod e arquivos .go.' }

    $dist = Join-Path $SourceDir 'dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $exe = Join-Path $dist 'AionWG.exe'
    $tmp = Join-Path $dist ('.AionWG-' + [guid]::NewGuid().ToString('N') + '.exe')
    try {
        Info 'Compilando Windows x64: GOOS=windows GOARCH=amd64 CGO_ENABLED=0...'
        & $goExe build -trimpath -ldflags '-s -w' -o $tmp .
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmp -PathType Leaf)) { throw 'go build falhou.' }
        if ((Get-Item -LiteralPath $tmp).Length -le 0) { throw 'Binario compilado esta vazio.' }
        Move-Item -LiteralPath $tmp -Destination $exe -Force
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    Info "EXE gerado: $exe"
    if ($NoPackage) {
        Info 'Empacotamento ignorado (-NoPackage). Concluido.'
        return
    }

    $stageRoot = Join-Path ([IO.Path]::GetTempPath()) ('aionwg-build-' + [guid]::NewGuid().ToString('N'))
    $stage = Join-Path $stageRoot 'AionWG-windows-x64'
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        Copy-Item -LiteralPath $exe -Destination $stage
        $assetNames = @('LICENSE','WinDivert.dll','WinDivert64.sys','wintun.dll','WinDivert-LICENSE.txt','shugo-compat.dll')
        $assetFolders = @($AssetsDir, $SourceDir, $dist, $PSScriptRoot)
        if ($AssetsZip) {
            Add-Type -AssemblyName System.IO.Compression
            $archive = [IO.Compression.ZipFile]::OpenRead($AssetsZip)
            try {
                foreach ($name in $assetNames) {
                    $entry = $archive.Entries | Where-Object { $_.Name -ieq $name -and $_.Length -gt 0 } | Select-Object -First 1
                    if (-not $entry) { continue }
                    $inStream = $entry.Open()
                    try {
                        $outStream = [IO.File]::Create((Join-Path $stage $name))
                        try { $inStream.CopyTo($outStream) } finally { $outStream.Dispose() }
                    } finally { $inStream.Dispose() }
                }
            } finally { $archive.Dispose() }
        }
        foreach ($name in $assetNames) {
            if (Test-Path -LiteralPath (Join-Path $stage $name) -PathType Leaf) { continue }
            $path = Resolve-AssetPath -Name $name -Folders $assetFolders
            if ($path) { Copy-Item -LiteralPath $path -Destination $stage }
        }
        @'
AionWG - build Windows x64

Mantenha AionWG.exe, WinDivert.dll e WinDivert64.sys na mesma pasta.
wintun.dll pode ser necessario para recursos que usam o adaptador Wintun.
Execute como Administrador para captura WinDivert.
Com [m] ligado, shugo-compat.dll (ao lado do EXE) faz o Shugo enxergar o relay.
O pacote NAO contem *.conf, chaves privadas ou configuracoes pessoais.
Build bem-sucedido nao garante captura/driver/roteamento; teste no Windows.
'@ | Set-Content -LiteralPath (Join-Path $stage 'LEIA-ME-BUILD.txt') -Encoding UTF8
        foreach ($name in @('WinDivert.dll','WinDivert64.sys')) {
            if (-not (Test-Path -LiteralPath (Join-Path $stage $name) -PathType Leaf)) { Write-Warning "$name ausente: ZIP pode nao executar corretamente." }
        }
        $zipOut = Join-Path $dist 'AionWG-windows-x64.zip'
        if (Test-Path -LiteralPath $zipOut) { Remove-Item -LiteralPath $zipOut -Force }
        Compress-Archive -LiteralPath $stage -DestinationPath $zipOut -CompressionLevel Optimal
        Info "ZIP gerado: $zipOut"
    } finally {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    Info 'Concluido. Teste o EXE no Windows antes de usar o tunel.'
} finally {
    Pop-Location
}
