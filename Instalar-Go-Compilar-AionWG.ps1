#requires -Version 5.1
<#
.SYNOPSIS
    Instala Go no Windows (se ausente), copia a fonte AionWG do WSL se necessario,
    compila AionWG.exe windows/amd64 e opcionalmente empacota as DLLs de runtime.
.EXAMPLE
    .\Instalar-Go-Compilar-AionWG.ps1 -AssetsZip "$HOME\Downloads\AionWG-windows-x64 (0990)xxxx.zip"
.EXAMPLE
    .\Instalar-Go-Compilar-AionWG.ps1 -SourceDir 'D:\Projetos\aionwg' -AssetsDir 'D:\AionWG\bin'
.NOTES
    Fonte padrao: \\wsl.localhost\CachyOS\home\avatar\aionwg
    Destino Windows: %USERPROFILE%\source\aionwg
    Instalador Go oficial com SHA-256 verificado.
#>
[CmdletBinding()]
param(
    [string]$SourceDir,
    [string]$WSLDistro = 'CachyOS',
    [string]$WSLSource = '/home/avatar/aionwg',
    [string]$WorkDir = (Join-Path $HOME 'source\aionwg'),
    [string]$AssetsZip,
    [string]$AssetsDir,
    [switch]$RefreshFromWSL,
    [switch]$SkipInstall,
    [switch]$NoPackage
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($AssetsZip -and $AssetsDir) { throw 'Use -AssetsZip OU -AssetsDir, nao ambos.' }
if ($AssetsZip) { $AssetsZip = (Resolve-Path -LiteralPath $AssetsZip -ErrorAction Stop).Path }
if ($AssetsDir) { $AssetsDir = (Resolve-Path -LiteralPath $AssetsDir -ErrorAction Stop).Path }

function Get-GoExe {
    $existing = Get-Command go.exe -ErrorAction SilentlyContinue
    if ($existing -and $existing.Source) { return $existing.Source }
    $default = Join-Path $env:ProgramFiles 'Go\bin\go.exe'
    if (Test-Path -LiteralPath $default) { return $default }
    return $null
}

function Ensure-Go {
    $goExe = Get-GoExe
    if ($goExe) {
        Write-Host "[GO] Ja instalado: $goExe"
        & $goExe version
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao executar o Go instalado.' }
        return $goExe
    }
    if ($SkipInstall) { throw 'Go nao encontrado; remova -SkipInstall ou instale manualmente.' }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Para instalar o Go, abra PowerShell como Administrador e execute novamente.'
    }

    # Versao e SHA256 publicados em https://go.dev/dl/ (consultado em 2026-11-11).
    $version = '1.27.4'
    $sha256 = 'ae9e383a027ac83c227efd0be3173bf98bccfa5d966a206dff7998f4a3d8449c'
    $file = "go$version.windows-amd64.msi"
    $url = "https://go.dev/dl/$file"
    $installer = Join-Path $env:TEMP $file
    Write-Host "[GO] Baixando $url"
    try {
        Invoke-WebRequest -Uri $url -OutFile $installer -ErrorAction Stop
        $hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $sha256) { throw "Checksum invalido. Esperado $sha256; recebido $hash. Abortando instalacao." }
        Write-Host '[GO] SHA256 validado; instalando Go silenciosamente...'
        $args = @('/i', ('"' + $installer + '"'), '/qn', '/norestart')
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru
        if ($process.ExitCode -notin @(0,3010)) { throw "O instalador retornou $($process.ExitCode)." }
    }
    finally {
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
    }
    $env:Path = (Join-Path $env:ProgramFiles 'Go\bin') + ';' + $env:Path
    $goExe = Get-GoExe
    if (-not $goExe) { throw 'Instalacao finalizada mas go.exe nao foi encontrado. Abra novo PowerShell e teste go version.' }
    & $goExe version
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao validar o Go.' }
    return $goExe
}

$goExe = Ensure-Go

# O ZIP previamente enviado contem apenas EXE/DLL: o codigo-fonte deve vir do WSL ou de -SourceDir.
if ($SourceDir) {
    $SourceDir = (Resolve-Path -LiteralPath $SourceDir -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $SourceDir 'go.mod'))) {
        throw "go.mod nao encontrado em $SourceDir. Indique a pasta do projeto Go, nao o ZIP de binarios."
    }
    $project = $SourceDir
} else {
    $project = $WorkDir
    if ($RefreshFromWSL -or -not (Test-Path -LiteralPath (Join-Path $project 'go.mod'))) {
        $wslPath = "\\wsl.localhost\$WSLDistro\" + ($WSLSource.TrimStart('/') -replace '/', '\')
        if (-not (Test-Path -LiteralPath (Join-Path $wslPath 'go.mod'))) {
            throw "Fonte nao encontrada em $wslPath. Inicie o WSL (wsl -d $WSLDistro) ou passe -SourceDir 'C:\caminho\aionwg'."
        }
        New-Item -ItemType Directory -Path $project -Force | Out-Null
        Write-Host "[FONTE] Copiando de $wslPath para $project"
        & robocopy.exe $wslPath $project /E /R:2 /W:1 /XD .git dist node_modules /NFL /NDL /NJH /NJS /NP
        $rc = $LASTEXITCODE
        if ($rc -ge 8) { throw "Robocopy falhou com codigo $rc." }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $project 'go.mod'))) {
        throw "go.mod nao encontrado em $project."
    }
}

$project = (Resolve-Path -LiteralPath $project).Path
$dist = Join-Path $project 'dist'
New-Item -ItemType Directory -Path $dist -Force | Out-Null
$exe = Join-Path $dist 'AionWG.exe'

# Salva e restaura o ambiente, evitando alterar a configuracao permanente do usuario.
$oldEnv = @{}
foreach ($var in @('GOOS', 'GOARCH', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOFLAGS')) {
    $oldEnv[$var] = [Environment]::GetEnvironmentVariable($var, 'Process')
}
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'local'
    $env:GOFLAGS = '-mod=mod'
    Push-Location -LiteralPath $project
    try {
        Write-Host "[BUILD] Fonte: $project"
        $name = & $goExe list -f '{{.Name}}' .
        if ($LASTEXITCODE -ne 0 -or ($name -join '').Trim() -ne 'main') {
            throw 'A raiz do projeto nao e um pacote main; verifique o projeto e execute a partir da pasta correta.'
        }
        & $goExe build -trimpath -ldflags '-s -w' -o $exe .
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe)) { throw 'go build falhou.' }
    } finally { Pop-Location }
} finally {
    foreach ($var in $oldEnv.Keys) {
        [Environment]::SetEnvironmentVariable($var, $oldEnv[$var], 'Process')
    }
}
Write-Host "[OK] Executavel gerado: $exe"

if (-not $NoPackage) {
    $stageRoot = Join-Path ([IO.Path]::GetTempPath()) ('aionwg-' + [guid]::NewGuid().ToString('N'))
    $stage = Join-Path $stageRoot 'AionWG-windows-x64'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    try {
        Copy-Item -LiteralPath $exe -Destination $stage
        $assets = @('WinDivert.dll', 'WinDivert64.sys', 'wintun.dll', 'WinDivert-LICENSE.txt')
        if ($AssetsZip) {
            Add-Type -AssemblyName System.IO.Compression
            $archive = [IO.Compression.ZipFile]::OpenRead($AssetsZip)
            try {
                foreach ($asset in $assets) {
                    $entry = $archive.Entries | Where-Object { $_.Name -ceq $asset } | Select-Object -First 1
                    if ($entry) {
                        $inputStream = $entry.Open()
                        try {
                            $outStream = [IO.File]::Create((Join-Path $stage $asset))
                            try { $inputStream.CopyTo($outStream) } finally { $outStream.Dispose() }
                        } finally { $inputStream.Dispose() }
                    }
                }
            } finally { $archive.Dispose() }
        } elseif ($AssetsDir) {
            foreach ($asset in $assets) {
                $candidate = Join-Path $AssetsDir $asset
                if (Test-Path -LiteralPath $candidate) { Copy-Item -LiteralPath $candidate -Destination $stage }
            }
        } else {
            foreach ($asset in $assets) {
                $candidate = Join-Path $dist $asset
                if (Test-Path -LiteralPath $candidate) { Copy-Item -LiteralPath $candidate -Destination $stage }
            }
        }
        foreach ($required in @('WinDivert.dll','WinDivert64.sys','wintun.dll')) {
            if (-not (Test-Path -LiteralPath (Join-Path $stage $required))) {
                Write-Warning "$required nao encontrado. O pacote pode nao executar todas as funcoes. Passe -AssetsZip ou -AssetsDir."
            }
        }
        @'
AionWG - Windows x64
Compilado com Go para Windows amd64 (CGO=0).
Para recursos WinDivert/Wintun, mantenha as DLLs e o driver junto ao EXE.
Execute com privilgios de administrador quando necessario para captura de rede.
Este pacote nao inclui arquivos .conf ou chaves privadas.
'@ | Set-Content -LiteralPath (Join-Path $stage 'LEIA-ME.txt') -Encoding UTF8
        $zipOut = Join-Path $dist 'AionWG-windows-x64.zip'
        if (Test-Path -LiteralPath $zipOut) { Remove-Item -LiteralPath $zipOut -Force }
        Compress-Archive -LiteralPath $stage -DestinationPath $zipOut -CompressionLevel Optimal
        Write-Host "[OK] ZIP gerado: $zipOut"
    } finally {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host '[PRONTO] Compilei o binario. Teste AionWG.exe no Windows antes de usar em producao.'
