# monitor-aion.ps1 - mostra ao vivo os IPs que o AION 2 (e os processos que
# ele abre, como a loja / navegador embutido) conectam.
#
# Uso (PowerShell, nao precisa ser admin):
#   powershell -ExecutionPolicy Bypass -File .\monitor-aion.ps1
#   powershell -ExecutionPolicy Bypass -File .\monitor-aion.ps1 -Name Aion2,steamwebhelper
#
# DPS meters (mostra tambem 127.0.0.1, portas abertas, UDP e a biblioteca
# de captura que cada um usa - rode o PowerShell como Administrador):
#   powershell -ExecutionPolicy Bypass -File .\monitor-aion.ps1 -Local -Name shugogg-companion,NotMeter,NotMeter.GpuiHost,AbyssDPSMeter
#
# Cores:
#   verde    = conectado pelo tunel (IP local 10.77.78.x)
#   amarelo  = pelo tunel, mas TRAVADO (SynSent: o servidor nao respondeu)
#   vermelho = saiu DIRETO, fora do tunel (IPv6 ou faixa fora do AllowedIPs)
#   ciano    = (-Local) conexao local 127.0.0.1, porta em escuta ou UDP
#   magenta  = (-Local) biblioteca de captura que o processo usa
#
# A coluna "rota" so vale para o WireGuard oficial. No AionWG o IP local
# continua sendo o da sua placa de rede mesmo indo pelo tunel.
# Tudo e gravado num .csv na Area de Trabalho.

param(
    [string[]]$Name = @('Aion2', 'Aion2-Win64-Shipping', 'AION2-Win64-Shipping'),
    [string]$TunnelPrefix = '10.77.78.',
    [int]$Interval = 1,
    [switch]$Local   # inclui 127.0.0.1, portas em escuta (Listen), UDP e libs de captura
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ErrorActionPreference = 'SilentlyContinue'
$desktop = [Environment]::GetFolderPath('Desktop')
$csv = Join-Path $desktop ('aion-conexoes-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date))
'hora,processo,pid,ip_remoto,porta,estado,ip_local,rota,dns' | Out-File $csv -Encoding utf8

$seen = @{}
$dnsCache = @{}
$seenProc = @{}

# Qual biblioteca de captura o processo carregou (Npcap/WinPcap, WinDivert...)
function Show-CaptureLibs([int]$procId, [string]$procName) {
    $mods = $null
    try { $mods = (Get-Process -Id $procId -ErrorAction Stop).Modules } catch {}
    if ($null -eq $mods) {
        Write-Host ('{0:HH:mm:ss}  {1} (PID {2}): sem acesso aos modulos - rode o PowerShell como Administrador' -f (Get-Date), $procName, $procId) -ForegroundColor DarkYellow
        return
    }
    $libs = $mods | Where-Object { $_.ModuleName -match 'wpcap|packet\.dll|npcap|windivert|pcap|wintun' } |
        Select-Object -ExpandProperty FileName -Unique
    if ($libs) {
        Write-Host ('{0:HH:mm:ss}  {1} (PID {2}) captura com: {3}' -f (Get-Date), $procName, $procId, ($libs -join ' | ')) -ForegroundColor Magenta
    } else {
        Write-Host ('{0:HH:mm:ss}  {1} (PID {2}): nenhuma biblioteca de captura carregada' -f (Get-Date), $procName, $procId) -ForegroundColor DarkGray
    }
}

# processo do jogo + todos os processos filhos (loja, navegador embutido...)
function Get-GameTree {
    $all = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name
    $tree = @{}
    foreach ($p in $all) {
        $n = [IO.Path]::GetFileNameWithoutExtension($p.Name)
        if ($Name -contains $n) { $tree[[int]$p.ProcessId] = $p.Name }
    }
    do {
        $added = $false
        foreach ($p in $all) {
            $id = [int]$p.ProcessId
            if (-not $tree.ContainsKey($id) -and $tree.ContainsKey([int]$p.ParentProcessId) -and $id -ne [int]$p.ParentProcessId) {
                $tree[$id] = $p.Name
                $added = $true
            }
        }
    } while ($added)
    return $tree
}

function Get-Ptr([string]$ip) {
    if ($dnsCache.ContainsKey($ip)) { return $dnsCache[$ip] }
    $h = ''
    try {
        $t = [System.Net.Dns]::GetHostEntryAsync($ip)
        if ($t.Wait(400)) { $h = $t.Result.HostName }
    } catch {}
    $dnsCache[$ip] = $h
    return $h
}

Write-Host ('Monitorando: ' + ($Name -join ', ') + ' + processos filhos.  Ctrl+C para parar.') -ForegroundColor Cyan
Write-Host ('Log: ' + $csv) -ForegroundColor DarkGray
Write-Host ('{0,-9} {1,-28} {2,-42} {3,-12} {4,-12} {5}' -f 'hora', 'processo', 'ip_remoto:porta', 'estado', 'rota', 'dns') -ForegroundColor DarkGray

$lastTree = ''
while ($true) {
    $tree = Get-GameTree
    if ($tree.Count -eq 0) {
        Write-Host ('{0:HH:mm:ss}  nenhum processo encontrado ({1})...' -f (Get-Date), ($Name -join ', ')) -ForegroundColor DarkYellow
        Start-Sleep 3
        continue
    }
    $treeStr = ($tree.Values | Sort-Object -Unique) -join ', '
    if ($treeStr -ne $lastTree) {
        Write-Host ('{0:HH:mm:ss}  processos: {1}' -f (Get-Date), $treeStr) -ForegroundColor Cyan
        $lastTree = $treeStr
    }

    if ($Local) {
        foreach ($procId in @($tree.Keys)) {
            if (-not $seenProc.ContainsKey($procId)) {
                $seenProc[$procId] = $true
                Show-CaptureLibs $procId $tree[$procId]
            }
        }
        # UDP: o Windows so informa a porta local (nao o destino)
        foreach ($u in (Get-NetUDPEndpoint | Where-Object { $tree.ContainsKey([int]$_.OwningProcess) })) {
            $key = 'udp|{0}|{1}|{2}' -f $u.OwningProcess, $u.LocalAddress, $u.LocalPort
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $proc = $tree[[int]$u.OwningProcess]
            Write-Host ('{0:HH:mm:ss}  {1,-28} {2,-42} {3,-12} {4,-12}' -f (Get-Date), $proc, ('UDP ' + $u.LocalAddress + ':' + $u.LocalPort), 'aberta', 'LOCAL') -ForegroundColor Cyan
            ('{0:HH:mm:ss},{1},{2},{3},{4},{5},{6},{7},' -f (Get-Date), $proc, $u.OwningProcess, '', '', 'UDP', ($u.LocalAddress + ':' + $u.LocalPort), 'LOCAL') |
                Out-File $csv -Append -Encoding utf8
        }
    }

    $conns = Get-NetTCPConnection | Where-Object {
        $tree.ContainsKey([int]$_.OwningProcess) -and
        ($Local -or (
            $_.RemoteAddress -notin @('0.0.0.0', '::', '127.0.0.1', '::1') -and
            $_.State -ne 'Listen'))
    }
    foreach ($c in $conns) {
        $state = [string]$c.State
        $key = '{0}|{1}|{2}|{3}' -f $c.OwningProcess, $c.RemoteAddress, $c.RemotePort, $state
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $proc = $tree[[int]$c.OwningProcess]
        $localIp = [string]$c.LocalAddress
        $remoteIp = [string]$c.RemoteAddress
        if ($state -eq 'Listen') { $rota = 'ESCUTANDO' }
        elseif ($remoteIp -in @('127.0.0.1', '::1') -or $remoteIp.StartsWith('127.')) { $rota = 'LOCAL' }
        elseif ($localIp.StartsWith($TunnelPrefix)) { $rota = 'TUNEL' }
        elseif ($localIp -like '*:*') { $rota = 'DIRETO-IPv6' }
        else { $rota = 'DIRETO' }

        $color = 'Green'
        if ($rota -eq 'ESCUTANDO' -or $rota -eq 'LOCAL') { $color = 'Cyan' }
        elseif ($rota -ne 'TUNEL') { $color = 'Red' }
        elseif ($state -eq 'SynSent') { $color = 'Yellow' }

        $dns = ''
        if ($rota -ne 'ESCUTANDO' -and $rota -ne 'LOCAL') { $dns = Get-Ptr $remoteIp }
        $remote = '{0}:{1}' -f $c.RemoteAddress, $c.RemotePort
        if ($rota -eq 'ESCUTANDO') { $remote = 'porta {0}:{1}' -f $localIp, $c.LocalPort }
        elseif ($rota -eq 'LOCAL') { $remote = '{0} <- :{1}' -f $remote, $c.LocalPort }
        Write-Host ('{0:HH:mm:ss}  {1,-28} {2,-42} {3,-12} {4,-12} {5}' -f (Get-Date), $proc, $remote, $state, $rota, $dns) -ForegroundColor $color
        ('{0:HH:mm:ss},{1},{2},{3},{4},{5},{6},{7},{8}' -f (Get-Date), $proc, $c.OwningProcess, $c.RemoteAddress, $c.RemotePort, $state, $localIp, $rota, $dns) |
            Out-File $csv -Append -Encoding utf8
    }
    Start-Sleep $Interval
}
