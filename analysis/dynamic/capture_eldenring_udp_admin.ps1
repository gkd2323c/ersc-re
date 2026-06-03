param(
    [int]$DurationSeconds = 120,
    [string]$OutputDirectory = "C:\Users\gkd2323c\Documents\Hanako\ersc-re\analysis\dynamic"
)

$ErrorActionPreference = "Continue"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $requestLog = Join-Path $OutputDirectory "pktmon-uac-request-$stamp.txt"
    "Requesting administrator rights at $(Get-Date -Format o)" | Set-Content -Path $requestLog
    $scriptPath = $PSCommandPath
    $argsList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$scriptPath`"",
        "-DurationSeconds", $DurationSeconds,
        "-OutputDirectory", "`"$OutputDirectory`""
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $argsList -Verb RunAs -WindowStyle Hidden
    Write-Host "UAC requested. Admin capture will write logs under: $OutputDirectory"
    exit 0
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$log = Join-Path $OutputDirectory "pktmon-eldenring-$stamp.log"
$etl = Join-Path $OutputDirectory "pktmon-eldenring-$stamp.etl"
$pcap = Join-Path $OutputDirectory "pktmon-eldenring-$stamp.pcapng"

function Log-Line($message) {
    $line = "$(Get-Date -Format o) $message"
    Add-Content -Path $log -Value $line
}

Log-Line "Admin capture started"
Log-Line "DurationSeconds=$DurationSeconds"

$target = Get-Process -Name "eldenring" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $target) {
    Log-Line "ERROR: eldenring.exe is not running"
    exit 2
}

Log-Line "Target PID=$($target.Id) Path=$($target.Path)"

$ports = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Where-Object { $_.OwningProcess -eq $target.Id } |
    Select-Object -ExpandProperty LocalPort |
    Sort-Object -Unique)

if ($ports.Count -eq 0) {
    Log-Line "ERROR: no UDP ports found for eldenring.exe"
    exit 3
}

Log-Line "UDP ports: $($ports -join ',')"

try {
    pktmon stop | Out-Null
} catch {}

try {
    pktmon filter remove | Out-Null
} catch {}

$filterCount = 0
foreach ($port in ($ports | Select-Object -First 32)) {
    $name = "er_udp_$port"
    $result = pktmon filter add $name -t UDP -p $port 2>&1
    Log-Line "filter add port=$port result=$result"
    $filterCount++
}

Log-Line "FilterCount=$filterCount"
Log-Line "Starting pktmon capture: $etl"
$startResult = pktmon start --capture --pkt-size 0 --file-name $etl 2>&1
Log-Line "pktmon start result=$startResult"

Start-Sleep -Seconds $DurationSeconds

$stopResult = pktmon stop 2>&1
Log-Line "pktmon stop result=$stopResult"

if (Test-Path $etl) {
    $convertResult = pktmon etl2pcap $etl --out $pcap 2>&1
    Log-Line "pktmon etl2pcap result=$convertResult"
} else {
    Log-Line "ERROR: ETL file was not created"
}

try {
    pktmon filter remove | Out-Null
} catch {}

$summary = [ordered]@{
    Log = $log
    Etl = $etl
    Pcap = $pcap
    TargetPid = $target.Id
    DurationSeconds = $DurationSeconds
    Ports = $ports
    EtlExists = (Test-Path $etl)
    PcapExists = (Test-Path $pcap)
    PcapSize = if (Test-Path $pcap) { (Get-Item $pcap).Length } else { 0 }
}

$summaryPath = Join-Path $OutputDirectory "pktmon-eldenring-$stamp.summary.json"
$summary | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryPath
Log-Line "Summary=$summaryPath"
Log-Line "Admin capture completed"
