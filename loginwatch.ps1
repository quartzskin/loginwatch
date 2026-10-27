[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'File', Mandatory)][string]$Path,
    [Parameter(ParameterSetName = 'Live')][switch]$Live,
    [Parameter(ParameterSetName = 'Sample')][switch]$Sample,
    [Parameter(ParameterSetName = 'Unblock')][switch]$Unblock,

    [Parameter(ParameterSetName = 'Live')][Parameter(ParameterSetName = 'File')][Parameter(ParameterSetName = 'Sample')]
    [string]$BaselinePath,
    [Parameter(ParameterSetName = 'Live')][Parameter(ParameterSetName = 'File')][Parameter(ParameterSetName = 'Sample')]
    [switch]$SaveBaseline,
    [Parameter(ParameterSetName = 'Live')][Parameter(ParameterSetName = 'File')][Parameter(ParameterSetName = 'Sample')]
    [string]$ExportJsonl,
    [Parameter(ParameterSetName = 'Live')][Parameter(ParameterSetName = 'File')][Parameter(ParameterSetName = 'Sample')]
    [switch]$Json,
    [Parameter(ParameterSetName = 'Live')][Parameter(ParameterSetName = 'File')][Parameter(ParameterSetName = 'Sample')]
    [switch]$BlockSuggestion,
    [Parameter(ParameterSetName = 'Live')][Parameter(ParameterSetName = 'File')][Parameter(ParameterSetName = 'Sample')]
    [switch]$Apply,

    [int]$Hours = 24,
    [int]$MaxEvents = 20000,
    [int]$BurstThreshold = 5,
    [int]$BurstWindowMinutes = 10,
    [int]$SprayAccounts = 4,
    [int]$SuccessAfterFailures = 3
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'LoginWatch.psm1') -Force

$shouldArgs = @{}
if ($PSBoundParameters.ContainsKey('WhatIf')) { $shouldArgs.WhatIf = $true }
if ($PSBoundParameters.ContainsKey('Confirm')) { $shouldArgs.Confirm = [bool]$PSBoundParameters['Confirm'] }
# -WhatIf must only reach the firewall calls, not every cmdlet in this script
$WhatIfPreference = $false
$ConfirmPreference = 'None'

try {
    if ($Unblock) {
        $r = @(Remove-LwBlock @shouldArgs)
        if (-not $r.Count) { Write-Host 'no loginwatch- firewall rules found' }
        $r | Format-Table -AutoSize | Out-String | Write-Host
        exit 0
    }

    if ($Sample) { $res = [pscustomobject]@{ Events = @(New-LwSampleEvents); Skipped = @(); Error = '' } }
    elseif ($Path) { $res = Import-LwEvents -Path $Path }
    else { $res = Import-LwEvents -Live -Hours $Hours -MaxEvents $MaxEvents }

    if ($res.Error) { [Console]::Error.WriteLine("loginwatch: $($res.Error)"); exit 2 }
    foreach ($s in $res.Skipped) { [Console]::Error.WriteLine("loginwatch: skipped $s") }

    if ($ExportJsonl) { Export-LwJsonLines -Events $res.Events -Path $ExportJsonl }

    $baseline = $null
    if ($BaselinePath) { $baseline = Import-LwBaseline -Path $BaselinePath }
    $cfg = @{
        BurstThreshold = $BurstThreshold; BurstWindowMinutes = $BurstWindowMinutes
        SprayAccounts = $SprayAccounts; SuccessAfterFailures = $SuccessAfterFailures
    }
    $findings = @(Get-LwFindings -Events $res.Events -Config $cfg -Baseline $baseline)

    if ($Json) {
        $findings | Select-Object Type, Severity, Source, Account, Start, End, Count, Summary, RecordIds | ConvertTo-Json -Depth 4
    }
    else {
        Write-Host ("{0} events read ({1} skipped), {2} findings" -f $res.Events.Count, $res.Skipped.Count, $findings.Count)
        foreach ($f in $findings) { Write-Host (Format-LwFinding $f); Write-Host '' }
    }

    if ($SaveBaseline) {
        if (-not $BaselinePath) { throw '-SaveBaseline needs -BaselinePath' }
        Export-LwBaseline -Baseline (Update-LwBaseline -Baseline $baseline -Events $res.Events) -Path $BaselinePath
        Write-Host "baseline written to $BaselinePath"
    }

    if ($BlockSuggestion -or $Apply) {
        $cands = @(Get-LwBlockCandidates $findings)
        $protected = @(Get-LwProtectedSources -Events $res.Events)
        if (-not $cands.Count) { Write-Host 'no sources worth blocking' }
        if ($BlockSuggestion) {
            foreach ($a in $cands) {
                if (Test-LwPrivateAddress $a) { Write-Host "# $a is private/loopback, not suggested"; continue }
                if ($protected -contains $a) { Write-Host "# $a is this machine or the current session, not suggested"; continue }
                Write-Host (Get-LwBlockCommand $a)
            }
        }
        if ($Apply -and $cands.Count) {
            Invoke-LwBlock -Address $cands -Protected $protected @shouldArgs | Format-Table -AutoSize | Out-String | Write-Host
        }
    }
    if ($findings.Count) { exit 1 } else { exit 0 }
}
catch {
    [Console]::Error.WriteLine("loginwatch: $($_.Exception.Message)")
    exit 2
}
