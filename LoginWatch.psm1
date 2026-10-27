Set-StrictMode -Version 2.0

$script:EventIds = 4624, 4625, 4634, 4648, 4672, 4776
$script:CountedTypes = 2, 3, 7, 10, 11
$script:Defaults = @{
    BurstThreshold       = 5
    BurstWindowMinutes   = 10
    SprayAccounts        = 4
    SprayWindowMinutes   = 10
    SuccessAfterFailures = 3
    SuccessWindowMinutes = 15
    MinBaselineLogons    = 20
}

function New-LwEvent {
    param($EventId, $RecordId, [DateTimeOffset]$Time, $Account, $Source, $LogonType, $Workstation, $Status)
    [pscustomobject]@{
        EventId     = [int]$EventId
        RecordId    = [long]$RecordId
        Time        = $Time
        Account     = [string]$Account
        Source      = ConvertTo-LwSource $Source
        LogonType   = [int]$LogonType
        Workstation = [string]$Workstation
        Status      = [string]$Status
    }
}

function ConvertTo-LwSource([string]$Value) {
    if (-not $Value) { return '' }
    $Value = $Value.Trim()
    if ($Value -eq '-') { return '' }
    if ($Value.StartsWith('::ffff:')) { $Value = $Value.Substring(7) }
    $Value
}

function ConvertTo-LwTime($Value) {
    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [DateTime]) { return [DateTimeOffset]$Value }
    $t = [DateTimeOffset]::MinValue
    $ok = [DateTimeOffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$t)
    if ($ok) { $t } else { $null }
}

function Get-LwProp($Object, [string]$Name) {
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function ConvertFrom-LwXml {
    param([Parameter(Mandatory)][string]$Xml)
    $doc = New-Object System.Xml.XmlDocument
    try { $doc.LoadXml($Xml) } catch { return $null }
    $idNode = $doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='EventID']")
    $recNode = $doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='EventRecordID']")
    $timeNode = $doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='TimeCreated']")
    if (-not $idNode -or -not $recNode -or -not $timeNode) { return $null }
    $id = 0; $rec = [long]0
    if (-not [int]::TryParse($idNode.InnerText, [ref]$id) -or $script:EventIds -notcontains $id) { return $null }
    if (-not [long]::TryParse($recNode.InnerText, [ref]$rec)) { return $null }
    $time = ConvertTo-LwTime $timeNode.GetAttribute('SystemTime')
    if (-not $time) { return $null }

    $d = @{}
    foreach ($n in $doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $d[$n.GetAttribute('Name')] = $n.InnerText
    }
    $f = { param($k) if ($d.ContainsKey($k)) { $d[$k] } else { '' } }
    $type = 0
    [void][int]::TryParse((& $f 'LogonType'), [ref]$type)

    switch ($id) {
        4672 { New-LwEvent $id $rec $time (& $f 'SubjectUserName') '' 0 '' '' }
        4776 { New-LwEvent $id $rec $time (& $f 'TargetUserName') '' 0 (& $f 'Workstation') (& $f 'Status') }
        4634 { New-LwEvent $id $rec $time (& $f 'TargetUserName') '' $type '' '' }
        4648 { New-LwEvent $id $rec $time (& $f 'TargetUserName') (& $f 'IpAddress') 0 '' '' }
        4625 {
            $st = & $f 'SubStatus'
            if (-not $st) { $st = & $f 'Status' }
            New-LwEvent $id $rec $time (& $f 'TargetUserName') (& $f 'IpAddress') $type (& $f 'WorkstationName') $st
        }
        default { New-LwEvent $id $rec $time (& $f 'TargetUserName') (& $f 'IpAddress') $type (& $f 'WorkstationName') '' }
    }
}

function New-LwReadResult($Events, $Skipped, [string]$Err) {
    [pscustomobject]@{ Events = @($Events); Skipped = @($Skipped); Error = $Err }
}

function Import-LwJsonLines {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return New-LwReadResult @() @() "file not found: $Path" }
    $events = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[string]
    $lines = [IO.File]::ReadAllLines((Resolve-Path -LiteralPath $Path).ProviderPath)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $line) { continue }
        $n = $i + 1
        try { $o = $line | ConvertFrom-Json -ErrorAction Stop } catch { $skipped.Add("line ${n}: not valid JSON"); continue }
        if ($o -isnot [pscustomobject]) { $skipped.Add("line ${n}: not a JSON object"); continue }
        $id = 0; $rec = [long]0
        if (-not [int]::TryParse([string](Get-LwProp $o 'EventId'), [ref]$id) -or $script:EventIds -notcontains $id) {
            $skipped.Add("line ${n}: missing or unsupported EventId"); continue
        }
        if (-not [long]::TryParse([string](Get-LwProp $o 'RecordId'), [ref]$rec)) {
            $skipped.Add("line ${n}: missing or bad RecordId"); continue
        }
        $time = ConvertTo-LwTime (Get-LwProp $o 'Time')
        if (-not $time) { $skipped.Add("line ${n}: missing or bad Time"); continue }
        $type = 0
        [void][int]::TryParse([string](Get-LwProp $o 'LogonType'), [ref]$type)
        $events.Add((New-LwEvent $id $rec $time (Get-LwProp $o 'Account') (Get-LwProp $o 'Source') $type `
                    (Get-LwProp $o 'Workstation') (Get-LwProp $o 'Status')))
    }
    New-LwReadResult $events.ToArray() $skipped.ToArray() ''
}

function ConvertFrom-LwWinEvents($Records) {
    $events = New-Object System.Collections.Generic.List[object]
    $skipped = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Records) {
        $e = ConvertFrom-LwXml $r.ToXml()
        if ($e) {
            $e.Time = $e.Time.ToLocalTime()
            $events.Add($e)
        }
        else { $skipped.Add("record $($r.RecordId): could not be parsed") }
    }
    New-LwReadResult $events.ToArray() $skipped.ToArray() ''
}

function Get-LwEventFilterXPath {
    '*[System[(' + (($script:EventIds | ForEach-Object { "EventID=$_" }) -join ' or ') + ')]]'
}

function Import-LwEvtx {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return New-LwReadResult @() @() "file not found: $Path" }
    try {
        $recs = Get-WinEvent -Path (Resolve-Path -LiteralPath $Path).ProviderPath -FilterXPath (Get-LwEventFilterXPath) -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return New-LwReadResult @() @() '' }
        return New-LwReadResult @() @() "cannot read evtx: $($_.Exception.Message)"
    }
    ConvertFrom-LwWinEvents $recs
}

function Test-LwAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-LwLive {
    param([int]$Hours = 24, [int]$MaxEvents = 20000)
    $filter = @{ LogName = 'Security'; Id = $script:EventIds; StartTime = (Get-Date).AddHours(-$Hours) }
    try {
        $recs = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch [UnauthorizedAccessException] {
        return New-LwReadResult @() @() 'access denied reading the Security log. Run from an elevated prompt (or add the account to Event Log Readers), or pass -Path with an exported .evtx / .jsonl file.'
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            # a filtered query reports access denied as 'no events', so probe unfiltered
            try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null }
            catch [UnauthorizedAccessException] { return New-LwReadResult @() @() 'access denied reading the Security log. Run from an elevated prompt (or add the account to Event Log Readers), or pass -Path with an exported .evtx / .jsonl file.' }
            catch { }
            return New-LwReadResult @() @() ''
        }
        if ($_.Exception.Message -match 'unauthorized|denied') {
            return New-LwReadResult @() @() 'access denied reading the Security log. Run from an elevated prompt (or add the account to Event Log Readers), or pass -Path with an exported .evtx / .jsonl file.'
        }
        return New-LwReadResult @() @() "cannot read the Security log: $($_.Exception.Message)"
    }
    ConvertFrom-LwWinEvents $recs
}

function Import-LwEvents {
    param([string]$Path, [switch]$Live, [int]$Hours = 24, [int]$MaxEvents = 20000)
    if ($Live) { return Import-LwLive -Hours $Hours -MaxEvents $MaxEvents }
    if ($Path -like '*.evtx') { return Import-LwEvtx -Path $Path }
    Import-LwJsonLines -Path $Path
}

function Export-LwJsonLines {
    param([Parameter(Mandatory)]$Events, [Parameter(Mandatory)][string]$Path)
    $out = foreach ($e in $Events) {
        [ordered]@{
            EventId = $e.EventId; RecordId = $e.RecordId; Time = $e.Time.ToString('o'); Account = $e.Account
            Source = $e.Source; LogonType = $e.LogonType; Workstation = $e.Workstation; Status = $e.Status
        } | ConvertTo-Json -Compress
    }
    [IO.File]::WriteAllLines($Path, [string[]]@($out))
}

function New-LwBaseline { @{ Accounts = @{} } }

function Test-LwCounts($e) {
    $e.EventId -eq 4624 -and $script:CountedTypes -contains $e.LogonType -and $e.Account `
        -and -not $e.Account.EndsWith('$') -and $e.Account -ne 'ANONYMOUS LOGON'
}

function Add-LwBaselineEvent($Baseline, $e) {
    $key = $e.Account.ToLowerInvariant()
    if (-not $Baseline.Accounts.ContainsKey($key)) {
        $Baseline.Accounts[$key] = @{ Total = 0; Hours = (New-Object 'int[]' 24); Sources = @{} }
    }
    $a = $Baseline.Accounts[$key]
    $a.Total++
    $a.Hours[$e.Time.Hour]++
    if ($e.Source) {
        if ($a.Sources.ContainsKey($e.Source)) { $a.Sources[$e.Source]++ } else { $a.Sources[$e.Source] = 1 }
    }
}

function Update-LwBaseline {
    param($Baseline, [Parameter(Mandatory)]$Events)
    if (-not $Baseline) { $Baseline = New-LwBaseline }
    foreach ($e in ($Events | Sort-Object Time, RecordId)) {
        if (Test-LwCounts $e) { Add-LwBaselineEvent $Baseline $e }
    }
    $Baseline
}

function Copy-LwBaseline($Baseline) {
    $copy = New-LwBaseline
    foreach ($k in $Baseline.Accounts.Keys) {
        $a = $Baseline.Accounts[$k]
        $copy.Accounts[$k] = @{ Total = $a.Total; Hours = [int[]]$a.Hours.Clone(); Sources = $a.Sources.Clone() }
    }
    $copy
}

function Import-LwBaseline {
    param([Parameter(Mandatory)][string]$Path)
    $base = New-LwBaseline
    if (-not (Test-Path -LiteralPath $Path)) { return $base }
    try {
        $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
        foreach ($p in $j.Accounts.PSObject.Properties) {
            $a = $p.Value
            $hours = New-Object 'int[]' 24
            $h = @($a.Hours)
            if ($h.Count -ne 24) { throw 'Hours must have 24 entries' }
            for ($i = 0; $i -lt 24; $i++) { $hours[$i] = [int]$h[$i] }
            $src = @{}
            foreach ($q in $a.Sources.PSObject.Properties) { $src[$q.Name] = [int]$q.Value }
            $base.Accounts[$p.Name] = @{ Total = [int]$a.Total; Hours = $hours; Sources = $src }
        }
    }
    catch { throw "baseline file '$Path' is not valid: $($_.Exception.Message)" }
    $base
}

function Export-LwBaseline {
    param([Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)][string]$Path)
    $plain = @{}
    foreach ($k in $Baseline.Accounts.Keys) {
        $a = $Baseline.Accounts[$k]
        # a bare int[] in a hashtable serializes as {value,Count} on 5.1
        $plain[$k] = @{ Total = $a.Total; Hours = @($a.Hours | ForEach-Object { $_ }); Sources = $a.Sources }
    }
    @{ Accounts = $plain } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding ASCII
}

function New-LwFinding($Type, $Severity, $Source, $Account, $Events, [string]$Summary) {
    $sorted = @($Events | Sort-Object Time, RecordId)
    [pscustomobject]@{
        Type      = $Type
        Severity  = $Severity
        Source    = $Source
        Account   = $Account
        Start     = $sorted[0].Time
        End       = $sorted[-1].Time
        Count     = $sorted.Count
        Summary   = $Summary
        RecordIds = @($sorted | ForEach-Object { $_.RecordId })
        Events    = $sorted
    }
}

function Find-LwRuns($Items, [double]$Minutes, [scriptblock]$Test) {
    $n = $Items.Count
    $mark = New-Object 'bool[]' $n
    for ($i = 0; $i -lt $n; $i++) {
        $j = $i
        while ($j + 1 -lt $n -and ($Items[$j + 1].Time - $Items[$i].Time).TotalMinutes -le $Minutes) { $j++ }
        if (& $Test @($Items[$i..$j])) { for ($k = $i; $k -le $j; $k++) { $mark[$k] = $true } }
    }
    $runs = New-Object System.Collections.Generic.List[object]
    $cur = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $n; $i++) {
        if ($mark[$i]) { $cur.Add($Items[$i]) }
        elseif ($cur.Count) { $runs.Add($cur.ToArray()); $cur = New-Object System.Collections.Generic.List[object] }
    }
    if ($cur.Count) { $runs.Add($cur.ToArray()) }
    , $runs
}

function Format-LwMinutes($Events) {
    $s = @($Events | Sort-Object Time)
    '{0:N1}' -f ($s[-1].Time - $s[0].Time).TotalMinutes
}

function Get-LwFindings {
    param([Parameter(Mandatory)]$Events, [hashtable]$Config = @{}, $Baseline)
    $c = $script:Defaults.Clone()
    foreach ($k in $Config.Keys) { $c[$k] = $Config[$k] }
    $sorted = @($Events | Sort-Object Time, RecordId)
    $findings = New-Object System.Collections.Generic.List[object]
    $th = [int]$c.BurstThreshold
    $sp = [int]$c.SprayAccounts

    $fails = @($sorted | Where-Object { $_.EventId -eq 4625 -and $_.Source })
    foreach ($g in ($fails | Group-Object Source)) {
        $items = @($g.Group)
        $sprayRuns = Find-LwRuns $items $c.SprayWindowMinutes { param($s) @($s | ForEach-Object Account | Sort-Object -Unique).Count -ge $sp }
        foreach ($run in $sprayRuns) {
            $accts = @($run | ForEach-Object Account | Sort-Object -Unique)
            $findings.Add((New-LwFinding 'PasswordSpray' 'High' $g.Name '' $run `
                        "$($accts.Count) different accounts failed from $($g.Name) in $(Format-LwMinutes $run) min ($($run.Count) failures: $($accts -join ', '))"))
        }
        $burstRuns = Find-LwRuns $items $c.BurstWindowMinutes { param($s) $s.Count -ge $th }
        foreach ($run in $burstRuns) {
            $ids = @($run | ForEach-Object RecordId)
            $covered = $false
            foreach ($sr in $sprayRuns) { if (@($sr | Where-Object { $ids -contains $_.RecordId }).Count) { $covered = $true } }
            if ($covered) { continue }
            $accts = @($run | ForEach-Object Account | Sort-Object -Unique)
            $types = @($run | ForEach-Object LogonType | Sort-Object -Unique)
            $sev = if ($run.Count -ge 2 * $th) { 'High' } else { 'Medium' }
            $findings.Add((New-LwFinding 'FailureBurst' $sev $g.Name '' $run `
                        "$($run.Count) failed logons from $($g.Name) in $(Format-LwMinutes $run) min (accounts: $($accts -join ', '); logon types: $($types -join ', '))"))
        }
    }

    $seen = @{}
    foreach ($s in ($sorted | Where-Object { $_.EventId -eq 4624 -and $_.Source })) {
        $key = "$($s.Source)|$($s.Account.ToLowerInvariant())"
        if ($seen.ContainsKey($key)) { continue }
        $before = @($fails | Where-Object {
                $_.Source -eq $s.Source -and $_.Account -eq $s.Account -and $_.Time -le $s.Time `
                    -and ($s.Time - $_.Time).TotalMinutes -le $c.SuccessWindowMinutes
            })
        if ($before.Count -ge $c.SuccessAfterFailures) {
            $seen[$key] = $true
            $ev = @($before) + @($s)
            $findings.Add((New-LwFinding 'SuccessAfterFailures' 'High' $s.Source $s.Account $ev `
                        "$($s.Account) logged on from $($s.Source) (type $($s.LogonType)) after $($before.Count) failures from the same source in $(Format-LwMinutes $ev) min"))
        }
    }

    $base = if ($Baseline) { Copy-LwBaseline $Baseline } else { New-LwBaseline }
    $odd = [ordered]@{}
    $new = [ordered]@{}
    foreach ($e in ($sorted | Where-Object { Test-LwCounts $_ })) {
        $key = $e.Account.ToLowerInvariant()
        if ($base.Accounts.ContainsKey($key) -and $base.Accounts[$key].Total -ge $c.MinBaselineLogons) {
            $a = $base.Accounts[$key]
            $h = $e.Time.Hour
            $near = $a.Hours[($h + 23) % 24] + $a.Hours[$h] + $a.Hours[($h + 1) % 24]
            $isOdd = $near -eq 0
            $isNew = $e.Source -and -not $a.Sources.ContainsKey($e.Source)
            if ($isOdd) { if (-not $odd.Contains($key)) { $odd[$key] = @() }; $odd[$key] += $e }
            if ($isNew) {
                $nk = "$key|$($e.Source)"
                if (-not $new.Contains($nk)) { $new[$nk] = @() }
                $new[$nk] += $e
            }
            if ($isOdd -or $isNew) { continue }
        }
        Add-LwBaselineEvent $base $e
    }
    foreach ($key in $odd.Keys) {
        $evs = @($odd[$key])
        $a = $base.Accounts[$key]
        $usual = @(0..23 | Where-Object { $a.Hours[$_] -gt 0 } | ForEach-Object { '{0:00}' -f $_ }) -join ','
        $when = @($evs | ForEach-Object { $_.Time.ToString('HH:mm') }) -join ', '
        $findings.Add((New-LwFinding 'OddHour' 'Medium' (($evs | Where-Object Source | Select-Object -First 1 | ForEach-Object Source)) $evs[0].Account $evs `
                    "$($evs[0].Account) logged on at $when, outside the usual hours (baseline of $($a.Total) logons active in hours $usual)"))
    }
    foreach ($nk in $new.Keys) {
        $evs = @($new[$nk])
        $a = $base.Accounts[$nk.Split('|')[0]]
        $known = @($a.Sources.Keys | Sort-Object | Select-Object -First 4) -join ', '
        $findings.Add((New-LwFinding 'NewSource' 'Medium' $evs[0].Source $evs[0].Account $evs `
                    "$($evs[0].Account) logged on from $($evs[0].Source), not among the $($a.Sources.Count) sources seen in $($a.Total) earlier logons ($known)"))
    }
    @($findings | Sort-Object @{ Expression = { @{ High = 0; Medium = 1; Low = 2 }[$_.Severity] } }, Start)
}

function Format-LwFinding {
    param([Parameter(Mandatory)]$Finding, [int]$MaxIds = 12)
    $ids = @($Finding.RecordIds)
    $shown = ($ids | Select-Object -First $MaxIds) -join ','
    if ($ids.Count -gt $MaxIds) { $shown += " (+$($ids.Count - $MaxIds) more)" }
    $who = @($Finding.Source, $Finding.Account | Where-Object { $_ }) -join ' / '
    "[{0}] {1} {2}`n    {3}`n    {4:yyyy-MM-dd HH:mm:ss} .. {5:HH:mm:ss}  record ids: {6}" -f `
        $Finding.Severity.ToUpper(), $Finding.Type, $who, $Finding.Summary, $Finding.Start, $Finding.End, $shown
}

function Test-LwPrivateAddress([string]$Address) {
    $ip = $null
    if (-not [IPAddress]::TryParse($Address, [ref]$ip)) { return $true }
    if ([IPAddress]::IsLoopback($ip)) { return $true }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq 'InterNetworkV6') {
        return ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast -or ($b[0] -band 0xFE) -eq 0xFC -or -not ($b | Where-Object { $_ }))
    }
    if ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0 -or $b[0] -ge 224) { return $true }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $true }
    $false
}

function Get-LwProtectedSources {
    param($Events = @())
    $p = New-Object System.Collections.Generic.HashSet[string]
    try {
        foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($u in $nic.GetIPProperties().UnicastAddresses) { [void]$p.Add($u.Address.IPAddressToString) }
        }
    }
    catch { }
    foreach ($v in $env:SSH_CLIENT, $env:SSH_CONNECTION) { if ($v) { [void]$p.Add($v.Split(' ')[0]) } }
    try {
        foreach ($c in (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Stop)) { [void]$p.Add($c.RemoteAddress) }
    }
    catch { }
    $mine = @($Events | Where-Object { $_.EventId -eq 4624 -and $_.Account -eq $env:USERNAME -and $_.Source } | Sort-Object Time | Select-Object -Last 1)
    if ($mine.Count) { [void]$p.Add($mine[0].Source) }
    @($p)
}

function Get-LwBlockCommand {
    param([Parameter(Mandatory)][string]$Address)
    $ip = $null
    if (-not [IPAddress]::TryParse($Address, [ref]$ip)) { throw "not an IP address: $Address" }
    $a = $ip.ToString()
    "netsh advfirewall firewall add rule name=`"loginwatch-$a`" dir=in action=block remoteip=$a enable=yes"
}

function Get-LwBlockCandidates {
    param([Parameter(Mandatory)]$Findings)
    @($Findings | Where-Object { $_.Type -in 'FailureBurst', 'PasswordSpray', 'SuccessAfterFailures' -and $_.Source } |
            ForEach-Object Source | Sort-Object -Unique)
}

$script:LwFirewall = $script:LwFirewallReal = @{
    Exists = { param($Name) [bool](Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue) }
    Add    = {
        param($Name, $Address)
        $out = & netsh advfirewall firewall add rule name="$Name" dir=in action=block remoteip=$Address enable=yes 2>&1
        [pscustomobject]@{ Ok = ($LASTEXITCODE -eq 0); Detail = ($out | Out-String).Trim() }
    }
}

# test hook: swap the firewall layer, pass $null to restore the real one
function Set-LwFirewall($Exists, $Add) {
    if ($Exists -and $Add) { $script:LwFirewall = @{ Exists = $Exists; Add = $Add } }
    else { $script:LwFirewall = $script:LwFirewallReal }
}

function Invoke-LwBlock {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string[]]$Address, [string[]]$Protected = @())
    if (-not $WhatIfPreference -and [object]::ReferenceEquals($script:LwFirewall, $script:LwFirewallReal) -and -not (Test-LwAdmin)) { throw 'creating firewall rules needs an elevated prompt' }
    foreach ($raw in $Address) {
        $ip = $null
        if (-not [IPAddress]::TryParse($raw, [ref]$ip)) { [pscustomobject]@{ Address = $raw; Action = 'skipped'; Detail = 'not an IP address' }; continue }
        $a = $ip.ToString()
        if (Test-LwPrivateAddress $a) { [pscustomobject]@{ Address = $a; Action = 'skipped'; Detail = 'private, loopback or reserved range' }; continue }
        if ($Protected -contains $a) { [pscustomobject]@{ Address = $a; Action = 'skipped'; Detail = 'source of this machine or current session' }; continue }
        $name = "loginwatch-$a"
        $exists = $false
        try { $exists = [bool](& $script:LwFirewall.Exists $name) } catch { }
        if ($exists) { [pscustomobject]@{ Address = $a; Action = 'exists'; Detail = "$name already present, not added again" }; continue }
        if ($PSCmdlet.ShouldProcess($a, "add inbound block firewall rule '$name'")) {
            $r = & $script:LwFirewall.Add $name $a
            $act = if ($r.Ok) { 'blocked' } else { 'failed' }
            [pscustomobject]@{ Address = $a; Action = $act; Detail = $r.Detail }
        }
        else { [pscustomobject]@{ Address = $a; Action = 'would block'; Detail = $name } }
    }
}

function Remove-LwBlock {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()
    if (-not $WhatIfPreference -and -not (Test-LwAdmin)) { throw 'removing firewall rules needs an elevated prompt' }
    $rules = @(Get-NetFirewallRule -DisplayName 'loginwatch-*' -ErrorAction SilentlyContinue)
    foreach ($r in $rules) {
        if ($PSCmdlet.ShouldProcess($r.DisplayName, 'remove firewall rule')) {
            Remove-NetFirewallRule -Name $r.Name
            [pscustomobject]@{ Rule = $r.DisplayName; Action = 'removed' }
        }
        else { [pscustomobject]@{ Rule = $r.DisplayName; Action = 'would remove' } }
    }
}

function New-LwSampleEvents {
    $script:rid = 1000
    $list = New-Object System.Collections.Generic.List[object]
    $at = { param($day, $h, $m, $s) ([DateTimeOffset]::new(2024, 3, $day, $h, $m, 0, [TimeSpan]::Zero)).AddSeconds($s) }
    $add = {
        param($id, $t, $acct, $src, $type, $status)
        $script:rid++
        $list.Add((New-LwEvent $id $script:rid $t $acct $src $type '' $status))
    }
    $fail = '0xc000006a'
    for ($d = 1; $d -le 14; $d++) {
        & $add 4624 (& $at $d 9 5 0) 'alice' '198.51.100.10' 10 ''
        & $add 4634 (& $at $d 12 30 0) 'alice' '' 10 ''
        & $add 4624 (& $at $d 10 15 0) 'alice' '198.51.100.20' 3 ''
        & $add 4624 (& $at $d 14 0 0) 'bob' '198.51.100.21' 3 ''
        & $add 4624 (& $at $d 15 30 0) 'bob' '198.51.100.21' 3 ''
    }
    & $add 4625 (& $at 15 8 59 0) 'alice' '198.51.100.10' 10 $fail
    & $add 4624 (& $at 15 9 0 0) 'alice' '198.51.100.10' 10 ''

    for ($i = 0; $i -lt 14; $i++) { & $add 4625 (& $at 15 2 10 ($i * 17)) 'admin' '192.0.2.66' 3 $fail }
    & $add 4624 (& $at 15 2 15 0) 'admin' '192.0.2.66' 3 ''
    & $add 4672 (& $at 15 2 15 1) 'admin' '' 0 ''

    $names = 'alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'svc-backup'
    for ($i = 0; $i -lt $names.Count; $i++) { & $add 4625 (& $at 15 19 40 ($i * 50)) $names[$i] '192.0.2.77' 10 $fail }

    for ($i = 0; $i -lt 9; $i++) { & $add 4625 (& $at 15 11 0 ($i * 40)) 'administrator' '192.0.2.88' 10 $fail }
    for ($i = 0; $i -lt 2; $i++) { & $add 4625 (& $at 15 14 20 ($i * 30)) 'guest' '192.0.2.201' 3 $fail }
    & $add 4776 (& $at 15 14 21 0) 'guest' '' 0 '0xc000006a'

    & $add 4624 (& $at 15 3 12 0) 'alice' '192.0.2.150' 10 ''
    $list.ToArray()
}

Export-ModuleMember -Function Import-LwEvents, Import-LwJsonLines, Import-LwEvtx, Import-LwLive, ConvertFrom-LwXml,
Export-LwJsonLines, New-LwEvent, New-LwBaseline, Update-LwBaseline, Import-LwBaseline, Export-LwBaseline, Get-LwFindings,
Format-LwFinding, Test-LwPrivateAddress, Test-LwAdmin, Get-LwProtectedSources, Get-LwBlockCommand, Get-LwBlockCandidates,
Invoke-LwBlock, Remove-LwBlock, Set-LwFirewall, New-LwSampleEvents
