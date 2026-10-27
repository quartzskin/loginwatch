$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'LoginWatch.psm1') -Force

$script:pass = 0; $script:fail = 0
function Test-Case([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:pass++; Write-Host "ok   $Name" }
    catch { $script:fail++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function Assert($Cond, [string]$Msg = 'assertion failed') { if (-not $Cond) { throw $Msg } }

$tmp = Join-Path $PSScriptRoot '_tmp'
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function New-Ev($id, $rid, $min, $acct, $src, $type = 3) {
    New-LwEvent $id $rid ([DateTimeOffset]::new(2024, 3, 5, 12, 0, 0, [TimeSpan]::Zero).AddMinutes($min)) $acct $src $type '' ''
}
function Types($f) { @($f | ForEach-Object Type) }

Test-Case 'failure burst reports record ids' {
    $ev = 1..6 | ForEach-Object { New-Ev 4625 (100 + $_) ($_ * 0.5) 'u1' '192.0.2.10' }
    $f = @(Get-LwFindings -Events $ev)
    Assert ($f.Count -eq 1 -and $f[0].Type -eq 'FailureBurst')
    Assert (($f[0].RecordIds -join ',') -eq '101,102,103,104,105,106')
    Assert ($f[0].Summary -match '192.0.2.10')
}
Test-Case 'below threshold gives nothing' {
    $ev = 1..4 | ForEach-Object { New-Ev 4625 $_ $_ 'u1' '192.0.2.10' }
    Assert (@(Get-LwFindings -Events $ev).Count -eq 0)
}
Test-Case 'failures spread beyond the window are not a burst' {
    $ev = 1..6 | ForEach-Object { New-Ev 4625 $_ ($_ * 30) 'u1' '192.0.2.10' }
    Assert (@(Get-LwFindings -Events $ev).Count -eq 0)
}
Test-Case 'password spray is one finding, not also a burst' {
    $ev = 1..6 | ForEach-Object { New-Ev 4625 $_ $_ "user$_" '198.51.100.5' 10 }
    $f = @(Get-LwFindings -Events $ev)
    Assert ($f.Count -eq 1 -and $f[0].Type -eq 'PasswordSpray') "got $(Types $f)"
}
Test-Case 'success after failures includes the success record' {
    $ev = @(1..4 | ForEach-Object { New-Ev 4625 $_ $_ 'bob' '192.0.2.20' }) + (New-Ev 4624 99 6 'bob' '192.0.2.20')
    $f = @(Get-LwFindings -Events $ev | Where-Object Type -eq 'SuccessAfterFailures')
    Assert ($f.Count -eq 1)
    Assert ($f[0].RecordIds -contains 99)
}
Test-Case 'success from another source is not flagged' {
    $ev = @(1..4 | ForEach-Object { New-Ev 4625 $_ $_ 'bob' '192.0.2.20' }) + (New-Ev 4624 99 6 'bob' '192.0.2.21')
    Assert (@(Get-LwFindings -Events $ev | Where-Object Type -eq 'SuccessAfterFailures').Count -eq 0)
}
Test-Case 'sample data yields every finding type' {
    $t = Types (Get-LwFindings -Events (New-LwSampleEvents))
    foreach ($x in 'FailureBurst', 'PasswordSpray', 'SuccessAfterFailures', 'OddHour', 'NewSource') { Assert ($t -contains $x) "missing $x" }
}
Test-Case 'odd hour and new source need an established baseline' {
    $ev = @(New-Ev 4624 1 0 'carol' '198.51.100.9' 10)
    Assert (@(Get-LwFindings -Events $ev).Count -eq 0)
}
Test-Case 'saved baseline round trips and drives detection' {
    $hist = 1..30 | ForEach-Object { New-Ev 4624 $_ ($_ * 1440) 'carol' '198.51.100.9' 10 }
    $base = Update-LwBaseline -Events $hist
    $file = Join-Path $tmp 'base.json'
    Export-LwBaseline -Baseline $base -Path $file
    $loaded = Import-LwBaseline -Path $file
    $night = New-LwEvent 4624 500 ([DateTimeOffset]::new(2024, 6, 1, 3, 0, 0, [TimeSpan]::Zero)) 'carol' '192.0.2.99' 10 '' ''
    $t = Types (Get-LwFindings -Events @($night) -Baseline $loaded)
    Assert ($t -contains 'OddHour' -and $t -contains 'NewSource') "got $t"
}
Test-Case 'corrupt baseline file is rejected' {
    $file = Join-Path $tmp 'bad.json'
    Set-Content -LiteralPath $file -Value '{"Accounts":{"x":{"Total":1,"Hours":[1,2],"Sources":{}}}}'
    $threw = $false
    try { Import-LwBaseline -Path $file | Out-Null } catch { $threw = $true }
    Assert $threw
}
Test-Case 'machine accounts and anonymous logons are ignored by the baseline' {
    $ev = @(New-Ev 4624 1 0 'HOST$' '192.0.2.1'), (New-Ev 4624 2 1 'ANONYMOUS LOGON' '192.0.2.1')
    Assert ((Update-LwBaseline -Events $ev).Accounts.Count -eq 0)
}

Test-Case 'jsonl skips malformed lines and keeps good ones' {
    $file = Join-Path $tmp 'mixed.jsonl'
    $lines = @(
        '{"EventId":4625,"RecordId":1,"Time":"2024-03-05T12:00:00Z","Account":"u","Source":"192.0.2.5","LogonType":3}',
        'not json at all',
        '[1,2,3]',
        '{"EventId":4625,"Time":"2024-03-05T12:00:00Z"}',
        '{"EventId":9999,"RecordId":3,"Time":"2024-03-05T12:00:00Z"}',
        '{"EventId":4625,"RecordId":4,"Time":"yesterday-ish"}',
        '{"EventId":"abc","RecordId":5,"Time":"2024-03-05T12:00:00Z"}',
        '',
        '{"EventId":4624,"RecordId":7,"Time":"2024-03-05T12:01:00+00:00","Account":"u","Source":"::ffff:192.0.2.5","LogonType":"10"}')
    [IO.File]::WriteAllLines($file, $lines)
    $r = Import-LwJsonLines -Path $file
    Assert ($r.Events.Count -eq 2) "events $($r.Events.Count)"
    Assert ($r.Skipped.Count -eq 6) "skipped $($r.Skipped.Count)"
    Assert ($r.Events[1].Source -eq '192.0.2.5' -and $r.Events[1].LogonType -eq 10)
}
Test-Case 'missing file is an error result, not an exception' {
    $r = Import-LwEvents -Path (Join-Path $tmp 'nope.jsonl')
    Assert ($r.Error -match 'not found')
}
Test-Case 'empty file gives no events' {
    $file = Join-Path $tmp 'empty.jsonl'
    [IO.File]::WriteAllText($file, '')
    $r = Import-LwJsonLines -Path $file
    Assert ($r.Events.Count -eq 0 -and -not $r.Error)
}
Test-Case 'jsonl export then import is lossless' {
    $ev = New-LwSampleEvents
    $file = Join-Path $tmp 'rt.jsonl'
    Export-LwJsonLines -Events $ev -Path $file
    $r = Import-LwJsonLines -Path $file
    Assert ($r.Events.Count -eq $ev.Count -and $r.Skipped.Count -eq 0)
    Assert ($r.Events[10].RecordId -eq $ev[10].RecordId -and $r.Events[10].Time -eq $ev[10].Time)
}

$ns = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
function Xml($id, $rec, $data, $time = '2024-03-05T12:00:00.000000000Z') {
    "<Event $ns><System><EventID>$id</EventID><EventRecordID>$rec</EventRecordID><TimeCreated SystemTime='$time'/></System><EventData>$data</EventData></Event>"
}
Test-Case 'xml 4625 uses SubStatus and IpAddress' {
    $e = ConvertFrom-LwXml (Xml 4625 55 "<Data Name='TargetUserName'>u9</Data><Data Name='IpAddress'>192.0.2.7</Data><Data Name='LogonType'>10</Data><Data Name='Status'>0xc000006d</Data><Data Name='SubStatus'>0xc000006a</Data>")
    Assert ($e.RecordId -eq 55 -and $e.Source -eq '192.0.2.7' -and $e.LogonType -eq 10 -and $e.Status -eq '0xc000006a')
}
Test-Case 'xml 4624 and 4776 parse' {
    $a = ConvertFrom-LwXml (Xml 4624 1 "<Data Name='TargetUserName'>u</Data><Data Name='IpAddress'>-</Data><Data Name='LogonType'>2</Data>")
    Assert ($a.Source -eq '' -and $a.LogonType -eq 2)
    $b = ConvertFrom-LwXml (Xml 4776 2 "<Data Name='TargetUserName'>u</Data><Data Name='Workstation'>WS01</Data><Data Name='Status'>0xc000006a</Data>")
    Assert ($b.Workstation -eq 'WS01')
}
Test-Case 'malformed xml events return null' {
    Assert ($null -eq (ConvertFrom-LwXml '<Event><oops'))
    Assert ($null -eq (ConvertFrom-LwXml (Xml 4625 'x' '')))
    Assert ($null -eq (ConvertFrom-LwXml (Xml 4625 1 '' 'garbage')))
    Assert ($null -eq (ConvertFrom-LwXml (Xml 1102 1 '')))
    Assert ($null -eq (ConvertFrom-LwXml "<Event $ns><System/></Event>"))
}
Test-Case 'unreadable evtx is reported cleanly' {
    $file = Join-Path $tmp 'junk.evtx'
    [IO.File]::WriteAllText($file, 'this is not an evtx file')
    $r = Import-LwEvents -Path $file
    Assert ($r.Error -and $r.Events.Count -eq 0) "error was '$($r.Error)'"
}
Test-Case 'live read without rights returns a clear error (or events when elevated)' {
    $r = Import-LwEvents -Live -Hours 1 -MaxEvents 50
    if (Test-LwAdmin) { Assert (-not $r.Error -or $r.Error -match 'cannot read') }
    else { Assert ($r.Error -match 'access denied|cannot read') "got '$($r.Error)'"; Write-Host "     (non-elevated: $($r.Error))" }
}

Test-Case 'private, loopback and reserved ranges are recognised' {
    foreach ($a in '10.1.2.3', '172.16.0.1', '172.31.255.1', '192.168.1.1', '127.0.0.1', '169.254.1.1', '::1', 'fe80::1', 'fd00::1', '100.64.0.1', 'garbage') {
        Assert (Test-LwPrivateAddress $a) "$a should be private"
    }
    foreach ($a in '192.0.2.1', '198.51.100.7', '172.32.0.1', '8.8.8.8') { Assert (-not (Test-LwPrivateAddress $a)) "$a should be public" }
}
Test-Case 'block suggestion only prints a netsh command with the prefix' {
    $c = Get-LwBlockCommand '192.0.2.66'
    Assert ($c -eq 'netsh advfirewall firewall add rule name="loginwatch-192.0.2.66" dir=in action=block remoteip=192.0.2.66 enable=yes')
    $threw = $false
    try { Get-LwBlockCommand '1.2.3.4; calc' | Out-Null } catch { $threw = $true }
    Assert $threw
}
Test-Case 'block candidates skip non-attack findings' {
    $c = @(Get-LwBlockCandidates (Get-LwFindings -Events (New-LwSampleEvents)))
    Assert ($c -contains '192.0.2.66' -and $c -notcontains '192.0.2.150') "got $c"
}
Test-Case 'Invoke-LwBlock -WhatIf skips protected and private, changes nothing' {
    $r = @(Invoke-LwBlock -Address '192.0.2.66', '10.0.0.5', '192.0.2.77', 'bogus' -Protected '192.0.2.77' -WhatIf)
    $by = @{}; foreach ($x in $r) { $by[$x.Address] = $x.Action }
    Assert ($by['192.0.2.66'] -eq 'would block') "got $($by['192.0.2.66'])"
    Assert ($by['10.0.0.5'] -eq 'skipped' -and $by['192.0.2.77'] -eq 'skipped' -and $by['bogus'] -eq 'skipped')
}
Test-Case 'Invoke-LwBlock refuses to apply when not elevated' {
    if (Test-LwAdmin) { return }
    $threw = $false
    try { Invoke-LwBlock -Address '192.0.2.66' -Confirm:$false | Out-Null } catch { $threw = $_.Exception.Message -match 'elevated' }
    Assert $threw
}
Test-Case 'Remove-LwBlock -WhatIf runs without elevation' {
    @(Remove-LwBlock -WhatIf) | Out-Null
}
Test-Case 'cli: sample run exits 1, prints ids, creates no rules' {
    $ErrorActionPreference = 'Continue'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'loginwatch.ps1') -Sample -BlockSuggestion 2>&1 | Out-String
    Assert ($LASTEXITCODE -eq 1) "exit $LASTEXITCODE"
    Assert ($out -match 'record ids: 1073' -and $out -match 'netsh advfirewall')
}
Test-Case 'Invoke-LwBlock skips a rule that already exists and says so' {
    $script:added = @()
    Set-LwFirewall { param($n) $n -eq 'loginwatch-192.0.2.66' } { param($n, $a) $script:added += $a; [pscustomobject]@{ Ok = $true; Detail = 'Ok.' } }
    try {
        $r = @(Invoke-LwBlock -Address '192.0.2.66', '192.0.2.67' -Confirm:$false -WhatIf:$false)
    }
    finally { Set-LwFirewall $null $null }
    $by = @{}; foreach ($x in $r) { $by[$x.Address] = $x }
    Assert ($by['192.0.2.66'].Action -eq 'exists' -and $by['192.0.2.66'].Detail -match 'already present')
    Assert ($by['192.0.2.67'].Action -eq 'blocked')
    Assert (($script:added -join ',') -eq '192.0.2.67') "added $($script:added)"
}
Test-Case 'cli: -Sample -Apply -WhatIf keeps findings and creates nothing' {
    $ErrorActionPreference = 'Continue'
    $cli = Join-Path $root 'loginwatch.ps1'
    $plain = & powershell -NoProfile -ExecutionPolicy Bypass -File $cli -Sample -Json 2>&1 | Out-String
    $dry = & powershell -NoProfile -ExecutionPolicy Bypass -File $cli -Sample -Json -Apply -WhatIf 2>&1 | Out-String
    $n = @($plain | ConvertFrom-Json).Count
    Assert ($n -gt 0) 'no findings in plain run'
    Assert ($dry -notmatch 'What if: Retrieve') 'WhatIf leaked into pipeline'
    Assert ($dry -match 'would block' -and $dry -notmatch 'no sources worth blocking') 'no would-block output'
    Assert ($dry -notmatch '(?m)^[\d.]+\s+(blocked|failed)\s') 'a rule was attempted'
    $jsonPart = $dry.Substring(0, $dry.LastIndexOf(']') + 1)
    Assert (@($jsonPart | ConvertFrom-Json).Count -eq $n) 'finding count differs'
    Assert (($jsonPart -replace '\s', '') -eq ($plain.Trim() -replace '\s', '')) 'findings differ'
    Assert (-not (Get-NetFirewallRule -DisplayName 'loginwatch-192.0.2.66' -ErrorAction SilentlyContinue)) 'rule was created'
}
Test-Case 'cli: missing file exits 2 with message' {
    $ErrorActionPreference = 'Continue'
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'loginwatch.ps1') -Path (Join-Path $tmp 'nope.jsonl') 2>&1 | Out-String
    Assert ($LASTEXITCODE -eq 2 -and $out -match 'not found')
}
Test-Case 'gui: self test passes and renders a png' {
    $ErrorActionPreference = 'Continue'
    $png = Join-Path $tmp 'gui.png'
    $out = & powershell -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $root 'loginwatch-gui.ps1') -SelfTest -Png $png 2>&1 | Out-String
    Assert ($LASTEXITCODE -eq 0 -and $out -match 'SELFTEST OK') "exit $LASTEXITCODE : $out"
    $head = [IO.File]::ReadAllBytes($png)[0..3]
    Assert (($head -join ',') -eq '137,80,78,71') 'not a png'
}
Test-Case 'gui: refuses to run on an MTA thread' {
    $ErrorActionPreference = 'Continue'
    $out = & powershell -NoProfile -MTA -ExecutionPolicy Bypass -File (Join-Path $root 'loginwatch-gui.ps1') -SelfTest 2>&1 | Out-String
    Assert ($LASTEXITCODE -eq 2 -and $out -match 'STA') "exit $LASTEXITCODE"
}

Remove-Item -Recurse -Force $tmp
Write-Host "`n$script:pass passed, $script:fail failed"
if ($script:fail) { exit 1 }
exit 0
