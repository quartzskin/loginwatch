[CmdletBinding()]
param(
    [string]$Path,
    [switch]$Live,
    [switch]$Sample,
    [int]$Hours = 24,
    [switch]$SelfTest,
    [string]$Png
)

$ErrorActionPreference = 'Stop'
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    [Console]::Error.WriteLine('loginwatch-gui: needs an STA thread, run it with powershell.exe -STA -File loginwatch-gui.ps1')
    exit 2
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Import-Module (Join-Path $PSScriptRoot 'LoginWatch.psm1') -Force

$xaml = @'
<Grid xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
      xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
      Width="1000" Height="640" Background="{x:Static SystemColors.ControlBrush}">
  <Grid.RowDefinitions>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="*"/>
    <RowDefinition Height="Auto"/>
    <RowDefinition Height="*"/>
    <RowDefinition Height="Auto"/>
  </Grid.RowDefinitions>
  <StackPanel Orientation="Horizontal" Margin="8">
    <Label Content="Source:" VerticalAlignment="Center"/>
    <ComboBox x:Name="Kind" Width="90" VerticalAlignment="Center" SelectedIndex="0">
      <ComboBoxItem Content="Live log"/>
      <ComboBoxItem Content="File"/>
    </ComboBox>
    <TextBox x:Name="PathBox" Width="420" Margin="8,0,0,0" VerticalContentAlignment="Center" IsEnabled="False"/>
    <Button x:Name="Browse" Content="Browse..." Margin="4,0,0,0" Padding="10,2" IsEnabled="False"/>
    <Button x:Name="LoadBtn" Content="Load" Margin="8,0,0,0" Padding="14,2" IsDefault="True"/>
  </StackPanel>
  <DataGrid x:Name="Findings" Grid.Row="1" Margin="8,0,8,0" AutoGenerateColumns="False" IsReadOnly="True"
            SelectionMode="Single" HeadersVisibility="Column" GridLinesVisibility="Horizontal">
    <DataGrid.Columns>
      <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="70"/>
      <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="140"/>
      <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="120"/>
      <DataGridTextColumn Header="Accounts" Binding="{Binding Accounts}" Width="330"/>
      <DataGridTextColumn Header="Count" Binding="{Binding Count}" Width="50"/>
      <DataGridTextColumn Header="First seen" Binding="{Binding First}" Width="130"/>
      <DataGridTextColumn Header="Last seen" Binding="{Binding Last}" Width="130"/>
    </DataGrid.Columns>
  </DataGrid>
  <Grid Grid.Row="2" Margin="8,8,8,4">
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="*"/>
      <ColumnDefinition Width="Auto"/>
    </Grid.ColumnDefinitions>
    <TextBlock x:Name="Summary" TextWrapping="Wrap" VerticalAlignment="Center" Text="Select a finding to see its evidence."/>
    <Button x:Name="CopyBtn" Grid.Column="1" Content="Copy block command" Padding="10,2" Margin="8,0,0,0" IsEnabled="False"/>
  </Grid>
  <DataGrid x:Name="Evidence" Grid.Row="3" Margin="8,0,8,0" AutoGenerateColumns="False" IsReadOnly="True"
            HeadersVisibility="Column" GridLinesVisibility="Horizontal">
    <DataGrid.Columns>
      <DataGridTextColumn Header="Record id" Binding="{Binding RecordId}" Width="80"/>
      <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="140"/>
      <DataGridTextColumn Header="Event" Binding="{Binding Event}" Width="190"/>
      <DataGridTextColumn Header="Account" Binding="{Binding Account}" Width="170"/>
      <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="120"/>
      <DataGridTextColumn Header="Logon type" Binding="{Binding LogonType}" Width="80"/>
      <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="100"/>
    </DataGrid.Columns>
  </DataGrid>
  <TextBlock x:Name="Status" Grid.Row="4" Margin="8,4,8,6" TextWrapping="Wrap"/>
</Grid>
'@

$root = [Windows.Markup.XamlReader]::Parse($xaml)
$ui = @{}
foreach ($n in 'Kind', 'PathBox', 'Browse', 'LoadBtn', 'Findings', 'Summary', 'CopyBtn', 'Evidence', 'Status') { $ui[$n] = $root.FindName($n) }

$eventNames = @{ 4624 = 'logon'; 4625 = 'failed logon'; 4634 = 'logoff'; 4648 = 'explicit credentials'; 4672 = 'special privileges'; 4776 = 'credential validation' }
$fmt = 'yyyy-MM-dd HH:mm:ss'
$script:findings = @()

function ConvertTo-FindingRow($f) {
    $accounts = $f.Account
    if (-not $accounts) { $accounts = (@($f.Events | ForEach-Object Account | Where-Object { $_ } | Sort-Object -Unique)) -join ', ' }
    [pscustomobject]@{
        Severity = $f.Severity; Type = $f.Type; Source = $f.Source; Accounts = $accounts; Count = $f.Count
        First = $f.Start.ToString($fmt); Last = $f.End.ToString($fmt); Finding = $f
    }
}

function ConvertTo-EvidenceRow($e) {
    $name = $eventNames[$e.EventId]
    if (-not $name) { $name = 'other' }
    [pscustomobject]@{
        RecordId = $e.RecordId; Time = $e.Time.ToString($fmt); Event = "$($e.EventId) $name"; Account = $e.Account
        Source = $e.Source; LogonType = $e.LogonType; Status = $e.Status
    }
}

function Get-SelectedFinding {
    $row = $ui.Findings.SelectedItem
    if ($row) { $row.Finding }
}

# Null when the source is private or this machine's own, so the button never offers a self-block.
function Get-BlockText($f, $protected) {
    if (-not $f -or -not $f.Source -or $f.Type -notin 'FailureBurst', 'PasswordSpray', 'SuccessAfterFailures') { return $null }
    if ((Test-LwPrivateAddress $f.Source) -or ($protected -contains $f.Source)) { return $null }
    Get-LwBlockCommand $f.Source
}

function Show-Details {
    $f = Get-SelectedFinding
    $ui.Evidence.ItemsSource = $null
    if (-not $f) {
        $ui.Summary.Text = 'Select a finding to see its evidence.'
        $ui.CopyBtn.IsEnabled = $false
        return
    }
    $ui.Summary.Text = $f.Summary
    $ui.Evidence.ItemsSource = @($f.Events | ForEach-Object { ConvertTo-EvidenceRow $_ })
    $ui.CopyBtn.IsEnabled = [bool](Get-BlockText $f $script:protected)
}

function Set-Data($res, [string]$Label) {
    $script:findings = @()
    $script:protected = @()
    if (-not $res.Error) {
        $script:findings = @(Get-LwFindings -Events $res.Events)
        $script:protected = @(Get-LwProtectedSources -Events $res.Events)
    }
    $ui.Findings.ItemsSource = @($script:findings | ForEach-Object { ConvertTo-FindingRow $_ })
    Show-Details
    if ($res.Error) { $ui.Status.Text = "$Label : $($res.Error)"; return }
    $ui.Status.Text = "$Label : $(@($res.Events).Count) events, $(@($res.Skipped).Count) skipped, $($script:findings.Count) findings"
}

function Read-Selected {
    if ($ui.Kind.SelectedIndex -eq 0) {
        return @{ Res = (Import-LwEvents -Live -Hours $Hours); Label = "Security log, last $Hours h" }
    }
    $p = $ui.PathBox.Text.Trim()
    if (-not $p) { return @{ Res = (New-Object psobject -Property @{ Events = @(); Skipped = @(); Error = 'no file chosen' }); Label = 'File' } }
    @{ Res = (Import-LwEvents -Path $p); Label = (Split-Path -Leaf $p) }
}

function Update-Source {
    $file = $ui.Kind.SelectedIndex -eq 1
    $ui.PathBox.IsEnabled = $file
    $ui.Browse.IsEnabled = $file
}

function Invoke-Load {
    $l = Read-Selected
    Set-Data $l.Res $l.Label
}

$ui.Kind.Add_SelectionChanged({ Update-Source })
$ui.Findings.Add_SelectionChanged({ Show-Details })
$ui.LoadBtn.Add_Click({ Invoke-Load })
$ui.Browse.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Event logs (*.evtx;*.jsonl)|*.evtx;*.jsonl|All files (*.*)|*.*'
        if ($dlg.ShowDialog()) { $ui.PathBox.Text = $dlg.FileName }
    })
$ui.CopyBtn.Add_Click({
        $text = Get-BlockText (Get-SelectedFinding) $script:protected
        if ($text) {
            [Windows.Clipboard]::SetText($text)
            $ui.Status.Text = "Copied to clipboard (not run): $text"
        }
    })

if ($SelfTest -or $Sample) {
    $ui.Kind.SelectedIndex = 1
    $sampleRes = [pscustomobject]@{ Events = @(New-LwSampleEvents); Skipped = @(); Error = '' }
    Set-Data $sampleRes 'synthetic sample'
}
elseif ($Path) {
    $ui.Kind.SelectedIndex = 1
    $ui.PathBox.Text = $Path
    Invoke-Load
}
else {
    Invoke-Load
}

if ($SelfTest) {
    $spray = 0..($script:findings.Count - 1) | Where-Object { $script:findings[$_].Source -eq '192.0.2.66' -and $script:findings[$_].Type -eq 'FailureBurst' } | Select-Object -First 1
    $ui.Findings.SelectedIndex = $spray
    Show-Details
    $block = Get-BlockText (Get-SelectedFinding) @()
    $nonAttack = $script:findings | Where-Object { $_.Type -eq 'NewSource' } | Select-Object -First 1

    $ui.Kind.SelectedIndex = 1
    $ui.PathBox.Text = Join-Path ([IO.Path]::GetTempPath()) 'loginwatch-no-such-file.jsonl'
    $good = @{ Rows = $ui.Findings.ItemsSource; Status = $ui.Status.Text }
    Invoke-Load
    $errStatus = $ui.Status.Text
    $emptyAfterError = @($ui.Findings.ItemsSource).Count -eq 0
    $ui.PathBox.Text = ''
    $ui.Findings.ItemsSource = $good.Rows
    $ui.Status.Text = $good.Status
    $ui.Findings.SelectedIndex = $spray
    Show-Details

    $checks = @(
        @('finding rows', (@($good.Rows).Count -ge 5)),
        @('evidence rows', (@($ui.Evidence.ItemsSource).Count -ge 14)),
        @('evidence has record ids', (@($ui.Evidence.ItemsSource)[0].RecordId -gt 1000)),
        @('copy enabled for public attacker', $ui.CopyBtn.IsEnabled),
        @('block text is the netsh command only', ($block -eq 'netsh advfirewall firewall add rule name="loginwatch-192.0.2.66" dir=in action=block remoteip=192.0.2.66 enable=yes')),
        @('no block text for non-attack finding', (-not (Get-BlockText $nonAttack @()))),
        @('no block text for protected source', (-not (Get-BlockText (Get-SelectedFinding) @('192.0.2.66')))),
        @('missing file reports an error', ($errStatus -match 'not found')),
        @('missing file clears the table', $emptyAfterError)
    )
    $bad = @($checks | Where-Object { -not $_[1] } | ForEach-Object { $_[0] })
    if ($Png) {
        $w = 1000; $h = 640
        $root.Measure((New-Object Windows.Size $w, $h))
        $root.Arrange((New-Object Windows.Rect 0, 0, $w, $h))
        $root.UpdateLayout()
        $rtb = New-Object Windows.Media.Imaging.RenderTargetBitmap $w, $h, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
        $rtb.Render($root)
        $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
        $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($rtb))
        $out = if ([IO.Path]::IsPathRooted($Png)) { $Png } else { Join-Path (Get-Location).Path $Png }
        $fs = [IO.File]::Create($out)
        try { $enc.Save($fs) } finally { $fs.Dispose() }
        Write-Host "wrote $out"
    }
    if ($bad.Count) { [Console]::Error.WriteLine("SELFTEST FAILED: $($bad -join ', ')"); exit 1 }
    Write-Host "SELFTEST OK: $(@($good.Rows).Count) findings, $(@($ui.Evidence.ItemsSource).Count) evidence rows"
    exit 0
}

$win = New-Object Windows.Window
$win.Title = 'loginwatch'
$win.SizeToContent = 'WidthAndHeight'
$win.Content = $root
$win.Add_KeyDown({ param($sender, $a) if ($a.Key -eq 'F5') { Invoke-Load } })
[void]$win.ShowDialog()
