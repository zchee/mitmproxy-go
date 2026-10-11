# Collect native fixture evidence without converting interrupted counts to passes.
[CmdletBinding()]
param(
    [ValidateSet('Test', 'Finalize')][string]$Mode = 'Test',
    [Parameter(Mandatory)][string]$EvidenceDirectory,
    [string]$Manifest = "$PSScriptRoot/windows-fixture-evidence.txt",
    [ValidateRange(3, 3600)][int]$BudgetSeconds = 3600,
    [string]$GoExecutable = 'go'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $EvidenceDirectory | Out-Null
$EvidenceDirectory = (Resolve-Path $EvidenceDirectory).Path
$planPath = Join-Path $EvidenceDirectory 'commands.json'
$clock = [Diagnostics.Stopwatch]::StartNew()

function Save-Plan {
    ConvertTo-Json -Depth 8 -InputObject @($script:plan) | Set-Content $planPath
}

function Invoke-Bounded([string]$Executable, [string[]]$Arguments, [string]$LogName) {
    $stdout = Join-Path $EvidenceDirectory "$LogName.jsonl"
    $stderr = Join-Path $EvidenceDirectory "$LogName.stderr.log"
    # Starting a new process is forbidden once the tree-cleanup reserve begins.
    if ($clock.Elapsed.TotalSeconds -ge $BudgetSeconds - 2) {
        return @{ ExitCode = $null; Interrupted = $true; Reason = 'aggregate budget exhausted before start' }
    }
    $info = [Diagnostics.ProcessStartInfo]::new($Executable)
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $outFile = [IO.File]::Create($stdout)
    $errFile = [IO.File]::Create($stderr)
    $interrupted = $false
    try {
        if (-not $process.Start()) { throw "Failed to start $Executable" }
        $outTask = $process.StandardOutput.BaseStream.CopyToAsync($outFile)
        $errTask = $process.StandardError.BaseStream.CopyToAsync($errFile)
        while (-not $process.WaitForExit(100)) {
            if ($clock.Elapsed.TotalSeconds -ge $BudgetSeconds - 2) {
                $interrupted = $true
                $process.Kill($true)
                if (-not $process.WaitForExit(1000)) { throw 'Process-tree termination did not finish' }
                break
            }
        }
        if (-not [Threading.Tasks.Task]::WaitAll(@($outTask, $errTask), 1000)) {
            throw 'Process output did not finish draining after termination'
        }
        return @{ ExitCode = $process.ExitCode; Interrupted = $interrupted; Reason = $(if ($interrupted) { 'aggregate cutoff; process tree terminated' } else { 'process exited' }) }
    } finally {
        if ($process.Id -and -not $process.HasExited) { $process.Kill($true) }
        $outFile.Dispose()
        $errFile.Dispose()
        $process.Dispose()
    }
}

if ($Mode -eq 'Test') {
    $plan = @()
    try {
        if (-not (Test-Path -PathType Leaf $Manifest)) { throw "Missing manifest: $Manifest" }
        Copy-Item $Manifest (Join-Path $EvidenceDirectory 'manifest.txt')
        foreach ($line in Get-Content $Manifest) {
            if ($line -match '^\s*(#|$)') { continue }
            $fields = $line.Trim() -split '\s+'
            if ($fields.Count -ne 3 -or $fields[0] -notmatch '^\./[a-zA-Z0-9_/.-]+$') {
                throw "Invalid manifest row: $line"
            }
            $index = $plan.Count
            $arguments = @('test', '-race', '-count=20', '-cpu=1,2,8', '-timeout=60m', '-json', '-run', $fields[1])
            if ($fields[2] -ne '-') { $arguments += @('-tags', $fields[2]) }
            $arguments += $fields[0]
            $plan += [ordered]@{
                Package = $fields[0]; Pattern = $fields[1]; Tags = $fields[2]
                Count = 20; CPU = @(1, 2, 8); ExpectedOrdinaryExecutions = 60
                Arguments = $arguments; Log = "package-$index"
                Status = 'INCOMPLETE'; Reason = 'not started'; ExitCode = $null
                Identities = @(); Started = $null; Finished = $null
            }
        }
        if ($plan.Count -eq 0) { throw 'Empty intended test set' }
        Save-Plan
        @("aggregate-budget-seconds=$BudgetSeconds", 'cleanup-reserve-seconds=2') | Set-Content (Join-Path $EvidenceDirectory 'budget.txt')
        if ($IsWindows) {
            foreach ($protocol in @('tcp', 'udp')) {
                foreach ($kind in @('excludedportrange', 'dynamicport')) {
                    $arguments = @('int', 'ipv4', 'show', $kind)
                    $arguments += $(if ($kind -eq 'excludedportrange') { "protocol=$protocol" } else { $protocol })
                    $range = Invoke-Bounded 'netsh' $arguments "$kind-$protocol"
                    if ($range.Interrupted -or $range.ExitCode -ne 0) { throw "Could not record IPv4 $kind $protocol" }
                }
            }
        } else {
            'NON-NATIVE wrapper validation only; no Windows range evidence' | Set-Content (Join-Path $EvidenceDirectory 'non-native.txt')
        }
        foreach ($row in $plan) {
            $row.Started = & bash -c "date '+%Y-%m-%d %H:%M:%S %Z'"
            $row.Reason = 'inventory or tests interrupted'
            Save-Plan
            $inventoryArgs = @('test', '-race', '-list', $row.Pattern)
            if ($row.Tags -ne '-') { $inventoryArgs += @('-tags', $row.Tags) }
            $inventoryArgs += $row.Package
            $inventory = Invoke-Bounded $GoExecutable $inventoryArgs "$($row.Log)-inventory"
            if ($inventory.Interrupted) { $row.Reason = $inventory.Reason; Save-Plan; break }
            if ($inventory.ExitCode -ne 0) { throw "Test inventory failed for $($row.Package)" }
            $row.Identities = @(Get-Content (Join-Path $EvidenceDirectory "$($row.Log)-inventory.jsonl") | Where-Object { $_ -cmatch '^Test\S+$' })
            if ($row.Identities.Count -eq 0) { throw "Empty expanded test set for $($row.Package)" }
            Save-Plan
            $result = Invoke-Bounded $GoExecutable $row.Arguments $row.Log
            $row.ExitCode = $result.ExitCode
            $row.Reason = $result.Reason
            $row.Finished = & bash -c "date '+%Y-%m-%d %H:%M:%S %Z'"
            if (-not $result.Interrupted) { $row.Status = $(if ($result.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) }
            Save-Plan
            if ($result.Interrupted) { break }
        }
        if (@($plan | Where-Object { $_.Status -ne 'PASS' }).Count) { exit 1 }
    } catch {
        $_.ToString() | Set-Content (Join-Path $EvidenceDirectory 'interruption.log')
        if ($plan.Count) { Save-Plan }
        exit 1
    } finally {
        $clock.Stop()
        $clock.Elapsed.TotalSeconds.ToString('F3', [Globalization.CultureInfo]::InvariantCulture) | Set-Content (Join-Path $EvidenceDirectory 'aggregate-elapsed-seconds.txt')
    }
    exit 0
}

# This separate invocation is an always() step: it can recover partially written logs.
$failed = $false
$tallies = @()
try {
    if (-not (Test-Path $planPath)) { throw 'Tests did not produce an expanded command manifest' }
    $plan = @(Get-Content -Raw $planPath | ConvertFrom-Json)
    foreach ($row in $plan) {
        $identities = @{}
        foreach ($name in $row.Identities) {
            $identities[$name] = [ordered]@{ Test = $name; Pass = 0; Fail = 0; Skip = 0; Run = 0 }
        }
        $packageTerminal = $null
        $observedPackage = $null
        $log = Join-Path $EvidenceDirectory "$($row.Log).jsonl"
        if (Test-Path $log) {
            foreach ($line in [IO.File]::ReadLines($log)) {
                try { $event = $line | ConvertFrom-Json } catch {
                    $row.Status = 'INCOMPLETE'; $row.Reason = 'malformed or truncated JSON log'; continue
                }
                if ($event.Package) { $observedPackage = $event.Package }
                if (-not $event.Test) {
                    if ($event.Action -in @('pass', 'fail', 'skip')) { $packageTerminal = $event.Action }
                    continue
                }
                if (-not $identities.ContainsKey($event.Test)) {
                    $identities[$event.Test] = [ordered]@{ Test = $event.Test; Pass = 0; Fail = 0; Skip = 0; Run = 0 }
                }
                switch ($event.Action) {
                    'run' { $identities[$event.Test].Run++ }
                    'pass' { $identities[$event.Test].Pass++ }
                    'fail' { $identities[$event.Test].Fail++ }
                    'skip' { $identities[$event.Test].Skip++ }
                }
            }
        }
        if (-not $packageTerminal -or $row.Status -eq 'INCOMPLETE') { $row.Status = 'INCOMPLETE' }
        elseif ($packageTerminal -eq 'fail' -or $row.ExitCode -ne 0) { $row.Status = 'FAIL' }
        $packageTallies = @()
        foreach ($name in ($identities.Keys | Sort-Object)) {
            $counts = $identities[$name]
            $completed = $counts.Pass + $counts.Fail + $counts.Skip
            $status = $row.Status
            if ($status -ne 'INCOMPLETE' -and $counts.Fail -gt 0) { $status = 'FAIL' }
            elseif ($status -eq 'PASS' -and $completed -gt 0 -and $counts.Skip -eq $completed) { $status = 'SKIP' }
            # Inventory lists ordinary top-level identities; nested rows retain observed counts.
            if ($name -in $row.Identities -and $completed -ne $row.ExpectedOrdinaryExecutions) { $status = 'INCOMPLETE' }
            if ($counts.Run -gt $completed) { $status = 'INCOMPLETE' }
            if ($status -eq 'INCOMPLETE') { $row.Status = 'INCOMPLETE' }
            $packageTallies += [ordered]@{ Package = $row.Package; ResolvedPackage = $observedPackage; Test = $name; Status = $status; Counts = $counts; ObservedCompletions = $completed; ExpectedOrdinaryExecutions = $(if ($name -in $row.Identities) { 60 } else { $null }); Interruption = $row.Reason }
        }
        if ($row.Status -eq 'INCOMPLETE') {
            foreach ($tally in $packageTallies) { $tally.Status = 'INCOMPLETE' }
        }
        $tallies += $packageTallies
        if ($row.Status -ne 'PASS') { $failed = $true }
    }
    Save-Plan
    ConvertTo-Json -Depth 8 -InputObject @($tallies) | Set-Content (Join-Path $EvidenceDirectory 'tallies.json')
} catch {
    $failed = $true
    $_.ToString() | Set-Content (Join-Path $EvidenceDirectory 'finalization-error.log')
} finally {
    $(if ($failed) { 'INCOMPLETE_OR_FAILED' } else { 'COMPLETE' }) | Set-Content (Join-Path $EvidenceDirectory 'result.txt')
    Get-ChildItem -File $EvidenceDirectory | Where-Object { $_.Name -ne 'SHA256SUMS' } | Sort-Object Name | ForEach-Object {
        "$( (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant())  $($_.Name)"
    } | Set-Content (Join-Path $EvidenceDirectory 'SHA256SUMS')
}
if ($failed) { exit 1 }
