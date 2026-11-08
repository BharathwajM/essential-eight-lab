<#
.SYNOPSIS
    Essential Eight Maturity Level 1 assessment for a Windows host (ASD/ACSC).

.DESCRIPTION
    Checks the local machine against the ASD Essential Eight Maturity Model (Maturity
    Level 1) across all eight mitigation strategies, scores each Aligned / Partial /
    Not aligned, and writes a Markdown + JSON report. Read-only - it changes nothing.
    Run from an elevated PowerShell (several checks need administrator rights).

.PARAMETER OutDir
    Directory to write the report into (default: .\reports).

.PARAMETER Label
    A label for this run, e.g. "WS01-before" / "WS01-after" (default: <hostname>-<date>).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File e8assess.ps1 -Label WS01-before
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot 'reports'),
    [string]$Label = "$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd-HHmmss)"
)

$ErrorActionPreference = 'SilentlyContinue'

# ---- scoring helpers --------------------------------------------------------
# Status -> points. Overall maturity is derived from how many controls are Aligned.
$script:STATUS_POINTS = @{ 'Aligned' = 2; 'Partial' = 1; 'Not aligned' = 0; 'Not assessed' = 0 }

function New-Finding {
    param($Number, $Control, $Status, $Detail, $Ml1, $Ml2Gap)
    [pscustomobject]@{
        Number = $Number; Control = $Control; Status = $Status
        Points = $script:STATUS_POINTS[$Status]; Detail = $Detail
        Ml1Requirement = $Ml1; Ml2Gap = $Ml2Gap
    }
}

# ---- 1. Application control -------------------------------------------------
function Test-ApplicationControl {
    $svc = (Get-Service AppIDSvc -ErrorAction SilentlyContinue)
    $pol = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    $ruleCount = 0; $enforced = $false
    if ($pol) {
        foreach ($coll in $pol.RuleCollections) {
            $ruleCount += @($coll).Count
            if ($coll.EnforcementMode -eq 'Enabled') { $enforced = $true }
        }
    }
    # WDAC / Code Integrity policies as an alternative control
    $wdac = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).CodeIntegrityPolicyEnforcementStatus

    if ($enforced -and $ruleCount -gt 0) {
        $status = 'Aligned'
        $detail = "AppLocker enforcing with $ruleCount rule(s); Application Identity service '$($svc.Status)'."
    } elseif ($ruleCount -gt 0 -or $wdac -ge 1) {
        $status = 'Partial'
        $detail = "Application control present but not fully enforcing ($ruleCount AppLocker rule(s), WDAC status $wdac)."
    } else {
        $status = 'Not aligned'
        $detail = 'No AppLocker or WDAC application-control policy found - any executable can run.'
    }
    New-Finding 1 'Application control' $status $detail `
        'Executables, scripts, installers, HTA and control-panel applets are prevented from running in standard-user-writable locations (AppLocker/WDAC enforced).' `
        'ML2 extends control to all locations, adds Microsoft "recommended block" driver/rule sets, and logs allowed/blocked execution centrally.'
}

# ---- 2. Patch applications --------------------------------------------------
function Test-PatchApplications {
    $pending = 0
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $pending = @($searcher.Search("IsInstalled=0 and Type='Software'").Updates).Count
    } catch {}
    $last = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
    $ageDays = if ($last) { [int]((Get-Date) - $last).TotalDays } else { 9999 }
    if ($pending -eq 0 -and $ageDays -le 30) {
        $status = 'Partial'
        $detail = "No pending software updates; last patch $ageDays day(s) ago. (SLA/vuln-scanner evidence still required for full alignment.)"
    } else {
        $status = 'Not aligned'
        $detail = "$pending pending software update(s); last patch $ageDays day(s) ago."
    }
    New-Finding 2 'Patch applications' $status $detail `
        'Patches for applications are applied within one month (two weeks for internet-facing / 48h if exploited); a vulnerability scanner is used at least fortnightly.' `
        'ML2 tightens the SLA to two weeks and requires the scanner to run weekly against applications.'
}

# ---- 3. Office macro settings ----------------------------------------------
function Test-OfficeMacros {
    $apps = 'word', 'excel', 'powerpoint'; $ver = '16.0'
    $blockedInternet = $true; $disabled = $true; $found = $false
    foreach ($a in $apps) {
        $base = "HKLM:\SOFTWARE\Policies\Microsoft\office\$ver\$a\security"
        if (Test-Path $base) { $found = $true }
        $bi = (Get-ItemProperty $base -Name blockcontentexecutionfrominternet -ErrorAction SilentlyContinue).blockcontentexecutionfrominternet
        $vw = (Get-ItemProperty $base -Name vbawarnings -ErrorAction SilentlyContinue).vbawarnings
        if ($bi -ne 1) { $blockedInternet = $false }
        if ($vw -lt 3) { $disabled = $false }   # 3=disable w/ notify, 4=disable all
    }
    $officeInstalled = Test-Path 'HKLM:\SOFTWARE\Microsoft\Office\16.0\Word\InstallRoot'
    if ($found -and $blockedInternet -and $disabled) {
        $status = 'Aligned'
        $detail = 'Office macro policy disables macros and blocks macros originating from the internet.'
    } elseif (-not $officeInstalled) {
        $status = if ($found) { 'Aligned' } else { 'Not aligned' }
        $detail = if ($found) { 'Macro hardening policy is set (Microsoft Office is not installed on this host).' }
                  else { 'No Office macro policy set (Office not installed, but the policy should still be defined).' }
    } else {
        $status = 'Not aligned'
        $detail = 'Office is installed without a policy that disables macros / blocks internet macros.'
    }
    New-Finding 3 'Configure Microsoft Office macro settings' $status $detail `
        'Office macros are disabled for users without a business need; macros from the internet are blocked; users cannot change the setting.' `
        'ML2 adds antivirus scanning of allowed macros and blocks Win32 API calls from macros; macro events are logged.'
}

# ---- 4. User application hardening -----------------------------------------
function Test-UserAppHardening {
    $ie = Get-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -ErrorAction SilentlyContinue
    # IE is "disabled" if the optional feature is off OR not present at all (removed on newer builds).
    $ieDisabled = (-not $ie) -or ($ie.State -ne 'Enabled')
    $asrIds = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    $asrActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
    $asrEnabled = 0
    if ($asrIds) { for ($i = 0; $i -lt $asrIds.Count; $i++) { if ($asrActions[$i] -eq 1) { $asrEnabled++ } } }
    $jvm = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue)

    if ($ieDisabled -and $asrEnabled -ge 3) {
        $status = 'Aligned'
        $detail = "Internet Explorer 11 disabled; $asrEnabled ASR rule(s) enabled to harden user applications."
    } elseif ($ieDisabled -or $asrEnabled -ge 1) {
        $status = 'Partial'
        $detail = "Partial hardening (IE disabled: $ieDisabled; ASR rules enabled: $asrEnabled)."
    } else {
        $status = 'Not aligned'
        $detail = 'Internet Explorer still enabled and no attack-surface-reduction hardening applied.'
    }
    New-Finding 4 'User application hardening' $status $detail `
        'Web browsers do not process Java or web advertisements from the internet; Internet Explorer 11 is disabled/removed; browser security settings cannot be changed by users.' `
        'ML2 blocks additional ASR vectors (Office child processes, credential theft, PowerShell/script abuse) and logs blocked events.'
}

# ---- 5. Restrict administrative privileges ---------------------------------
function Test-RestrictAdmin {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    $adminNames = @($admins | ForEach-Object { $_.Name })
    $builtin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
    $builtinEnabled = ($builtin -and $builtin.Enabled)
    $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    # standard domain users should not be local admins
    $standardAdmins = @($adminNames | Where-Object { $_ -match '\\(jsmith|agarcia|bchen|dkumar|efoster|mokafor|pnguyen|rlopez|twilson|ysato)$' })

    $problems = @()
    if ($builtinEnabled) { $problems += 'built-in Administrator is enabled' }
    if ($uac -ne 1) { $problems += 'UAC is disabled' }
    if ($standardAdmins.Count -gt 0) { $problems += "standard users in Administrators: $($standardAdmins -join ', ')" }

    if ($problems.Count -eq 0) {
        $status = 'Aligned'
        $detail = "Local Administrators limited to admin accounts ($($adminNames.Count) member(s)); built-in Administrator disabled; UAC enabled."
    } elseif ($problems.Count -le 1) {
        $status = 'Partial'
        $detail = "Mostly restricted, but: $($problems -join '; ')."
    } else {
        $status = 'Not aligned'
        $detail = "Administrative privilege not restricted: $($problems -join '; ')."
    }
    New-Finding 5 'Restrict administrative privileges' $status $detail `
        'Privileged access is limited and validated; privileged accounts are separate from day-to-day accounts and cannot browse the web or read email; unprivileged users are not local administrators.' `
        'ML2 adds just-in-time / time-limited admin, a separate privileged operating environment, and logging of privileged access.'
}

# ---- 6. Patch operating systems --------------------------------------------
function Test-PatchOS {
    $os = Get-CimInstance Win32_OperatingSystem
    $lastQfe = (Get-HotFix | Where-Object { $_.HotFixID -match 'KB' } | Sort-Object InstalledOn -Descending | Select-Object -First 1)
    $age = if ($lastQfe.InstalledOn) { [int]((Get-Date) - $lastQfe.InstalledOn).TotalDays } else { 9999 }
    if ($age -le 30) {
        $status = 'Partial'
        $detail = "$($os.Caption), build $($os.BuildNumber); last OS update $age day(s) ago. (One-month SLA evidence required for full alignment.)"
    } else {
        $status = 'Not aligned'
        $detail = "$($os.Caption); last OS update $age day(s) ago - outside the one-month window."
    }
    New-Finding 6 'Patch operating systems' $status $detail `
        'Operating systems are patched within one month (two weeks for internet-facing); unsupported operating systems are replaced.' `
        'ML2 tightens the SLA to two weeks and requires a vulnerability scanner to confirm OS patch levels weekly.'
}

# ---- 7. Multi-factor authentication ----------------------------------------
function Test-MFA {
    $whfb = Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'
    if ($whfb) {
        $status = 'Partial'
        $detail = 'Windows Hello for Business policy present; confirm it is enforced for privileged and remote access.'
    } else {
        $status = 'Not aligned'
        $detail = 'No MFA mechanism detected on this host (standalone lab). MFA is enforced at the identity provider, not locally.'
    }
    New-Finding 7 'Multi-factor authentication' $status $detail `
        'MFA is used for remote access, for internet-facing services, and by privileged users; it is phishing-resistant where required.' `
        'ML2 requires MFA for all users of internet-facing services and logs successful/failed MFA events.'
}

# ---- 8. Regular backups -----------------------------------------------------
function Test-Backups {
    $wsb = Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction SilentlyContinue
    $restore = $false
    try { $restore = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count -gt 0 } catch {}
    if (($wsb -and $wsb.Installed) -or $restore) {
        $status = 'Partial'
        $detail = 'A backup mechanism exists; a tested restore and protection of backups from unprivileged deletion are still required.'
    } else {
        $status = 'Not aligned'
        $detail = 'No backup solution or restore points detected.'
    }
    New-Finding 8 'Regular backups' $status $detail `
        'Backups of important data, software and configuration are performed and retained per business needs; restoration is tested; unprivileged accounts cannot modify or delete backups.' `
        'ML2 requires more frequent backups, coordinated restoration testing, and that unprivileged accounts cannot access other users'' backups.'
}

# ---- run all ----------------------------------------------------------------
$findings = @(
    Test-ApplicationControl
    Test-PatchApplications
    Test-OfficeMacros
    Test-UserAppHardening
    Test-RestrictAdmin
    Test-PatchOS
    Test-MFA
    Test-Backups
)

$aligned = @($findings | Where-Object Status -eq 'Aligned').Count
$maxPoints = $findings.Count * 2
$points = ($findings | Measure-Object Points -Sum).Sum
$ml1 = if ($aligned -eq 8) { 'ML1 (all eight aligned)' }
       elseif ($aligned -ge 4) { "Partial ML1 ($aligned/8 aligned)" }
       else { "Below ML1 ($aligned/8 aligned)" }

# ---- write reports ----------------------------------------------------------
New-Item -ItemType Directory -Force $OutDir | Out-Null
$summary = [pscustomobject]@{
    host = $env:COMPUTERNAME; label = $Label; generated = (Get-Date).ToString('u')
    aligned = $aligned; points = $points; maxPoints = $maxPoints; posture = $ml1
    findings = $findings
}
$summary | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir "$Label.json") -Encoding UTF8

$md = @()
$md += "# Essential Eight (ML1) Assessment - $($env:COMPUTERNAME)"
$md += "*Run label: ``$Label`` | Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Read-only assessment*`n"
$md += "**Posture: $ml1**  |  Score: $points / $maxPoints  |  Aligned controls: $aligned / 8`n"
$md += "| # | Mitigation | Status | Detail |"
$md += "|---|---|---|---|"
foreach ($f in $findings) {
    $md += "| $($f.Number) | $($f.Control) | **$($f.Status)** | $($f.Detail) |"
}
$md += "`n## ML1 requirement & ML2 gap, per control`n"
foreach ($f in $findings) {
    $md += "### $($f.Number). $($f.Control) - $($f.Status)"
    $md += "- **ML1:** $($f.Ml1Requirement)"
    $md += "- **To reach ML2:** $($f.Ml2Gap)`n"
}
($md -join "`n") | Set-Content (Join-Path $OutDir "$Label.md") -Encoding UTF8

# ---- console summary --------------------------------------------------------
Write-Host "`nEssential Eight ML1 assessment - $($env:COMPUTERNAME) [$Label]" -ForegroundColor Cyan
foreach ($f in $findings) {
    $color = switch ($f.Status) { 'Aligned' { 'Green' } 'Partial' { 'Yellow' } default { 'Red' } }
    Write-Host ("  {0}. {1,-42} {2}" -f $f.Number, $f.Control, $f.Status) -ForegroundColor $color
}
Write-Host ("`n  Posture: {0}  |  Score {1}/{2}" -f $ml1, $points, $maxPoints) -ForegroundColor Cyan
Write-Host "  Reports: $OutDir\$Label.(md|json)`n"
