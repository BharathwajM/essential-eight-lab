<#  Essential Eight #5 - Restrict administrative privileges.
    Removes ordinary domain users from the local Administrators group, disables the
    built-in Administrator account, and re-enables User Account Control. Run elevated.
    Note: re-enabling UAC takes effect on the next reboot. #>
$ErrorActionPreference = 'Continue'

# --- Remove standard (non-admin) domain users from local Administrators ---
$standard = 'jsmith', 'agarcia', 'bchen', 'dkumar', 'efoster', 'mokafor', 'pnguyen', 'rlopez', 'twilson', 'ysato'
$removed = @()
$members = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
foreach ($m in $members) {
    $leaf = ($m.Name -split '\\')[-1]
    if ($standard -contains $leaf) {
        Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name -ErrorAction SilentlyContinue
        $removed += $m.Name
    }
}
Write-Output ("Local Administrators: removed {0} standard user(s){1}." -f $removed.Count,
    $(if ($removed) { " ($($removed -join ', '))" } else { '' }))

# --- Disable the built-in Administrator account ---
$builtin = Get-LocalUser -Name 'Administrator' -ErrorAction SilentlyContinue
if ($builtin -and $builtin.Enabled) {
    Disable-LocalUser -Name 'Administrator'
    Write-Output 'Built-in Administrator account disabled.'
} else {
    Write-Output 'Built-in Administrator already disabled.'
}

# --- Re-enable User Account Control (was turned off for the VirtualBox lab) ---
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
New-ItemProperty -Path $sys -Name 'EnableLUA' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $sys -Name 'ConsentPromptBehaviorAdmin' -Value 5 -PropertyType DWord -Force | Out-Null
Write-Output 'User Account Control re-enabled (effective after reboot).'
