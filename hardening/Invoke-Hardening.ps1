<#  Applies the implementable Essential Eight ML1 controls in order, from this folder.
    Controls 1, 3, 4 and 5 are enforced here; 2 (patch apps), 6 (patch OS), 7 (MFA)
    and 8 (backups) are process/infrastructure controls that the assessment reports
    on with remediation guidance. Run elevated. UAC re-enables on the next reboot. #>
$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
foreach ($step in 'application-control.ps1', 'office-macros.ps1', 'user-app-hardening.ps1', 'restrict-admin.ps1') {
    Write-Host "=== $step ===" -ForegroundColor Cyan
    & (Join-Path $here $step)
}
Write-Host "=== hardening complete (reboot to finish IE removal + UAC) ===" -ForegroundColor Green
