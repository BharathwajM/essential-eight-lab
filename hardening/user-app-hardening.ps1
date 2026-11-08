<#  Essential Eight #4 - User application hardening.
    Disables Internet Explorer 11, disables Windows Script Host, and enables a set of
    Microsoft Defender Attack Surface Reduction (ASR) rules that harden the common
    user-application execution paths (Office child processes, script/credential abuse,
    executable content from email/web). Run elevated. #>
$ErrorActionPreference = 'Continue'

# --- Disable Internet Explorer 11 (if still present as an optional feature) ---
$ie = Get-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -ErrorAction SilentlyContinue
if ($ie -and $ie.State -eq 'Enabled') {
    Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Write-Output 'Internet Explorer 11 optional feature disabled (reboot to complete).'
} else {
    Write-Output 'Internet Explorer 11 already disabled/removed.'
}

# --- Disable Windows Script Host (blocks .vbs/.js double-click execution) ---
$wsh = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
New-Item -Path $wsh -Force | Out-Null
New-ItemProperty -Path $wsh -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Output 'Windows Script Host disabled.'

# --- Enable Microsoft Defender ASR rules (Enabled = 1) ---
# Rule GUIDs: Office child process, Office exe content, Office code injection,
# obfuscated scripts, JS/VBS launching downloads, credential theft from LSASS,
# executable content from email client/webmail, untrusted USB processes.
$asr = @(
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a',  # Block Office apps creating child processes
    '3b576869-a4ec-4529-8536-b80a7769e899',  # Block Office apps creating executable content
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',  # Block Office apps injecting into other processes
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc',  # Block obfuscated JS/VBS/PS/macro scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d',  # Block JS/VBS launching downloaded executable content
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',  # Block credential stealing from LSASS
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',  # Block executable content from email/webmail
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'   # Block untrusted/unsigned processes from USB
)
foreach ($id in $asr) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
}
$enabled = 0
$ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$acts = (Get-MpPreference).AttackSurfaceReductionRules_Actions
if ($ids) { for ($i = 0; $i -lt $ids.Count; $i++) { if ($acts[$i] -eq 1) { $enabled++ } } }
Write-Output "User application hardening applied: $enabled ASR rule(s) enabled."
