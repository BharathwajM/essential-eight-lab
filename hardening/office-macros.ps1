<#  Essential Eight #3 - Configure Microsoft Office macro settings.
    Sets the enterprise policy that disables macros (with notification) and blocks
    macros that originate from the internet, for Word/Excel/PowerPoint. The keys are
    the same ones Group Policy writes, so the control is in force whether or not
    Office is currently installed. Run elevated. #>
$ErrorActionPreference = 'Stop'
$ver = '16.0'
foreach ($app in 'word', 'excel', 'powerpoint') {
    $key = "HKLM:\SOFTWARE\Policies\Microsoft\office\$ver\$app\security"
    New-Item -Path $key -Force | Out-Null
    # vbawarnings: 3 = disable all macros with notification (4 = disable without notification)
    New-ItemProperty -Path $key -Name 'vbawarnings' -Value 3 -PropertyType DWord -Force | Out-Null
    # block macros in files downloaded from the internet (Mark-of-the-Web)
    New-ItemProperty -Path $key -Name 'blockcontentexecutionfrominternet' -Value 1 -PropertyType DWord -Force | Out-Null
}
Write-Output 'Office macro policy applied: macros disabled (with notification) and internet macros blocked for Word/Excel/PowerPoint.'
