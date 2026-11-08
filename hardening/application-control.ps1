<#  Essential Eight #1 - Application control (AppLocker).
    Applies an enforcing AppLocker policy with the standard default rules:
    standard users may only run from %PROGRAMFILES% and %WINDIR% (and
    administrators from anywhere). That implicitly blocks execution from
    user-writable locations (Downloads, Temp, AppData) - the ML1 requirement.
    Run elevated. #>
$ErrorActionPreference = 'Continue'

# Application Identity service must run for AppLocker to enforce. AppIDSvc is a
# protected service, so set its start type via the registry (Set-Service is denied)
# and start it. 2 = Automatic.
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc' -Name Start -Value 2 -ErrorAction SilentlyContinue
& sc.exe config AppIDSvc start= auto | Out-Null
Start-Service AppIDSvc -ErrorAction SilentlyContinue

$xml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default) All files in Program Files" Description="Allows members of the Everyone group to run applications in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default) All files in Windows folder" Description="Allows members of the Everyone group to run applications in the Windows folder, except user-writable subfolders." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions>
      <Exceptions>
        <FilePathCondition Path="%WINDIR%\Temp\*"/>
        <FilePathCondition Path="%WINDIR%\Tasks\*"/>
      </Exceptions></FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default) All files for Administrators" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="Enabled">
    <FilePathRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default) All Windows Installer files in Windows\Installer" Description="Allows members of the Everyone group to run digitally signed Windows Installer files." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\Installer\*"/></Conditions></FilePathRule>
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="(Default) All Windows Installer files for Administrators" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*.*"/></Conditions></FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="Enabled">
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="(Default) All scripts in Program Files" Description="Allows members of the Everyone group to run scripts in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="(Default) All scripts in Windows folder" Description="Allows members of the Everyone group to run scripts in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default) All scripts for Administrators" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@

$tmp = Join-Path $env:TEMP 'e8-applocker.xml'
Set-Content -Path $tmp -Value $xml -Encoding UTF8
Set-AppLockerPolicy -XmlPolicy $tmp
Remove-Item $tmp -Force
gpupdate /force | Out-Null
Restart-Service AppIDSvc -ErrorAction SilentlyContinue

$pol = Get-AppLockerPolicy -Effective
$n = ($pol.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Output "Application control applied: AppLocker enforcing, $n rule(s), AppIDSvc $((Get-Service AppIDSvc).Status)."
