# Essential Eight Workstation Checks and Hardening — WS01

**Target:** WS01 — Windows 11 Enterprise, domain-joined member of `soclab.local`
**Scope:** Selected [ASD Essential Eight Maturity Level 1](https://www.cyber.gov.au/publication/essential-eight-maturity-model) requirements on one lab workstation.
**Method:** baseline assessment → apply hardening → re-assess, using the repeatable
[`e8assess.ps1`](../e8assess.ps1) scoring tool. Full tool output is in
[`reports/`](../reports/) (`WS01-before` and `WS01-after`, Markdown + JSON).

---

## Result at a glance

| | Checks rated aligned by the tool | Internal lab score |
|---|---|---|
| **Before** | 0 / 8 | 2 / 16 |
| **After** | **4 / 8** | **8 / 16** |

The lab score compares the tool's local checks before and after hardening. The evidence below describes what WS01 demonstrated and where further validation is needed.

| # | Mitigation | Evidence status | What the lab shows |
|---|---|---|---|
| 1 | Application control | **Verified for EXE, MSI and CMD probes** | Event 8004 records the EXE block. Event 8007 records blocks of the MSI and CMD probes in the standard user's Downloads folder. |
| 2 | Patch applications | **Not assessed against the full requirement** | The host reported five pending software updates. Application patch timelines and scanner coverage need separate evidence. |
| 3 | Office macro settings | **Configured** | Word, Excel, and PowerPoint policy values were set. Effective macro behaviour in Office needs a functional test. |
| 4 | User application hardening | **Configured** | The after report records IE11 disabled and eight Defender ASR rules enabled. Browser controls and ASR enforcement were not functionally tested. |
| 5 | Restrict admin privileges | **Configured** | UAC was enabled, the built-in Administrator was disabled, and the local check looked for the lab's named standard accounts. Effective privileges and account separation need separate verification. |
| 6 | Patch operating systems | **Not assessed against the full requirement** | The last host update was 57 days old. Patch management across the environment needs separate evidence. |
| 7 | Multi-factor authentication | **Not assessed** | Verify enforcement and coverage at the identity provider. |
| 8 | Regular backups | **Not assessed** | Verify backup coverage, permissions, and a successful restore. |

---

## What was implemented (controls 1, 3, 4, 5)

Each control was applied with a documented, re-runnable script in
[`hardening/`](../hardening/).

### 1 — Application control (AppLocker)
Applied an **enforcing** AppLocker policy (Exe, MSI, Script collections) using the
lab policy for EXE, MSI and scripts, with the EXE allow rule excluding the writable Windows
Temp and Tasks paths. The Application Identity service was set to start automatically.
The captured tests cover an EXE, a no-op MSI and a CMD script in user-writable directories.

**Evidence — a standard user was actually blocked.** Running a copied executable from
a user-writable folder as the standard domain user `SOCLAB\jsmith` produced AppLocker
event **8004**:

```
Microsoft-Windows-AppLocker/EXE and DLL — Event 8004
%OSDRIVE%\USERS\PUBLIC\E8TEST\DOWNLOADED-APP.EXE was prevented from running.
```

**Follow-up MSI and script validation.** Two harmless probes were staged in the Downloads folder of `SOCLAB\jsmith` on WS01. The CMD file only echoed a marker. The MSI contained no payload or install actions and was invoked in administrative extraction mode. AppLocker blocked both under the standard user account.

| Probe | UTC timestamp | Windows event | Record | AppLocker outcome |
|---|---|---:|---:|---|
| `E8-Probe.cmd` | 2026-11-08 11:01:57.443 | 8007 | 10 | Prevented from running |
| `E8-Probe.msi` | 2026-11-08 11:01:58.902 | 8007 | 13 | Prevented from running |

The records are from `Microsoft-Windows-AppLocker/MSI and Script` on `WS01.soclab.local`. To reproduce, stage a harmless CMD script and a no-payload MSI in a standard user's Downloads directory. Run the commands below under that account, then check that event 8007 names each probe. See [Microsoft's AppLocker event reference](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker).

```cmd
call "%USERPROFILE%\Downloads\E8-Probe.cmd"
start /wait "" msiexec.exe /a "%USERPROFILE%\Downloads\E8-Probe.msi" /qn TARGETDIR="%TEMP%\E8-AdminProbe"
wevtutil qe "Microsoft-Windows-AppLocker/MSI and Script" /q:"*[System[(EventID=8007)]]" /rd:true /f:text /c:6
```

**Allowed-path control.** The original CMD probe was copied byte for byte to `C:\Program Files\E8-AppLocker-Validation\E8-Probe.cmd` by a lab administrator. Both copies had SHA-256 `b86d740a04ab7db8a703f67199d02a8eede0c308eed0808cb5d7ba198ab66fa5`. The same standard user, `SOCLAB\jsmith`, ran both copies in the same way.

| Path | UTC timestamp | Windows event | Record | Result |
|---|---|---:|---:|---|
| `%OSDRIVE%\USERS\JSMITH\DOWNLOADS\E8-PROBE.CMD` | 2026-11-08 11:15:37.455 | 8007 | 18 | Blocked |
| `%PROGRAMFILES%\E8-APPLOCKER-VALIDATION\E8-PROBE.CMD` | 2026-11-08 11:15:37.703 | 8005 | 19 | Allowed by `(Default) All scripts in Program Files` and printed `E8-SCRIPT-RAN` |

Both AppLocker records had the same target user SID. To reproduce the pair, stage an identical copy in the approved directory as an administrator, then run each copy as the standard user and query the MSI and Script log for events 8005 and 8007. The approved staging copy was removed after the test.

### 3 — Office macro settings
Set the enterprise Group Policy registry values for Word, Excel and PowerPoint:
`vbawarnings = 3` (disable macros with notification) and
`blockcontentexecutionfrominternet = 1` (block macros carrying Mark-of-the-Web).
The lab captured registry settings. The current script reports those settings separately and leaves runtime enforcement as **Not assessed** until tested in Office.

### 4 — User application hardening
Disabled Internet Explorer 11, disabled **Windows Script Host** (stops `.vbs`/`.js`
double-click execution), and enabled **8 Microsoft Defender Attack Surface Reduction
(ASR) rules** covering the common user-application abuse paths:

```
Block Office apps creating child processes / executable content / code injection
Block obfuscated JS/VBS/PS/macro scripts
Block JS/VBS launching downloaded executable content
Block credential stealing from LSASS
Block executable content from email/webmail
Block untrusted/unsigned processes from USB
```

### 5 — Restrict administrative privileges
Re-enabled **User Account Control**, **disabled the built-in Administrator** account,
and checked local Administrators for the named standard lab accounts. This check
covers those direct memberships and does not resolve nested group membership.

---

## Remediation for the remaining controls (2, 6, 7, 8)

These require organisation-level process or infrastructure, not a host setting:

- **Patch applications / operating systems (2, 6):** establish a patch regime (WSUS /
  Intune / third-party patching) and record patch deadlines and scanning cadence
  against the ASD maturity model. WS01 showed
  5 pending updates and a 57-day-old patch level.
- **Multi-factor authentication (7):** enforce MFA for remote access, internet-facing
  services and privileged users at the identity provider (e.g., Entra ID Conditional
  Access, or Windows Hello for Business for the domain).
- **Regular backups (8):** implement scheduled backups with tested restoration and
  ensure unprivileged accounts cannot modify or delete them.

---

## Further validation

Extend the AppLocker tests to additional file types and writable paths. On a workstation with Office installed, test downloaded and
local macros and record the effective policy. Review browser settings and
effective admin group membership separately.

*Assessed and hardened with the repeatable `e8assess.ps1` tool; all work performed in
an isolated VirtualBox lab.*
