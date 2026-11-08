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
| 1 | Application control | **Verified for one EXE test** | AppLocker event 8004 confirms a standard user was blocked from running an executable in a user-writable folder. Other file types need separate functional tests. |
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
The captured test below covers an EXE in a user-writable directory.

**Evidence — a standard user was actually blocked.** Running a copied executable from
a user-writable folder as the standard domain user `SOCLAB\jsmith` produced AppLocker
event **8004**:

```
Microsoft-Windows-AppLocker/EXE and DLL — Event 8004
%OSDRIVE%\USERS\PUBLIC\E8TEST\DOWNLOADED-APP.EXE was prevented from running.
```

### 3 — Office macro settings
Set the enterprise Group Policy registry values for Word, Excel and PowerPoint:
`vbawarnings = 3` (disable macros with notification) and
`blockcontentexecutionfrominternet = 1` (block macros carrying Mark-of-the-Web).
The lab captured registry settings. Runtime enforcement would need testing in Office.

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

Re-run the AppLocker test with a standard user against representative EXE, MSI
and script files. On a workstation with Office installed, test downloaded and
local macros and record the effective policy. Review browser settings and
effective admin group membership separately.

*Assessed and hardened with the repeatable `e8assess.ps1` tool; all work performed in
an isolated VirtualBox lab.*
