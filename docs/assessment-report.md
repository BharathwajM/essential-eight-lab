# Essential Eight (ML1) Assessment & Hardening — WS01

**Target:** WS01 — Windows 11 Enterprise, domain-joined member of `soclab.local`
**Framework:** ASD/ACSC Essential Eight Maturity Model, **Maturity Level 1**
**Method:** baseline assessment → apply hardening → re-assess, using the repeatable
[`e8assess.ps1`](../e8assess.ps1) scoring tool. Full tool output is in
[`reports/`](../reports/) (`WS01-before` and `WS01-after`, Markdown + JSON).

---

## Result at a glance

| | Aligned controls | Score |
|---|---|---|
| **Before** | 0 / 8 | 2 / 16 |
| **After** | **4 / 8** | **8 / 16** |

The four **host-enforceable** controls — application control, Office macros, user
application hardening, and restrict administrative privileges — were lifted from
*Not aligned* to **Aligned (ML1)**. The remaining four (patch applications, patch
operating systems, MFA, backups) are process- and infrastructure-level controls that
a single workstation cannot satisfy on its own; they are assessed below with a
remediation path.

| # | Mitigation | Before | After | What changed |
|---|-----------|--------|-------|--------------|
| 1 | Application control | Partial | **Aligned** | AppLocker policy enforced (default rules); standard users can only run from `%ProgramFiles%` / `%Windir%` |
| 2 | Patch applications | Not aligned | Not aligned | 5 updates pending, last patch 57 days ago — needs an update regime (see remediation) |
| 3 | Office macro settings | Not aligned | **Aligned** | Macros disabled with notification; internet macros blocked (policy enforced) |
| 4 | User application hardening | Not aligned | **Aligned** | IE 11 off; Windows Script Host disabled; 8 Defender ASR rules enabled |
| 5 | Restrict admin privileges | Partial | **Aligned** | UAC re-enabled; built-in Administrator disabled; no standard users in local Administrators |
| 6 | Patch operating systems | Not aligned | Not aligned | Last OS update 57 days ago — needs an update regime |
| 7 | Multi-factor authentication | Not aligned | Not aligned | No on-host MFA; enforced at the identity provider (see remediation) |
| 8 | Regular backups | Not aligned | Not aligned | No backup/restore configured (see remediation) |

---

## What was implemented (controls 1, 3, 4, 5)

Each control was applied with a documented, re-runnable script in
[`hardening/`](../hardening/).

### 1 — Application control (AppLocker)
Applied an **enforcing** AppLocker policy (Exe, MSI, Script collections) using the
standard default rules: the *Everyone* group may run only from `%ProgramFiles%` and
`%Windir%` (minus user-writable subfolders); administrators may run anything. This
implicitly denies execution from `Downloads`, `Temp` and `AppData`, where malware
typically lands. The Application Identity service was set to start automatically.

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
`blockcontentexecutionfrominternet = 1` (block macros carrying Mark-of-the-Web). The
control is in force whether or not Office is installed, and users cannot change it.

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
and confirmed **no standard domain users** are members of the local Administrators
group — so everyday accounts cannot perform privileged actions.

---

## Remediation for the remaining controls (2, 6, 7, 8)

These require organisation-level process or infrastructure, not a host setting:

- **Patch applications / operating systems (2, 6):** establish a patch regime (WSUS /
  Intune / third-party patching) meeting the ML1 one-month SLA (two weeks for
  internet-facing), and run a vulnerability scanner at least fortnightly. WS01 showed
  5 pending updates and a 57-day-old patch level.
- **Multi-factor authentication (7):** enforce MFA for remote access, internet-facing
  services and privileged users at the identity provider (e.g., Entra ID Conditional
  Access, or Windows Hello for Business for the domain).
- **Regular backups (8):** implement scheduled backups with tested restoration and
  ensure unprivileged accounts cannot modify or delete them.

---

## Reaching Maturity Level 2

Each control's `WS01-after` report entry lists what ML2 additionally requires — in
summary: tighter patch SLAs with scanner verification, macro AV scanning and Win32
API blocking, more ASR coverage with central logging, just-in-time admin in a
separate privileged environment, MFA event logging, and coordinated backup-restore
testing.

*Assessed and hardened with the repeatable `e8assess.ps1` tool; all work performed in
an isolated VirtualBox lab.*
