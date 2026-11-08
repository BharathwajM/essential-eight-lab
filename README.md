# Essential Eight Workstation Hardening Lab

A Windows hardening lab that **assesses selected ASD Essential Eight Maturity Level 1 (ML1) requirements** on one workstation. It includes a read-only PowerShell check, hardening scripts, and before-and-after evidence.

The [Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) is the Australian government's baseline of eight mitigation strategies, each rated against a Maturity Model (ML0–ML3). The target is a Windows 11 workstation (`WS01`) from my [Active Directory lab](https://github.com/BharathwajM/ad-attack-detection-lab).

## The result

| | Checks rated aligned by the tool | Internal lab score |
|---|---|---|
| **Before hardening** | 0 / 8 | 2 / 16 |
| **After hardening** | **4 / 8** | **8 / 16** |

The score compares local configuration checks on WS01 and has no equivalent in the ASD maturity model. AppLocker events verify that EXE, MSI and CMD probes were blocked for a standard user. The [assessment report](docs/assessment-report.md) separates that verified result from configured settings and requirements that need further evidence.

## `e8assess.ps1` — the assessment tool

The script checks local signals across the eight mitigation strategies and writes Markdown and JSON reports. The *Aligned*, *Partial*, and *Not aligned* labels describe the tool's own checks. Run it from an elevated PowerShell session on the intended lab host.

```powershell
powershell -ExecutionPolicy Bypass -File e8assess.ps1 -Label WS01-before
```

Historical WS01 output from the earlier version of the tool.

```
Essential Eight workstation checks - WS01 [WS01-after]
  1. Application control                        Aligned
  2. Patch applications                         Not aligned
  3. Configure Microsoft Office macro settings  Aligned
  4. User application hardening                 Aligned
  5. Restrict administrative privileges         Aligned
  6. Patch operating systems                    Not aligned
  7. Multi-factor authentication                Not aligned
  8. Regular backups                            Not aligned

  Lab checks: 4/8 rated aligned  |  Internal score 8/16
```

The per-strategy notes are starting points. Use the [ASD Essential Eight Maturity Model](https://www.cyber.gov.au/publication/essential-eight-maturity-model) for the full criteria.

The Office check reports **Configured**, **Incomplete**, or **Missing** for the machine policy. Its runtime result is **Not assessed** and earns zero points until supported by a separate functional test. The checked-in WS01 reports preserve the results originally captured.

## Hardening applied

Documented, re-runnable scripts in [`hardening/`](hardening/) ([`Invoke-Hardening.ps1`](hardening/Invoke-Hardening.ps1) runs them in order):

| Control | Script | What it does |
|---|---|---|
| Application control | [`application-control.ps1`](hardening/application-control.ps1) | Enforcing **AppLocker** default-rules policy (Exe/MSI/Script) |
| Office macros | [`office-macros.ps1`](hardening/office-macros.ps1) | Disable macros + block internet macros (Word/Excel/PowerPoint) |
| User app hardening | [`user-app-hardening.ps1`](hardening/user-app-hardening.ps1) | Disable IE11 & Windows Script Host; enable **8 Defender ASR rules** |
| Restrict admin | [`restrict-admin.ps1`](hardening/restrict-admin.ps1) | Re-enable UAC; disable built-in Administrator; strip standard users from local admins |

**Verified AppLocker tests.** A standard domain user was blocked from running an EXE (event **8004**), an MSI and a CMD script (event **8007**) from user-writable folders. The identical CMD probe was allowed from Program Files under the same user (event **8005**). The [assessment report](docs/assessment-report.md#1--application-control-applocker) includes the records and reproduction steps.

**ASD Essentials transition.** ASD's October 2026 Essentials for enterprise IT maps application control to the **Trustworthy software** principle. The AppLocker allow and block events are evidence for software execution control on one user device. The lab assessment retains its original scope of selected Essential Eight ML1 requirements. [ASD transition guidance](https://www.cyber.gov.au/publication/transitioning-from-the-essential-eight#application-control)

## Repo layout

```
e8assess.ps1            the workstation checks and internal scoring tool
hardening/              the four hardening controls + an orchestrator
reports/                WS01-before / WS01-after  (.md and .json)
docs/assessment-report.md   the before -> after assessment write-up
```

---

*Part of my security portfolio, alongside an [AD attack & detection lab](https://github.com/BharathwajM/ad-attack-detection-lab), a [phishing triage tool](https://github.com/BharathwajM/phishing-triage-automation) and a [SOC monitoring lab](https://github.com/BharathwajM/soc-portfolio-lab). All work was performed in an isolated VirtualBox lab.*
