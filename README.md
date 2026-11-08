# Essential Eight Maturity Assessment & Hardening Lab

A hands-on project that **measures a Windows host against the ASD/ACSC Essential Eight, hardens it, and measures again** to prove the lift — the way a real Essential Eight uplift is done. It ships a repeatable assessment tool, the hardening scripts, and the before/after evidence.

The [Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) is the Australian government's baseline of eight mitigation strategies, each rated against a Maturity Model (ML0–ML3). This lab targets **Maturity Level 1** on a Windows 11 workstation (`WS01`) from my [Active Directory lab](https://github.com/BharathwajM/ad-attack-detection-lab).

## The result

| | Aligned controls | Score |
|---|---|---|
| **Before hardening** | 0 / 8 | 2 / 16 |
| **After hardening** | **4 / 8** | **8 / 16** |

The four **host-enforceable** controls — application control, Office macros, user application hardening, restrict admin privileges — were lifted to **ML1**. The other four (patching ×2, MFA, backups) are process/infrastructure controls that a single host can't satisfy; the tool assesses them and the report gives a remediation path. Full write-up: **[`docs/assessment-report.md`](docs/assessment-report.md)**.

## `e8assess.ps1` — the assessment tool

A read-only PowerShell tool that checks a Windows host against **all eight** ML1 controls, scores each *Aligned / Partial / Not aligned*, and writes a Markdown + JSON report. It changes nothing, so it's safe to run against any host.

```powershell
powershell -ExecutionPolicy Bypass -File e8assess.ps1 -Label WS01-before
```

```
Essential Eight ML1 assessment - WS01 [WS01-after]
  1. Application control                        Aligned
  2. Patch applications                         Not aligned
  3. Configure Microsoft Office macro settings  Aligned
  4. User application hardening                 Aligned
  5. Restrict administrative privileges         Aligned
  6. Patch operating systems                    Not aligned
  7. Multi-factor authentication                Not aligned
  8. Regular backups                            Not aligned

  Posture: Partial ML1 (4/8 aligned)  |  Score 8/16
```

Each control's report entry also states **what ML2 would additionally require**, so the output doubles as a roadmap.

## Hardening applied

Documented, re-runnable scripts in [`hardening/`](hardening/) ([`Invoke-Hardening.ps1`](hardening/Invoke-Hardening.ps1) runs them in order):

| Control | Script | What it does |
|---|---|---|
| Application control | [`application-control.ps1`](hardening/application-control.ps1) | Enforcing **AppLocker** default-rules policy (Exe/MSI/Script) |
| Office macros | [`office-macros.ps1`](hardening/office-macros.ps1) | Disable macros + block internet macros (Word/Excel/PowerPoint) |
| User app hardening | [`user-app-hardening.ps1`](hardening/user-app-hardening.ps1) | Disable IE11 & Windows Script Host; enable **8 Defender ASR rules** |
| Restrict admin | [`restrict-admin.ps1`](hardening/restrict-admin.ps1) | Re-enable UAC; disable built-in Administrator; strip standard users from local admins |

**Proof it enforces:** running an executable from a user-writable folder as a standard domain user triggered AppLocker event **8004 — "…DOWNLOADED-APP.EXE was prevented from running."** (see the report).

## Repo layout

```
e8assess.ps1            the ML1 assessment / scoring tool
hardening/              the four hardening controls + an orchestrator
reports/                WS01-before / WS01-after  (.md and .json)
docs/assessment-report.md   the before -> after assessment write-up
```

---

*Part of my security portfolio, alongside an [AD attack & detection lab](https://github.com/BharathwajM/ad-attack-detection-lab), a [phishing triage tool](https://github.com/BharathwajM/phishing-triage-automation) and a [SOC monitoring lab](https://github.com/BharathwajM/soc-portfolio-lab). All work was performed in an isolated VirtualBox lab.*
