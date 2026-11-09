# Essential Eight Workstation Hardening Lab

I wrote a PowerShell tool that checks a Windows 11 workstation against the ASD Essential Eight at Maturity Level 1 (ML1). I ran it, hardened the workstation, then ran it again to measure the change. The workstation is `WS01` from my [Active Directory lab](https://github.com/BharathwajM/ad-attack-detection-lab).

The [Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) is the Australian Signals Directorate's baseline of eight mitigation strategies, each rated from Maturity Level 0 to 3.

## Result

I hardened the four controls a single workstation can enforce. The other four depend on organisation-wide processes.

| # | Control | Before | After | How the "after" was checked |
|---|---|---|---|---|
| 1 | Application control | Partial | **Aligned** | AppLocker blocked an EXE, an MSI and a CMD script from user folders (events 8004/8007). The same script ran from Program Files (event 8005). |
| 3 | Office macro settings | Not aligned | **Aligned** in the captured run | Macro policy set for Word, Excel and PowerPoint. WS01 has no Office installed, so the policy could not be tested in practice (see note). |
| 4 | User application hardening | Not aligned | **Aligned** | IE11 and Windows Script Host disabled, 8 Defender ASR rules enabled |
| 5 | Restrict admin privileges | Partial | **Aligned** | UAC back on, built-in Administrator disabled, standard users removed from local Administrators |
| 2, 6 | Patch applications / OS | Not aligned | Not aligned | Needs a patching process (WSUS, Intune) across the fleet |
| 7 | Multi-factor authentication | Not aligned | Not aligned | Enforced at the identity provider, not on the host |
| 8 | Regular backups | Not aligned | Not aligned | Needs a backup system and a tested restore |

**Captured runs:** 0/8 aligned before, 4/8 after (tool score 2/16 to 8/16). The reports are in [`reports/`](reports/), and the full write-up is in [`docs/assessment-report.md`](docs/assessment-report.md).

**Note on Office macros.** After the runs, I made the Office check stricter. It now reports the registry policy as *Configured* but scores the result as *Not assessed* until macros are tested in Office. Under that rule, the same after-state would score 3/8 aligned (6/16).

## `e8assess.ps1`

The tool checks local settings for all eight strategies and rates each one *Aligned*, *Partial*, *Not aligned* or *Not assessed*. It writes a Markdown and a JSON report and changes nothing on the host. Run it from an elevated PowerShell session:

```powershell
powershell -ExecutionPolicy Bypass -File e8assess.ps1 -Label WS01-before
```

The score (2 points per aligned control, 1 per partial) is the tool's own measure. It is not an official ASD maturity rating. The report summarises the ML1 requirement for each control; the [ASD maturity model](https://www.cyber.gov.au/publication/essential-eight-maturity-model) has the full criteria.

## Hardening scripts

All of the scripts in [`hardening/`](hardening/) can be re-run. [`Invoke-Hardening.ps1`](hardening/Invoke-Hardening.ps1) runs them in order.

| Control | Script | What it does |
|---|---|---|
| Application control | [`application-control.ps1`](hardening/application-control.ps1) | Enforces an **AppLocker** policy for EXE, MSI and scripts |
| Office macros | [`office-macros.ps1`](hardening/office-macros.ps1) | Disables macros and blocks macros from the internet (Word, Excel, PowerPoint) |
| User app hardening | [`user-app-hardening.ps1`](hardening/user-app-hardening.ps1) | Disables IE11 and Windows Script Host, and enables **8 Defender ASR rules** |
| Restrict admin | [`restrict-admin.ps1`](hardening/restrict-admin.ps1) | Re-enables UAC, disables the built-in Administrator, and removes standard users from local admins |

## ASD Essentials for enterprise IT

ASD has since evolved the Essential Eight into [ASD Essentials for enterprise IT](https://www.cyber.gov.au/publication/transitioning-from-the-essential-eight#application-control), which maps application control to its **Trustworthy software** principle. The AppLocker block and allow events in this lab are the kind of evidence that principle asks for on a user device. This lab was scoped and scored against the Essential Eight ML1.

## Repo layout

```
e8assess.ps1                the assessment and scoring tool
hardening/                  the four hardening scripts and a runner
reports/                    WS01-before and WS01-after (.md and .json)
docs/assessment-report.md   the before and after write-up with evidence
```

---

*Part of my security portfolio, alongside an [AD attack & detection lab](https://github.com/BharathwajM/ad-attack-detection-lab), a [phishing triage tool](https://github.com/BharathwajM/phishing-triage-automation) and a [SOC monitoring lab](https://github.com/BharathwajM/soc-portfolio-lab). All work was done in an isolated VirtualBox lab.*
