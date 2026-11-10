# Mapping this lab to ASD Essentials for enterprise IT

ASD has evolved the Essential Eight into **ASD Essentials for enterprise IT**. On 15 October 2026 it published [Transitioning from the Essential Eight](https://www.cyber.gov.au/publication/transitioning-from-the-essential-eight), which maps each Essential Eight strategy to the new principles and actions. This page applies that mapping to the WS01 work in this repo. It shows which evidence carries over, and what an assessment under the new model would still ask for.

This lab was scoped and scored against Essential Eight Maturity Level 1. The ratings below are my own reading of ASD's guidance for one lab workstation, not an ASD assessment.

## What changes

| Essential Eight | ASD Essentials for enterprise IT |
|---|---|
| Eight mitigation strategies with requirements | Principles (the security outcome), each supported by actions (what to do) |
| Maturity Levels 0 to 3 | Priority phases that set the order of work. They are not ratings. |
| Requirements applied across the whole environment | Eight domains, such as *User devices*, *Identity services* and *Privileged environments*. Each action is assessed per domain. |
| Assessed against specific requirements | Each action rated **not assessed**, **not effective**, **partially effective** or **fully effective**, based on whether it achieves its outcome |

The change that matters most for this lab is about **evidence**. ASD says evidence that a control is *deployed* (configuration records, policies, settings) remains useful but does not show it is *effective*. Operational evidence such as test results and monitoring records carries more weight.

WS01 is a user device, so the tables below cover the *User devices* domain unless they say otherwise.

## The four controls hardened in this lab

### Application control → Trustworthy software, Secure configuration management

| Action (paraphrased) | Lab evidence | Evidence type | Gap |
|---|---|---|---|
| Only supported, verified, authorised software runs. Exceptions are minimised, risk accepted, time-bound and reviewed. | AppLocker enforced for EXE, MSI and scripts. Events 8004 and 8007 show blocks in a user's Downloads folder. Event 8005 shows the same script allowed from Program Files. | **Effectiveness**: observed block and allow events | No exceptions register. The default rules trust all of Program Files and Windows. Nothing checks whether allowed software is still supported. |
| Admin and management tools are limited to approved sets and locations. | None | None | Admin tools were not identified or controlled separately |
| Configuration drift is found by scheduled assessments. | `e8assess.ps1` re-checks the policy | Deployment (run by hand twice) | Run the check on a schedule and alert on changes |

My reading: **partially effective**. The block and allow events are the kind of operational evidence ASD asks for. Exceptions and admin tooling are not covered.

### Office macro settings → Secure configuration management, Trustworthy software

| Action (paraphrased) | Lab evidence | Evidence type | Gap |
|---|---|---|---|
| Define and deploy an approved configuration baseline | `vbawarnings = 3` and `blockcontentexecutionfrominternet = 1` for Word, Excel and PowerPoint | Deployment only | Office is not installed on WS01, so the policy was never tested |

My reading: **not assessed**. ASD uses *not assessed* when there is not enough evidence to judge an outcome, and keeps it separate from *not effective*. This matches the stricter rule I added to `e8assess.ps1`, which reports the macro policy as *Configured* but scores it *Not assessed* until it is tested in Office.

### User application hardening → Secure configuration management, Content filtering

| Action (paraphrased) | Lab evidence | Evidence type | Gap |
|---|---|---|---|
| Define and deploy a hardened baseline that turns off unneeded features and insecure settings | IE11 disabled, Windows Script Host disabled, 8 Defender ASR rules enabled | Deployment only | ASR rules and browser settings were not functionally tested. The baseline is not formally approved. |
| Block outbound connections to known malicious destinations | None | None | Not in scope for a host-only lab. It needs web filtering or DNS protection. |

My reading: **partially effective** for the baseline actions. A next step would be to trigger each ASR rule with a harmless test file and capture the Defender block events.

### Restrict administrative privileges → Least privilege access, Identity, credential and access management, Secure administration, Network segmentation

| Action (paraphrased) | Lab evidence | Evidence type | Gap |
|---|---|---|---|
| Give accounts only the access they need | Standard users removed from local Administrators. UAC re-enabled. | Deployment | Effective privileges were not tested, for example by trying an admin action as `jsmith` |
| Disable or remove default and unused accounts | Built-in Administrator disabled | Deployment | No regular review process |
| Run admin work only from dedicated, hardened environments | None on WS01 | None | No privileged access workstation. In the [AD lab](https://github.com/BharathwajM/ad-attack-detection-lab), Administrator logged on to WS01 from SPLUNK01, which the [04b detection](https://github.com/BharathwajM/ad-attack-detection-lab/blob/main/detections/04b-unexpected-privileged-ntlm.spl) flags. |
| Record admin actions with user, time and target | None | None | Admin changes on WS01 were not logged centrally |

My reading: **partially effective** for least privilege on WS01. Secure administration needs a separate admin environment that this lab does not have.

## The four controls not hardened in this lab

| Essential Eight strategy | Mapped principles | Lab evidence |
|---|---|---|
| Patch applications, patch operating systems | Vulnerability management, Asset identification, Legacy system management | `e8assess.ps1` recorded 5 pending software updates and a last OS update 57 days old. No patching process. |
| Multi-factor authentication | Identity, credential and access management | None. ASD now asks for *phishing-resistant* MFA. |
| Regular backups | Regular and proven backups, Least privilege access | None. ASD now asks for isolated backup storage and restore tests that meet recovery time and recovery point objectives. |

## Logging and detection

The Essential Eight spread logging requirements across several strategies. ASD Essentials puts them in a *Visibility and response* domain with principles for centralised event logging, detection and incident response.

The AppLocker events in this lab were read on WS01 itself. The AD lab's Splunk forwarder sends the Security, System, Sysmon and PowerShell logs but not the AppLocker logs. Forwarding `Microsoft-Windows-AppLocker/EXE and DLL` and `MSI and Script` to Splunk, and alerting on event 8004 and 8007 bursts, would turn this lab's application control into evidence for *Centralised event logging* and *Cyber security event detection* as well.

## Not covered by either framework in this lab

ASD Essentials adds principles with no Essential Eight equivalent, including governance and culture (executive accountability, supplier assurance, AI accountability), content filtering, security awareness training and cyber supply chain security. These are organisation-level and out of scope for a single-workstation lab.

---

*Source: ASD, [Transitioning from the Essential Eight](https://www.cyber.gov.au/publication/transitioning-from-the-essential-eight), published 15 October 2026. Action wording is paraphrased; the [ASD Essentials for enterprise IT](https://www.cyber.gov.au/) publication is the authoritative source.*
