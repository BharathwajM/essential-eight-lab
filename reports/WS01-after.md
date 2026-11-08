# Essential Eight Workstation Checks - WS01
*Run label: `WS01-after` | Generated 2026-11-08 19:36 | Read-only assessment*

**Lab checks: 4/8 rated aligned by the tool**  |  Internal lab score: 8 / 16

The status labels reflect local checks. Refer to the ASD maturity model for the full criteria.

| # | Mitigation | Status | Detail |
|---|---|---|---|
| 1 | Application control | **Aligned** | AppLocker enforcing with 8 rule(s); Application Identity service 'Running'. |
| 2 | Patch applications | **Not aligned** | 5 pending software update(s); last patch 57 day(s) ago. |
| 3 | Configure Microsoft Office macro settings | **Aligned** | Office macro policy disables macros and blocks macros originating from the internet. |
| 4 | User application hardening | **Aligned** | Internet Explorer 11 disabled; 8 ASR rule(s) enabled to harden user applications. |
| 5 | Restrict administrative privileges | **Aligned** | Local Administrators limited to admin accounts (3 member(s)); built-in Administrator disabled; UAC enabled. |
| 6 | Patch operating systems | **Not aligned** | Microsoft Windows 11 Enterprise Evaluation; last OS update 57 day(s) ago - outside the one-month window. |
| 7 | Multi-factor authentication | **Not aligned** | No MFA mechanism detected on this host (standalone lab). MFA is enforced at the identity provider, not locally. |
| 8 | Regular backups | **Not aligned** | No backup solution or restore points detected. |

## Selected maturity model references

### 1. Application control - Aligned
- **ML1:** Executables, scripts, installers, HTA and control-panel applets are prevented from running in standard-user-writable locations (AppLocker/WDAC enforced).
- **To reach ML2:** ML2 extends control to all locations, adds Microsoft "recommended block" driver/rule sets, and logs allowed/blocked execution centrally.

### 2. Patch applications - Not aligned
- **ML1:** Scanning runs daily for online services and weekly for specified application categories. Patch deadlines depend on the application category and vulnerability severity.
- **To reach ML2:** ML2 extends scanning and patching coverage to other applications. Check the ASD model for the full criteria.

### 3. Configure Microsoft Office macro settings - Aligned
- **ML1:** Office macros are disabled for users without a business need; macros from the internet are blocked; users cannot change the setting.
- **To reach ML2:** ML2 adds antivirus scanning of allowed macros and blocks Win32 API calls from macros; macro events are logged.

### 4. User application hardening - Aligned
- **ML1:** Web browsers do not process Java or web advertisements from the internet; Internet Explorer 11 is disabled/removed; browser security settings cannot be changed by users.
- **To reach ML2:** ML2 blocks additional ASR vectors (Office child processes, credential theft, PowerShell/script abuse) and logs blocked events.

### 5. Restrict administrative privileges - Aligned
- **ML1:** Privileged access is limited and validated; privileged accounts are separate from day-to-day accounts and cannot browse the web or read email; unprivileged users are not local administrators.
- **To reach ML2:** ML2 adds just-in-time / time-limited admin, a separate privileged operating environment, and logging of privileged access.

### 6. Patch operating systems - Not aligned
- **ML1:** Operating systems are patched within one month (two weeks for internet-facing); unsupported operating systems are replaced.
- **To reach ML2:** ML2 tightens the SLA to two weeks and requires a vulnerability scanner to confirm OS patch levels weekly.

### 7. Multi-factor authentication - Not aligned
- **ML1:** MFA is used for remote access, for internet-facing services, and by privileged users; it is phishing-resistant where required.
- **To reach ML2:** ML2 requires MFA for all users of internet-facing services and logs successful/failed MFA events.

### 8. Regular backups - Not aligned
- **ML1:** Backups of important data, software and configuration are performed and retained per business needs; restoration is tested; unprivileged accounts cannot modify or delete backups.
- **To reach ML2:** ML2 requires more frequent backups, coordinated restoration testing, and that unprivileged accounts cannot access other users' backups.

