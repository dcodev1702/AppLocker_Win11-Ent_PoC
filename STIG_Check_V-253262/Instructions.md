# V-253262 AppLocker STIG Check - Setup & Run Instructions

**Windows 11 Enterprise VM**

### AppLocker Policy - Expected State

| Collection | Mode | STIG Required |
|------------|------|---------------|
| Exe | Enabled (Enforce Rules) | Yes |
| Msi | Enabled (Enforce Rules) | Yes |
| Script | Enabled (Enforce Rules) | Yes |
| Appx | Enabled (Enforce Rules) | Yes |
| Dll | AuditOnly (logs only, no blocking) | No |

> [!CAUTION]
> **DLL enforcement is intentionally set to AuditOnly.** When set to `Enabled` or even `NotConfigured` with rules present, AppLocker enforces DLL rules on every DLL load — blocking user-installed applications (e.g., VS Code in AppData) and causing significant performance overhead. Microsoft states that the DLL rule collection is not enabled by default because DLL rules can cause performance problems, and AppLocker must check each DLL that an application loads when DLL rules are enforced. See: [DLL rules in AppLocker | Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/dll-rules-in-applocker). Setting DLL to `AuditOnly` still logs DLL violations in Event Viewer without breaking applications. This does **not** affect STIG V-253262 compliance — the check only requires Exe, Msi, Script, and Appx collections to be enforcing a deny-all, permit-by-exception policy. DLL rules are an optional advanced feature and are not evaluated by the STIG control.

---

## Prerequisites

- Windows 11 Enterprise VM
- Administrator access on the VM
- SCC 5.14 installed at:
  ```
  C:\Users\Lorenzo.SKYNET\Downloads\WIN11 STIG\scc-5.14_Windows_bundle\scc-5.14_Windows\scc-5.14_Windows\scc_5.14\
  ```
- NIWC Enhanced SCAP content loaded in SCC (`Microsoft_Windows_11_STIG v002.007.016`)
- Autoanswer template already generated in SCC's Templates folder

---

## Step 1 - Copy Scripts to the VM

Copy these two files to a folder on the VM (e.g. `C:\STIG_Scripts\`):

- `Check-V253262.ps1`
- `Run-STIGScan.ps1`

## Step 2 - Open PowerShell as Administrator

Right-click the Start menu > **Windows Terminal (Admin)**
or search for PowerShell, right-click > **Run as administrator**

## Step 3 - Navigate to the Script Folder

```powershell
cd C:\STIG_Scripts
```

## Step 4 - Run the Script

**Option A** - Check and update the answer file only:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run-STIGScan.ps1
```

**Option B** - Check, update the answer file, AND launch the SCC scan:

```powershell
powershell -ExecutionPolicy Bypass -File .\Run-STIGScan.ps1 -RunScan
```

## Step 5 - Review the Output

The script will display:

- The AppLocker enforcement status for each collection (Exe, Msi, Script, Appx)
- Whether the result is **COMPLIANT** or **NON-COMPLIANT**
- Confirmation that the answer file was saved

Example output (compliant system):

```
=== Running V-253262 AppLocker Check ===
  Compliant collections:
    - Exe    : Enforce Rules (3 rule(s)).
    - Msi    : Enforce Rules (2 rule(s)).
    - Script : Enforce Rules (2 rule(s)).
    - Appx   : Enforce Rules (1 rule(s)).

  RESULT: NOT A FINDING

  --> COMPLIANT (will mark: Not a Finding)

=== Answer file saved ===
  V-253262 marked as: Not a Finding
```

## Step 6 - Verify in SCC (Optional)

1. Open the SCC GUI
2. Click on the Windows 11 STIG content
3. Click **Manual Questions**
4. Question 4 (V-253262) should now show your answer instead of "Not Reviewed"
5. Run the scan - V-253262 will be included in the results

## Step 7 - Verify in STIG Viewer

Import the SCC results into STIG Viewer 3.7 to confirm V-253262 shows as **Not a Finding** with a score of 100%.

![V-253262 STIG Viewer - Not a Finding](images/stig-viewer-v253262-pass.png)

---

## What Each Result Means

| Result | Meaning |
|--------|---------|
| **NOT A FINDING** | All 4 AppLocker collections (Exe, Msi, Script, Appx) are set to "Enforce Rules" mode. The system is blocking unauthorized software. |
| **OPEN FINDING** | One or more collections are set to "Audit Only" or "Not Configured". AppLocker is not actively blocking unauthorized software. |

---

## Troubleshooting

**"Application Identity service is not running"**
```powershell
Start-Service AppIDSvc
Set-Service AppIDSvc -StartupType Automatic
```

**"Unable to retrieve AppLocker policy"**
- Ensure you are running as Administrator
- Ensure AppLocker policies are configured via Group Policy or local policy

**"Autoanswer template not found"**
- Open SCC GUI, load the enhanced Windows 11 content, click **Manual Questions** to generate the template, then re-run the script
