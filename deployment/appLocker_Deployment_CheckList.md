# AppLocker STIG + AaronLocker (Windows 11 25H2)
## Implementation Checklist

## Scope
This checklist is for **Windows 11 25H2 Enterprise** endpoints that must be compliant with:

- **STIG Version ID:** `WN11-00-000035`
- **VULN ID:** `253262`
- **RULE ID:** `SV-253262R958808`

## STIG Check Metadata

- **Benchmark / Product:** Microsoft Windows 11 STIG
- **STIG Release:** V2R6
- **Group ID:** `V-253262`
- **Rule ID:** `SV-253262R958808`
- **Version / STIG ID:** `WN11-00-000035`
- **SRG:** `SRG-OS-000370-GPOS-00155`
- **CCI:** `CCI-001774`
- **Severity:** `medium` / `CAT II`
- **DPMS Target Identifier:** `5471`
- **Rule Title:** The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

Recommended baseline for this environment:

- **Executable Rules:** Enabled
- **Windows Installer Rules:** Enabled
- **Script Rules:** Enabled
- **Packaged app Rules:** Enabled
- **DLL Rules:** Disabled / Off

---

## Objective
Implement the Windows 11 STIG check `WN11-00-000035` by using AppLocker with AaronLocker to satisfy a **deny-all, permit-by-exception** model for authorized software. For this check, the purpose is to ensure only approved software is allowed to run, that **packaged apps are included in scope**, that custom safe paths are validated and hardened before trust is granted, and that the policy is deployed in **Audit only** mode first before moving to enforcement.

The extracted local STIG source for this check states that AppLocker is an allowlisting application built into Windows 11 Enterprise, that a deny-by-default implementation begins when rules are enabled in a rule collection, and that the validation must include **packaged apps such as the universal apps installed by default on systems**.

---

## 1. Confirm platform and scope
Verify the following before deployment:

- Devices are running **Windows 11 Enterprise**
- Devices are in scope for the target GPO / container GPO
- Endpoints are managed through **MECM**
- AaronLocker will be used to generate the AppLocker policy

---

## 2. Use these approved custom safe paths
These applications are installed outside the normal trusted paths like `C:\Program Files` and `C:\Windows`, so they must be added as **safe paths** only if standard users cannot write to them.

Add the following to:

`GetSafePathsToAllow.ps1`

- `C:\Fonsi\*`

### Important

Only use these entries in `GetSafePathsToAllow.ps1` if the folders are **not writable by non-admin users**.

If any of these paths are user-writable, they should **not** be treated as safe paths.

---

## 3. Validate and harden NTFS permissions on custom paths

Before trusting the custom install paths, confirm they are admin-write only.

Target folders:

* `C:\Fonsi`

### ACL validation script

[acl_validation.ps1](acl_validation.ps1)

Use this script to review the custom path and identify non-admin write-capable ACEs that would make it unsafe for AppLocker path rules.

You can also validate arbitrary folders directly:

```powershell
.\acl_validation.ps1 -Paths 'C:\Fonsi'
```

---

## 4. Apply hardened NTFS ACLs to custom paths

Use the following script to harden the custom install paths so they can safely remain in `GetSafePathsToAllow.ps1`.

### Hardened NTFS ACL script

[acl_ntfs_hardening.ps1](acl_ntfs_hardening.ps1)

Use this script to back up and harden NTFS permissions on the custom install paths before treating them as AppLocker-safe locations.

The script now also resets folder ownership to `BUILTIN\Administrators`, which closes a common edge case where a non-admin owner could still rewrite the ACL after hardening.

### Lightweight deployment validation

[Invoke-DeploymentValidation.ps1](Invoke-DeploymentValidation.ps1)

Use this script after updating deployment scripts to parse all `.ps1` files in the deployment folder and exercise the ACL hardening workflow on a disposable test directory.

```powershell
.\Invoke-DeploymentValidation.ps1
```

---

## 5. Build the AppLocker baseline policy

Use AaronLocker to generate the AppLocker policy.

Recommended rule collections:

* **Executable Rules** = Enabled
* **Windows Installer Rules** = Enabled
* **Script Rules** = Enabled
* **Packaged app Rules** = Enabled
* **DLL Rules** = Disabled / Off

### Recommendation on DLL rules

For this rollout, leave **DLL rules disabled**. This reduces operational burden and still aligns with the intended baseline for this STIG implementation.

---

## 6. Create default rules for all enabled rule collections

When you generate the policy with **AaronLocker `Create-Policies.ps1`**, the baseline default rules for the enabled AppLocker collections are created as part of the generated policy.

That means you do **not** need to manually create default rules in the GPO editor if you are importing the AaronLocker-generated XML.

The generated baseline should already include defaults for:

* **Executable Rules**
* **Windows Installer Rules**
* **Script Rules**
* **Packaged app Rules**

Do **not** enable DLL rules for this rollout.

```powershell
# Create AppLocker policy
.\Users\xadmin\AaronLocker\Create-Policy.ps1 -Excel
```

```console
The 'Output' directory is where your AUDIT & ENFORCING XML policies reside
```

---

## 7. Packaged apps: what specifically must be added?

This is the important step that often causes confusion.

### Required packaged app action

If you are using an **AaronLocker-generated policy**, no separate manual Appx step is required. `Create-Policies.ps1` handles the packaged app baseline automatically as part of the generated policy.

If you are building or editing an AppLocker policy manually in the GPO editor instead of importing AaronLocker XML, then the required Appx action is:

1. Go to **Packaged app Rules**
2. Right-click **Packaged app Rules**
3. Select **Create Default Rules**

### Why this matters

If you enforce classic AppLocker collections like EXE rules, but you do not also account for packaged apps, built-in packaged Windows apps can be impacted.

### Baseline recommendation

For this environment, use the **default packaged app rules** as the baseline. In the AaronLocker workflow, this should already be present in the generated XML and does not need to be added manually afterward.

You do **not** need to manually create separate rules for each built-in packaged app unless you want tighter restrictions later.

### Exact AppLocker XML structure required

The effective policy must contain an **Appx** rule collection with enforcement enabled and the default allow rule for signed packaged apps.

```xml
<RuleCollection Type="Appx" EnforcementMode="Enabled">
  <FilePublisherRule
    Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba"
    Name="(Default Rule) All signed packaged apps"
    Description="Allows members of the Everyone group to run packaged apps that are signed."
    UserOrGroupSid="S-1-1-0"
    Action="Allow">
    <Conditions>
      <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
        <BinaryVersionRange LowSection="0.0.0.0" HighSection="*"/>
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>
</RuleCollection>
```

### What to verify before moving to enforcement

After exporting the effective policy, confirm all of the following are present:

* `RuleCollection Type="Appx"`
* `EnforcementMode="Enabled"` when you move out of audit mode
* `Name="(Default Rule) All signed packaged apps"`
* `UserOrGroupSid="S-1-1-0"`
* `PublisherName="*" ProductName="*" BinaryName="*"`

If this Appx collection or its default allow rule is missing from the **effective** policy, packaged apps can fail when enforcement is enabled.

---

## 8. Configure enforcement mode

Set all enabled collections to **Audit only** first.

Audit only for:

* Executable Rules
* Windows Installer Rules
* Script Rules
* Packaged app Rules

Leave **DLL Rules** disabled.

### Goal

Use Audit mode to identify what would have been blocked before moving to full enforcement.

---

## 9. Ensure Application Identity service is enabled

AppLocker depends on the **Application Identity** service.

Required action:

* Set **Application Identity** service startup to **Automatic**
* Verify the service is running on targeted endpoints

---

## 10. Review AppLocker audit events from Terminal

Use the following PowerShell script to review AppLocker events that indicate an audited action **would have been blocked if the policy were enforced**.

### AppLocker audit review script

[Get-AppLockerWouldBlockEvents.ps1](Get-AppLockerWouldBlockEvents.ps1)

Use this script to review AppLocker audit-only events that show which executables, scripts, installers, DLLs, or packaged apps would be blocked if enforcement were enabled.

### Example usage

```powershell
# Last 7 days on local machine
.\Get-AppLockerWouldBlockEvents.ps1

# Last 3 days, only events mentioning C:\Fonsi
.\Get-AppLockerWouldBlockEvents.ps1 -DaysBack 3 -PathMatch 'C:\Fonsi' -IncludeMessage

# Export results
.\Get-AppLockerWouldBlockEvents.ps1 -DaysBack 14 -ExportCsv -CsvPath .\AppLocker-Audit.csv
```

### Signed and unsigned script validation

For user-profile script testing, validate both a signed approved script and an unsigned comparison script from the same user-writable location such as `C:\Users\appuser\Downloads`.

Validated test files:

* `Get-AppLockerWouldBlockEvents.ps1` - signed
* `AppLocker-LOLBin-PolicyCheck.ps1` - signed
* `Get-BasicSystemState.ps1` - unsigned by design

### Validate Authenticode state before testing

```powershell
Get-AuthenticodeSignature .\Get-AppLockerWouldBlockEvents.ps1 |
  Format-List Status, StatusMessage, SignerCertificate

Get-AuthenticodeSignature .\AppLocker-LOLBin-PolicyCheck.ps1 |
  Format-List Status, StatusMessage, SignerCertificate

Get-AuthenticodeSignature .\Get-BasicSystemState.ps1 |
  Format-List Status, StatusMessage, SignerCertificate
```

Expected result:

* `Get-AppLockerWouldBlockEvents.ps1` = `Valid`
* `AppLocker-LOLBin-PolicyCheck.ps1` = `Valid`
* `Get-BasicSystemState.ps1` = `NotSigned`

### AaronLocker change required for signer-based script trust

The signer rule for approved PowerShell scripts was implemented in AaronLocker by updating `CustomizationInputs\TrustedSigners.ps1` to use an exemplar signed script instead of a manually typed `PublisherName`.

```powershell
@{
label = "XDR Lab-signed PowerShell scripts";
RuleCollection = "Script";
exemplar = "C:\Users\azureadmin\Downloads\AppLocker\AppLocker_Win11-Ent_PoC\deployment\Get-AppLockerWouldBlockEvents.ps1";
}
```

Why this matters:

* AppLocker evaluates signed `.ps1` publisher metadata differently than a raw certificate subject string in some cases
* Using `exemplar` lets AaronLocker derive the publisher condition from the signed script itself
* This was the change that made the signed scripts match the effective Script publisher rule correctly

### Execute signed and unsigned test scripts

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Get-AppLockerWouldBlockEvents.ps1 -DaysBack 1
powershell.exe -ExecutionPolicy Bypass -File .\AppLocker-LOLBin-PolicyCheck.ps1
powershell.exe -ExecutionPolicy Bypass -File .\Get-BasicSystemState.ps1
```

### Review resulting AppLocker audit events

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-AppLocker/MSI and Script'
  Id = 8006
  StartTime = (Get-Date).AddMinutes(-15)
} |
Where-Object {
  $_.Message -match 'Get-AppLockerWouldBlockEvents\.ps1|Get-BasicSystemState\.ps1|AppLocker-LOLBin-PolicyCheck\.ps1'
} |
Select-Object TimeCreated, Message |
Format-List
```

Expected result after policy refresh:

* The signed scripts run without generating new 8006 events
* The unsigned script still runs in Audit mode but generates an 8006 event showing it would be blocked if enforcement were enabled

---

## 11. Pilot deployment

Deploy the policy to a small pilot group first.

### During pilot, review:

* Apps installed in:

  * `C:\Fonsi`
* Administrative scripts and automation tools
* Any packaged apps users rely on
* Installer activity
* Unexpected audit-only “would be blocked” events

---

## 12. Refine the policy

Based on pilot results:

* Keep rules narrow
* Avoid introducing new writable trusted paths
* Add only necessary allow-list entries
* Revalidate ACLs on all custom safe paths

---

## 13. Move to enforcement in waves

After audit review and pilot validation:

1. Switch enabled collections from **Audit only** to **Enforce rules**
2. Roll out in phases across the device estate
3. Continue monitoring AppLocker events after each wave

---

## 14. Final recommended baseline

Use this as the implementation target:

* **Executable Rules:** Enabled
* **Windows Installer Rules:** Enabled
* **Script Rules:** Enabled
* **Packaged app Rules:** Enabled
* **DLL Rules:** Disabled

### Required policy actions

* Generate the policy with AaronLocker so the default enabled collections are included automatically:

  * Executable
  * Windows Installer
  * Script
  * Packaged app
* Add safe paths:

  * `C:\Fonsi\*`
* Validate and harden NTFS ACLs on all custom paths
* Start in Audit only
* Review AppLocker audit events
* Move to Enforce after pilot success

---

## Plain-English summary

To meet this baseline:

* Use AaronLocker to generate your AppLocker policy
* Trust normal Windows locations through the AaronLocker-generated default baseline
* Trust `C:\Fonsi\*` only after ACL hardening
* Verify the generated policy still contains the **Appx** collection and default packaged app allow rule
* Leave **DLL rules off**
* Deploy in **Audit only** first, then enforce in phases

---

## .RESOURCES

### STIG Source And Metadata

- **Official DISA Windows 11 STIG download:** [U_MS_Windows_11_V2R6_STIG.zip](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R6_STIG.zip)
- **DISA STIG downloads page:** [Operating Systems filter](https://public.cyber.mil/stigs/downloads/?_dl_facet_stigs=operating-systems)
- **Local extracted STIG source file:** [STIG/Windows_11/V2R6_Manual_STIG/U_MS_Windows_11_STIG_V2R6_Manual-xccdf.xml](STIG/Windows_11/V2R6_Manual_STIG/U_MS_Windows_11_STIG_V2R6_Manual-xccdf.xml)
- **Local STIG package folder:** [STIG/Windows_11/V2R6_Manual_STIG](STIG/Windows_11/V2R6_Manual_STIG)
- **Local STIG stylesheet:** [STIG/Windows_11/V2R6_Manual_STIG/STIG_unclass.xsl](STIG/Windows_11/V2R6_Manual_STIG/STIG_unclass.xsl)
- **Current deployment STIG root:** [STIG](STIG)
- **Current local STIG folder layout:** `deployment/STIG/Windows_11/V2R6_Manual_STIG/`
- **STIG release package name in this repo:** `Windows_11/V2R6_Manual_STIG`
- **Benchmark / Product:** Microsoft Windows 11 STIG
- **STIG release:** `V2R6`
- **Group ID:** `V-253262`
- **Rule ID:** `SV-253262R958808`
- **Rule XML ID:** `SV-253262r958808_rule`
- **Version / STIG ID:** `WN11-00-000035`
- **SRG:** `SRG-OS-000370-GPOS-00155`
- **CCI:** `CCI-001774`
- **Severity:** `medium`
- **Category:** `CAT II`
- **DPMS Target Identifier:** `5471`
- **Rule title:** The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

### STIG Discussion Summary

The local Windows 11 V2R6 STIG states that allowlisting is a configuration management method for permitting only authorized software to execute, which reduces risk by limiting the number of potential vulnerabilities. It further states that the organization must identify authorized software and only permit execution of authorized software.

### STIG Fix Summary

The local STIG fix text states to configure an application allowlisting program that uses a deny-all, permit-by-exception model. It explicitly identifies **AppLocker** as an allowlisting capability built into Windows 11 Enterprise and points administrators to configure it through:

`Computer Configuration >> Windows Settings >> Security Settings >> Application Control Policies >> AppLocker`

### STIG Check Summary

The local STIG check text says verification must confirm the operating system uses a deny-all, permit-by-exception approach and that this **must include packaged apps**, including universal apps installed by default. It also notes that if no application allowlisting program is in use, this is a finding. For AppLocker review, the STIG instructs administrators to export the effective policy with:

```powershell
Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml
```

### Microsoft References

- [AppLocker overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)
- [Working with AppLocker rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [Packaged apps and packaged app installer rules in AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/packaged-apps-and-packaged-app-installer-rules-in-applocker)
- [Configure an AppLocker policy for Audit only](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/configure-an-applocker-policy-for-audit-only)
- [Understand AppLocker policy design decisions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understand-applocker-policy-design-decisions)
- [Requirements to use AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/requirements-to-use-applocker)

### NSA Reference Noted By The STIG

The extracted local STIG text explicitly says implementation guidance is available in the NSA paper titled **"Application allowlisting using Microsoft AppLocker"**. In this V2R6 source file, the accompanying URL printed in both the fix and check text is the Microsoft AppLocker deployment guide path below:

- [URL printed in the local STIG text: Microsoft AppLocker deployment guide](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-policies-deployment-guide)

Because the local STIG text names the NSA paper but prints a Microsoft documentation URL, this checklist uses the exact wording from the extracted source and includes the current Microsoft Learn AppLocker references above.
