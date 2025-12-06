# 🚀 AppLocker 🔐 Policy Enablement - w/ LOLBin Blocks

## What is AppLocker?

**AppLocker** is a Windows application control and enforcement mechanism that enables administrators to restrict application execution based on authoritative file characteristics—specifically publisher certificate metadata, file path rules, and cryptographic hash values.

By leveraging these rule types, AppLocker enforces deterministic allow/deny decisions across executables, DLLs, scripts, Windows Installer packages, and packaged apps.
It integrates with Group Policy and the Application Identity (AppID) service to validate each process launch against policy, providing a robust method for reducing attack surface, preventing unauthorized code execution, and supporting a Zero Trust execution model within enterprise environments.

**Microsoft Documentation:** [AppLocker Overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)

### Rule Collection Extensions (Windows 10+)

Starting with Windows 10 and Windows Server 2016, AppLocker supports **Rule Collection Extensions** that extend policy enforcement beyond user-context processes. These extensions are configured by editing AppLocker policy XML directly and are available for EXE and DLL rule collections.

**Microsoft Documentation:** [AppLocker Rule Collection Extensions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/rule-collection-extensions)

| Extension | Element | Purpose |
|-----------|---------|---------|
| **Services Enforcement** | `<ThresholdExtensions>` | Applies AppLocker rules to non-user processes (services, scheduled tasks running as SYSTEM/LocalService/NetworkService) |
| **System Apps** | `<RedstoneExtensions>` | Automatically allows Windows system code to run when enforcing on non-user processes |

**Important:** When adding rule collection extensions, you must include **both** `ThresholdExtensions` and `RedstoneExtensions` or the policy will cause unexpected behavior.

```xml
<RuleCollectionExtensions>
    <ThresholdExtensions>
        <Services EnforcementMode="Enabled"/>
    </ThresholdExtensions>
    <RedstoneExtensions>
        <SystemApps Allow="Enabled"/>
    </RedstoneExtensions>
</RuleCollectionExtensions>
```

This policy implements these extensions to ensure AppLocker rules apply to scheduled tasks and services running under SYSTEM context—closing a common gap where attackers leverage non-user processes to bypass application control.

### Why Use AppLocker for Defense-in-Depth?

Traditional security controls like antivirus and EDR are **reactive** - they detect known malware signatures or suspicious behaviors after execution begins. AppLocker provides a **proactive** layer by preventing unauthorized code from executing in the first place.

| Security Layer | Function | Limitation |
|----------------|----------|------------|
| **Antivirus/EDR** | Detects known malware and suspicious behavior | Can miss zero-days, fileless attacks, LOLBins |
| **AppLocker** | Prevents unauthorized executables from running | Requires careful & continuous policy management |
| **AppLocker Rule Collection Extensions** | Extends AppLocker enforcement to services and scheduled tasks running as SYSTEM/LocalService/NetworkService | Requires Windows 10+ / Server 2016+; must include both ThresholdExtensions and RedstoneExtensions |
| **ASR** | Attack Surface Reduction | Requires MDAV and careful management |
| **OS Hardening** | Harden OS w/ Best Practices | Enable OS hardening and auditing |
| **Combined** | Defense-in-depth - multiple layers of protection | Most effective approach |

**Key Defense-in-Depth Benefits:**

1. **Blocks Unknown Malware:** Even if malware evades AV detection, it cannot execute if not whitelisted
2. **Prevents LOLBin Abuse:** Blocks legitimate Windows tools that attackers repurpose for malicious actions
3. **Stops User-Initiated Threats:** Prevents users from running malicious downloads, even accidentally
4. **Reduces Attack Surface:** Limits what can execute to only approved applications
5. **Complements Other Controls:** Works alongside (not instead of) AV, EDR, and other security tools
6. **Enforces on Non-User Processes:** With Rule Collection Extensions enabled, policies apply to services and scheduled tasks running as SYSTEM—preventing attackers from bypassing controls via privileged scheduled tasks or service execution

---

## AppLocker Architecture and Components 🏗️

AppLocker uses the **Application Identity service** to provide attributes for a file and to evaluate the AppLocker policy for the file. AppLocker policies are conditional access control entries (ACEs), and policies are evaluated using the attribute-based access control `SeAccessCheckWithSecurityAttributes` or `AuthzAccessCheck` functions.

**Microsoft Documentation:** [AppLocker Architecture and Components](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-architecture-and-components)

AppLocker provides three ways to intercept and validate if a file is allowed to run:

### 🔩 A New Process is Created

When an app file is run, a new process is created. When that happens, AppLocker calls the Application Identity component to calculate the attributes of the main executable file used to create the new process. It then updates the new process's token with these attributes and checks the AppLocker policy to verify that the executable file is allowed to run.

### 🔩 A DLL is Loaded

When a DLL is loaded, a notification is sent to AppLocker to verify that the DLL is allowed to load. AppLocker calls the Application Identity component to calculate the file attributes. It duplicates the existing process token and replaces those Application Identity attributes in the duplicated token with attributes of the loaded DLL. AppLocker then evaluates the policy for this DLL, and the duplicated token is discarded. Depending on the result of this check, the system either continues to load the DLL or stops the process.

### 🔩 A Script is Run

Before a script file is run, the script host (for example, PowerShell) calls AppLocker to verify the script. AppLocker calls the Application Identity component in user-mode with the file name or file handle to calculate the file properties. The script file is then evaluated against the AppLocker policy to verify that it should run.

---

### The AppLocker Management Challenge

While AppLocker is powerful, Microsoft provides **no built-in GUI or tooling** for creating and managing comprehensive policies. Administrators must either:

- Manually craft XML policy files (error-prone and time-consuming)
- Use basic GPO wizards that create overly simplistic rules
- Build custom PowerShell automation from scratch

This gap between AppLocker's capabilities and its management tooling has historically led to failed deployments, overly permissive policies, or abandoned implementations.

Learn more about Microsoft's AppLocker Tools [here.](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/tools-to-use-with-applocker)

**This is where AaronLocker comes in! 🔧**

---

## ✨ Enter, AaronLocker

**AaronLocker** fills the management gap by providing a complete, production-ready toolkit for creating robust AppLocker policies. Developed by Aaron Margosis at Microsoft, it transforms AppLocker from a powerful-but-impractical feature into a deployable security control.

**Source:** [GitHub - microsoft/AaronLocker](https://github.com/microsoft/AaronLocker)

### What is AaronLocker?

AaronLocker is a set of PowerShell scripts and documentation designed to make Windows application whitelisting with AppLocker dramatically easier and more practical. It addresses the real-world challenges that have historically made AppLocker deployments difficult to implement and maintain.

1. **Intro to 'AaronLocker'** (7 min, circa Feb. 2019): https://youtu.be/nQyODwPR5qo

2. **AaronLocker Quick Start** (13 min, circa Feb. 2019): https://youtu.be/E-IrqFtJOKU
   - How to build, customize, and deploy robust and practical AppLocker rules quickly using AaronLocker

### Why Use AaronLocker?

Without AaronLocker ⚙️ (or similar tooling), organizations face significant barriers:

| Challenge | How AaronLocker Solves It |
|-----------|---------------------------|
| **No management GUI** | Provides ready-to-use scripts that generate comprehensive policies automatically |
| **Maintenance burden** | Creates rules based on publisher signatures rather than file paths, reducing update churn |
| **User writeable paths** | Automatically identifies and blocks execution from user-writable locations |
| **LOLBin gaps** | Generates deny rules for known bypass techniques (enhanced further by this policy) |
| **Testing difficulty** | Includes audit mode support and validation tools |
| **Policy complexity** | Outputs clean, well-structured XML that can be reviewed and version-controlled |

### Key Benefits 💡

1. **Publisher-Based Rules:** Uses digital signatures rather than paths, so applications continue to work after updates without policy changes.

2. **Denies User-Writable Paths:** Automatically blocks execution from locations where standard users can write files (AppData, Downloads, etc.) - the primary attack vector for malware.

3. **Practical Defaults:** Designed for real enterprise environments where users need to run legitimate software while blocking malware.

4. **Scriptable & Repeatable:** Entire policy generation is automated via PowerShell, making it auditable and version-controllable.

### How This Policy Extends AaronLocker

The base AaronLocker policy provides excellent protection, but this enhancement adds:

- **42 additional EXE deny rules** for Microsoft-documented LOLBins
- **5 additional DLL deny rules** for critical bypass libraries
- **Explicit blocks** for tools like MSBuild.exe, mshta.exe, and cscript.exe that sophisticated cyber threat actors commonly abuse

This layered approach combines AaronLocker's practical whitelisting with Microsoft's recommended block list for defense-in-depth.

---

## 🛡️ LOLBin Enhancement Overview

This document details the Microsoft Recommended Block Rules that have been added to the base AaronLocker policy. These rules target "Living Off the Land Binaries" (LOLBins) - legitimate Microsoft-signed tools that attackers abuse to bypass security controls.

**Source:** [Microsoft Learn - Applications that can bypass App Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)

---

## Implementation Details 📜

- **Rule Type:** FilePublisherRule with Action="Deny"
- **Target SID:** S-1-1-0 (Everyone)
- **Publisher:** O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US
- **Placement:** Deny rules placed at the beginning of each RuleCollection (takes precedence over Allow rules)

---

## Blocked Executables (42 Rules)

| Binary Name | Category | Description |
|------------|----------|-------------|
| AddInProcess.exe | .NET Framework | MAF host process - can execute arbitrary code |
| AddInProcess32.exe | .NET Framework | MAF host process (32-bit) - can execute arbitrary code |
| AddInUtil.exe | .NET Framework | Add-in utility - can load arbitrary assemblies |
| aspnet_compiler.exe | ASP.NET | ASP.NET compilation tool - can compile and execute code |
| bash.exe | WSL | Windows Subsystem for Linux - bypasses Windows controls |
| cdb.exe | Debugging | Console debugger - can inject code into processes |
| cscript.exe | Scripting | Windows Script Host - executes VBScript/JScript |
| csi.exe | Roslyn | C# Interactive - can execute arbitrary C# code |
| dbghost.exe | Debugging | Debug host process - can execute arbitrary code |
| dbgsvc.exe | Debugging | Debug service - can execute arbitrary code |
| dbgsrv.exe | Debugging | Debug server - can execute arbitrary code |
| dnx.exe | .NET | .NET Execution Environment - can run arbitrary .NET code |
| dotnet.exe | .NET | .NET CLI host - can execute arbitrary .NET code |
| fsi.exe | F# | F# Interactive - can execute arbitrary F# code |
| fsiAnyCpu.exe | F# | F# Interactive (AnyCPU) - can execute arbitrary F# code |
| infdefaultinstall.exe | Windows | INF file installer - can execute setup commands |
| InstallUtil.exe | .NET Framework | .NET Installer utility - can execute arbitrary code |
| kd.exe | Debugging | Kernel debugger - can execute arbitrary code |
| kill.exe | Debugging | Process termination tool - from debugging tools |
| lxrun.exe | WSL | WSL legacy management tool - bypasses Windows controls |
| Microsoft.Workflow.Compiler.exe | .NET Framework | Workflow compiler - can compile and execute arbitrary XOML |
| MSBuild.exe | .NET Framework | Microsoft Build Engine - can execute arbitrary code via tasks |
| mshta.exe | Internet Explorer | HTML Application Host - can execute arbitrary scripts |
| ntkd.exe | Debugging | NT Kernel debugger - can execute arbitrary code |
| ntsd.exe | Debugging | NT Symbolic debugger - can execute arbitrary code |
| powershellcustomhost.exe | PowerShell | PowerShell custom host - can bypass PS restrictions |
| rcsi.exe | Roslyn | Roslyn C# Interactive - can execute arbitrary C# code |
| runscripthelper.exe | Windows | Run Script Helper - can execute arbitrary scripts |
| texttransform.exe | Visual Studio | T4 Text Template transformation - can execute arbitrary code |
| visualuiaverifynative.exe | Windows | UI Automation Verify - can load arbitrary assemblies |
| wfc.exe | .NET Framework | Workflow Command-line Compiler - can compile arbitrary code |
| windbg.exe | Debugging | Windows Debugger - can inject code into processes |
| wmic.exe | Windows | WMI Command-line - can execute arbitrary WMI commands |
| wscript.exe | Scripting | Windows Script Host - executes VBScript/JScript |
| wsl.exe | WSL | Windows Subsystem for Linux - bypasses Windows controls |
| wslconfig.exe | WSL | WSL configuration tool - WSL management |
| wslhost.exe | WSL | WSL host process - WSL execution environment |
| RegAsm.exe | .NET Framework | Assembly Registration Utility - can load assemblies |
| RegSvcs.exe | .NET Framework | Component Services Utility - can register components |
| PresentationHost.exe | WPF | WPF host process - can execute XAML applications |
| runas.exe | Windows | Run As command - can elevate privileges |
| cipher.exe | Windows | Encrypting File System tool - can be used for data exfiltration |

---

## Blocked DLLs (5 Rules)

| Binary Name | Category | Description |
|------------|----------|-------------|
| lxssmanager.dll | WSL | WSL Manager DLL - core WSL functionality |
| Microsoft.Build.dll | .NET Framework | MSBuild core library - build engine component |
| MSBuild.dll | .NET Framework | MSBuild library - build engine component |
| System.Management.Automation.dll | PowerShell | PowerShell core DLL - all PS versions |
| davsvc.dll | WebDAV | WebDAV client (WebClnt) - can be used for remote code execution |

---

## 🚨 Existing Rules Preserved

Your original policy already contained some protective measures that have been preserved:

1. **BgInfo Deny Rule:** Blocks Sysinternals Bginfo.exe versions ≤4.25 (vulnerable versions)
2. **PowerShell v2 Deny Rules:** Blocks older PowerShell versions via DLL and path rules
3. **Path Exceptions:** Multiple LOLBins were already blocked as exceptions in the Windows folder allow rule

---

## 🧾 Rule Processing Order

AppLocker processes rules in this order:

1. **Deny rules** are evaluated first (highest priority)
2. **Allow rules** are evaluated second
3. If no explicit rule matches, the file is denied by default

By placing all LOLBin Deny rules at the beginning of each RuleCollection, we ensure they take precedence over any Allow rules that might match the same files.

---

## Deployment Notes

### Testing Recommendations

1. **Audit Mode First:** Consider testing in Audit mode before enforcement
   - Change `EnforcementMode="Enabled"` to `EnforcementMode="AuditOnly"`
   - Monitor Event Log in Event Viewer: `Applications and Services Logs\Microsoft\Windows\AppLocker`
     <img width="1495" height="686" alt="image" src="https://github.com/user-attachments/assets/88a5de13-ae27-439e-b23d-81e0a1ec1c04" />

2. **Critical Applications:** Verify no critical applications depend on blocked binaries:
   - Development environments may need dotnet.exe, MSBuild.exe
   - WSL environments will be completely blocked
   - Debugging tools will be blocked

### Potential Business Impact

Some binaries may be needed for legitimate purposes:

| Binary | Potential Legitimate Use | Mitigation |
|--------|--------------------------|------------|
| dotnet.exe | .NET development | Create exception for developer workstations |
| MSBuild.exe | Build processes | Use dedicated build servers with different policy |
| wsl.exe | Linux development | Evaluate if WSL is needed in your environment |
| windbg.exe | Debugging | Allow for IT/Security teams only |

### Group Policy Deployment

```powershell
# Import the policy via PowerShell
Set-AppLockerPolicy -XmlPolicy "\\domain\sysvol\policies\AppLockerPolicy-Enhanced-LOLBins-Blocked.xml" -Ldap "LDAP://CN={GPO-GUID},CN=Policies,CN=System,DC=domain,DC=com"

# Or import to local policy for testing
Set-AppLockerPolicy -XmlPolicy "C:\Policies\AppLockerPolicy-Enhanced-LOLBins-Blocked.xml"
```

---

### [DOMAIN CONTROLLER] - Create & Link a new GPO to the desired OU (Workstations)

<img width="1430" height="544" alt="image" src="https://github.com/user-attachments/assets/47bf338b-dd21-4321-bf98-8454054923b4" />

### [DOMAIN CONTROLLER] - Download [AppLocker Policies](https://github.com/dcodev1702/AppLocker_Win11-Ent_PoC/tree/main/AppLocker_Policies) and apply them. 
  * Edit the GPO, navigate to "AppLocker", right click and 'Import Policy' 

<img width="1276" height="944" alt="image" src="https://github.com/user-attachments/assets/e1a3ed09-8106-464e-9864-70b51269982d" />

### [DOMAIN CONTROLLER] - Update the Group Policy and reboot the CLIENT VM
```powershell
gpupdate /force
```

### [CLIENT 🖥️] - For good measure, restart the VM after the Group Policy update has been applied.
```powershell
Restart-Computer
```

### [CLIENT 🖥️] - Elevate to a PS Administrator session & validate that the GPO is successfully applied to your OU and Assets within the OU.
```powershell
gpresult /r /source computer
```

<img width="743" height="1127" alt="image" src="https://github.com/user-attachments/assets/42035a7a-e660-4dc5-bdd4-50983275b562" />

### [CLIENT 🖥️] - Lastly, run the PS script and examine the behavior of the applied AppLocker policy.
```powershell
.\AppLocker-LOLBin-PolicyCheck.ps1
```

<img width="452" height="985" alt="image" src="https://github.com/user-attachments/assets/15fd585e-3fd9-454c-9d1b-abaeb8e4587a" />

### [CLIENT 🖥️] - Observe the results and tune AppLocker policy rules using AaronLocker and Claude as necessary.

<img width="646" height="860" alt="image" src="https://github.com/user-attachments/assets/73c3f03b-f598-48ce-9452-a28771b87278" />

---

## 🧬 Anatomy of AppLocker Rules 🔍

AppLocker rules control what applications can run in your organization. Each rule is based on a **rule condition**—criteria that AppLocker uses to identify the apps the rule affects. There are three primary rule condition types.

**Microsoft Documentation:** [Understanding AppLocker Rule Condition Types](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-rule-condition-types)

### [Publisher Condition]()


Publisher conditions identify an app based on its **digital signature**. The digital signature contains information about the publisher (the company that created the app), along with extended attributes like product name, file name, and version number.

**Advantages:**
- Rules survive application updates (signature remains valid)
- More secure than path conditions
- Easier to maintain than file hash conditions

**Disadvantages:**
- Only works with digitally signed files
- Version-specific rules may need updates when new versions release

**Example from this policy** - Block MSBuild.exe (LOLBin):
```xml
<FilePublisherRule Id="cacd0075-1701-4b30-85a3-8d3efb1f9ef9" Name="LOLBin Block: MSBuild.exe" 
                   Description="Microsoft Recommended Block - MSBuild.exe - Microsoft Build Engine" 
                   UserOrGroupSid="S-1-1-0" Action="Deny">
    <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" 
                                ProductName="*" BinaryName="MSBUILD.EXE">
            <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
    </Conditions>
</FilePublisherRule>
```

**Example from this policy** - Allow OneDrive:
```xml
<FilePublisherRule Id="84b5d302-accb-452d-a7f2-fb6081750b50" Name="OneDrive: ONEDRIVE" 
                   Description="Product: ONEDRIVE" UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" 
                                ProductName="ONEDRIVE" BinaryName="*">
            <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
    </Conditions>
</FilePublisherRule>
```

### [Path Condition]()

Path conditions identify an app by its **location in the file system**. Path rules affect all files in the specified directory and its subdirectories unless explicitly exempted.

**Advantages:**
- Works with any file (signed or unsigned)
- Easy to create and understand
- Good for controlling execution from specific directories

**Disadvantages:**
- Less secure—users or malware can copy files to allowed locations
- Must account for user-writable subdirectories
- Deny rules are less effective (files can be moved)

**Example from this policy** - Allow Windows folder with exceptions:
```xml
<FilePathRule Id="38080c1b-54bc-4f7e-804d-fafb70bf781b" Name="All files located in the Windows folder" 
              Description="Allows members of the Everyone group to run applications that are located in the Windows folder." 
              UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
        <FilePathCondition Path="%WINDIR%\*"/>
    </Conditions>
    <Exceptions>
        <FilePathCondition Path="%SYSTEM32%\tasks\*"/>
        <FilePathCondition Path="%WINDIR%\tasks\*"/>
        <FilePathCondition Path="%WINDIR%\temp\*"/>
        <!-- Additional exceptions for user-writable paths and LOLBins -->
    </Exceptions>
</FilePathRule>
```

**Example from this policy** - Allow network share:
```xml
<FilePathRule Id="42a13910-e372-4cf0-a008-b24d6ff596c9" Name="Additional allowed path: \\hawk-ir.local\netlogon\*" 
              Description="Allows Everyone to execute from \\hawk-ir.local\netlogon\*" 
              UserOrGroupSid="S-1-1-0" Action="Allow">
    <Conditions>
        <FilePathCondition Path="\\hawk-ir.local\netlogon\*"/>
    </Conditions>
</FilePathRule>
```

### [File Hash Condition]()

File hash conditions identify an app using a **cryptographic hash** (Authenticode hash) of the file. Each unique file version produces a unique hash value.

**Advantages:**
- Works with any file (signed or unsigned)
- Most specific—identifies exact file version
- Cannot be spoofed or bypassed

**Disadvantages:**
- Must update rules for every new file version
- High maintenance overhead
- Hash must be recalculated after any file change

**Example from this policy** - AaronLocker timestamp marker:
```xml
<FileHashRule Id="456bd77c-5528-4a93-8ab8-51c6b950c541" Name="Rule set created 2025-12-02 18:04" 
              Description="Never-applicable rule to document that this AppLocker rule set was created via AaronLocker at 2025-12-02 18:04" 
              UserOrGroupSid="S-1-3-0" Action="Deny">
    <Conditions>
        <FileHashCondition>
            <FileHash Type="SHA256" Data="0x0000000000000000000000000000000000000000000000000020251202180406" 
                      SourceFileName="DateTimeInfo" SourceFileLength="1"/>
        </FileHashCondition>
    </Conditions>
</FileHashRule>
```

### Choosing the Right Condition Type

| Question | Recommendation |
|----------|----------------|
| Is the file digitally signed? | Use **Publisher** condition (preferred) |
| Is the file unsigned but in a trusted location? | Use **Path** condition with exceptions for user-writable subdirectories |
| Do you need to allow a specific file version only? | Use **File Hash** condition |
| Do you want rules that survive updates? | Use **Publisher** condition |

**Best Practice:** Use publisher conditions whenever possible. They provide the best balance of security and maintainability. Reserve path conditions for unsigned software in controlled directories, and file hash conditions for specific files that must be pinned to exact versions.

---

## ✔️ References

- [AaronLocker - Microsoft GitHub](https://github.com/microsoft/AaronLocker) - Robust and practical application control for Windows
- [Microsoft - Applications that can bypass App Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)
- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries, Scripts and Libraries
- [Ultimate WDAC Bypass List](https://github.com/bohops/UltimateWDACBypassList)
- [AppLocker Architecture and Components](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-architecture-and-components)
- [Understanding AppLocker Rule Condition Types](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-rule-condition-types)
- [AppLocker Rule Collection Extensions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/rule-collection-extensions)

## 🎯 Application Whitelisting – Official Guidance Links

| Source / Agency | Link | Description |
|-----------------|------|-------------|
| **NSA** | [Application Whitelisting Best Practices](https://apps.nsa.gov/iaarchive/library/ias/adversary-mitigations/application-whitelisting-best-practices.cfm) | Official NSA guidance on implementing and managing application whitelisting. |
| **NSA** | [Application Whitelisting (Trifold Overview)](https://apps.nsa.gov/iaarchive/library/ia-guidance/archive/application-whitelisting-trifold.cfm) | High-level NSA summary of allowlisting concepts and benefits. |
| **ASD / ACSC** | [Implementing Application Control](https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/implementing-application-control) | Australian Essential Eight guidance for deploying application control. |
| **JPCERT/CC** | [Security Guidance & Technical Notes](https://www.jpcert.or.jp/english/) | JPCERT’s official defensive security publications (general system-hardening; no dedicated allowlisting document). |
| **NIST** | [SP 800-167 – Guide to Application Whitelisting](https://csrc.nist.gov/pubs/sp/800/167/final) | U.S. NIST’s comprehensive vendor-agnostic framework for allowlisting. |



- [NSA – Application Whitelisting Best Practices](https://apps.nsa.gov/iaarchive/library/ias/adversary-mitigations/application-whitelisting-best-practices.cfm) – Official NSA guidance on implementing and managing application whitelisting.
- [NSA – Application Whitelisting (Trifold Overview)](https://apps.nsa.gov/iaarchive/library/ia-guidance/archive/application-whitelisting-trifold.cfm) – High-level NSA summary of whitelisting concepts and benefits.
- [ASD / ACSC – Implementing Application Control](https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/implementing-application-control) – Australia's authoritative guidance for deploying allowlisting as part of the Essential Eight.
- [JPCERT/CC – Security Guidance & Technical Notes](https://www.jpcert.or.jp/english/) – JPCERT’s official repository of defensive security publications (no dedicated allowlisting guide, but relevant system-hardening content).
- [NIST SP 800-167 – Guide to Application Whitelisting](https://csrc.nist.gov/pubs/sp/800/167/final) – U.S. NIST’s comprehensive, vendor-agnostic framework for understanding and implementing application whitelisting.


---

*Generated: December 3, 2025* <br/>
*AppLocker Tool & Base Policy: AaronLocker* <br/>
*Enhancements: Microsoft Recommended Block Rules & Rule Collection Extension*
