# AppLocker Policy Enhancement - LOLBins Block Summary

## What is AppLocker?

**AppLocker** is a Windows application control feature that allows administrators to specify which users or groups can run particular applications based on unique identities of files. It provides granular control over executables, scripts, Windows Installer files, packaged apps, and DLLs.

**Microsoft Documentation:** [AppLocker Overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)

### Why Use AppLocker for Defense-in-Depth?

Traditional security controls like antivirus and EDR are **reactive** - they detect known malware signatures or suspicious behaviors after execution begins. AppLocker provides a **proactive** layer by preventing unauthorized code from executing in the first place.

| Security Layer | Function | Limitation |
|----------------|----------|------------|
| **Antivirus/EDR** | Detects known malware and suspicious behavior | Can miss zero-days, fileless attacks, LOLBins |
| **AppLocker** | Prevents unauthorized executables from running | Requires careful policy management |
| **Combined** | Defense-in-depth - multiple layers of protection | Most effective approach |

**Key Defense-in-Depth Benefits:**

1. **Blocks Unknown Malware:** Even if malware evades AV detection, it cannot execute if not whitelisted
2. **Prevents LOLBin Abuse:** Blocks legitimate Windows tools that attackers repurpose for malicious actions
3. **Stops User-Initiated Threats:** Prevents users from running malicious downloads, even accidentally
4. **Reduces Attack Surface:** Limits what can execute to only approved applications
5. **Complements Other Controls:** Works alongside (not instead of) AV, EDR, and other security tools

### The AppLocker Management Challenge

While AppLocker is powerful, Microsoft provides **no built-in GUI or tooling** for creating and managing comprehensive policies. Administrators must either:

- Manually craft XML policy files (error-prone and time-consuming)
- Use basic GPO wizards that create overly simplistic rules
- Build custom PowerShell automation from scratch

This gap between AppLocker's capabilities and its management tooling has historically led to failed deployments, overly permissive policies, or abandoned implementations.

**This is where AaronLocker comes in.**

---

## About AaronLocker - The Foundation

**AaronLocker** fills the management gap by providing a complete, production-ready toolkit for creating robust AppLocker policies. Developed by Aaron Margosis at Microsoft, it transforms AppLocker from a powerful-but-impractical feature into a deployable security control.

**Source:** [GitHub - microsoft/AaronLocker](https://github.com/microsoft/AaronLocker)

### What is AaronLocker?

AaronLocker is a set of PowerShell scripts and documentation designed to make Windows application whitelisting with AppLocker dramatically easier and more practical. It addresses the real-world challenges that have historically made AppLocker deployments difficult to implement and maintain.

### Why Use AaronLocker?

Without AaronLocker (or similar tooling), organizations face significant barriers:

| Challenge | How AaronLocker Solves It |
|-----------|---------------------------|
| **No management GUI** | Provides ready-to-use scripts that generate comprehensive policies automatically |
| **Maintenance burden** | Creates rules based on publisher signatures rather than file paths, reducing update churn |
| **User writeable paths** | Automatically identifies and blocks execution from user-writable locations |
| **LOLBin gaps** | Generates deny rules for known bypass techniques (enhanced further by this policy) |
| **Testing difficulty** | Includes audit mode support and validation tools |
| **Policy complexity** | Outputs clean, well-structured XML that can be reviewed and version-controlled |

### Key Benefits

1. **Publisher-Based Rules:** Uses digital signatures rather than paths, so applications continue to work after updates without policy changes.

2. **Denies User-Writable Paths:** Automatically blocks execution from locations where standard users can write files (AppData, Downloads, etc.) - the primary attack vector for malware.

3. **Practical Defaults:** Designed for real enterprise environments where users need to run legitimate software while blocking malware.

4. **Scriptable & Repeatable:** Entire policy generation is automated via PowerShell, making it auditable and version-controllable.

### How This Policy Extends AaronLocker

The base AaronLocker policy provides excellent protection, but this enhancement adds:

- **42 additional EXE deny rules** for Microsoft-documented LOLBins
- **5 additional DLL deny rules** for critical bypass libraries
- **Explicit blocks** for tools like MSBuild.exe, mshta.exe, and cscript.exe that sophisticated attackers abuse

This layered approach combines AaronLocker's practical whitelisting with Microsoft's recommended block list for defense-in-depth.

---

## LOLBin Enhancement Overview

This document details the Microsoft Recommended Block Rules that have been added to the base AaronLocker policy. These rules target "Living Off the Land Binaries" (LOLBins) - legitimate Microsoft-signed tools that attackers abuse to bypass security controls.

**Source:** [Microsoft Learn - Applications that can bypass App Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)

---

## Implementation Details

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

## Existing Rules Preserved

Your original policy already contained some protective measures that have been preserved:

1. **BgInfo Deny Rule:** Blocks Sysinternals Bginfo.exe versions ≤4.25 (vulnerable versions)
2. **PowerShell v2 Deny Rules:** Blocks older PowerShell versions via DLL and path rules
3. **Path Exceptions:** Multiple LOLBins were already blocked as exceptions in the Windows folder allow rule

---

## Rule Processing Order

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
   - Monitor Event Log: `Applications and Services Logs\Microsoft\Windows\AppLocker`

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

## References

- [AaronLocker - Microsoft GitHub](https://github.com/microsoft/AaronLocker) - Robust and practical application control for Windows
- [Microsoft - Applications that can bypass App Control](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol)
- [LOLBAS Project](https://lolbas-project.github.io/) - Living Off The Land Binaries, Scripts and Libraries
- [Ultimate WDAC Bypass List](https://github.com/bohops/UltimateWDACBypassList)

---

## [DOMAIN CONTROLLER] - Create & Link a new GPO to the desired OU (Workstations)

<img width="1430" height="544" alt="image" src="https://github.com/user-attachments/assets/47bf338b-dd21-4321-bf98-8454054923b4" />

## [DOMAIN CONTROLLER] - Download the [AppLocker Policies](https://github.com/dcodev1702/AppLocker_Win11-Ent_PoC/tree/main/AppLocker_Policies) and apply them using the proper naming convention. 
  * Edit the GPO, navigate to "AppLocker", right click and 'Import Policy' 

<img width="1276" height="944" alt="image" src="https://github.com/user-attachments/assets/e1a3ed09-8106-464e-9864-70b51269982d" />

## [DOMAIN CONTROLLER] - Update the Group Policy and reboot the CLIENT VM
```powershell
gpupdate /force
```

## [CLIENT VM] - Validate that the GPO is successfully applied to your OU and Assets within the OU.
```powershell
gpresult /r /source computer
```

<img width="743" height="1127" alt="image" src="https://github.com/user-attachments/assets/42035a7a-e660-4dc5-bdd4-50983275b562" />

## [CLIENT VM] - Lastly, run various tests and examine the behavior of AppLocker.
```powershell
.\LOLBin_AppLocker_Tests.ps1
```

<img width="452" height="985" alt="image" src="https://github.com/user-attachments/assets/15fd585e-3fd9-454c-9d1b-abaeb8e4587a" />

## [CLIENT VM] - Observe the results and tune using AaronLocker and Claude as necessary.

<img width="646" height="860" alt="image" src="https://github.com/user-attachments/assets/73c3f03b-f598-48ce-9452-a28771b87278" />

---

*Generated: December 3, 2025*
*Base Policy: AaronLocker*
*Enhancement: Microsoft Recommended Block Rules*
