# AppLocker LOLBin Manual Test Commands

## Quick Validation Tests

Run these commands from a **non-administrator** command prompt or PowerShell session.
If AppLocker is working correctly, each command should **fail with an access denied error**.

> ⚠️ **Important:** Run as a standard user, not as Administrator. 
> Administrators typically have blanket allow rules in AppLocker policies.

---

## Test 1: cipher.exe

**Threat Actor Use Case:** 
- Secure deletion of files to cover tracks
- Overwriting free space after ransomware encryption
- Data exfiltration preparation

**Test Command (CMD):**
```cmd
cipher /?
```

**Test Command (PowerShell):**
```powershell
& cipher.exe /?
```

**Expected Result if BLOCKED:**
```
This program is blocked by group policy. For more information, contact your system administrator.
```

**If NOT blocked:** You'll see the cipher help text explaining encryption options.

---

## Test 2: mshta.exe

**Threat Actor Use Case:**
- Execute malicious HTA files from phishing emails
- Inline VBScript/JScript execution
- Download and execute payloads (very common in initial access)
- Bypass application whitelisting

**Test Command (CMD):**
```cmd
mshta javascript:close();
```

**Test Command (PowerShell):**
```powershell
Start-Process mshta.exe -ArgumentList 'javascript:close();' -ErrorAction Stop
```

**Expected Result if BLOCKED:**
```
This program is blocked by group policy. For more information, contact your system administrator.
```

**If NOT blocked:** A brief flash of a window that immediately closes (the javascript:close() command).

---

## Test 3: msbuild.exe

**Threat Actor Use Case:**
- Execute arbitrary C# or VB.NET code via inline tasks
- Compile and run malicious payloads without dropping executables
- Bypass application control (code runs within trusted msbuild.exe)
- Used by APT groups and red teams extensively

**Find all MSBuild instances (PowerShell):**
```powershell
# Discover all MSBuild.exe installations
Get-ChildItem -Path "$env:SystemRoot\Microsoft.NET\Framework*" -Filter "MSBuild.exe" -Recurse -ErrorAction SilentlyContinue | 
ForEach-Object {
    $ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName)
    [PSCustomObject]@{
        Path = $_.FullName
        Version = $ver.FileVersion
        Arch = if ($_.FullName -match 'Framework64') {'x64'} else {'x86'}
    }
} | Format-Table -AutoSize
```

**Test each discovered instance:**
```powershell
# Test all discovered MSBuild instances
Get-ChildItem -Path "$env:SystemRoot\Microsoft.NET\Framework*" -Filter "MSBuild.exe" -Recurse -EA SilentlyContinue | 
ForEach-Object {
    Write-Host "Testing: $($_.FullName)" -ForegroundColor Cyan
    & $_.FullName /version 2>&1
    Write-Host ""
}
```

**Test a specific instance (CMD):**
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe /version
```

**Expected Result if BLOCKED:**
```
This program is blocked by group policy. For more information, contact your system administrator.
```

**If NOT blocked:** You'll see version info like:
```
Microsoft (R) Build Engine version 4.8.9037.0
```

---

## Test 4: cscript.exe

**Threat Actor Use Case:**
- Execute malicious VBScript files
- COM object abuse for system access
- Download cradles for malware
- WMI-based attacks
- Very common in macro-based malware

**Test Command (CMD):**
```cmd
cscript //?
```

**Test Command (PowerShell):**
```powershell
& cscript.exe //?
```

**Expected Result if BLOCKED:**
```
This program is blocked by group policy. For more information, contact your system administrator.
```

**If NOT blocked:** You'll see the Windows Script Host help text.

---

## Checking AppLocker Event Logs

After running tests, check if blocks were logged:

**PowerShell (run as Admin):**
```powershell
# Get recent AppLocker events (IDs 8003, 8004, 8006, 8007)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    ID = 8003, 8004, 8006, 8007
} -MaxEvents 20 | 
Format-Table TimeCreated, Id, @{L='Status';E={
    switch ($_.Id) {
        8003 { 'ALLOWED/AUDIT' }
        8004 { 'BLOCKED' }
        8006 { 'Policy Applied' }
        8007 { 'Policy NOT Applied' }
    }
}}, Message -Wrap
```

**Event Viewer Path:**
```
Applications and Services Logs > Microsoft > Windows > AppLocker > EXE and DLL
```

**Event IDs:**
| ID | Meaning | Color in Script |
|----|---------|-----------------|
| 8003 | Allowed / Audit logged (shows what WOULD be blocked) | Yellow |
| 8004 | Blocked by policy (Enforce mode - working!) | Green |
| 8006 | Policy applied successfully | Cyan |
| 8007 | Policy not applied (check AppIDSvc) | Red | |

---

## Quick All-in-One Test Block

Copy and paste this entire block into PowerShell to test all four at once:

```powershell
Write-Host "`n=== AppLocker LOLBin Quick Test ===" -ForegroundColor Cyan
Write-Host "Running as: $env:USERNAME`n" -ForegroundColor Yellow

# Test cipher, mshta, cscript
$tests = @(
    @{Name="cipher.exe"; Cmd={& cipher.exe /? 2>&1}},
    @{Name="mshta.exe"; Cmd={& mshta.exe "javascript:close();" 2>&1}},
    @{Name="cscript.exe"; Cmd={& cscript.exe //? 2>&1}}
)

foreach ($test in $tests) {
    Write-Host "Testing $($test.Name)... " -NoNewline
    try {
        $result = & $test.Cmd
        if ($result -match "blocked by group policy|Access is denied") {
            Write-Host "BLOCKED ✓" -ForegroundColor Green
        } else {
            Write-Host "NOT BLOCKED ✗" -ForegroundColor Red
        }
    } catch {
        Write-Host "BLOCKED ✓" -ForegroundColor Green
    }
}

# Dynamically discover and test all MSBuild instances
Write-Host "`nDiscovering MSBuild.exe instances..." -ForegroundColor Gray
$msbuildList = Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework*" -Filter "MSBuild.exe" -Recurse -EA SilentlyContinue
foreach ($msbuild in $msbuildList) {
    $arch = if ($msbuild.FullName -match 'Framework64') {'x64'} else {'x86'}
    $ver = ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($msbuild.FullName)).FileVersion
    Write-Host "Testing msbuild.exe [$arch v$ver]... " -NoNewline
    try {
        $result = & $msbuild.FullName /version 2>&1
        if ($result -match "blocked by group policy|Access is denied") {
            Write-Host "BLOCKED ✓" -ForegroundColor Green
        } else {
            Write-Host "NOT BLOCKED ✗" -ForegroundColor Red
        }
    } catch {
        Write-Host "BLOCKED ✓" -ForegroundColor Green
    }
}

# Show recent AppLocker events
Write-Host "`n=== Recent AppLocker Events ===" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-AppLocker/EXE and DLL'
    ID=8003,8004,8006,8007
} -MaxEvents 10 -EA SilentlyContinue | 
Where-Object {$_.TimeCreated -gt (Get-Date).AddSeconds(-30)} |
ForEach-Object {
    $color = switch($_.Id){8003{'Yellow'};8004{'Green'};8006{'Cyan'};8007{'Red'};default{'Gray'}}
    Write-Host "  [$($_.Id)] " -NoNewline -ForegroundColor $color
    Write-Host ($_.Message -split "`n")[0].Substring(0,[Math]::Min(80,($_.Message -split "`n")[0].Length)) -ForegroundColor Gray
}
Write-Host ""
```

---

## Troubleshooting

If tests show "NOT BLOCKED":

1. **Verify policy is applied:**
   ```powershell
   Get-AppLockerPolicy -Effective -Xml | Out-File C:\temp\effective-policy.xml
   # Then check the XML for your deny rules
   ```

2. **Force Group Policy update:**
   ```cmd
   gpupdate /force
   ```

3. **Check Application Identity service:**
   ```powershell
   Get-Service AppIDSvc | Select Status, StartType
   # Should be: Running, Automatic
   ```

4. **Verify you're not an admin:**
   ```powershell
   ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   # Should return: False
   ```

5. **Check enforcement mode:**
   ```powershell
   Get-AppLockerPolicy -Effective | Select -ExpandProperty RuleCollections | 
   Select RuleCollectionType, EnforcementMode
   # Should show: Enabled (not AuditOnly)
   ```

---

## Why These 4 LOLBins?

| LOLBin | MITRE ATT&CK | Prevalence | Notes |
|--------|--------------|------------|-------|
| **cipher.exe** | T1485, T1070 | Medium | Ransomware cleanup, anti-forensics |
| **mshta.exe** | T1218.005 | Very High | #1 phishing payload delivery method |
| **msbuild.exe** | T1127.001 | High | APT favorite, executes C# inline |
| **cscript.exe** | T1059.005 | Very High | Classic malware delivery via VBS |

All four are in Microsoft's recommended block list and are commonly observed in real-world attacks.
