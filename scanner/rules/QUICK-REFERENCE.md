# PowerShell Security Detection Rules - Quick Reference

## Critical Threats (CVSS 9.0+)

| Rule ID | Threat | CVSS | Detection |
|---------|--------|------|-----------|
| PS018 | Unencrypted Authentication | 9.8 | `-AllowUnencryptedAuthentication` |
| PS019 | Certificate Validation Bypass | 9.1 | `ServerCertificateValidationCallback` |
| PS044 | Script Block Logging Disabled | 9.0 | Disables PowerShell logging |
| PS045 | AMSI Bypass | 9.8 | `AmsiUtils`, `amsiInitFailed` |
| PS046 | Constrained Language Mode Bypass | 9.5 | `LanguageMode`, `FullLanguage` |
| PS049 | Reflective DLL Injection | 9.0 | `VirtualAlloc`, `WriteProcessMemory` |
| PS050 | Process Injection | 9.3 | `CreateProcess`, `VirtualAllocEx` |
| PS052 | Kerberos Ticket Manipulation | 9.0 | `Invoke-Mimikatz`, `kerberos::ptt` |

## High Priority Threats (CVSS 7.0-8.9)

| Rule ID | Threat | Key Indicators |
|---------|--------|----------------|
| PS001 | Invoke-Expression Usage | `Invoke-Expression` |
| PS003 | Start-Process with Variable | Variable command paths |
| PS010 | ConvertTo-SecureString PlainText | `-AsPlainText` parameter |
| PS015 | Weak Encryption | DES, TripleDES, RC2, RC4 |
| PS024 | Path Traversal | File ops with user input |
| PS031 | Disabled Security Features | Defender, UAC, Firewall |
| PS041 | .NET Reflection Loading | `[Reflection.Assembly]::Load` |
| PS043 | WMI/CIM Execution | `Invoke-WmiMethod` |
| PS048 | Encoded Commands | `-EncodedCommand` |
| PS053 | Event Log Manipulation | `Clear-EventLog` |
| PS054 | Token Manipulation | `DuplicateToken` |
| PS057 | UAC Bypass | `eventvwr.exe`, `fodhelper` |
| PS060 | DNS Tunneling | Suspicious DNS queries |

## Common Attack Patterns

### Defense Evasion
- **AMSI Bypass** (PS045): Malware disables antimalware scanning
- **Logging Disabled** (PS044): Attackers hide activities
- **CLM Bypass** (PS046): Escape language restrictions
- **Execution Policy** (PS047): Bypass script execution controls

### Credential Theft
- **Hardcoded Credentials** (PS009): Passwords in code
- **Credential Logging** (PS012): Passwords in logs
- **Kerberos Attacks** (PS052): Pass-the-ticket
- **Token Theft** (PS054): Privilege escalation

### Code Execution
- **Invoke-Expression** (PS001): Arbitrary code execution
- **Add-Type** (PS002): Dynamic .NET compilation
- **Reflection** (PS041): Load malicious assemblies
- **DLL Injection** (PS049): In-memory attacks

### Lateral Movement
- **WMI/CIM** (PS043): Remote command execution
- **PowerShell Remoting** (PS056): Session hijacking
- **LOLBins** (PS055): Abuse of trusted binaries

## Remediation Priority

### Immediate Action Required
1. Enable and enforce **Script Block Logging** (prevent PS044)
2. Ensure **AMSI is enabled** and not bypassed (prevent PS045)
3. Implement **Constrained Language Mode** via WDAC (prevent PS046)
4. Remove all **hardcoded credentials** (PS009, PS010)
5. Fix **certificate validation bypasses** (PS019)

### High Priority
1. Replace **Invoke-Expression** with safer alternatives (PS001)
2. Validate all **file paths** for traversal (PS024)
3. Remove **weak encryption algorithms** (PS014, PS015)
4. Enable **Windows Defender** and security features (PS031)
5. Implement **input validation** for all user input

### Best Practices
1. Use **approved verbs** for functions (PS040)
2. Add **CmdletBinding** to advanced functions (PS037)
3. Avoid **empty catch blocks** (PS036)
4. Minimize **global variable** usage (PS039)
5. Use **PSCredential** instead of separate username/password (PS011)

## Detection by Category

### Code Execution (9 rules)
PS001, PS002, PS003, PS041, PS042, PS043, PS049, PS050, PS055

### Credentials (6 rules)
PS009, PS010, PS011, PS012, PS052, PS054

### Cryptography (2 rules)
PS014, PS015

### Network Security (5 rules)
PS018, PS019, PS020, PS051, PS060

### Windows Security (8 rules)
PS031, PS031B, PS032, PS033, PS044, PS045, PS046, PS047, PS053, PS057

### Obfuscation (4 rules)
PS027, PS028, PS030, PS048

### File System (1 rule)
PS024

### Best Practices (4 rules)
PS036, PS037, PS039, PS040

### Data Exfiltration (3 rules)
PS058, PS059, PS060

## MITRE ATT&CK Mapping

| Tactic | Technique | Rules |
|--------|-----------|-------|
| Initial Access | Phishing (T1566) | PS030, PS048 |
| Execution | PowerShell (T1059.001) | PS001, PS002, PS041-PS050 |
| Persistence | Registry Run Keys (T1547.001) | PS032 |
| Persistence | Scheduled Task (T1053.005) | PS033 |
| Privilege Escalation | Token Manipulation (T1134) | PS054 |
| Privilege Escalation | UAC Bypass (T1548.002) | PS057 |
| Defense Evasion | AMSI Bypass | PS045 |
| Defense Evasion | CLM Bypass | PS046 |
| Defense Evasion | Indicator Removal (T1070) | PS053 |
| Credential Access | Kerberos (T1558) | PS052 |
| Discovery | Network Service Discovery | PS043 |
| Lateral Movement | Remote Services (T1021) | PS043, PS056 |
| Collection | Clipboard Data (T1115) | PS058 |
| Collection | Screen Capture (T1113) | PS059 |
| Exfiltration | DNS (T1048.002) | PS060 |

## Testing Your Code

### Critical Checks
```powershell
# 1. No AMSI bypass attempts
Get-Content .\script.ps1 | Select-String -Pattern "AmsiUtils|amsiInitFailed"

# 2. No encoded commands
Get-Content .\script.ps1 | Select-String -Pattern "-EncodedCommand|-enc"

# 3. No hardcoded credentials
Get-Content .\script.ps1 | Select-String -Pattern "password|apikey|secret"

# 4. No Invoke-Expression
Get-Content .\script.ps1 | Select-String -Pattern "Invoke-Expression|iex"

# 5. No reflection abuse
Get-Content .\script.ps1 | Select-String -Pattern "\[Reflection\.Assembly\]::Load"
```

## Compliance Standards

| Standard | Relevant Rules |
|----------|----------------|
| **OWASP Top 10** | PS001 (Injection), PS009 (Credentials), PS015 (Crypto) |
| **CIS Controls** | PS044 (Logging), PS031 (Security Features) |
| **NIST 800-53** | PS010 (Crypto), PS019 (TLS), PS053 (Audit) |
| **PCI DSS** | PS009 (Credentials), PS014 (Crypto), PS024 (Path Traversal) |

## Version Information
- **Current Version**: 1.1.0
- **Last Updated**: 2025-11-25
- **Total Rules**: 45
- **Critical Rules**: 11
- **High Rules**: 13
