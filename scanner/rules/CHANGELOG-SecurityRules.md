# Security Detection Rules Changelog

## Version 1.1.0 (2025-11-25)

### Summary
Comprehensive update based on latest PowerShell security research from Microsoft, OWASP, and MITRE ATT&CK framework. Added 20 new critical security detection rules covering modern attack techniques and defense evasion methods.

### New Critical Security Rules Added

#### Code Execution & Injection (PS041-PS043, PS049-PS050)
- **PS041**: .NET Reflection Assembly Loading - Detects reflection-based assembly loading for arbitrary code execution
- **PS042**: COM Object Creation - Identifies COM object instantiation for privilege escalation
- **PS043**: WMI/CIM Command Execution - Catches lateral movement via WMI/CIM
- **PS049**: Reflective DLL Injection - Detects in-memory malicious code loading
- **PS050**: Process Injection Techniques - Identifies process hollowing and injection

#### Security Feature Bypass (PS044-PS047)
- **PS044**: Script Block Logging Disabled - Critical detection for logging tampering (CVSS 9.0)
- **PS045**: AMSI Bypass Attempt - Detects Anti-Malware Scan Interface bypass (CVSS 9.8)
- **PS046**: Constrained Language Mode Bypass - Identifies CLM security control bypass (CVSS 9.5)
- **PS047**: Execution Policy Bypass - Catches common policy bypass techniques

#### Credential & Token Attacks (PS052, PS054)
- **PS052**: Kerberos Ticket Manipulation - Detects pass-the-ticket attacks (CVSS 9.0)
- **PS054**: Token Manipulation - Identifies Windows access token manipulation (CVSS 8.0)

#### Windows Security Controls (PS053, PS057)
- **PS053**: Windows Event Log Manipulation - Detects audit log tampering
- **PS057**: UAC Bypass Techniques - Identifies UAC bypass methods

#### Advanced Techniques
- **PS048**: Suspicious Encoded Command - Detects obfuscated -EncodedCommand usage
- **PS051**: Suspicious Web Request - Identifies potential C2 communication
- **PS055**: Living Off The Land Binaries (LOLBins) - Detects LOLBin abuse
- **PS056**: PowerShell Remoting Suspicious Usage - Catches lateral movement
- **PS058**: Clipboard Access - Detects potential data theft
- **PS059**: Screen Capture Attempt - Identifies surveillance attempts
- **PS060**: DNS Tunneling Indicators - Detects DNS-based exfiltration

### Research Sources
1. **Microsoft Learn**: PowerShell security features, AMSI integration, constrained language mode
2. **OWASP**: Injection prevention cheat sheets, command injection defense
3. **MITRE ATT&CK**: T1059.001 (Command and Scripting Interpreter: PowerShell) techniques
4. **Microsoft Defender for Endpoint**: AMSI demonstrations and threat intelligence

### Key Security Improvements

#### Enhanced Detection Coverage
- **Attack Surface Reduction**: 20 new rules covering MITRE ATT&CK techniques
- **Defense Evasion**: Better detection of AMSI, CLM, and logging bypass attempts
- **Privilege Escalation**: Improved coverage of token manipulation and UAC bypass
- **Lateral Movement**: Enhanced WMI/CIM and PowerShell remoting detection

#### Updated CVSS Scores
Critical severity rules now range from CVSS 9.0-9.8 for:
- AMSI bypass attempts
- Constrained language mode bypass
- Reflective DLL injection
- Kerberos ticket manipulation

#### Remediation Guidance Enhanced
All new rules include:
- Specific remediation steps
- Microsoft recommended security controls
- References to Windows Defender features (WDAC, Credential Guard, etc.)
- Best practice implementation guidance

### Statistics
- **Total Rules**: Increased from 25 to 45 (+80%)
- **Critical Rules**: Increased from 5 to 11
- **High Severity Rules**: Increased from 6 to 13
- **Coverage**: Now includes MITRE ATT&CK T1059.001 common techniques

### Breaking Changes
None - all existing rules maintained with same IDs and structure.

### Recommended Actions for Release
1. **Update Documentation**: Review and update any references to rule counts
2. **Test Scanner**: Verify all new rules work with the scanner engine
3. **Baseline Testing**: Run against PSFramework to establish new baseline
4. **Update Reports**: Regenerate security reports with new rules
5. **Communication**: Inform users of enhanced detection capabilities

### Next Steps
Consider adding:
- Machine learning-based anomaly detection
- Behavioral analysis for script execution patterns
- Integration with Microsoft Defender for Endpoint alerts
- Custom rules for organization-specific threats

### References
- [PowerShell Security Features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
- [AMSI Integration](https://learn.microsoft.com/en-us/defender-endpoint/amsi-on-mdav)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Constrained Language Mode](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/how-app-control-works)
