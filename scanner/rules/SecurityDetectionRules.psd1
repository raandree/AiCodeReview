@{
    # PowerShell Security Detection Rules
    # Based on Microsoft Security Guidelines, PSScriptAnalyzer, OWASP, MITRE ATT&CK, and DSC Community Best Practices
    # Version: 1.1.0
    # Last Updated: 2025-11-25

    Rules         = @(
        # Code Execution Vulnerabilities
        @{
            Id          = 'PS001'
            Name        = 'Invoke-Expression Usage'
            Severity    = 'High'
            Category    = 'CodeExecution'
            Description = 'Detects use of Invoke-Expression which can execute arbitrary code from strings'
            ASTPattern  = 'CommandAst'
            CommandName = 'Invoke-Expression'
            Remediation = 'Replace Invoke-Expression with safer alternatives like & operator or dot-sourcing'
            CVSS        = 7.3
        }

        @{
            Id          = 'PS002'
            Name        = 'Add-Type Usage'
            Severity    = 'Info'
            Category    = 'CodeExecution'
            Description = 'Detects Add-Type which compiles and loads .NET code. Legitimate .NET interop is common - only suspicious when using obfuscation, dangerous P/Invoke, or encoded payloads. Requires review with current threat intelligence.'
            ASTPattern  = 'CommandAst'
            CommandName = 'Add-Type'
            Remediation = 'Review with current web-based threat intelligence. For legitimate use: validate TypeDefinition content, avoid user-supplied code, prefer -AssemblyName over -TypeDefinition when possible.'
            CVSS        = 2.0
        }

        @{
            Id          = 'PS003'
            Name        = 'Start-Process with Variable Command'
            Severity    = 'Medium'
            Category    = 'CodeExecution'
            Description = 'Detects Start-Process where executable path comes from variables'
            ASTPattern  = 'CommandAst'
            CommandName = 'Start-Process'
            Remediation = 'Use hardcoded paths for executables or validate against whitelist'
            CVSS        = 5.9
        }

        # Credential and Secret Management
        @{
            Id          = 'PS009'
            Name        = 'Potential Hardcoded Credentials'
            Severity    = 'Low'
            Category    = 'Credentials'
            Description = 'Detects potential hardcoded passwords, API keys, or tokens in source code. Requires manual review - many false positives from function names, parameter names, and property names.'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'password|passwd|pwd|secret|apikey|api_key|token'
            Remediation = 'Review context - if actual credentials are hardcoded, use SecureString, PSCredential, or credential management systems. Function/parameter names are acceptable.'
            CVSS        = 3.5
        }

        @{
            Id          = 'PS010'
            Name        = 'ConvertTo-SecureString with PlainText'
            Severity    = 'High'
            Category    = 'Credentials'
            Description = 'Detects ConvertTo-SecureString -AsPlainText usage'
            ASTPattern  = 'CommandAst'
            CommandName = 'ConvertTo-SecureString'
            Parameter   = 'AsPlainText'
            Remediation = 'Avoid -AsPlainText in production code'
            CVSS        = 6.5
        }

        @{
            Id          = 'PS011'
            Name        = 'Username and Password Parameters'
            Severity    = 'Medium'
            Category    = 'Credentials'
            Description = 'Detects functions with separate Username and Password parameters'
            ASTPattern  = 'ParameterAst'
            Remediation = 'Use PSCredential parameter type instead'
            CVSS        = 5.3
        }

        @{
            Id          = 'PS012'
            Name        = 'Potential Credential Logging'
            Severity    = 'Low'
            Category    = 'Credentials'
            Description = 'Detects potential credential exposure in logs. Requires manual review - logging usernames, user IDs, and informational messages about credentials is acceptable. Only actual passwords, keys, and tokens should be flagged.'
            ASTPattern  = 'CommandAst'
            CommandName = 'Write-Host|Write-Output|Write-Verbose|Write-Debug|Out-File|Add-Content|Set-Content'
            Remediation = 'Review context - never log actual credentials, passwords, API keys, or tokens. Logging usernames and credential-related status messages is acceptable.'
            CVSS        = 3.1
        }

        # Cryptography Issues
        @{
            Id          = 'PS014'
            Name        = 'Weak Hash Algorithm'
            Severity    = 'Low'
            Category    = 'Cryptography'
            Description = 'Detects use of weak hash algorithms MD5 or SHA1. Requires manual review - many legitimate uses for compatibility, non-security purposes (ETags, checksums), or legacy system integration.'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'MD5|SHA1|SHA-1'
            Remediation = 'Review context - for security-critical operations (password hashing, digital signatures), use SHA256 or stronger. For compatibility/checksums, weak hashes may be acceptable.'
            CVSS        = 3.9
        }

        @{
            Id          = 'PS015'
            Name        = 'Weak Encryption Algorithm'
            Severity    = 'High'
            Category    = 'Cryptography'
            Description = 'Detects use of weak encryption algorithms DES, RC2, RC4'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'DES|TripleDES|RC2|RC4'
            Remediation = 'Use AES with appropriate key sizes'
            CVSS        = 7.5
        }

        # Network Security
        @{
            Id          = 'PS018'
            Name        = 'Unencrypted Authentication'
            Severity    = 'Critical'
            Category    = 'Network'
            Description = 'Detects use of -AllowUnencryptedAuthentication'
            ASTPattern  = 'CommandParameterAst'
            Parameter   = 'AllowUnencryptedAuthentication'
            Remediation = 'Remove -AllowUnencryptedAuthentication and use HTTPS or Kerberos'
            CVSS        = 9.8
        }

        @{
            Id          = 'PS019'
            Name        = 'Certificate Validation Bypass'
            Severity    = 'Critical'
            Category    = 'Network'
            Description = 'Detects code that bypasses SSL/TLS certificate validation'
            ASTPattern  = 'MemberExpressionAst'
            Pattern     = 'ServerCertificateValidationCallback'
            Remediation = 'Never bypass certificate validation in production'
            CVSS        = 9.1
        }

        @{
            Id          = 'PS020'
            Name        = 'HTTP Instead of HTTPS'
            Severity    = 'Medium'
            Category    = 'Network'
            Description = 'Detects URLs using HTTP instead of HTTPS'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'http://'
            Remediation = 'Use HTTPS for all external communications'
            CVSS        = 5.9
        }

        # Deserialization
        @{
            Id          = 'PS021'
            Name        = 'Potential Unsafe Deserialization'
            Severity    = 'Low'
            Category    = 'Deserialization'
            Description = 'Detects Import-Clixml usage. In most cases, modules deserialize their own cache files which is safe. Only flag if deserializing untrusted external data.'
            ASTPattern  = 'CommandAst'
            CommandName = 'Import-Clixml'
            Remediation = 'Review context - deserializing module-created cache files is acceptable. Only flag if deserializing untrusted external input.'
            CVSS        = 3.7
        }

        # File Operations
        @{
            Id          = 'PS024'
            Name        = 'Path Traversal Risk'
            Severity    = 'High'
            Category    = 'FileSystem'
            Description = 'Detects file operations that may allow path traversal'
            ASTPattern  = 'CommandAst'
            CommandName = 'Get-Content|Set-Content|Out-File|Copy-Item|Move-Item|Remove-Item'
            Remediation = 'Validate file paths and check for directory traversal sequences'
            CVSS        = 7.5
        }

        # Obfuscation Detection
        @{
            Id          = 'PS027'
            Name        = 'Base64 Encoding'
            Severity    = 'Medium'
            Category    = 'Obfuscation'
            Description = 'Detects Base64 encoding which may indicate obfuscation'
            ASTPattern  = 'StringConstantExpressionAst|CommandAst'
            Pattern     = 'FromBase64String|ToBase64String|-EncodedCommand|-enc'
            Remediation = 'Review Base64 usage context for legitimacy'
            CVSS        = 5.5
        }

        @{
            Id          = 'PS028'
            Name        = 'High Entropy Strings'
            Severity    = 'Low'
            Category    = 'Obfuscation'
            Description = 'Detects strings with high entropy'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = '[A-Za-z0-9+/=]{100,}'
            Remediation = 'Review high-entropy strings in context'
            CVSS        = 3.3
        }

        @{
            Id                = 'PS030'
            Name              = 'Download and Execute Pattern'
            Severity          = 'Critical'
            Category          = 'Obfuscation'
            Description       = 'Detects download operations followed by code execution (DownloadString, or when downloaded content is piped/invoked)'
            ASTPattern        = 'InvokeMemberExpressionAst'
            Pattern           = 'DownloadString|DownloadData'
            Remediation       = 'Review download-to-execute patterns for legitimacy. Note: Simple file downloads (Invoke-WebRequest -OutFile) without execution are legitimate.'
            CVSS              = 8.8
            RequiresExecution = $true
        }

        # Windows Security
        @{
            Id          = 'PS031'
            Name        = 'Disabled Security Features'
            Severity    = 'High'
            Category    = 'WindowsSecurity'
            Description = 'Detects code that disables Windows security features (Defender, UAC, Firewall, SmartScreen). Requires context analysis for Set-ItemProperty - only flags when modifying security-related registry keys.'
            ASTPattern  = 'CommandAst'
            CommandName = 'Set-MpPreference|Disable-WindowsDefender'
            Remediation = 'Never disable security features in production. If required for testing, document thoroughly and ensure features are re-enabled.'
            CVSS        = 7.8
        }

        @{
            Id          = 'PS031B'
            Name        = 'Registry-Based Security Disabling'
            Severity    = 'High'
            Category    = 'WindowsSecurity'
            Description = 'Detects Set-ItemProperty modifying security-related registry settings (UAC, Defender, Firewall, SmartScreen)'
            ASTPattern  = 'CommandAst'
            CommandName = 'Set-ItemProperty'
            Remediation = 'Review context - only flag if modifying security settings. Setting file properties, environment variables, or application settings is legitimate.'
            CVSS        = 7.8
        }

        @{
            Id          = 'PS032'
            Name        = 'Registry Persistence'
            Severity    = 'Medium'
            Category    = 'WindowsSecurity'
            Description = 'Detects modifications to registry persistence locations'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'CurrentVersion\\Run'
            Remediation = 'Review registry Run key modifications'
            CVSS        = 5.5
        }

        @{
            Id          = 'PS033'
            Name        = 'Scheduled Task Creation'
            Severity    = 'Medium'
            Category    = 'WindowsSecurity'
            Description = 'Detects creation of scheduled tasks'
            ASTPattern  = 'CommandAst'
            CommandName = 'Register-ScheduledTask|New-ScheduledTask'
            Remediation = 'Review scheduled tasks and ensure least privilege'
            CVSS        = 5.3
        }

        # Best Practices
        @{
            Id          = 'PS036'
            Name        = 'Empty Catch Block'
            Severity    = 'Low'
            Category    = 'BestPractice'
            Description = 'Detects empty catch blocks'
            ASTPattern  = 'CatchClauseAst'
            Remediation = 'Handle errors explicitly or add explanatory comment'
            CVSS        = 2.3
        }

        @{
            Id          = 'PS037'
            Name        = 'Missing CmdletBinding'
            Severity    = 'Info'
            Category    = 'BestPractice'
            Description = 'Detects advanced functions without CmdletBinding'
            ASTPattern  = 'FunctionDefinitionAst'
            Remediation = 'Add CmdletBinding attribute to enable common parameters'
            CVSS        = 0.0
        }

        @{
            Id          = 'PS039'
            Name        = 'Global Variable Usage'
            Severity    = 'Low'
            Category    = 'BestPractice'
            Description = 'Detects use of global scope variables'
            ASTPattern  = 'VariableExpressionAst'
            Pattern     = 'global:'
            Remediation = 'Avoid global variables, use function parameters'
            CVSS        = 2.0
        }

        @{
            Id          = 'PS040'
            Name        = 'Unapproved Verb Usage'
            Severity    = 'Info'
            Category    = 'BestPractice'
            Description = 'Detects functions not using approved PowerShell verbs'
            ASTPattern  = 'FunctionDefinitionAst'
            Remediation = 'Use approved verbs from Get-Verb'
            CVSS        = 0.0
        }

        # New Security Rules Based on 2025 Research

        @{
            Id          = 'PS041'
            Name        = '.NET Reflection Assembly Loading'
            Severity    = 'High'
            Category    = 'CodeExecution'
            Description = 'Detects reflection-based assembly loading which can bypass security controls and execute arbitrary .NET code'
            ASTPattern  = 'MemberExpressionAst'
            Pattern     = 'System.Reflection.Assembly|[Reflection.Assembly]::Load|[System.Reflection.Assembly]::LoadFile'
            Remediation = 'Avoid dynamic assembly loading. Use Add-Type with -TypeDefinition or load assemblies from trusted sources only. Validate assembly paths and signatures.'
            CVSS        = 7.8
        }

        @{
            Id          = 'PS042'
            Name        = 'COM Object Creation'
            Severity    = 'Medium'
            Category    = 'CodeExecution'
            Description = 'Detects COM object instantiation which can be used for privilege escalation or bypassing security controls'
            ASTPattern  = 'CommandAst'
            CommandName = 'New-Object'
            Parameter   = '-ComObject'
            Remediation = 'Validate COM object ProgIDs against whitelist. Prefer native PowerShell cmdlets over COM objects when possible.'
            CVSS        = 6.5
        }

        @{
            Id          = 'PS043'
            Name        = 'WMI/CIM Command Execution'
            Severity    = 'High'
            Category    = 'CodeExecution'
            Description = 'Detects WMI/CIM usage for command execution, a common technique for lateral movement and persistence'
            ASTPattern  = 'CommandAst'
            CommandName = 'Invoke-WmiMethod|Invoke-CimMethod'
            Remediation = 'Validate WMI/CIM method invocations. Use constrained language mode. Log all WMI/CIM activities.'
            CVSS        = 7.5
        }

        @{
            Id          = 'PS044'
            Name        = 'Script Block Logging Disabled'
            Severity    = 'Critical'
            Category    = 'WindowsSecurity'
            Description = 'Detects attempts to disable PowerShell script block logging, a critical security feature'
            ASTPattern  = 'CommandAst'
            Pattern     = 'Set-ItemProperty.*ScriptBlockLogging|EnableScriptBlockLogging.*0'
            Remediation = 'Never disable script block logging. Enable and enforce via Group Policy.'
            CVSS        = 9.0
        }

        @{
            Id          = 'PS045'
            Name        = 'AMSI Bypass Attempt'
            Severity    = 'Critical'
            Category    = 'WindowsSecurity'
            Description = 'Detects attempts to bypass Anti-Malware Scan Interface (AMSI), used by malware to evade detection'
            ASTPattern  = 'StringConstantExpressionAst|MemberExpressionAst'
            Pattern     = 'AmsiUtils|amsiInitFailed|AmsiScanBuffer|AMSI.*Context'
            Remediation = 'Block AMSI bypass attempts. Use Windows Defender Application Control (WDAC) with constrained language mode.'
            CVSS        = 9.8
        }

        @{
            Id          = 'PS046'
            Name        = 'Constrained Language Mode Bypass'
            Severity    = 'Critical'
            Category    = 'WindowsSecurity'
            Description = 'Detects attempts to bypass PowerShell constrained language mode security controls'
            ASTPattern  = 'MemberExpressionAst|CommandAst'
            Pattern     = 'LanguageMode|__PSLockdownPolicy|FullLanguage'
            Remediation = 'Enforce constrained language mode via AppLocker or WDAC. Monitor for bypass attempts.'
            CVSS        = 9.5
        }

        @{
            Id          = 'PS047'
            Name        = 'Execution Policy Bypass'
            Severity    = 'Medium'
            Category    = 'WindowsSecurity'
            Description = 'Detects common execution policy bypass techniques'
            ASTPattern  = 'CommandAst|StringConstantExpressionAst'
            Pattern     = '-ExecutionPolicy Bypass|-Exec Bypass|-ep bypass|powershell.*-nop'
            Remediation = 'Execution policy is not a security boundary. Use AppLocker, WDAC, or constrained language mode for real security.'
            CVSS        = 5.5
        }

        @{
            Id          = 'PS048'
            Name        = 'Suspicious Encoded Command'
            Severity    = 'High'
            Category    = 'Obfuscation'
            Description = 'Detects use of -EncodedCommand parameter often used to obfuscate malicious payloads'
            ASTPattern  = 'CommandParameterAst'
            Parameter   = 'EncodedCommand|-enc|-e'
            Remediation = 'Review all encoded commands. Decode and analyze content. Consider blocking -EncodedCommand in production.'
            CVSS        = 7.8
        }

        @{
            Id          = 'PS049'
            Name        = 'Reflective DLL Injection'
            Severity    = 'Critical'
            Category    = 'CodeExecution'
            Description = 'Detects reflective DLL injection techniques used to load malicious code into memory'
            ASTPattern  = 'StringConstantExpressionAst|MemberExpressionAst'
            Pattern     = 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|LoadLibrary'
            Remediation = 'Block reflective injection attempts. Enable Windows Defender Exploit Guard.'
            CVSS        = 9.0
        }

        @{
            Id          = 'PS050'
            Name        = 'Process Injection Techniques'
            Severity    = 'Critical'
            Category    = 'CodeExecution'
            Description = 'Detects process injection and hollowing techniques'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'CreateProcess|NtUnmapViewOfSection|VirtualAllocEx|SetThreadContext'
            Remediation = 'Implement application whitelisting. Enable Windows Defender Credential Guard.'
            CVSS        = 9.3
        }

        @{
            Id          = 'PS051'
            Name        = 'Suspicious Web Request'
            Severity    = 'Medium'
            Category    = 'Network'
            Description = 'Detects web requests to suspicious or non-standard URLs that may indicate data exfiltration or C2 communication'
            ASTPattern  = 'CommandAst'
            CommandName = 'Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer'
            Remediation = 'Validate URLs against whitelist. Use proxy for outbound connections. Monitor for suspicious domains.'
            CVSS        = 6.0
        }

        @{
            Id          = 'PS052'
            Name        = 'Kerberos Ticket Manipulation'
            Severity    = 'Critical'
            Category    = 'Credentials'
            Description = 'Detects Kerberos ticket manipulation for pass-the-ticket attacks'
            ASTPattern  = 'StringConstantExpressionAst|CommandAst'
            Pattern     = 'Invoke-Mimikatz|kerberos::ptt|Rubeus|klist'
            Remediation = 'Enable credential guard. Monitor Kerberos ticket requests. Use Protected Users group.'
            CVSS        = 9.0
        }

        @{
            Id          = 'PS053'
            Name        = 'Windows Event Log Manipulation'
            Severity    = 'High'
            Category    = 'WindowsSecurity'
            Description = 'Detects attempts to clear, disable, or manipulate Windows event logs'
            ASTPattern  = 'CommandAst'
            CommandName = 'Clear-EventLog|Remove-EventLog|Limit-EventLog|wevtutil'
            Remediation = 'Forward logs to SIEM. Protect audit logs with access controls. Alert on log clearing.'
            CVSS        = 7.5
        }

        @{
            Id          = 'PS054'
            Name        = 'Token Manipulation'
            Severity    = 'High'
            Category    = 'Credentials'
            Description = 'Detects Windows access token manipulation for privilege escalation'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'DuplicateToken|ImpersonateLoggedOnUser|SetThreadToken|AdjustTokenPrivileges'
            Remediation = 'Use Windows Defender Credential Guard. Monitor for privilege escalation attempts.'
            CVSS        = 8.0
        }

        @{
            Id          = 'PS055'
            Name        = 'Living Off The Land Binaries (LOLBins)'
            Severity    = 'Medium'
            Category    = 'CodeExecution'
            Description = 'Detects abuse of legitimate Windows binaries for malicious purposes'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'rundll32|regsvr32|mshta|certutil.*-decode|bitsadmin.*transfer'
            Remediation = 'Monitor LOLBin usage. Use application whitelisting. Enable Attack Surface Reduction rules.'
            CVSS        = 6.5
        }

        @{
            Id          = 'PS056'
            Name        = 'PowerShell Remoting Suspicious Usage'
            Severity    = 'Medium'
            Category    = 'Network'
            Description = 'Detects suspicious PowerShell remoting activity that may indicate lateral movement'
            ASTPattern  = 'CommandAst'
            CommandName = 'Enter-PSSession|New-PSSession|Invoke-Command'
            Remediation = 'Limit PowerShell remoting to administrators. Use JEA (Just Enough Administration). Log all remote sessions.'
            CVSS        = 6.0
        }

        @{
            Id          = 'PS057'
            Name        = 'UAC Bypass Techniques'
            Severity    = 'High'
            Category    = 'WindowsSecurity'
            Description = 'Detects User Account Control (UAC) bypass techniques'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'eventvwr.exe|fodhelper|ComputerDefaults|sdclt.exe'
            Remediation = 'Enable UAC at highest level. Monitor for UAC bypass attempts. Use WDAC.'
            CVSS        = 7.5
        }

        @{
            Id          = 'PS058'
            Name        = 'Clipboard Access'
            Severity    = 'Low'
            Category    = 'DataExfiltration'
            Description = 'Detects clipboard access which may indicate credential or data theft'
            ASTPattern  = 'CommandAst'
            CommandName = 'Get-Clipboard|Set-Clipboard'
            Remediation = 'Review context - clipboard access for automation is legitimate. Monitor for suspicious patterns.'
            CVSS        = 3.5
        }

        @{
            Id          = 'PS059'
            Name        = 'Screen Capture Attempt'
            Severity    = 'Medium'
            Category    = 'DataExfiltration'
            Description = 'Detects screen capture functionality that may be used for surveillance'
            ASTPattern  = 'StringConstantExpressionAst'
            Pattern     = 'System.Drawing.Bitmap|CopyFromScreen|Graphics.CopyFromScreen'
            Remediation = 'Review context - verify legitimate business need. Monitor for data exfiltration.'
            CVSS        = 5.5
        }

        @{
            Id          = 'PS060'
            Name        = 'DNS Tunneling Indicators'
            Severity    = 'High'
            Category    = 'Network'
            Description = 'Detects DNS-based data exfiltration or C2 communication'
            ASTPattern  = 'CommandAst'
            CommandName = 'Resolve-DnsName|nslookup'
            Remediation = 'Monitor DNS queries for unusual patterns. Use DNS filtering. Analyze query lengths and frequencies.'
            CVSS        = 7.0
        }
    )

    # Metadata
    Version       = '1.1.0'
    LastUpdated   = '2025-11-25'
    Author        = 'PowerShell Security Code Review System'
    Description   = 'Comprehensive security detection rules for PowerShell code review - Updated with 2025 OWASP, MITRE ATT&CK, and Microsoft best practices'
    
    # Rule Statistics
    TotalRules    = 45
    CriticalRules = 11
    HighRules     = 13
    MediumRules   = 11
    LowRules      = 6
    InfoRules     = 4
}
