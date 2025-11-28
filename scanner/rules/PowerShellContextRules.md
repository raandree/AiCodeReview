# PowerShell-Specific Context Rules

## Purpose

This document defines PowerShell-specific context for security rules to reduce false positives and ensure accurate security analysis.

## Rule Realignment for PowerShell Context

### 1. Sensitive Data in Logs (PS012 - Credential Logging)

**Original Severity**: Critical (CVSS 9.1)  
**PowerShell Context**: **Remains Critical for actual credentials**

#### What is CRITICAL

- Plaintext passwords being logged
- Security keys or tokens being logged  
- API keys being written to files or console
- SecureString being converted to plaintext for logging

#### What is ACCEPTABLE

- User names or user IDs in log files (essential for debugging)
- Computer names in logs
- Non-sensitive configuration values
- Error messages that don't expose credentials

#### Detection Strategy

```powershell
# CRITICAL - Flag this
Write-Verbose "Password: $plaintextPassword"
Write-Host "API Key: $apiKey"
$password | Out-File log.txt

# ACCEPTABLE - Don't flag this
Write-Verbose "Processing user: $userName"
Write-Verbose "Connecting to: $computerName"
Write-Output "User ID: $userId authenticated successfully"
```

### 2. High Entropy Strings (PS028)

**Original Severity**: Low (CVSS 3.3)  
**PowerShell Context**: **Deemphasized - Info level**

#### Why Deemphasized

PowerShell by its nature uses high-entropy strings frequently for legitimate purposes:

- Module GUIDs in manifests
- Base64-encoded configuration data
- Compressed or encoded data for transport
- Hash values and checksums
- Encrypted configuration strings

#### Detection Strategy

Do NOT automatically flag high-entropy strings. Instead:

1. **Analyze Context**: Where does the string appear?
   - In module manifest GUID: **IGNORE**
   - In ConvertFrom-SecureString output: **IGNORE**
   - Near Invoke-Expression: **FLAG**
   - Near Download functions: **FLAG**

2. **Check Combinations**: Flag only when combined with:
   - Invoke-Expression or IEX
   - Download commands (Invoke-WebRequest, etc.)
   - Add-Type with suspicious patterns
   - Obfuscation indicators

#### Example Analysis

```powershell
# IGNORE - Module GUID (legitimate high entropy)
GUID = '9b8c7d6e-5f4a-3b2c-1d0e-9f8e7d6c5b4a'

# IGNORE - Secure configuration (legitimate high entropy)
$encryptedConfig = '01000000d08c9ddf0115...'

# FLAG - High entropy with Invoke-Expression (suspicious)
$payload = 'SGVsbG8gV29ybGQ...'
Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)))
```

### 3. Script Block Usage

**Context**: Script blocks are a fundamental PowerShell feature

#### Legitimate Script Block Usage

Many PowerShell cmdlets REQUIRE script blocks to function:

```powershell
# LEGITIMATE - Where-Object requires script block
Get-Process | Where-Object { $_.CPU -gt 100 }

# LEGITIMATE - ForEach-Object requires script block  
1..10 | ForEach-Object { $_ * 2 }

# LEGITIMATE - Invoke-Command with static script block
Invoke-Command -ScriptBlock { Get-Service }

# LEGITIMATE - Filter with script block
$users | Where-Object { $_.Department -eq 'IT' }
```

#### Suspicious Script Block Usage

```powershell
# SUSPICIOUS - Script block from string
$code = "Get-Process"
& ([ScriptBlock]::Create($code))

# SUSPICIOUS - Dynamic script block construction
Invoke-Command -ScriptBlock ([ScriptBlock]::Create($userInput))
```

#### Detection Rule

- **Don't flag**: Script blocks used with Where-Object, ForEach-Object, Invoke-Command (static), Select-Object -FilterScript
- **Do flag**: ScriptBlock::Create() with variables or user input

### 4. Character Substitution and String Escaping

**Context**: PowerShell string escaping requires specific character patterns

#### Legitimate Escaping Patterns

PowerShell requires these patterns for string escaping:

```powershell
# LEGITIMATE - Escaping single quotes
'Don''t use this'

# LEGITIMATE - Escaping double quotes  
"He said ""Hello"""

# LEGITIMATE - Using backtick for line continuation
Get-Process -Name explorer `
    -ErrorAction SilentlyContinue

# LEGITIMATE - Escaping special characters
"Path: C:\`$Recycle.Bin"

# LEGITIMATE - String concatenation for readability
$message = "Hello " + $userName + ", " +
           "Welcome to the system"
```

#### Suspicious Patterns

```powershell
# SUSPICIOUS - Excessive single-character concatenation
$cmd = 'G'+'e'+'t'+'-'+'P'+'r'+'o'+'c'+'e'+'s'+'s'

# SUSPICIOUS - Character code obfuscation
$cmd = [char]71+[char]101+[char]116

# SUSPICIOUS - Mixed quote styles without reason
"''"''"''""''"
```

#### Detection Rule

- **Don't flag**: Normal quote escaping ('', ""), backtick line continuation, path escaping
- **Do flag**: Excessive single-char concatenation (>10 chars), char code usage, unusual quote mixing

### 5. Hostname or Domain Checks

**Context**: Configuration management code commonly checks hostnames

#### Legitimate Hostname Usage

```powershell
# LEGITIMATE - Environment-specific configuration
if ($env:COMPUTERNAME -eq 'PRODSERVER01') {
    $config = 'Production'
}

# LEGITIMATE - Domain membership check
if ((Get-WmiObject Win32_ComputerSystem).Domain -eq 'contoso.com') {
    # Domain-specific settings
}

# LEGITIMATE - Site-specific logic
switch -Wildcard ($env:COMPUTERNAME) {
    'NYC-*' { $site = 'NewYork' }
    'LON-*' { $site = 'London' }
}
```

#### Suspicious Hostname Usage

```powershell
# SUSPICIOUS - Malware sandbox detection
if ($env:COMPUTERNAME -match 'SANDBOX|VM|VIRTUAL') {
    exit
}

# SUSPICIOUS - Targeting specific victim
if ($env:USERDOMAIN -eq 'TARGET_CORP') {
    # Malicious payload
}
```

#### Detection Rule

Investigate hostname checks in context:

- **Acceptable**: Configuration management, deployment scripts, environment detection
- **Suspicious**: Combined with exit/return without action, VM detection patterns, specific victim targeting

### 6. ConvertTo-SecureString -AsPlainText

**Context**: Sometimes required for automation scenarios

#### When It's Acceptable

```powershell
# ACCEPTABLE - Reading from secure configuration file
$encryptedPwd = Get-Content secure.txt
$securePassword = ConvertTo-SecureString $encryptedPwd

# ACCEPTABLE - During initial setup (documented)
# NOTE: This is one-time setup, password stored securely afterward
$initialPassword = Read-Host "Enter initial admin password" -AsSecureString
```

#### When It's a Problem

```powershell
# PROBLEM - Hardcoded password
$password = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force

# PROBLEM - Password from variable (suggests it was plaintext)
$plainPwd = "MyPassword"
$securePwd = ConvertTo-SecureString $plainPwd -AsPlainText -Force
```

#### Detection Rule

- Flag all usage but adjust severity based on context
- Critical if hardcoded string literal
- Medium if from variable (investigate source)
- Low if reading from encrypted file

## Summary of Adjustments

| Rule | Original Severity | Adjusted Severity | Notes |
|------|------------------|-------------------|-------|
| Credential Logging | Critical | **Critical** (when actual credentials) | Usernames/IDs acceptable |
| High Entropy Strings | Low | **Info** (context-dependent) | Deemphasized, check combinations |
| Script Block Injection | Medium | **Info** (for legitimate cmdlets) | Don't flag Where-Object, etc. |
| Character Substitution | Low | **Info** (for normal escaping) | Flag only excessive patterns |
| Hostname Checks | Medium | **Info** (context-dependent) | Acceptable in configuration code |
| ConvertTo-SecureString | High | **High to Low** (context-dependent) | Severity varies by usage |

## Implementation Notes

1. **Context Analysis Required**: Many rules require analyzing surrounding code, not just pattern matching
2. **Combination Detection**: Some patterns are only suspicious when combined with other indicators
3. **Documentation**: Code comments can provide context for legitimate use of suspicious patterns
4. **False Positive Tracking**: Maintain list of known false positives for refinement

## Validation Approach

For each finding:

1. **Check Context**: What is the code trying to accomplish?
2. **Verify Impact**: Would this actually expose credentials or enable attacks?
3. **Consider Legitimate Use**: Is this a normal PowerShell pattern?
4. **Assess Severity**: Adjust based on actual risk in context

## Next Steps

These context rules will be implemented in the scanner logic to:

- Reduce false positives
- Provide more accurate severity ratings
- Focus on real security issues
- Understand PowerShell-specific patterns
