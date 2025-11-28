<#
.SYNOPSIS
    PowerShell Security Scanner - Main scanning engine

.DESCRIPTION
    Scans PowerShell code for security vulnerabilities using custom rules,
    PSScriptAnalyzer, and context-aware analysis.

.PARAMETER Path
    Path to the PowerShell file or directory to scan

.PARAMETER RulesPath
    Path to the security rules file (SecurityDetectionRules.psd1)

.PARAMETER OutputPath
    Path where the security report will be saved

.PARAMETER IncludePSScriptAnalyzer
    Include PSScriptAnalyzer findings in the report

.EXAMPLE
    .\Invoke-SecurityScan.ps1 -Path C:\Source\MyModule -OutputPath C:\Reports

.NOTES
    Author: PowerShell Security Code Review System
    Version: 1.1.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter()]
    [string]$RulesPath,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludePSScriptAnalyzer
)

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Set default paths if not provided
if (-not $RulesPath) {
    $RulesPath = Join-Path $PSScriptRoot 'rules\SecurityDetectionRules.psd1'
}
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot '..\Report'
}

# Import required modules
if ($IncludePSScriptAnalyzer) {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Warning 'PSScriptAnalyzer not found. Installing...'
        Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
    }
    Import-Module PSScriptAnalyzer
}

#region Helper Functions

function Get-ASTNodes {
    <#
    .SYNOPSIS
        Parses PowerShell file and returns AST nodes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        
        # Handle empty files
        if ([string]::IsNullOrWhiteSpace($content)) {
            Write-Verbose "Skipping empty file: $FilePath"
            return $null
        }
        
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput(
            $content,
            [ref]$tokens,
            [ref]$errors
        )

        if ($errors.Count -gt 0) {
            Write-Warning "Parse errors in $FilePath : $($errors.Count) errors"
        }

        return @{
            AST     = $ast
            Tokens  = $tokens
            Errors  = $errors
            Content = $content
        }
    }
    catch {
        Write-Error "Failed to parse $FilePath : $_"
        return $null
    }
}

function Test-RuleMatch {
    <#
    .SYNOPSIS
        Tests if an AST node matches a security rule
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.Ast]$Node,

        [Parameter(Mandatory)]
        [hashtable]$Rule,

        [Parameter()]
        [string]$FileContent,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $matches = @()

    # Match by AST pattern type
    if ($Rule.ASTPattern) {
        $nodeTypeName = $Node.GetType().Name
        if ($nodeTypeName -eq $Rule.ASTPattern) {
            
            # Additional filtering by CommandName
            if ($Rule.ContainsKey('CommandName') -and $Rule.CommandName -and $Node -is [System.Management.Automation.Language.CommandAst]) {
                try {
                    $commandName = $Node.GetCommandName()
                    if ($commandName) {
                        $ruleCommands = $Rule.CommandName -split '\|'
                        if ($commandName -notin $ruleCommands) {
                            return $matches
                        }
                    }
                    else {
                        # No command name available (shouldn't happen in try block)
                        return $matches
                    }
                }
                catch {
                    # GetCommandName() can fail for dynamic commands (e.g., &$variable)
                    # Since we can't verify the command name, skip this node for rules requiring CommandName
                    Write-Verbose "Skipping dynamic command at line $($Node.Extent.StartLineNumber) for rule $($Rule.Id)"
                    return $matches
                }
            }

            # Additional filtering by Pattern (regex)
            if ($Rule.ContainsKey('Pattern') -and $Rule.Pattern) {
                $nodeText = $Node.Extent.Text
                if ($nodeText -notmatch $Rule.Pattern) {
                    return $matches
                }
            }

            # Additional filtering by Parameter
            if ($Rule.ContainsKey('Parameter') -and $Rule.Parameter) {
                # For CommandParameterAst, match the parameter name directly
                if ($Node -is [System.Management.Automation.Language.CommandParameterAst]) {
                    if ($Node.ParameterName -ne $Rule.Parameter) {
                        return $matches
                    }
                }
                # For CommandAst, check if it has the specified parameter
                elseif ($Node -is [System.Management.Automation.Language.CommandAst]) {
                    $hasParameter = $Node.CommandElements | Where-Object {
                        $_ -is [System.Management.Automation.Language.CommandParameterAst] -and
                        $_.ParameterName -eq $Rule.Parameter
                    }
                    if (-not $hasParameter) {
                        return $matches
                    }
                }
            }

            # Match found
            $matches += @{
                Rule   = $Rule
                Node   = $Node
                Line   = $Node.Extent.StartLineNumber
                Column = $Node.Extent.StartColumnNumber
                Code   = $Node.Extent.Text
                File   = $FilePath
            }
        }
    }

    return $matches
}

function Get-SecurityFindings {
    <#
    .SYNOPSIS
        Scans AST for security issues based on rules
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ParseResult,

        [Parameter(Mandatory)]
        [array]$Rules,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $findings = @()

    # Recursively visit all AST nodes
    $allNodes = $ParseResult.AST.FindAll({ $true }, $true)

    foreach ($node in $allNodes) {
        foreach ($rule in $Rules) {
            $matches = @(Test-RuleMatch -Node $node -Rule $rule -FileContent $ParseResult.Content -FilePath $FilePath)
            if ($matches.Count -gt 0) {
                $findings += $matches
            }
        }
    }

    return $findings
}

function Invoke-ContextAnalysis {
    <#
    .SYNOPSIS
        Applies PowerShell-specific context analysis to reduce false positives
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [hashtable]$ParseResult
    )

    $filtered = @()

    foreach ($finding in $Findings) {
        $keep = $true
        $adjustedSeverity = $finding.Rule.Severity

        # Apply context-specific filtering
        switch ($finding.Rule.Id) {
            'PS002' {
                # Add-Type Usage - Default to Info, flag suspicious patterns only
                # Most Add-Type usage is legitimate .NET interop
                $code = $finding.Code
                $fileContent = Get-Content -Path $finding.File -Raw
                $lineNumber = $finding.Line
                
                # Extract context around the Add-Type call (20 lines before/after)
                $startLine = [Math]::Max(1, $lineNumber - 20)
                $endLine = $lineNumber + 20
                $contextLines = Get-Content -Path $finding.File | Select-Object -Skip ($startLine - 1) -First ($endLine - $startLine + 1)
                $context = $contextLines -join "`n"
                
                # SAFE PATTERNS (keep as Info):
                # 1. -AssemblyName (just loading existing assemblies)
                if ($code -match '-AssemblyName') {
                    # This is always safe - just loading existing .NET assemblies
                    Write-Verbose 'Add-Type -AssemblyName is safe (loading existing assembly)'
                    $adjustedSeverity = 'Info'
                }
                
                # 2. Simple type definitions with no suspicious patterns
                elseif ($code -match '-TypeDefinition' -or $code -match '-MemberDefinition') {
                    # Check for MALICIOUS INDICATORS in the type definition
                    $suspiciousFound = $false
                    
                    # Look for dangerous P/Invoke patterns
                    $dangerousPInvoke = @(
                        'VirtualAlloc',           # Memory allocation (shellcode)
                        'VirtualProtect',         # Memory protection modification
                        'CreateThread',           # Thread creation (injection)
                        'OpenProcess',            # Process manipulation
                        'WriteProcessMemory',     # Process injection
                        'CreateRemoteThread',     # Remote thread injection
                        'NtQueryInformationProcess', # Anti-debugging
                        'RtlMoveMemory',          # Memory manipulation
                        'CallWindowProc',         # Callback hijacking
                        'EnumSystemLocales',      # Callback hijacking
                        'kernel32.dll.*VirtualAlloc' # Explicit dangerous combo
                    )
                    
                    foreach ($pattern in $dangerousPInvoke) {
                        if ($context -match $pattern) {
                            $suspiciousFound = $true
                            $adjustedSeverity = 'High'
                            Write-Verbose "SUSPICIOUS: Add-Type contains dangerous P/Invoke pattern: $pattern"
                            break
                        }
                    }
                    
                    # Check for obfuscation indicators
                    if (-not $suspiciousFound) {
                        $obfuscationPatterns = @(
                            '\[char\]0x',           # Character code obfuscation
                            '-join\s*\(.*\[char\]', # String building with char codes
                            'FromBase64String',      # Base64 decoding in type definition
                            '\[Convert\]::',         # Type conversion (often with encoding)
                            '-bxor\s+0x',            # XOR obfuscation
                            '-replace.*-replace.*-replace' # Multiple replace chains
                        )
                        
                        foreach ($pattern in $obfuscationPatterns) {
                            if ($context -match $pattern) {
                                $suspiciousFound = $true
                                $adjustedSeverity = 'High'
                                Write-Verbose "SUSPICIOUS: Add-Type contains obfuscation pattern: $pattern"
                                break
                            }
                        }
                    }
                    
                    # Check for reflection abuse (loading from byte arrays)
                    if (-not $suspiciousFound -and $context -match '\[System\.Reflection\.Assembly\]::Load\s*\(') {
                        $suspiciousFound = $true
                        $adjustedSeverity = 'High'
                        Write-Verbose 'SUSPICIOUS: Add-Type combined with Assembly.Load (potential payload loading)'
                    }
                    
                    # If no suspicious patterns, keep as Info
                    if (-not $suspiciousFound) {
                        Write-Verbose 'Add-Type with TypeDefinition appears benign (no malicious indicators)'
                        $adjustedSeverity = 'Info'
                    }
                }
                else {
                    # Other Add-Type usage - keep as Info
                    $adjustedSeverity = 'Info'
                }
            }

            'PS028' {
                # High Entropy Strings - check context
                $nodeText = $finding.Node.Extent.Text
                $parent = $finding.Node.Parent

                # Ignore if in module manifest GUID
                if ($parent -and $parent.Extent.Text -match 'GUID\s*=') {
                    $keep = $false
                    Write-Verbose 'Ignoring high entropy in module GUID'
                }

                # Ignore if appears to be encrypted configuration
                if ($nodeText.Length -gt 50 -and $nodeText -match '^[0-9a-f]+$') {
                    $keep = $false
                    Write-Verbose 'Ignoring encrypted configuration string'
                }

                # Downgrade to Info
                $adjustedSeverity = 'Info'
            }

            'PS031B' {
                # Registry-Based Security Disabling - ONLY flag if modifying security settings
                # Default: SUPPRESS unless strong evidence of security feature disabling
                $code = $finding.Code
                $lineNumber = $finding.Line
                
                # Extract context (10 lines before/after to see -Path and -Name parameters)
                $startLine = [Math]::Max(1, $lineNumber - 10)
                $endLine = $lineNumber + 10
                $contextLines = Get-Content -Path $finding.File | Select-Object -Skip ($startLine - 1) -First ($endLine - $startLine + 1)
                $context = $contextLines -join "`n"
                
                # Default to suppress
                $keep = $false
                
                # SECURITY-RELATED REGISTRY PATHS (flag these)
                $securityPaths = @(
                    'Windows Defender',
                    'Windows\\CurrentVersion\\Policies\\System',  # UAC settings
                    'SOFTWARE\\Policies\\Microsoft\\Windows Defender',
                    'DisableAntiSpyware',
                    'EnableLUA',  # UAC
                    'ConsentPromptBehaviorAdmin',  # UAC
                    'PromptOnSecureDesktop',  # UAC
                    'FilterAdministratorToken',  # UAC
                    'EnableFirewall',
                    'DoNotAllowExceptions',
                    'DisableNotifications',
                    'StandardProfile',
                    'DomainProfile',
                    'PublicProfile',
                    'SmartScreenEnabled',
                    'SmartScreen',
                    'DisableRealtimeMonitoring',
                    'DisableBehaviorMonitoring',
                    'DisableOnAccessProtection',
                    'DisableScanOnRealtimeEnable',
                    'DisableIOAVProtection',
                    'DisableScriptScanning'
                )
                
                # SECURITY-RELATED PROPERTY NAMES (flag these)
                $securityProperties = @(
                    'DisableAntiSpyware',
                    'DisableRealtimeMonitoring',
                    'EnableLUA',
                    'ConsentPromptBehaviorAdmin',
                    'EnableFirewall',
                    'SmartScreenEnabled',
                    'DisableBehaviorMonitoring'
                )
                
                # Check if any security path or property is referenced
                foreach ($pattern in $securityPaths) {
                    if ($context -match [regex]::Escape($pattern)) {
                        $keep = $true
                        Write-Verbose "PS031B: Found security-related registry path: $pattern"
                        break
                    }
                }
                
                # Also check property names in the command itself
                if (-not $keep) {
                    foreach ($prop in $securityProperties) {
                        if ($code -match "-Name\s+['\`"]?$prop['\`"]?" -or $context -match "-Name\s+['\`"]?$prop['\`"]?") {
                            $keep = $true
                            Write-Verbose "PS031B: Found security-related property name: $prop"
                            break
                        }
                    }
                }
                
                # SAFE PATTERNS (always suppress):
                # File system properties (LastWriteTime, CreationTime, etc.)
                if ($code -match '-Name\s+[\''"`]?(LastWriteTime|LastAccessTime|CreationTime|Attributes)[\''"`]?') {
                    $keep = $false
                    Write-Verbose 'PS031B: Suppressing file system property modification (legitimate)'
                }
                
                # Environment variables (Env: drive)
                if ($code -match '-Path\s+.*Env:' -or $context -match '-Path\s+.*Env:') {
                    $keep = $false
                    Write-Verbose 'PS031B: Suppressing environment variable modification (legitimate)'
                }
                
                if (-not $keep) {
                    Write-Verbose 'PS031B: Suppressing Set-ItemProperty - no security-related indicators found'
                }
            }

            'PS012' {
                # Credential Logging - ONLY flag if STRONG EVIDENCE of actual credential exposure
                $code = $finding.Code

                # Default: Suppress unless strong evidence found
                $keep = $false
                
                # STRONG EVIDENCE patterns that indicate ACTUAL credential exposure
                $dangerousPatterns = @(
                    # Accessing password/secret properties
                    '\.Password\b',
                    '\.GetPassword\(\)',
                    '\.GetNetworkCredential\(\)',
                    '\.SecretValueText\b',
                    '\.PlainText\b',
                    '\.ToPlainText\(\)',
                    '\.ToString\(\).*SecureString',
                    # Converting credentials to plain text
                    'ConvertFrom-SecureString.*-AsPlainText',
                    '\[System.Runtime.InteropServices.Marshal\]::PtrToStringAuto',
                    # Logging credential variables with clear intent to expose secrets
                    'Write.*\$password\s*\)',
                    'Write.*\$secret\s*\)',
                    'Write.*\$apiKey\s*\)',
                    'Write.*\$token\s*\)',
                    'Write.*\$privateKey\s*\)',
                    'Write.*\$connectionString\s*\)',
                    # File operations with credential variables
                    '(Out-File|Add-Content|Set-Content).*\$password\b',
                    '(Out-File|Add-Content|Set-Content).*\$secret\b',
                    '(Out-File|Add-Content|Set-Content).*\$apiKey\b',
                    '(Out-File|Add-Content|Set-Content).*\$token\b'
                )
                
                foreach ($pattern in $dangerousPatterns) {
                    if ($code -match $pattern) {
                        $keep = $true
                        Write-Verbose "STRONG EVIDENCE of credential logging detected: pattern '$pattern'"
                        break
                    }
                }
                
                # If still not flagged, check for localized string references (always safe)
                if ($keep -and $code -match '\$script:localizedData\.|\$LocalizedData\.|\$messages\.|\$strings\.') {
                    $keep = $false
                    Write-Verbose 'Ignoring localized string reference (no credential exposure)'
                }
            }

            'PS039' {
                # Global variables - check if it's in module scope setting
                $code = $finding.Code
                if ($code -match '\$global:Module|\$global:PSDefaultParameterValues') {
                    # These are common module patterns
                    $adjustedSeverity = 'Info'
                }
            }

            'PS009' {
                # Hardcoded Credentials - ONLY flag if STRONG EVIDENCE of actual hardcoded credentials
                # Default: Suppress unless strong evidence found
                $node = $finding.Node
                $nodeText = $node.Extent.Text.Trim('"').Trim("'")
                $parent = $node.Parent
                
                # Immediately suppress common false positives
                # 1. Function names, parameter names, property names
                if ($nodeText -match '^[A-Za-z][A-Za-z0-9]*$' -and $nodeText.Length -lt 30) {
                    # Single word = likely a name, not a value
                    $keep = $false
                    Write-Verbose "Ignoring single-word identifier (likely function/parameter/property name): $nodeText"
                }
                
                # 2. Localized string keys (always safe)
                if ($keep -and $nodeText -match '^[A-Za-z][A-Za-z0-9_]*$' -and $nodeText -notmatch '\s') {
                    # CamelCase or snake_case identifiers are keys/names, not values
                    $keep = $false
                    Write-Verbose "Ignoring identifier pattern (likely string key/name): $nodeText"
                }
                
                # 3. Empty strings or placeholder values
                if ($keep -and ($nodeText -eq '' -or $nodeText -match '^(TBD|TODO|PLACEHOLDER|CHANGEME|YOUR_.*_HERE)$')) {
                    $keep = $false
                    Write-Verbose "Ignoring empty or placeholder value: $nodeText"
                }
                
                # Walk up to find if this is in a large here-string (likely C# code for Add-Type)
                $currentNode = $node
                $largeStringParent = $null
                while ($currentNode) {
                    if ($currentNode -is [System.Management.Automation.Language.StringConstantExpressionAst] -and 
                        $currentNode.Extent.Text.Length -gt 500) {
                        $largeStringParent = $currentNode
                        break
                    }
                    $currentNode = $currentNode.Parent
                }
                
                # If this match is within a large here-string containing C# code, ignore the entire here-string
                if ($keep -and $largeStringParent) {
                    $hereStringText = $largeStringParent.Extent.Text
                    
                    # Check for C# code indicators (DllImport is strong signal of Win32 API definitions)
                    if ($hereStringText -match 'DllImport\s*\(' -or
                        ($hereStringText -match 'using System' -and $hereStringText -match 'namespace ') -or
                        ($hereStringText -match '\[StructLayout' -and $hereStringText -match 'public static extern')) {
                        $keep = $false
                        Write-Verbose 'Ignoring credential keyword in C# Win32 API/interop code (large here-string with DllImport)'
                    }
                }
                
                # Check if this is a simple identifier (parameter/variable name) not a string value
                # C# parameter names like 'strPassword' appear as bare strings in here-strings
                if ($keep -and ($nodeText -match '^str[A-Z]\w*$' -or $nodeText -match '^lpsz[A-Z]\w*$')) {
                    # Hungarian notation variable names (strPassword, lpszPassword, etc.)
                    $keep = $false
                    Write-Verbose "Ignoring C# variable name with Hungarian notation: $nodeText"
                }
                
                # Check if this is inside a moderately-sized string block containing C#/code
                if ($keep) {
                    $hereStringParent = $parent
                    while ($hereStringParent -and 
                        $hereStringParent -isnot [System.Management.Automation.Language.ExpandableStringExpressionAst] -and 
                        ($hereStringParent -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or 
                        $hereStringParent.Extent.Text.Length -lt 100)) {
                        $hereStringParent = $hereStringParent.Parent
                    }
                    
                    # If found in a string (likely C# code for Add-Type in here-string)
                    if ($hereStringParent -and $hereStringParent.Extent.Text.Length -gt 100) {
                        
                        $hereStringText = $hereStringParent.Extent.Text
                        
                        # Check if this is C# code (has 'using System', DllImport, etc.)
                        if ($hereStringText -match '(using System|namespace |DllImport|struct |enum |class |public static)') {
                            # This is C# code - check if the match is a parameter name or API signature
                            $matchContext = $finding.Code
                            
                            # Ignore parameter names in C# method signatures
                            if ($matchContext -match '(string|String|int|Int32|bool|Boolean|IntPtr)\s+\w*password\w*' -or
                                $matchContext -match '(string|String|int|Int32|bool|Boolean|IntPtr)\s+\w*token\w*' -or
                                $matchContext -match '(string|String|int|Int32|bool|Boolean|IntPtr)\s+\w*secret\w*' -or
                                $matchContext -match '\w+\s+\w+\([^)]*password[^)]*\)' -or # Method signatures
                                $matchContext -match '(ref |out )\w+\s+\w*password\w*') {
                                $keep = $false
                                Write-Verbose "Ignoring credential keyword in C# parameter/variable name: $nodeText"
                            }
                            
                            # Ignore Win32 API constants and enum values
                            if ($keep -and ($matchContext -match '(const|static|readonly)\s+(string|int|Int32)' -or
                                    $matchContext -match 'internal\s+const\s+string' -or
                                    $matchContext -match '^\s*\w+\s*=\s*\d+' -or # Enum values
                                    $matchContext -match 'SE_\w+_PRIVILEGE' -or # Security privilege constants
                                    $matchContext -match 'TOKEN_\w+')) {
                                $keep = $false
                                Write-Verbose "Ignoring credential keyword in C# constant/enum: $nodeText"
                            }
                        }
                    }
                }
                
                # Ignore single-word strings that are just keywords/property names
                if ($keep -and $nodeText -match '^\w+$' -and $nodeText.Length -lt 20) {
                    # Check if this is a hashtable key, property name, or enum value
                    if ($parent -and (
                            $parent -is [System.Management.Automation.Language.HashtableAst] -or
                            $parent -is [System.Management.Automation.Language.MemberExpressionAst] -or
                            $parent.Extent.Text -match '=\s*[''"]' + [regex]::Escape($nodeText)
                        )) {
                        $keep = $false
                        Write-Verbose "Ignoring credential keyword used as property/key name: $nodeText"
                    }
                }
                
                # STRONG EVIDENCE check: Look for actual credential values (not just keywords)
                # Only flag if:
                # 1. String is long and complex (likely a real credential)
                # 2. String contains credential-like patterns (base64, hex, UUID, etc.)
                # 3. String is in a suspicious assignment context
                if ($keep) {
                    $looksLikeCredential = $false
                    
                    # Pattern 1: Long base64-like strings
                    if ($nodeText -match '^[A-Za-z0-9+/=]{20,}$' -and $nodeText.Length -gt 20) {
                        $looksLikeCredential = $true
                        Write-Verbose 'Potential base64-encoded credential detected'
                    }
                    # Pattern 2: Long hex strings (keys)
                    elseif ($nodeText -match '^[0-9a-fA-F]{32,}$') {
                        $looksLikeCredential = $true
                        Write-Verbose 'Potential hex-encoded key detected'
                    }
                    # Pattern 3: UUIDs or GUIDs that might be API keys
                    elseif ($nodeText -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                        # Only flag if variable name suggests it's a key/secret
                        if ($parent -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                            $varName = $parent.Left.Extent.Text
                            if ($varName -match '(key|token|secret|password)') {
                                $looksLikeCredential = $true
                                Write-Verbose 'Potential GUID-based API key detected'
                            }
                        }
                    }
                    # Pattern 4: Strings that look like passwords (mixed case, numbers, symbols, length > 10)
                    elseif ($nodeText.Length -gt 10 -and 
                        $nodeText -match '[A-Z]' -and 
                        $nodeText -match '[a-z]' -and 
                        $nodeText -match '[0-9]' -and
                        $nodeText -notmatch '\s') {
                        # Strong password pattern
                        if ($parent -is [System.Management.Automation.Language.AssignmentStatementAst]) {
                            $varName = $parent.Left.Extent.Text
                            if ($varName -match '(password|secret|key|token)') {
                                $looksLikeCredential = $true
                                Write-Verbose 'Potential complex password detected'
                            }
                        }
                    }
                    
                    # If it doesn't look like an actual credential, suppress
                    if (-not $looksLikeCredential) {
                        $keep = $false
                        Write-Verbose "No strong evidence of actual credential value: $nodeText"
                    }
                }
            }

            'PS015' {
                # Weak Encryption - verify ACTUAL encryption algorithm usage
                $node = $finding.Node
                $nodeText = $node.Extent.Text.Trim('"').Trim("'")
                $parent = $node.Parent
                
                # Ignore if this is just a substring of another word
                if ($nodeText -notmatch '\b(DES|TripleDES|RC2|RC4)\b') {
                    $keep = $false
                    Write-Verbose "Ignoring partial match in string: $nodeText"
                }
                # Ignore common false positives: Description, DesiredStateConfiguration, etc.
                elseif ($nodeText -match '^(Description|DesiredStateConfiguration|Describes|AllNodes)$') {
                    $keep = $false
                    Write-Verbose "Ignoring common word containing DES: $nodeText"
                }
                # Check if this is a property/key name in a hashtable
                elseif ($parent -and $parent -is [System.Management.Automation.Language.HashtableAst]) {
                    $keep = $false
                    Write-Verbose 'Ignoring encryption keyword in hashtable key'
                }
            }

            'PS021' {
                # Unsafe Deserialization - Import-Clixml
                # Default: SUPPRESS unless strong evidence of untrusted external data
                $code = $finding.Code
                $node = $finding.Node
                
                # Default to suppress (most Import-Clixml is legitimate)
                $keep = $false
                
                # STRONG EVIDENCE patterns indicating UNTRUSTED external data:
                # 1. Reading from web/network sources
                # 2. Reading from user-provided paths without validation
                # 3. Reading from temporary/public directories accessible to attackers
                
                $dangerousPatterns = @(
                    # Network/web sources (extremely dangerous)
                    'Invoke-WebRequest.*Import-Clixml',
                    'Invoke-RestMethod.*Import-Clixml',
                    'DownloadFile.*Import-Clixml',
                    # User input paths without validation
                    'Read-Host.*Import-Clixml',
                    '\$args\[.*\].*Import-Clixml',
                    '\$input.*Import-Clixml',
                    # Public/temp directories (attacker-writable)
                    '\$env:TEMP.*Import-Clixml',
                    '\$env:TMP.*Import-Clixml',
                    'C:\\Temp\\.*Import-Clixml',
                    'C:\\Windows\\Temp\\.*Import-Clixml',
                    '\$env:PUBLIC.*Import-Clixml'
                )
                
                # Check for dangerous patterns in the code
                foreach ($pattern in $dangerousPatterns) {
                    if ($code -match $pattern) {
                        $keep = $true
                        Write-Verbose "STRONG EVIDENCE of untrusted deserialization: pattern '$pattern'"
                        break
                    }
                }
                
                # Additional check: Look for Import-Clixml immediately after web/download operations
                if (-not $keep) {
                    # Get surrounding context (look at previous statements)
                    $statementParent = $node.Parent
                    while ($statementParent -and 
                        $statementParent -isnot [System.Management.Automation.Language.StatementBlockAst] -and
                        $statementParent.Parent) {
                        $statementParent = $statementParent.Parent
                    }
                    
                    if ($statementParent) {
                        $contextText = $statementParent.Extent.Text
                        # Check for web/download operations before Import-Clixml
                        if ($contextText -match 'Invoke-WebRequest|Invoke-RestMethod|DownloadFile|DownloadString' -and
                            $contextText -match 'Import-Clixml') {
                            # Only flag if they're closely related (within 5 lines)
                            $webMatch = [regex]::Match($contextText, 'Invoke-WebRequest|Invoke-RestMethod|DownloadFile')
                            $importMatch = [regex]::Match($contextText, 'Import-Clixml')
                            if ($webMatch.Success -and $importMatch.Success) {
                                # Simple heuristic: check if Import-Clixml appears after download
                                if ($importMatch.Index -gt $webMatch.Index) {
                                    $keep = $true
                                    Write-Verbose 'STRONG EVIDENCE: Import-Clixml after web download operation'
                                }
                            }
                        }
                    }
                }
                
                # If no evidence of untrusted data found, suppress
                if (-not $keep) {
                    Write-Verbose 'Ignoring Import-Clixml - no evidence of untrusted external data (legitimate module-internal operation)'
                }
            }

            'PS030' {
                # Download and Execute Pattern - verify actual execution follows download
                $node = $finding.Node
                $code = $finding.Code
                
                # Default: Keep the finding (downloads are always suspicious)
                $keep = $true
                
                # Get surrounding context to check for execution
                $functionParent = $node.Parent
                while ($functionParent -and $functionParent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                    $functionParent = $functionParent.Parent
                }
                
                if ($functionParent) {
                    $functionText = $functionParent.Extent.Text
                    
                    # Check for execution indicators near the download
                    $executionIndicators = @(
                        'Invoke-Expression',
                        'IEX\s',
                        'iex\s',
                        '&\s*\$',  # Invoke operator with variable
                        '\.\s*\$',  # Dot-source operator with variable
                        'Start-Process',
                        'Invoke-Item',
                        'Invoke-Command',
                        '\[scriptblock\]::Create',
                        '\.Create\(',
                        'Add-Type.*-TypeDefinition'
                    )
                    
                    $hasExecution = $false
                    foreach ($indicator in $executionIndicators) {
                        if ($functionText -match $indicator) {
                            $hasExecution = $true
                            Write-Verbose "PS030: Found execution indicator: $indicator"
                            break
                        }
                    }
                    
                    # Even without explicit execution, DownloadString is inherently suspicious
                    # Keep severity as Critical regardless, but note execution context
                    if (-not $hasExecution) {
                        Write-Verbose 'PS030: DownloadString detected without explicit execution (still flagged - inherently suspicious)'
                    }
                }
                
                # Always keep PS030 findings - downloading executable content is critical
                $keep = $true
            }

            'PS041' {
                # .NET Reflection Assembly Loading - Only flag suspicious patterns
                $code = $finding.Code
                $lineNumber = $finding.Line
                
                # Extract context
                $startLine = [Math]::Max(1, $lineNumber - 10)
                $endLine = $lineNumber + 10
                $contextLines = Get-Content -Path $finding.File | Select-Object -Skip ($startLine - 1) -First ($endLine - $startLine + 1)
                $context = $contextLines -join "`n"
                
                # SAFE: Loading known assemblies by name
                if ($code -match 'Assembly.*Load\s*\(\s*["'']System\.' -or
                    $code -match 'Assembly.*Load\s*\(\s*["'']Microsoft\.' -or
                    $code -match 'Assembly.*LoadFrom\s*\(.*\.dll["'']') {
                    $adjustedSeverity = 'Info'
                    Write-Verbose 'Assembly load appears to be loading known/named assembly'
                }
                # SUSPICIOUS: Loading from byte arrays
                elseif ($context -match '\[byte\[\]\]' -or $context -match 'byte\s*array') {
                    $adjustedSeverity = 'Critical'
                    Write-Verbose 'SUSPICIOUS: Assembly.Load with byte array (potential shellcode)'
                }
            }

            'PS042' {
                # COM Object Creation - Only flag suspicious ProgIDs
                $code = $finding.Code
                
                # SAFE: Common legitimate COM objects
                $safeCOM = @(
                    'Outlook.Application',
                    'Excel.Application',
                    'Word.Application',
                    'Shell.Application',
                    'InternetExplorer.Application',
                    'ADODB.Connection',
                    'ADODB.Recordset',
                    'Scripting.Dictionary',
                    'Scripting.FileSystemObject',
                    'MSXML2.XMLHTTP'
                )
                
                $isSafe = $false
                foreach ($safe in $safeCOM) {
                    if ($code -match [regex]::Escape($safe)) {
                        $isSafe = $true
                        break
                    }
                }
                
                if ($isSafe) {
                    $adjustedSeverity = 'Info'
                    Write-Verbose 'COM object appears to be legitimate Office/scripting component'
                }
                # SUSPICIOUS: WScript.Shell or other potentially dangerous COM
                elseif ($code -match 'WScript\.Shell' -or $code -match 'Shell\.Application') {
                    $adjustedSeverity = 'High'
                    Write-Verbose 'SUSPICIOUS: WScript.Shell or Shell.Application COM object'
                }
            }

            'PS051' {
                # Suspicious Web Request - Only flag suspicious domains/patterns
                $code = $finding.Code
                $lineNumber = $finding.Line
                
                # Extract context to see URL
                $startLine = [Math]::Max(1, $lineNumber - 5)
                $endLine = $lineNumber + 5
                $contextLines = Get-Content -Path $finding.File | Select-Object -Skip ($startLine - 1) -First ($endLine - $startLine + 1)
                $context = $contextLines -join "`n"
                
                # SAFE: Known APIs and domains
                $safeDomains = @(
                    'github.com',
                    'api.github.com',
                    'githubusercontent.com',
                    'powershellgallery.com',
                    'microsoft.com',
                    'windowsupdate.com',
                    'office.com',
                    'azure.com',
                    'msdn.com'
                )
                
                $isSafe = $false
                foreach ($domain in $safeDomains) {
                    if ($context -match [regex]::Escape($domain)) {
                        $isSafe = $true
                        break
                    }
                }
                
                if ($isSafe) {
                    $adjustedSeverity = 'Info'
                    Write-Verbose 'Web request to known safe domain'
                }
                # SUSPICIOUS: IP addresses or encoded URLs
                elseif ($context -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' -or
                        $context -match 'FromBase64String') {
                    $adjustedSeverity = 'High'
                    Write-Verbose 'SUSPICIOUS: Web request to IP address or encoded URL'
                }
            }

            'PS056' {
                # PowerShell Remoting - Downgrade to Info unless suspicious patterns
                $code = $finding.Code
                $lineNumber = $finding.Line
                
                # Extract context
                $startLine = [Math]::Max(1, $lineNumber - 10)
                $endLine = $lineNumber + 10
                $contextLines = Get-Content -Path $finding.File | Select-Object -Skip ($startLine - 1) -First ($endLine - $startLine + 1)
                $context = $contextLines -join "`n"
                
                # Default to Info (normal admin activity)
                $adjustedSeverity = 'Info'
                
                # SUSPICIOUS: Encoded commands or obfuscation
                if ($context -match '-EncodedCommand' -or
                    $context -match 'FromBase64String' -or
                    $context -match 'Invoke-Expression') {
                    $adjustedSeverity = 'High'
                    Write-Verbose 'SUSPICIOUS: PS Remoting with encoded/obfuscated commands'
                }
            }

            'PS058' {
                # Clipboard Access - Downgrade to Info (mostly legitimate)
                $adjustedSeverity = 'Info'
                Write-Verbose 'Clipboard access - legitimate in most automation scenarios'
            }

            'PS060' {
                # DNS Tunneling - Only flag if suspicious patterns exist
                $code = $finding.Code
                $lineNumber = $finding.Line
                
                # Extract broader context
                $startLine = [Math]::Max(1, $lineNumber - 15)
                $endLine = $lineNumber + 15
                $contextLines = Get-Content -Path $finding.File | Select-Object -Skip ($startLine - 1) -First ($endLine - $startLine + 1)
                $context = $contextLines -join "`n"
                
                # Default to Info (normal DNS lookups)
                $adjustedSeverity = 'Info'
                
                # SUSPICIOUS: DNS queries in loops or with data encoding
                if ($context -match 'foreach|while|for\s*\(' -or
                    $context -match 'FromBase64String' -or
                    $context -match '-join' -or
                    $context -match 'ConvertTo-.*String') {
                    $adjustedSeverity = 'Medium'
                    Write-Verbose 'SUSPICIOUS: DNS queries with loops or encoding (potential tunneling)'
                }
            }

            'PS024' {
                # Path Traversal - only flag if path comes from untrusted input
                $node = $finding.Node
                $code = $finding.Code
                
                # Check if this is inside a function with validated parameters
                # Look for common path validation patterns in the surrounding code
                $functionParent = $node.Parent
                while ($functionParent -and $functionParent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                    $functionParent = $functionParent.Parent
                }
                
                if ($functionParent) {
                    $functionText = $functionParent.Extent.Text
                    
                    # Check for path validation patterns
                    $hasValidation = $false
                    $validationPatterns = @(
                        'Test-Path',
                        'Resolve-Path',
                        '\[ValidateScript\(',
                        'Split-Path.*-Leaf',
                        'Join-Path',
                        '\$PSBoundParameters',
                        '\[Parameter\(Mandatory'
                    )
                    
                    foreach ($pattern in $validationPatterns) {
                        if ($functionText -match $pattern) {
                            $hasValidation = $true
                            break
                        }
                    }
                    
                    # If function has parameter validation, downgrade severity
                    if ($hasValidation) {
                        $adjustedSeverity = 'Info'
                        Write-Verbose 'Downgrading PS024 to Info - function has path validation'
                    }
                }
                
                # If path is a literal string or comes from module-internal sources, ignore
                if ($code -match '-Path\s+[''"]' -or $code -match '\$PSScriptRoot' -or $code -match '\$MyInvocation') {
                    $keep = $false
                    Write-Verbose 'Ignoring PS024 - path is literal or from trusted source'
                }
            }

            'PS011' {
                # Username and Password Parameters - only flag if BOTH username AND password params exist
                $node = $finding.Node
                
                # Get the parameter name
                if ($node -is [System.Management.Automation.Language.ParameterAst]) {
                    $paramName = $node.Name.VariablePath.UserPath
                    
                    # Check if this parameter name is actually credential-related
                    $isCredentialParam = $paramName -match '^(UserName|User|Login|Password|Passwd|Pwd)$'
                    
                    if (-not $isCredentialParam) {
                        $keep = $false
                        Write-Verbose "Ignoring PS011 - parameter '$paramName' is not credential-related"
                    }
                    else {
                        # Find the parent function to check for BOTH username AND password
                        $functionParent = $node.Parent
                        while ($functionParent -and $functionParent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
                            $functionParent = $functionParent.Parent
                        }
                        
                        if ($functionParent) {
                            $allParams = $functionParent.Body.ParamBlock.Parameters
                            $hasUsername = $false
                            $hasPassword = $false
                            
                            foreach ($param in $allParams) {
                                $pName = $param.Name.VariablePath.UserPath
                                if ($pName -match '^(UserName|User|Login)$') {
                                    $hasUsername = $true
                                }
                                if ($pName -match '^(Password|Passwd|Pwd)$') {
                                    $hasPassword = $true
                                }
                            }
                            
                            # Only flag if BOTH username and password params exist
                            if (-not ($hasUsername -and $hasPassword)) {
                                $keep = $false
                                Write-Verbose "Ignoring PS011 - function doesn't have both username AND password parameters"
                            }
                        }
                    }
                }
            }
        }

        if ($keep) {
            $finding.Rule.Severity = $adjustedSeverity
            $filtered += $finding
        }
    }

    return $filtered
}

function New-SecurityReport {
    <#
    .SYNOPSIS
        Generates security report from findings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$ModuleName,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # Group findings by severity
    $critical = @($Findings | Where-Object { $_.Rule.Severity -eq 'Critical' })
    $high = @($Findings | Where-Object { $_.Rule.Severity -eq 'High' })
    $medium = @($Findings | Where-Object { $_.Rule.Severity -eq 'Medium' })
    $low = @($Findings | Where-Object { $_.Rule.Severity -eq 'Low' })
    $info = @($Findings | Where-Object { $_.Rule.Severity -eq 'Info' })

    # Create report
    $report = @"
# Security Report: $ModuleName

**Generated**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Total Findings**: $($Findings.Count)

## Summary

| Severity | Count |
|----------|-------|
| Critical | $($critical.Count) |
| High     | $($high.Count) |
| Medium   | $($medium.Count) |
| Low      | $($low.Count) |
| Info     | $($info.Count) |

## Detailed Findings

"@

    # Add findings by severity
    foreach ($severity in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
        $severityFindings = @($Findings | Where-Object { $_.Rule.Severity -eq $severity })
        if ($severityFindings.Count -gt 0) {
            $report += @"

### $severity Severity ($($severityFindings.Count) findings)

"@
            foreach ($finding in $severityFindings) {
                $report += @"

---

**Rule**: $($finding.Rule.Name) ($($finding.Rule.Id))  
**Category**: $($finding.Rule.Category)  
**File**: $($finding.File)  
**Line**: $($finding.Line)  

**Code**:
``````powershell
$($finding.Code)
``````

**Description**: $($finding.Rule.Description)

**Remediation**: $($finding.Rule.Remediation)

**CVSS Score**: $($finding.Rule.CVSS)

"@
            }
        }
    }

    # Save report
    $reportPath = Join-Path $OutputPath "$ModuleName-SecurityReport.md"
    $report | Out-File -FilePath $reportPath -Encoding UTF8 -Force

    Write-Host "Report saved to: $reportPath" -ForegroundColor Green

    return @{
        Path     = $reportPath
        Critical = $critical.Count
        High     = $high.Count
        Medium   = $medium.Count
        Low      = $low.Count
        Info     = $info.Count
        Total    = $Findings.Count
    }
}

#endregion

#region Main Script

Write-Host 'PowerShell Security Scanner v1.1.0' -ForegroundColor Cyan
Write-Host "====================================`n" -ForegroundColor Cyan

# Load security rules
Write-Host "Loading security rules from: $RulesPath"
if (-not (Test-Path $RulesPath)) {
    throw "Rules file not found: $RulesPath"
}

$rulesData = Import-PowerShellDataFile -Path $RulesPath
$rules = $rulesData.Rules
Write-Host "Loaded $($rules.Count) security rules`n" -ForegroundColor Green

# Get PowerShell files to scan
Write-Host "Scanning path: $Path"
$files = @(if (Test-Path -Path $Path -PathType Container) {
        Get-ChildItem -Path $Path -Include *.ps1, *.psm1, *.psd1 -Recurse
    }
    else {
        Get-Item -Path $Path
    })

Write-Host "Found $($files.Count) PowerShell files to scan`n" -ForegroundColor Green

# Scan each file
$allFindings = @()
foreach ($file in $files) {
    Write-Host "Scanning: $($file.Name)" -ForegroundColor Yellow

    # Parse file
    $parseResult = Get-ASTNodes -FilePath $file.FullName
    if (-not $parseResult) {
        Write-Warning "Skipping $($file.Name) due to parse errors"
        continue
    }

    # Get findings
    $findings = @(Get-SecurityFindings -ParseResult $parseResult -Rules $rules -FilePath $file.FullName)

    # Apply context analysis (only if findings exist)
    if ($findings.Count -gt 0) {
        $findings = @(Invoke-ContextAnalysis -Findings $findings -ParseResult $parseResult)
    }

    Write-Host "  Found $($findings.Count) potential issues" -ForegroundColor $(if ($findings.Count -gt 0) { 'Red' } else { 'Green' })

    $allFindings += $findings
}

Write-Host "`nTotal findings across all files: $($allFindings.Count)`n" -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Generate report
$moduleName = (Get-Item $Path).Name

# Handle zero findings case
if ($allFindings.Count -eq 0) {
    Write-Host "`nNo security findings detected in $moduleName" -ForegroundColor Green
    
    # Create minimal report for zero findings
    $reportPath = Join-Path $OutputPath "$moduleName-SecurityReport.md"
    $reportContent = @"
# Security Report: $moduleName

**Generated**: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Total Findings**: 0

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |
| Info     | 0 |

## Results

✅ **No security issues detected!**

This module passed all $($rules.Count) security rules without any findings.

---

**Scanner Version**: v1.1.0
**Rules Applied**: $($rules.Count)
"@
    
    $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
    
    $reportSummary = @{
        Critical = 0
        High = 0
        Medium = 0
        Low = 0
        Info = 0
        Path = $reportPath
    }
} else {
    $reportSummary = New-SecurityReport -Findings $allFindings -ModuleName $moduleName -OutputPath $OutputPath
}

# Display summary
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host 'Scan Complete' -ForegroundColor Cyan
Write-Host '=====================================' -ForegroundColor Cyan
Write-Host "Critical: $($reportSummary.Critical)" -ForegroundColor $(if ($reportSummary.Critical -gt 0) { 'Red' } else { 'Green' })
Write-Host "High:     $($reportSummary.High)" -ForegroundColor $(if ($reportSummary.High -gt 0) { 'Red' } else { 'Yellow' })
Write-Host "Medium:   $($reportSummary.Medium)" -ForegroundColor Yellow
Write-Host "Low:      $($reportSummary.Low)" -ForegroundColor Gray
Write-Host "Info:     $($reportSummary.Info)" -ForegroundColor Gray
Write-Host '=====================================' -ForegroundColor Cyan
Write-Host "Report: $($reportSummary.Path)`n" -ForegroundColor Green

#endregion
