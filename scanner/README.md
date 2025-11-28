# Security Scanner

## Overview

The security scanner is an automated PowerShell code analysis tool that identifies security vulnerabilities, malicious code patterns, and deviations from PowerShell security best practices.

## Components

### Main Scanner

**File**: `Invoke-SecurityScan.ps1` (692 lines)

**Purpose**: Core scanning engine that analyzes PowerShell code using Abstract Syntax Tree (AST) parsing and pattern matching.

**Key Features**:

- AST-based code analysis
- Context-aware false positive filtering
- Batch file processing
- Markdown report generation
- Severity-based categorization
- CVSS risk scoring

### Detection Rules

**File**: `rules/SecurityDetectionRules.psd1`

**Purpose**: Defines 25 comprehensive security detection rules with CVSS scoring and remediation guidance.

**Rule Structure**:

```powershell
@{
    Id = 'PS001'
    Name = 'Invoke-Expression Usage'
    Severity = 'High'
    Category = 'CodeExecution'
    Description = 'Detects use of Invoke-Expression which can execute arbitrary code'
    ASTPattern = 'CommandAst'
    CommandName = 'Invoke-Expression'
    Remediation = 'Replace with safer alternatives like & operator'
    CVSS = 7.3
}
```

### Context Rules

**File**: `rules/PowerShellContextRules.md`

**Purpose**: Documentation of PowerShell-specific context patterns used to reduce false positives.

## Usage

### Basic Scan

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\MyModule -OutputPath .\Report
```

### Verbose Output

```powershell
.\scanner\Invoke-SecurityScan.ps1 `
    -Path .\source\MyModule `
    -OutputPath .\Report `
    -Verbose
```

### Scan Multiple Modules

```powershell
Get-ChildItem .\source -Directory | ForEach-Object {
    .\scanner\Invoke-SecurityScan.ps1 `
        -Path $_.FullName `
        -OutputPath .\Report `
        -Verbose
}
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-Path` | Yes | Path to PowerShell module directory to scan |
| `-OutputPath` | Yes | Directory where reports will be saved |
| `-Verbose` | No | Shows detailed scanning progress |

## Detection Categories

### Code Execution (9 rules)

- Invoke-Expression usage
- Add-Type usage
- Start-Process with variable commands
- New-Object with .NET types
- Reflection usage
- Script block injection
- Call operator with variables

### Injection Vulnerabilities (6 rules)

- Command injection
- Script block injection
- Path traversal
- SQL injection patterns
- LDAP injection

### Credential Security (6 rules)

- Hardcoded credentials
- ConvertTo-SecureString with PlainText
- Username/Password parameters
- Credential logging
- Weak password patterns

### Cryptography (4 rules)

- Weak hash algorithms (MD5, SHA1)
- Hardcoded encryption keys
- Weak encryption algorithms
- Insecure random number generation

### Network Security (3 rules)

- Certificate validation bypass
- Insecure protocols
- Download and execute patterns

### File Operations (3 rules)

- Path traversal
- Unsafe file operations
- Temporary file usage

### Obfuscation (8 rules)

- Base64 encoding
- Character substitution
- String concatenation patterns
- High entropy strings
- Variable name obfuscation

### Input Validation (2 rules)

- Missing input validation
- Unsafe variable expansion

### Dangerous APIs (4 rules)

- Runspace manipulation
- Debugger attachment
- Registry modifications
- WMI/CIM dangerous operations

## Context-Aware Filtering

The scanner includes PowerShell-specific intelligence to reduce false positives:

### Legitimate Patterns Recognized

1. **DSC Patterns**:
   - Script blocks in DSC resources
   - Module scope variables
   - DSC parameter patterns

2. **Credential Handling**:
   - PSCredential type usage
   - Certificate-based encryption
   - SecureString conversion

3. **Function Names**:
   - Functions/parameters containing security keywords
   - Property names in objects
   - Variable names that aren't actual credentials

4. **Path Validation**:
   - Functions implementing path validation
   - Test-Path usage before operations
   - Path normalization functions

5. **Win32 API Interop**:
   - Legitimate .NET P/Invoke declarations
   - Windows API calls for system functions
   - Add-Type for native interop

### Context Analysis Functions

The scanner performs multi-level context analysis:

- **Parent AST Traversal**: Examines surrounding code structure
- **Function-Level Analysis**: Checks for validation patterns
- **String Content Analysis**: Distinguishes keywords from actual values
- **Parameter Pattern Recognition**: Identifies credential-safe patterns

## Report Structure

### Report Sections

1. **Header**: Module name, generation timestamp, total findings
2. **Summary**: Findings count by severity level
3. **Detailed Findings**: Grouped by severity (Critical → High → Medium → Low → Info)

### Finding Format

```markdown
**Rule**: Rule Name (RuleID)
**Category**: Category
**File**: Full/Path/To/File.psm1
**Line**: LineNumber

**Code**:
```powershell
[code snippet]
```

**Description**: Detailed description of the issue
**Remediation**: Specific guidance on how to fix
**CVSS Score**: X.X

```

## Severity Levels

| Severity | CVSS Range | Color | Action |
|----------|------------|-------|--------|
| Critical | 9.0-10.0 | 🔴 Red | Fix immediately |
| High | 7.0-8.9 | 🟠 Orange | Fix soon |
| Medium | 4.0-6.9 | 🟡 Yellow | Review and fix |
| Low | 0.1-3.9 | 🔵 Blue | Best practice improvement |
| Info | 0.0 | ⚪ White | Informational only |

## Performance

### Scan Statistics

- **Files/Second**: ~5-10 (depending on file size)
- **Lines/Second**: ~1000-2000
- **Memory Usage**: <500MB for large codebases
- **Parallelization**: Single-threaded (sequential processing)

### Optimization Tips

1. **Exclude Test Files**: Focus on production code
2. **Use Include Patterns**: Scan specific file types only
3. **Batch Processing**: Process multiple modules separately
4. **Cache Results**: Reuse reports for unchanged files

## Customization

### Adding New Rules

Edit `rules/SecurityDetectionRules.psd1`:

```powershell
@{
    Id = 'CUSTOM001'
    Name = 'Your Rule Name'
    Severity = 'High'  # Critical|High|Medium|Low|Info
    Category = 'YourCategory'
    Description = 'What this rule detects'
    ASTPattern = 'CommandAst'  # AST node type
    CommandName = 'Command-Name'  # Optional: specific command
    Pattern = 'regex-pattern'  # Optional: string pattern
    Remediation = 'How to fix this issue'
    CVSS = 7.5  # 0.0-10.0
}
```

### AST Pattern Types

Common AST node types for rules:

- `CommandAst` - Command invocations
- `StringConstantExpressionAst` - String literals
- `VariableExpressionAst` - Variable references
- `ParameterAst` - Function parameters
- `FunctionDefinitionAst` - Function definitions
- `InvokeMemberExpressionAst` - Method calls
- `BinaryExpressionAst` - Binary operations

### Modifying Context Filters

Edit the `Invoke-ContextAnalysis` function in `Invoke-SecurityScan.ps1`:

```powershell
function Invoke-ContextAnalysis {
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Language.Ast]$AstObject,
        
        [Parameter(Mandatory)]
        [hashtable]$Rule,
        
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    
    # Add your custom context logic here
    
    return $contextResult
}
```

## Integration

### CI/CD Pipeline

#### Azure DevOps

```yaml
- task: PowerShell@2
  displayName: 'Security Scan'
  inputs:
    filePath: 'scanner/Invoke-SecurityScan.ps1'
    arguments: '-Path $(Build.SourcesDirectory)/modules -OutputPath $(Build.ArtifactStagingDirectory)/Reports'
  continueOnError: true

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)/Reports'
    ArtifactName: 'SecurityReports'
```

#### GitHub Actions

```yaml
- name: Security Scan
  run: |
    ./scanner/Invoke-SecurityScan.ps1 `
      -Path ./modules `
      -OutputPath ./reports `
      -Verbose
  shell: pwsh

- name: Upload Reports
  uses: actions/upload-artifact@v3
  with:
    name: security-reports
    path: ./reports
```

### Pre-Commit Hook

```powershell
# .git/hooks/pre-commit (rename to remove .ps1 extension)
#!/usr/bin/env pwsh
$changedFiles = git diff --cached --name-only --diff-filter=ACM | Where-Object { $_ -match '\.ps(m?)1$' }

if ($changedFiles) {
    .\scanner\Invoke-SecurityScan.ps1 -Path $changedFiles -OutputPath .\temp-reports
    
    # Check for Critical/High findings
    $report = Get-Content .\temp-reports\*-SecurityReport.md -Raw
    if ($report -match 'Critical|High') {
        Write-Error "Security issues found. Review reports before committing."
        exit 1
    }
}
```

## Troubleshooting

### Common Issues

**Issue**: Parse errors in scanned files
**Solution**: Scanner skips files with syntax errors. Fix syntax first.

**Issue**: Too many false positives
**Solution**: Adjust context filters in `Invoke-ContextAnalysis` function.

**Issue**: Scan is slow
**Solution**: Process smaller file sets or optimize AST traversal logic.

**Issue**: Missing rules in output
**Solution**: Verify rule file format and loading in scanner.

### Debug Mode

```powershell
# Enable PowerShell debugging
$DebugPreference = 'Continue'

.\scanner\Invoke-SecurityScan.ps1 -Path .\source\MyModule -OutputPath .\Report -Verbose -Debug
```

## Testing

Run scanner tests with Pester:

```powershell
Invoke-Pester -Path ..\tests\SecurityScanner.Tests.ps1 -Output Detailed
```

## Related Documentation

- [Detection Rules Context](rules/PowerShellContextRules.md)
- [Detection Rules File](rules/SecurityDetectionRules.psd1)
- [Test Suite](../tests/README.md)
- [Report Examples](../Report/README.md)

---

**Need help?** Check the main [README](../README.md) or review example scans in the [Report](../Report/) directory.
