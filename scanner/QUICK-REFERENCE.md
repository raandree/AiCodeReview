# PowerShell Security Scanner - Quick Reference

Version: v1.1.0

## Quick Start

### Scan a Single Module

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule -OutputPath .\Report
```

### Scan All Modules in Source Directory

```powershell
Get-ChildItem .\source -Directory | ForEach-Object {
    .\scanner\Invoke-SecurityScan.ps1 -Path $_.FullName -OutputPath .\Report
}
```

### Scan with Verbose Output

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule -OutputPath .\Report -Verbose
```

## Understanding Output

### Severity Levels

| Severity | CVSS Range | Meaning | Action |
|----------|------------|---------|--------|
| **Critical** | 9.0-10.0 | Definite vulnerabilities | Fix immediately |
| **High** | 7.0-8.9 | Clear security issues | Prioritize remediation |
| **Medium** | 4.0-6.9 | Potential risks | Review and validate |
| **Low** | 0.1-3.9 | Awareness items | Address when time permits |
| **Info** | 0.0 | Common patterns | Informational only |

### Sample Output

```text
PowerShell Security Scanner v1.1.0
====================================
Loaded 45 security rules

Found 125 PowerShell files to scan
Total findings: 946

Critical: 0
High:     41
Medium:   56
Low:      208
Info:     641
====================================
Report: .\Report\YourModule-SecurityReport.md
```

## Common Detection Rules

### Code Execution (High Risk)

- **PS001**: Invoke-Expression usage
- **PS002**: Add-Type usage (especially P/Invoke)
- **PS004**: Start-Process with user input
- **PS041**: .NET Reflection for code execution

### Credential Handling

- **PS009**: Hardcoded credentials
- **PS010**: ConvertTo-SecureString -AsPlainText
- **PS011**: Unencrypted credential transmission
- **PS012**: Credential logging

### Injection Vulnerabilities

- **PS005**: Command injection
- **PS006**: SQL injection patterns
- **PS007**: Script injection

### Windows Security

- **PS031**: Disabled security features (Defender, UAC, Firewall)
- **PS032**: Registry persistence mechanisms

### Network Security

- **PS018**: Unencrypted authentication
- **PS019**: Certificate validation bypass
- **PS020**: Unencrypted HTTP usage

## Context-Aware Features

The scanner intelligently filters false positives:

### ✅ Recognized as Safe

- Scriptblocks in Where-Object, ForEach-Object
- PSCredential parameter in functions
- Path validation functions (Test-Path, Split-Path)
- DSC configuration patterns
- Add-Type with -AssemblyName (loading existing assemblies)

### ⚠️ Requires Context Review

- ConvertTo-SecureString in lab automation
- Security feature disabling for testing
- Start-Process in deployment scripts

## Report Structure

Generated reports include:

1. **Summary Table** - Severity distribution
2. **Detailed Findings** - Grouped by severity
   - Rule name and ID
   - Category
   - File path and line numbers
   - Code excerpt
   - Description
   - Remediation guidance
   - CVSS score

## Common Scenarios

### Pre-Deployment Security Check

```powershell
# Scan production module before deployment
.\scanner\Invoke-SecurityScan.ps1 -Path .\ProductionModule -OutputPath .\Reports

# Review Critical and High findings only
Get-Content .\Reports\*SecurityReport.md | Select-String "(Critical|High) Severity"
```

### Third-Party Module Audit

```powershell
# Save module from gallery
Save-Module -Name ThirdPartyModule -Path .\source

# Scan for security issues
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\ThirdPartyModule -OutputPath .\Reports
```

### CI/CD Integration

Add to your pipeline:

```yaml
# Azure Pipelines example
- task: PowerShell@2
  displayName: 'Security Scan'
  inputs:
    filePath: 'scanner/Invoke-SecurityScan.ps1'
    arguments: '-Path $(Build.SourcesDirectory)/module -OutputPath $(Build.ArtifactStagingDirectory)/SecurityReports'
```

## Troubleshooting

### No Findings Detected

- ✅ Good! Your code passed all security rules
- Review report to confirm scan completed successfully

### Too Many Informational Findings

- Info findings (76% typical) are expected
- Focus on Critical/High/Medium findings
- Use as learning opportunity for developers

### False Positives

If legitimate code is flagged:

1. Review context in detailed report
2. Verify security controls are in place
3. Document business justification
4. Consider custom rule adjustments if pattern is common

## Quick Tips

### 💡 Focus on What Matters

1. **First**: Address all Critical findings
2. **Second**: Review High severity findings
3. **Third**: Evaluate Medium findings by module importance
4. **Last**: Use Info findings for code quality improvements

### 📊 Use Statistics Export

```powershell
# Reports include ScanStatistics.csv for analysis
Import-Csv .\Report\ScanStatistics.csv | Format-Table
```

### 🔍 Search Specific Rules

```powershell
# Find all instances of a specific rule
Get-Content .\Report\*SecurityReport.md | Select-String "PS010"
```

## Scanner Version

- **Current**: v1.1.0
- **Rules**: 45 comprehensive detection rules
- **2025 Threat Coverage**: MITRE ATT&CK T1059.001 patterns

## Resources

- **Detailed Reports**: `Report/` directory
- **Rule Definitions**: `scanner/rules/SecurityDetectionRules.psd1`
- **Rule Documentation**: `scanner/rules/PowerShellContextRules.md`
- **Project Documentation**: `README.md`
- **Memory Bank**: `memory-bank/` directory

---

**Quick Help**: Run with `-Verbose` flag to see detailed analysis decisions

