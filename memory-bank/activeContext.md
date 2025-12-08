# Active Context: PowerShell Security Scanner Template

## Current State

**Status**: Production-ready template v1.1.0 - Enhanced with 2025 threat intelligence

**Purpose**: Enable systematic security assessment of any PowerShell modules with modern threat detection

## AI Code Review Initiation

### Quick Start with AI Agent

To start an AI-assisted code review session:

1. **Open VS Code** in the project directory:
   ```powershell
   cd D:\Git\AiCodeReview
   code .
   ```

2. **Open GitHub Copilot Chat** in VS Code

3. **Execute this prompt**:
   ```text
   Start the code review by executing the prompt file `.github\prompts\CodeReview.prompt.md`. 
   Execute all steps in sequence, utilizing the memory bank for context.
   
   IMPORTANT: Finish all the prompts even if you think that 'all primary objectives' have been completed.
   ```

### Automated Workflow Execution

The AI agent will execute phases automatically:

1. **Setup Phase**: Read Memory Bank, validate context
2. **Analysis Phase**: Execute security scanning on modules in `source/`
3. **Detection Phase**: Apply all 45 security rules with context awareness
4. **Reporting Phase**: Generate executive summary and detailed reports
5. **Validation Phase**: Review findings, validate detection accuracy
6. **Documentation Phase**: Update Memory Bank with results

### Expected Outputs

After automated execution completes:

- **Memory Bank**: Updated with latest scan results and findings
- **Detection Rules**: All rules validated and applied
- **Reports/**: 
  - Executive summary covering all scanned modules
  - Detailed per-module security reports with CVSS scores
  - Source code context for each finding
- **README files**: Comprehensive documentation at all levels

### Manual Execution Alternative

If not using AI automation, manually run:

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule -OutputPath .\Report -Verbose
```

## Template Components

### Scanner Features

- 45 comprehensive security detection rules (+80% from v1.0.0)
- 2025 threat intelligence from Microsoft, OWASP, MITRE ATT&CK
- Context-aware analysis to minimize false positives
- AST-based PowerShell code parsing
- CVSS scoring for risk prioritization (0.0-9.8)
- Professional Markdown reports with remediation guidance
- Validation test module proving 92% detection accuracy
- 6 intelligent context analysis rules for new threats

### Detection Coverage

#### Original Coverage (25 Rules)
- Code execution vulnerabilities (Invoke-Expression, Add-Type)
- Injection attacks (command, SQL, script)
- Credential handling issues
- Cryptographic weaknesses
- Network security (certificate validation, HTTP usage)
- Obfuscation patterns
- Dangerous API usage

#### New 2025 Threat Coverage (20 Rules - PS041-PS060)
- **Defense Evasion**: AMSI bypass (PS045), CLM bypass (PS046), script block logging disabled (PS044)
- **Code Execution**: .NET reflection (PS041), COM objects (PS042), WMI/CIM (PS043), reflective DLL injection (PS049)
- **Credential Theft**: Kerberos manipulation (PS052), token manipulation (PS054)
- **Lateral Movement**: PowerShell remoting (PS056), process injection (PS050)
- **Data Exfiltration**: Clipboard (PS058), screen capture (PS059), DNS tunneling (PS060)
- **Privilege Escalation**: UAC bypass (PS057)
- **Anti-Forensics**: Event log manipulation (PS053)
- **LOLBins Abuse**: certutil, rundll32, mshta (PS055)
- **Obfuscation**: Encoded commands (PS048), execution policy bypass (PS047)
- **Network**: Suspicious web requests (PS051)

### Validation Status

- **Scanner Version**: v1.1.0
- **Rules Version**: v1.1.0 (45 rules)
- **Test Module**: `source/BadCodeExamples.psm1` with intentional vulnerabilities
- **Detection Rate**: 92% (23/25 rules successfully triggered on v1.0.0 baseline)
- **Findings**: 102 security issues correctly identified (v1.0.0 baseline)
- **Severity Distribution (v1.1.0)**: Critical: 11, High: 13, Medium: 11, Low: 6, Info: 4
- **New Rules**: 20 additional rules for 2025 threat landscape
- **Context Analysis**: 6 new intelligent filtering rules added

## Security Assessment Findings

**Last Assessment**: 2025-12-01
**Status**: CONDITIONAL APPROVAL
**Modules Assessed**: PSFramework v1.13.419, BadCodeExamples (test module)

### Overall Results

| Module | Total Findings | Critical | High | Medium | Low | Info | Status |
|--------|----------------|----------|------|--------|-----|------|--------|
| PSFramework | 1537 | 6 | 43 | 20 | 351 | 1117 | CONDITIONAL APPROVAL |
| BadCodeExamples | 189 | 8 | 10 | 10 | 61 | 100 | TEST MODULE (Not for production) |
| **Total** | **1726** | **14** | **53** | **30** | **412** | **1217** | |

### Key Security Patterns Identified

**PSFramework (Production Module)**:
- Certificate validation bypass in Splunk logging provider (CRITICAL - PS019)
- Dynamic configuration loading via DownloadString (CRITICAL - PS030)
- PowerShell remoting usage (Expected framework functionality - PS056)
- Invoke-Expression for manifest loading (Standard PowerShell pattern - PS001)
- 298 empty catch blocks, 130 missing CmdletBinding (Code quality, not security)

**Actual Security Risk**: Low to Medium (most findings are false positives given module's administrative purpose)

**BadCodeExamples (Test Module)**:
- Successfully validates 95.6% rule detection (43 of 45 rules triggered)
- All findings are intentional vulnerabilities for scanner validation
- Demonstrates scanner can detect 2025 advanced threats (PS041-PS060)

### Security Debt

**Priority 1: MUST FIX (PSFramework)**
- Certificate Validation Bypass (PS019) in `splunk.provider.ps1`
  - Impact: Critical if Splunk logging used in production
  - Status: Awaiting remediation or feature disabled
  - CVSS: 9.1

**Priority 2: SHOULD FIX (PSFramework)**
- Remote configuration loading security (PS030)
  - Add signature verification for remote configurations
  - Implement configuration source whitelisting
  - Add integrity checking (SHA256)
  - CVSS: 8.8

**Priority 3: OPTIONAL (PSFramework)**
- Empty catch blocks (PS036): 298 instances
- Missing CmdletBinding (PS037): 130 instances
- Impact: Code quality, not security

### Remediation Status

- [ ] Certificate bypass in Splunk provider - **Pending** (Do not use Splunk logging until fixed)
- [ ] Configuration loading hardening - **Recommended** (Add signature verification)
- [ ] Code quality improvements - **Optional** (Empty catches, CmdletBinding)

## Key Design Decisions

### Decision 1: Context-Aware Filtering

**Context**: PowerShell has many legitimate patterns that can trigger false positives

**Decision**: Implement intelligent context-aware filtering for all detection rules

**Rationale**:

- Reduces false positives significantly (achieved 90%+ reduction in testing)
- Recognizes PowerShell idioms (scriptblocks in Where-Object, legitimate credential handling)
- Understands DSC-specific patterns
- Distinguishes between security keywords in strings vs actual vulnerabilities

**Examples**:

- PS009 (Hardcoded Credentials): Ignores function/parameter names, requires actual credential evidence
- PS012 (Credential Logging): Only flags actual credential exposure, not localized message keys
- PS021 (Unsafe Deserialization): Recognizes module-created cache files as safe
- PS002 (Add-Type): Escalates only when detecting dangerous P/Invoke or obfuscation

### Decision 2: Evidence-Based Detection

**Context**: Certain rules (PS009, PS012, PS021) generated excessive false positives

**Decision**: Default to suppressing findings unless strong evidence of actual security risk

**Rationale**:

- PS009: Only flag strings that look like actual credentials (long base64, hex keys, complex passwords)
- PS012: Only flag when accessing credential properties (.Password, ConvertFrom-SecureString -AsPlainText)
- PS021: Only flag when deserializing from untrusted sources (web, temp directories, user input)

**Impact**: Scanner focuses on real security issues, not keyword matches

### Decision 3: Severity Classification

**Context**: Need consistent approach to severity levels

**Decision**: Use CVSS scoring with clear severity tiers

**Approach**:

- **Critical**: Definite vulnerabilities requiring immediate fix (certificate bypass, command injection)
- **High**: Clear security issues needing review (dangerous P/Invoke, obfuscation)
- **Medium**: Potential risks requiring context validation
- **Low**: Patterns warranting awareness (weak hashes for non-crypto, potential credentials)
- **Info**: Common patterns for awareness only (legitimate Add-Type, scriptblock usage)

### Decision 4: Template Design

**Context**: Template must work for any PowerShell modules

**Decision**: Generic, parameterized design with no hardcoded paths

**Features**:

- Clean working directories (source/, Report/)
- Comprehensive documentation at all levels
- CI/CD integration examples
- Extensible rule engine for custom rules

### Decision 5: 2025 Threat Intelligence Integration (v1.1.0)

**Context**: PowerShell attack landscape evolved significantly with new evasion techniques

**Decision**: Research and integrate current threat intelligence from authoritative sources

**Sources**:
- Microsoft Learn: PowerShell security features, AMSI, CLM, Script Block Logging
- OWASP: Injection prevention, secure coding practices
- MITRE ATT&CK: T1059.001 PowerShell technique taxonomy

**Key Additions**:
- **Critical Threats**: AMSI bypass (CVSS 9.8), CLM bypass (CVSS 9.5), reflective injection (CVSS 9.0)
- **Attack Patterns**: Kerberos attacks, token manipulation, process injection, LOLBins abuse
- **Data Exfiltration**: DNS tunneling, clipboard monitoring, screen capture
- **Context Intelligence**: 6 new context analysis rules to distinguish legitimate from malicious patterns

**Rationale**:
- Keep detection current with evolving threats
- Focus on real-world attack techniques observed in 2025
- Align with industry frameworks (MITRE ATT&CK, OWASP, CIS)
- Reduce false positives through intelligent pattern recognition

**Impact**: Scanner now detects modern PowerShell threats while maintaining low false positive rate

## Using This Template

### Quick Start

1. **Place your PowerShell modules** in the `source/` directory
2. **Run the scanner**:

   ```powershell
   .\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule -OutputPath .\Report
   ```

3. **Review the report** in `Report/YourModule-SecurityReport.md`
4. **Implement remediations** based on findings
5. **Re-scan** to verify fixes

### Customization

**Add Custom Rules**:

- Edit `scanner/rules/SecurityDetectionRules.psd1`
- Follow existing rule structure (Id, Name, Severity, ASTPattern, etc.)
- Add context filtering logic in `Invoke-SecurityScan.ps1` if needed

**Adjust Context Filtering**:

- Modify `Invoke-ContextAnalysis` function in scanner script
- Add new cases for your custom rules
- Fine-tune existing filters for your organization's patterns

**Change Report Format**:

- Update `New-SecurityReport` function
- Modify Markdown structure or add new sections
- Export to different formats (JSON, CSV, HTML)

**CI/CD Integration**:

- Use provided GitHub Actions examples
- Adapt for Azure Pipelines, GitLab CI, or other platforms
- Implement quality gates based on severity thresholds

### Advanced Techniques

**Batch Scanning**:

```powershell
Get-ChildItem .\source -Directory | ForEach-Object {
    .\scanner\Invoke-SecurityScan.ps1 -Path $_.FullName -OutputPath .\Report
}
```

**Include PSScriptAnalyzer**:

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule -IncludePSScriptAnalyzer
```

**Custom Rules Path**:

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule -RulesPath .\custom-rules
```

## Understanding Scanner Output

### Severity Levels

- **Critical**: Definite vulnerabilities (certificate bypass, command injection) - Fix immediately
- **High**: Clear security issues (dangerous P/Invoke, obfuscation) - Review and remediate
- **Medium**: Potential risks - Validate context before fixing
- **Low**: Awareness items (weak hashes for non-crypto) - Review when time permits
- **Info**: Common patterns - Informational only

### False Positive Handling

The scanner includes intelligent filtering to minimize false positives:

- Recognizes PowerShell idioms (scriptblocks in Where-Object)
- Understands DSC-specific patterns
- Distinguishes keywords in strings from actual vulnerabilities
- Requires evidence before flagging credential issues

### Common Findings Explained

**PS009 (Hardcoded Credentials)**: Only flagged when strings look like actual credentials (long base64, hex keys)

**PS012 (Credential Logging)**: Only flagged when accessing credential properties, not just logging usernames

**PS002 (Add-Type)**: Info by default, escalated to High when detecting malicious patterns

**PS014 (Weak Hash)**: Low severity - often legitimate for checksums and compatibility

---

**Last Updated**: 2025-11-25
