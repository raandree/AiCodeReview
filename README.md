# PowerShell Security Code Review Template

[![Security Scanning](https://img.shields.io/badge/Security-Automated%20Scanning-blue)](./scanner)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> [!WARNING]  
> **Disclaimer**: This automated security code review tool is designed to assist in identifying potential security vulnerabilities and code quality issues. However, it does not guarantee that the reviewed code is completely safe or free from all security risks. The tool may produce false positives or miss certain vulnerabilities. **User discretion is advised**. Always perform manual security reviews by qualified security professionals for critical systems and consider this tool as part of a defense-in-depth security strategy, not as a replacement for comprehensive security assessment.

## Overview

This repository provides a **comprehensive template and framework for AI-assisted security code reviews** of PowerShell modules. It includes automated security scanning tools, detection rules, and reporting templates designed to identify security vulnerabilities, malicious code patterns, and adherence to PowerShell security best practices.

### Key Features

✅ **45 Comprehensive Security Rules** (PS001-PS060) covering 2025 threat landscape  
✅ **Software Release Pipeline Chat Modes** for structured SDLC workflow  
✅ **Context-Aware Analysis** to minimize false positives in PowerShell code  
✅ **Automated Scanning** with detailed Markdown reports  
✅ **CVSS Risk Scoring** for all findings  
✅ **Executive Summary Generation** for stakeholder reporting  
✅ **AI-Optimized Workflow** designed for AI coding agents  
✅ **Production Readiness Validation** with security gating  

## Setup and Installation

### Prerequisites

Before using this template, ensure your system meets these requirements:

- **Windows 10/11** or **Windows Server 2016+**
- **Administrator privileges** (for initial setup)
- **PowerShell 5.1+** installed
- **Internet connectivity** for downloading packages
- **10GB+ free disk space** recommended

### Quick Installation

```powershell
# Install required PowerShell modules
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber
Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck

# Verify installation
Get-Module -Name PSScriptAnalyzer, Pester -ListAvailable
```

### Complete Setup Guide

For comprehensive setup instructions including:

- **Chocolatey installation** - Automated package management for Windows
- **Tool installation** - PowerShell Core, Git, VS Code via Chocolatey or manual
- **Windows Defender configuration** - Optional exclusions or disable for development machines
- **Troubleshooting** - Solutions for common installation issues
- **Maintenance** - Keeping tools updated and cleanup procedures

📖 **See the complete [SETUP.md](SETUP.md) guide**

## Quick Start

### Starting an AI-Assisted Code Review

1. Save the PowerShell modules you want to review into the `source/` directory. In the example, we save the module `PSFramework` from the PowerShell Gallery:

```powershell
Save-Module -Name PSFramework -Path .\source\
```

2. To initiate an AI-assisted security code review session, use this prompt with your AI coding agent:

> [!IMPORTANT]  
> Make sure you are using the chat mode `Security & Quality Assurance Agent v1` and Claude Sonnet 4.5 for best results.

```text
Start the code review by executing the prompt file `.github\prompts\CodeReview.prompt.md`. Execute all steps in sequence, utilizing the memory bank for context.
```

> [!TIP]  
> **Enterprise Open Source Governance**: This tool is particularly valuable as part of a comprehensive governance framework for integrating open source PowerShell modules into corporate environments. By incorporating automated security scanning into your CI/CD pipeline, you can establish a systematic vetting process for third-party code before it enters your network. Use this scanner as a **mandatory gate** in your deployment pipeline to assess open source modules from the PowerShell Gallery or other sources, generating audit trails and security reports that support compliance requirements. Combined with manual reviews, code signing policies, and runtime monitoring, this tool helps organizations safely leverage the benefits of open source while maintaining security standards and regulatory compliance.

### Manual Code Review

1. **Place PowerShell modules in the `source/` directory**

   ```
   source/
   ├── YourModule1/
   └── YourModule2/
   ```

2. **Run the security scanner**

   ```powershell
   .\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule1 -OutputPath .\Report -Verbose
   ```

3. **Review the generated reports**

   - Executive Summary: `Report/ExecutiveSummary.md`
   - Detailed Report: `Report/YourModule1-SecurityReport.md`

## Repository Structure

```
.
├── .clinerules/              # AI agent configuration
│   ├── chatmodes/           # Software release pipeline chat modes
│   │   ├── Software Engineer Agent v1.chatmode.md
│   │   ├── Security & Quality Assurance Agent v1.chatmode.md
│   │   ├── README.md        # Pipeline documentation
│   │   └── QUICK-START.md   # Quick usage guide
│   └── prompts/             # Automated workflow prompts
│       └── CodeReview.prompt.md
├── memory-bank/             # Project documentation and context
│   ├── projectbrief.md
│   ├── productContext.md
│   ├── systemPatterns.md
│   ├── promptHistory.md
│   └── ... (see memory-bank/README.md)
├── scanner/                 # Security scanning tools
│   ├── Invoke-SecurityScan.ps1
│   └── rules/
│       ├── SecurityDetectionRules.psd1
│       └── PowerShellContextRules.md
├── source/                  # Place your PowerShell modules here
│   ├── BadCodeExamples.psm1  # Test module with intentional vulnerabilities
│   └── README.md
├── Report/                  # Generated security reports
│   └── README.md
├── tests/                   # Scanner test suite
│   └── SecurityScanner.Tests.ps1
└── README.md               # This file
```

### 🆕 Software Release Pipeline Chat Modes

This template now includes AI agent chat modes for a complete software development lifecycle:

1. **[Software Engineer Agent v1](.clinerules/chatmodes/Software%20Engineer%20Agent%20v1.chatmode.md)** - Production-ready code development
2. **[Security & QA Agent v1](.clinerules/chatmodes/Security%20&%20Quality%20Assurance%20Agent%20v1.chatmode.md)** - Comprehensive security validation and production readiness

**Quick Start**: See [Chat Modes Quick Start](.clinerules/chatmodes/QUICK-START.md) for usage examples and workflow guidance.

For detailed information about each directory, see the README.md file in that directory.

## Documentation

### Getting Started

- 📖 **[SETUP.md](SETUP.md)** - **Complete installation and setup guide**
  - Chocolatey package manager installation
  - Tool installation (PowerShell, Git, VS Code)
  - Windows Defender configuration options
  - Troubleshooting common issues
  - Maintenance and update procedures

### Core Documentation

- **[Project Brief](memory-bank/projectbrief.md)** - Project overview and objectives
- **[Product Context](memory-bank/productContext.md)** - Usage workflows and use cases
- **[System Patterns](memory-bank/systemPatterns.md)** - Technical architecture
- **[Tech Context](memory-bank/techContext.md)** - Technologies and dependencies

### Component Documentation

- **[Scanner](scanner/README.md)** - Security scanning tools and usage
- **[Detection Rules](scanner/rules/PowerShellContextRules.md)** - Rule definitions and context
- **[Source](source/README.md)** - Module placement and test modules
- **[Reports](Report/README.md)** - Report structure and examples
- **[Tests](tests/README.md)** - Testing framework
- **[Memory Bank](memory-bank/README.md)** - AI context documentation system

## Validation and Testing

This template includes a comprehensive test module (`source/BadCodeExamples.psm1`) that validates the scanner's detection capabilities:

- **Test Module**: Contains intentional security vulnerabilities for all 25 rules
- **Validation Results**: 92% detection rate (23/25 rules triggered)
- **Total Findings**: 102 security issues correctly identified
- **Purpose**: Proves scanner accuracy and rule effectiveness

⚠️ **Warning**: The test module contains intentionally insecure code patterns. Never use code from this module in production!

### Running Validation

```powershell
# Scan the test module to verify scanner functionality
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\BadCodeExamples.psm1 -OutputPath .\Report

# Expected: 102 findings across all severity levels
# Critical: 6 | High: 19 | Medium: 9 | Low: 10 | Info: 58
```

## Security Detection Coverage

### Vulnerability Categories

| Category | Rules | Examples |
|----------|-------|----------|
| **Code Execution** | 9 | Invoke-Expression, Add-Type, Start-Process |
| **Injection** | 6 | Command/Script/Path injection patterns |
| **Credentials** | 6 | Hardcoded credentials, insecure credential handling |
| **Cryptography** | 4 | Weak algorithms, hardcoded keys |
| **Network** | 3 | Certificate bypass, suspicious downloads |
| **File Operations** | 3 | Path traversal, unsafe file operations |
| **Obfuscation** | 8 | Character substitution, encoding patterns |
| **Input Validation** | 2 | Missing validation, unsafe expansion |
| **Dangerous APIs** | 4 | Reflection, runspace manipulation |

### Context-Aware Filtering

The scanner includes PowerShell-specific intelligence to reduce false positives:

- ✅ Recognizes legitimate DSC patterns
- ✅ Understands PSCredential best practices
- ✅ Differentiates function names from actual credentials
- ✅ Validates scriptblock legitimacy
- ✅ Detects path validation functions

## Usage Scenarios

### Scenario 1: Pre-Deployment Security Check

```powershell
# Scan a module before deploying to production
.\scanner\Invoke-SecurityScan.ps1 `
    -Path .\source\ProductionModule `
    -OutputPath .\Report `
    -Verbose

# Review critical and high severity findings
Get-Content .\Report\ProductionModule-SecurityReport.md | Select-String "Critical|High"
```

### Scenario 2: CI/CD Integration

```yaml
# Example Azure Pipeline step
- task: PowerShell@2
  displayName: 'Security Scan'
  inputs:
    filePath: 'scanner/Invoke-SecurityScan.ps1'
    arguments: '-Path $(Build.SourcesDirectory)/modules -OutputPath $(Build.ArtifactStagingDirectory)/SecurityReports'
    
- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)/SecurityReports'
    ArtifactName: 'SecurityReports'
```

### Scenario 3: Third-Party Module Audit

```powershell
# Audit a third-party PowerShell module
Copy-Item -Path "C:\Program Files\WindowsPowerShell\Modules\ThirdPartyModule" `
          -Destination ".\source\ThirdPartyModule" -Recurse

.\scanner\Invoke-SecurityScan.ps1 -Path .\source\ThirdPartyModule -OutputPath .\Report
```

## Customization

### Adding Custom Detection Rules

Edit `scanner/rules/SecurityDetectionRules.psd1`:

```powershell
@{
    Id = 'CUSTOM001'
    Name = 'Your Custom Rule'
    Severity = 'High'
    Category = 'CustomCategory'
    Description = 'Detects specific pattern in your organization'
    ASTPattern = 'CommandAst'
    CommandName = 'Dangerous-Command'
    Remediation = 'Use approved alternative'
    CVSS = 7.5
}
```

### Adjusting Context Filters

Modify the `Invoke-ContextAnalysis` function in `scanner/Invoke-SecurityScan.ps1` to tune false positive filtering for your environment.

### Customizing Reports

Modify the `New-SecurityReport` function in `scanner/Invoke-SecurityScan.ps1` to change report format or add additional sections.

## Testing

Run the scanner test suite with Pester:

```powershell
# Install Pester if needed
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run tests
Invoke-Pester -Path .\tests\SecurityScanner.Tests.ps1 -Output Detailed
```

## Requirements

- **PowerShell**: 5.1 or higher (PowerShell 7+ recommended)
- **Modules**: None (scanner is self-contained)
- **Platform**: Windows, Linux, macOS

## AI-Assisted Workflow

This template is optimized for AI coding agents:

1. **Automated Prompt Execution**: Use `CodeReview.prompt.md` for sequential task execution
2. **Memory Bank System**: AI agents can read context from structured documentation
3. **Self-Documenting**: All findings include remediation guidance
4. **Extensible Rules**: AI can suggest new rules based on findings

### AI Agent Instructions

To use this template with an AI coding agent:

1. Provide the starting prompt (see Quick Start above)
2. The AI will execute all prompts in sequence:
   - Initialize memory bank
   - Validate detection rules
   - Execute security scan
   - Generate reports
   - Identify pending tasks
   - Create documentation

## Example Results

### Sample Finding

```markdown
**Rule**: Certificate Validation Bypass (PS019)
**Category**: Network
**File**: MyModule.psm1
**Line**: 156

**Code**:
```powershell
$webRequest.ServerCertificateValidationCallBack = { $true }
```

**Description**: Detects code that bypasses SSL/TLS certificate validation
**Remediation**: Never bypass certificate validation in production
**CVSS Score**: 9.1

```

### Report Statistics

From a real scan of 65 PowerShell files:

- Total Findings: 797
- Critical: 2 (0.3%)
- High: 2 (0.3%)
- Medium: 15 (1.9%)
- Low: 84 (10.5%)
- Info: 694 (87.0%)

Context-aware filtering reduced false positives by ~60%.

## Contributing

Contributions are welcome! Areas of interest:

- Additional detection rules
- Improved context filtering
- New report formats
- CI/CD integration examples
- Additional language support

## License

MIT License - See [LICENSE](LICENSE) for details

## Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Documentation**: See `memory-bank/` directory for detailed documentation
- **Security**: For security concerns, see SECURITY.md

## Credits

Developed as a template for AI-assisted PowerShell security code reviews. Detection rules based on:

- Microsoft PowerShell Security Best Practices
- PSScriptAnalyzer community rules
- DSC Community security guidelines
- OWASP secure coding principles

## Related Resources

- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)
- [DSC Community](https://github.com/dsccommunity)
- [Microsoft PowerShell Security](https://docs.microsoft.com/en-us/powershell/scripting/security/overview)
- [PowerShell Gallery](https://www.powershellgallery.com/)

---

**Ready to start?** Use the Quick Start prompt above with your AI coding agent, or run the scanner manually on your PowerShell modules.
