# Project Brief: PowerShell Security Code Review Template

## Project Overview

This project provides a comprehensive template and framework for **AI-assisted security code reviews** of PowerShell modules. The primary purpose is to enable AI coding agents to perform systematic, thorough security assessments with minimal human intervention. The system includes detection rules, scanning scripts, and reporting templates designed to identify security vulnerabilities, malicious code patterns, and adherence to PowerShell security best practices.

### Initial Usage

To start an AI-assisted code review session, use this prompt:

```text
Start the code review by executing the prompt file `D:\Git\ai1\.clinerules\prompts\CodeReview.prompt.md`
```

## Core Objectives

1. **Security Assessment**: Identify potential security vulnerabilities and malicious code patterns in PowerShell modules
2. **Compliance Validation**: Ensure code adheres to PowerShell security coding guidelines and best practices
3. **Automated Detection**: Develop automated security scanning capabilities using PSScriptAnalyzer and custom rules
4. **Comprehensive Reporting**: Generate detailed security reports with findings, remediation guidance, and CVSS scoring

## Scope

### In Scope

- Framework for scanning any PowerShell modules placed in the `source/` directory
- Security vulnerability detection (code execution, injection, credential exposure)
- PSScriptAnalyzer integration and custom rule development
- Automated scanning script creation
- Executive summary and detailed per-module security report templates
- Comprehensive detection rules with PowerShell-specific context awareness

### Out of Scope

- Performance optimization (unless security-related)
- General code quality issues (unless security-relevant)
- Functional testing of module features
- Specific analysis of any particular modules (this is a template repository)

## Success Criteria

1. Complete Memory Bank documentation established
2. Security detection rules defined based on industry standards
3. Automated scanning scripts created and functional
4. Comprehensive security reports generated for all modules
5. All findings documented with remediation guidance and CVSS scores
6. Project documentation (README files) created at all levels

## Deliverables

1. **Memory Bank**: Complete project documentation and context
2. **Detection Rules**: Comprehensive security rule definitions with PowerShell-specific context
3. **Scanning Scripts**: Automated PowerShell security scanners using PSScriptAnalyzer and Pester
4. **Report Templates**:
   - Executive summary template covering all modules
   - Detailed per-module report template with findings structure
5. **Documentation**: README files at root and folder levels describing the framework
6. **Usage Guide**: Instructions for using this template for your own code reviews

## Timeline Phases

1. **Setup Phase**: Memory Bank creation, initial documentation
2. **Research Phase**: Security guidelines research, rule definition
3. **Development Phase**: Scanning script creation
4. **Execution Phase**: Code review execution, report generation
5. **Documentation Phase**: Additional documentation creation
6. **Optional Phase**: Execute optional enhancement tasks

## Stakeholders

- **Primary**: Security assessment team
- **Audience**: Module developers, security auditors, compliance teams

## Constraints

- PowerShell-specific security context (e.g., credential handling conventions)
- False positive management (especially for high entropy strings, scriptblocks)
- Context-aware analysis (e.g., hostname checks in configuration code)

## Risk Factors

- **False Positives**: PowerShell's nature may trigger false alarms (scriptblocks, string escaping)
- **Context Misinterpretation**: Some patterns are legitimate in specific contexts
- **Incomplete Coverage**: New or emerging threat patterns may not be covered

## Current Status

**Phase**: Template Conversion
**Progress**: Removing test module references, converting to reusable template
