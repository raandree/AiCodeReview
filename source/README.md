# Source Directory

## Purpose

This directory is where you place PowerShell modules that you want to analyze for security vulnerabilities.

## Test Modules

### BadCodeExamples.psm1

⚠️ **WARNING: This module contains intentionally insecure code!**

This test module demonstrates every security vulnerability that the scanner is designed to detect. It serves as:

- **Validation Tool**: Verify the scanner detects all rule violations
- **Reference Guide**: See examples of what NOT to do in PowerShell
- **Testing Resource**: Use for scanner development and testing

**DO NOT use any code from this module in production!**

The module contains examples triggering all 25+ security rules:

- **Critical**: Unencrypted authentication, certificate bypass, download-and-execute
- **High**: Weak encryption, hardcoded credentials, security feature disabling
- **Medium**: HTTP usage, path traversal, Base64 obfuscation
- **Low**: Weak hashing, credential logging, empty catch blocks
- **Info**: Missing CmdletBinding, unapproved verbs

Run the scanner against this module to verify detection:

```powershell
.\scanner\Invoke-SecurityScan.ps1 -Path .\source\BadCodeExamples.psm1 -OutputPath .\Report
```

Expected result: The scanner should flag all intentional violations.

## Usage

### Adding Modules for Analysis

1. **Copy your PowerShell module(s) into this directory**

   ```
   source/
   ├── YourModule1/
   │   ├── YourModule1.psd1
   │   ├── YourModule1.psm1
   │   └── Functions/
   │       └── *.ps1
   └── YourModule2/
       ├── YourModule2.psd1
       └── YourModule2.psm1
   ```

2. **Run the security scanner**

   ```powershell
   .\scanner\Invoke-SecurityScan.ps1 -Path .\source\YourModule1 -OutputPath .\Report
   ```

### Supported Module Structures

The scanner supports any standard PowerShell module structure:

- **Simple modules**: Just `.psd1` and `.psm1` files
- **Script modules**: With separate function files
- **Binary modules**: With `.dll` files (scans only PowerShell code)
- **Mixed modules**: Combination of the above

### What Gets Scanned

The scanner recursively searches for and analyzes:

- `*.ps1` - PowerShell scripts
- `*.psm1` - PowerShell module files
- `*.psd1` - PowerShell data files (manifests, localization)

## Example Structure

```
source/
├── MySecurityModule/
│   ├── MySecurityModule.psd1       # Module manifest
│   ├── MySecurityModule.psm1       # Root module
│   ├── Public/                     # Public functions
│   │   ├── Get-SecurityStatus.ps1
│   │   └── Set-SecurityPolicy.ps1
│   ├── Private/                    # Private/helper functions
│   │   └── Test-InternalSecurity.ps1
│   ├── en-US/                      # Localization
│   │   └── MySecurityModule.strings.psd1
│   └── Tests/                      # Pester tests (optional)
│       └── MySecurityModule.Tests.ps1
```

## Tips

### Before Scanning

1. **Ensure Valid Syntax**: The scanner uses AST parsing which requires syntactically valid PowerShell code
2. **Include Dependencies**: If your module has nested modules, include them in the scan path
3. **Check File Permissions**: Ensure the scanner has read access to all files

### After Scanning

1. **Review Reports**: Check `Report/` directory for generated security reports
2. **Prioritize Findings**: Focus on Critical and High severity findings first
3. **Implement Remediations**: Follow the remediation guidance in the reports
4. **Re-scan**: After fixes, re-run the scanner to verify improvements

## Cleanup

After completing your security review:

1. **Keep or Remove**: Decide whether to keep scanned modules in this directory
2. **Archive Reports**: Move security reports to a secure location
3. **Track Progress**: Use the reports to track security improvements over time

## Notes

- This is a **working directory** for security analysis
- Modules placed here are **not** part of the template repository
- Add this directory to `.gitignore` if you don't want to track scanned modules
- The scanner does **not** modify your source code - it only reads and analyzes

## Next Steps

After placing your modules here:

1. Read the [main README](../README.md) for scanner usage
2. Review [scanner documentation](../scanner/README.md) for advanced options
3. Check [detection rules](../scanner/rules/PowerShellContextRules.md) to understand what's detected
4. Run your first scan and review the generated reports

---

**Template Version**: 1.0.0  
**Purpose**: PowerShell module security analysis workspace
