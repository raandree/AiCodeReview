# Setup Guide: PowerShell Security Code Review Template

## Overview

This guide provides step-by-step instructions for setting up a machine to perform automated PowerShell security code verification using this template framework.

## Quick Setup Checklist

- [ ] Windows 10/11 or Windows Server 2016+
- [ ] Administrator privileges available
- [ ] Internet connectivity established
- [ ] 10GB+ free disk space
- [ ] PowerShell 5.1+ installed
- [ ] Git installed
- [ ] VS Code with GitHub Copilot configured
- [ ] PSScriptAnalyzer module installed
- [ ] Pester 5.x module installed

## Detailed Setup Instructions

### Step 1: Install Chocolatey Package Manager

Chocolatey simplifies software installation on Windows.

**Installation**:

1. Open **PowerShell** as **Administrator**
2. Execute:

```powershell
# Set execution policy for this process
Set-ExecutionPolicy Bypass -Scope Process -Force

# Configure TLS 1.2 support
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# Download and install Chocolatey
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

3. **Verify**:

```powershell
choco --version
# Expected: Version number (e.g., 2.3.0)
```

### Step 2: Install Required Software

**Using Chocolatey**:

```powershell
# Install PowerShell Core (latest version)
choco install powershell-core -y

# Install Git for version control
choco install git.install -y

# Install Visual Studio Code
choco install vscode -y
```

**Manual Alternative**:

- PowerShell 7+: [GitHub Releases](https://github.com/PowerShell/PowerShell/releases)
- Git: [git-scm.com](https://git-scm.com/)
- VS Code: [code.visualstudio.com](https://code.visualstudio.com/)

### Step 3: Install PowerShell Modules

**Required Modules**:

```powershell
# Install PSScriptAnalyzer for code analysis
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force -AllowClobber

# Install Pester for testing framework
Install-Module -Name Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -AllowClobber -SkipPublisherCheck
```

**Optional Modules**:

```powershell
# Install platyPS for help documentation
Install-Module -Name platyPS -Scope CurrentUser -Force
```

### Step 4: Configure Development Environment

**Set Execution Policy**:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Configure VS Code Extensions**:

1. Open VS Code
2. Install extensions:
   - PowerShell (ms-vscode.powershell)
   - GitHub Copilot (github.copilot)

### Step 5: Clone Repository

```powershell
# Navigate to your Git directory
cd D:\Git

# Clone the repository
git clone <repository-url> AiCodeReview

# Navigate into the repository
cd AiCodeReview
```

### Step 6: Verify Installation

**Run Verification Script**:

```powershell
# Check PowerShell version
7.5.4

# Check Git installation
git --version

# Check VS Code installation
code --version

# Check required PowerShell modules
Get-Module -Name PSScriptAnalyzer, Pester -ListAvailable

# Verify Chocolatey packages
choco list --local-only
```

**Expected Output**:
- PowerShell version 5.1 or higher
- Git version 2.x
- VS Code version 1.x
- PSScriptAnalyzer and Pester modules listed

## Optional: Windows Defender Configuration

**⚠️ WARNING**: Disabling Windows Defender reduces system security. Only do this on isolated test/development machines, never on production systems.

### Recommended Approach - Add Exclusions Instead

Use folder/process exclusions instead of full disable when possible:

```powershell
# Add folder exclusion for the project directory
Add-MpPreference -ExclusionPath "D:\Git\AiCodeReview"

# Add process exclusion for PowerShell and VS Code
Add-MpPreference -ExclusionProcess "pwsh.exe", "powershell.exe", "Code.exe"

# Verify exclusions
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess
```

**Remove Exclusions After Analysis**:

```powershell
# Remove Windows Defender exclusions
Remove-MpPreference -ExclusionPath "D:\Git\AiCodeReview"
Remove-MpPreference -ExclusionProcess "pwsh.exe", "powershell.exe", "Code.exe"
```

### Alternative - Full Disable (NOT RECOMMENDED for production)

Only use in isolated lab environments:

```powershell
# Disable Windows Defender real-time protection (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true

# Verify status
Get-MpPreference | Select-Object -Property Disable*
```

**Re-enable Windows Defender when done**:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisablePrivacyMode $false
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
```

## Troubleshooting

### Issue: Chocolatey Installation Fails

**Solutions**:
- Ensure running PowerShell as Administrator
- Check internet connectivity
- Verify TLS 1.2 is enabled:
  ```powershell
  [Net.ServicePointManager]::SecurityProtocol
  ```

### Issue: Module Installation Fails

**Solutions**:
- Update PowerShellGet first:
  ```powershell
  Install-Module -Name PowerShellGet -Force -AllowClobber
  ```
- Check PSGallery trust:
  ```powershell
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  ```

### Issue: Execution Policy Prevents Script Execution

**Solution**:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue: Git Command Not Found

**Solutions**:
- Close and reopen PowerShell to refresh PATH
- Manually add to PATH: `C:\Program Files\Git\cmd`
- Verify installation:
  ```powershell
  C:\Program Files\PowerShell\7;c:\Users\randr\AppData\Roaming\Code\User\globalStorage\github.copilot-chat\debugCommand;c:\Users\randr\AppData\Roaming\Code\User\globalStorage\github.copilot-chat\copilotCli;C:\Python314\Scripts\;C:\Python314\;C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\;C:\Program Files\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\ProgramData\chocolatey\bin;C:\Program Files\dotnet\;C:\Program Files\Microsoft VS Code\bin;C:\Program Files\Git\cmd;C:\Program Files\Tailscale\;C:\Program Files\PowerShell\7\;C:\Program Files\nodejs\;C:\Users\randr\AppData\Local\Microsoft\WindowsApps;C:\Users\randr\.dotnet\tools;C:\Users\randr\OneDrive\Documents\PowerShell\Scripts;C:\Users\randr\.dotnet\tools;C:\Users\randr\AppData\Roaming\npm -split ';' | Select-String 'Git'
  ```

### Issue: VS Code Extensions Not Installing

**Solutions**:
- Install manually from VS Code Extensions marketplace
- Use command line:
  ```powershell
  code --install-extension ms-vscode.powershell
  code --install-extension github.copilot
  ```

## Maintenance

### Updating Tools

**Update Chocolatey Packages**:

```powershell
choco upgrade all -y
```

**Update PowerShell Modules**:

```powershell
Update-Module -Name PSScriptAnalyzer, Pester
```

**Update Git**:

```powershell
git update-git-for-windows
```

### Cleanup After Analysis

**Remove Windows Defender Exclusions**:

```powershell
Remove-MpPreference -ExclusionPath ""D:\Git\AiCodeReview""
Remove-MpPreference -ExclusionProcess ""pwsh.exe"", ""powershell.exe"", ""Code.exe""
```

## Next Steps

After completing setup:

1. **Review Memory Bank**: Read all files in `memory-bank/` directory
2. **Place Modules**: Copy PowerShell modules to analyze into `source/` directory
3. **Run Scanner**: Execute `.\scanner\Invoke-SecurityScan.ps1`
4. **Review Reports**: Check generated reports in `Report/` directory

Or use AI-assisted workflow (see `activeContext.md` for details).

## Resources

### Official Documentation

- [Chocolatey](https://chocolatey.org/)
- [PowerShell Docs](https://docs.microsoft.com/en-us/powershell/)
- [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer)
- [Pester](https://pester.dev/)
- [GitHub Copilot](https://docs.github.com/en/copilot)

### Security Resources

- [PowerShell Security Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/dev-cross-plat/security/securing-powershell)
- [CVSS Scoring System](https://www.first.org/cvss/)
- [MITRE ATT&CK](https://attack.mitre.org/)

## Security Considerations

### Important Notes

1. **Isolated Environment**: Perform analysis in development/test environments only
2. **Credential Management**: Never commit real credentials to repository
3. **Code Review**: Review generated scripts before production execution
4. **Backup**: Maintain backups before system-level changes
5. **Re-enable Protection**: Always re-enable Windows Defender after analysis

### Audit Trail

Document setup changes:

```powershell
# Create audit log
$AuditLog = @{
    Timestamp = Get-Date
    User = $env:USERNAME
    Machine = $env:COMPUTERNAME
    Changes = @(
        ""Installed Chocolatey""
        ""Installed PowerShell Core""
        ""Installed PSScriptAnalyzer""
        ""Configured Windows Defender exclusions""
    )
}

# Save audit log
$AuditLog | ConvertTo-Json | Out-File "".\setup-audit.json""
```
