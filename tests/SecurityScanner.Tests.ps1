<#
.SYNOPSIS
    Pester tests for PowerShell Security Scanner

.DESCRIPTION
    Validates the security scanner functionality, rule matching,
    and context-aware analysis capabilities.
#>

BeforeAll {
    # Import the scanner script
    $scannerPath = Join-Path $PSScriptRoot '..\scanner\Invoke-SecurityScan.ps1'
    
    # Dot-source helper functions for testing
    . $scannerPath
    
    # Load security rules
    $rulesPath = Join-Path $PSScriptRoot '..\scanner\rules\SecurityDetectionRules.psd1'
    $script:rulesData = Import-PowerShellDataFile -Path $rulesPath
    $script:rules = $script:rulesData.Rules
}

Describe 'Security Scanner - Core Functionality' {
    
    Context 'AST Parsing' {
        It 'Should parse valid PowerShell file' {
            # Create temp test file
            $testFile = New-TemporaryFile
            '@{ Name = "Test" }' | Out-File $testFile -Encoding UTF8
            
            $result = Get-ASTNodes -FilePath $testFile.FullName
            
            $result | Should -Not -BeNullOrEmpty
            $result.AST | Should -Not -BeNullOrEmpty
            $result.Tokens | Should -Not -BeNullOrEmpty
            
            Remove-Item $testFile -Force
        }
        
        It 'Should handle parse errors gracefully' {
            $testFile = New-TemporaryFile
            'function Test { # Missing closing brace' | Out-File $testFile -Encoding UTF8
            
            $result = Get-ASTNodes -FilePath $testFile.FullName
            
            $result | Should -Not -BeNullOrEmpty
            $result.Errors.Count | Should -BeGreaterThan 0
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'Rule Loading' {
        It 'Should load security rules successfully' {
            $script:rules | Should -Not -BeNullOrEmpty
            $script:rules.Count | Should -BeGreaterThan 0
        }
        
        It 'Should have required rule properties' {
            foreach ($rule in $script:rules) {
                $rule.Id | Should -Not -BeNullOrEmpty
                $rule.Name | Should -Not -BeNullOrEmpty
                $rule.Severity | Should -Not -BeNullOrEmpty
                $rule.Category | Should -Not -BeNullOrEmpty
                $rule.Description | Should -Not -BeNullOrEmpty
                $rule.Remediation | Should -Not -BeNullOrEmpty
                $rule.CVSS | Should -BeOfType [double]
            }
        }
        
        It 'Should have valid severity levels' {
            $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Info')
            foreach ($rule in $script:rules) {
                $rule.Severity | Should -BeIn $validSeverities
            }
        }
    }
}

Describe 'Security Scanner - Rule Detection' {
    
    Context 'PS001 - Invoke-Expression Detection' {
        It 'Should detect Invoke-Expression usage' {
            $testFile = New-TemporaryFile
            'Invoke-Expression "Get-Process"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS001' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            $findings[0].Rule.Id | Should -Be 'PS001'
            
            Remove-Item $testFile -Force
        }
        
        It 'Should not detect other commands' {
            $testFile = New-TemporaryFile
            'Get-Process' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS001' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -Be 0
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'PS009 - Hardcoded Credentials Detection' {
        It 'Should detect password in string' {
            $testFile = New-TemporaryFile
            '$password = "MySecretPassword123"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS009' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'PS010 - ConvertTo-SecureString Detection' {
        It 'Should detect -AsPlainText parameter' {
            $testFile = New-TemporaryFile
            'ConvertTo-SecureString -String "password" -AsPlainText -Force' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS010' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            $findings[0].Rule.Id | Should -Be 'PS010'
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'PS014 - Weak Hash Algorithm Detection' {
        It 'Should detect MD5 usage' {
            $testFile = New-TemporaryFile
            '$hash = "MD5"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS014' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            
            Remove-Item $testFile -Force
        }
        
        It 'Should detect SHA1 usage' {
            $testFile = New-TemporaryFile
            '$algorithm = "SHA1"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS014' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'PS021 - Unsafe Deserialization Detection' {
        It 'Should detect Import-Clixml usage' {
            $testFile = New-TemporaryFile
            'Import-Clixml -Path "data.xml"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS021' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            $findings[0].Rule.Id | Should -Be 'PS021'
            
            Remove-Item $testFile -Force
        }
    }
}

Describe 'Security Scanner - Context Analysis' {
    
    Context 'High Entropy String Filtering' {
        It 'Should filter out module GUID' {
            $testFile = New-TemporaryFile
            'GUID = "9b8c7d6e-5f4a-3b2c-1d0e-9f8e7d6c5b4a"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS028' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            if ($findings.Count -gt 0) {
                $filtered = Invoke-ContextAnalysis -Findings $findings -ParseResult $parseResult
                $filtered.Count | Should -Be 0
            }
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'Credential Logging Filtering' {
        It 'Should allow username logging' {
            $testFile = New-TemporaryFile
            'Write-Verbose "Processing user: $userName"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS012' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            
            if ($findings.Count -gt 0) {
                $filtered = Invoke-ContextAnalysis -Findings $findings -ParseResult $parseResult
                $filtered.Count | Should -Be 0
            }
            
            Remove-Item $testFile -Force
        }
        
        It 'Should flag password logging' {
            $testFile = New-TemporaryFile
            'Write-Verbose "Password: $password"' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $rule = $script:rules | Where-Object { $_.Id -eq 'PS012' }
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules @($rule) -FilePath $testFile.FullName
            $filtered = Invoke-ContextAnalysis -Findings $findings -ParseResult $parseResult
            
            $filtered.Count | Should -BeGreaterThan 0
            
            Remove-Item $testFile -Force
        }
    }
}

Describe 'Security Scanner - Report Generation' {
    
    Context 'Report Creation' {
        It 'Should generate report with findings' {
            $testFindings = @(
                @{
                    Rule = @{
                        Id          = 'PS001'
                        Name        = 'Test Rule'
                        Severity    = 'High'
                        Category    = 'Test'
                        Description = 'Test description'
                        Remediation = 'Test remediation'
                        CVSS        = 7.5
                    }
                    File = 'test.ps1'
                    Line = 1
                    Code = 'Test code'
                }
            )
            
            $outputPath = Join-Path $TestDrive 'Reports'
            New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
            
            $report = New-SecurityReport -Findings $testFindings -ModuleName 'TestModule' -OutputPath $outputPath
            
            $report | Should -Not -BeNullOrEmpty
            $report.Total | Should -Be 1
            $report.High | Should -Be 1
            Test-Path $report.Path | Should -Be $true
        }
        
        It 'Should group findings by severity' {
            $testFindings = @(
                @{
                    Rule = @{
                        Id          = 'PS001'
                        Name        = 'Critical Rule'
                        Severity    = 'Critical'
                        Category    = 'Test'
                        Description = 'Test'
                        Remediation = 'Test'
                        CVSS        = 9.0
                    }
                    File = 'test.ps1'
                    Line = 1
                    Code = 'Test'
                },
                @{
                    Rule = @{
                        Id          = 'PS002'
                        Name        = 'High Rule'
                        Severity    = 'High'
                        Category    = 'Test'
                        Description = 'Test'
                        Remediation = 'Test'
                        CVSS        = 7.0
                    }
                    File = 'test.ps1'
                    Line = 2
                    Code = 'Test'
                }
            )
            
            $outputPath = Join-Path $TestDrive 'Reports'
            $report = New-SecurityReport -Findings $testFindings -ModuleName 'TestModule' -OutputPath $outputPath
            
            $report.Critical | Should -Be 1
            $report.High | Should -Be 1
            $report.Total | Should -Be 2
        }
    }
}

Describe 'Security Scanner - Edge Cases' {
    
    Context 'Empty Files' {
        It 'Should handle empty file' {
            $testFile = New-TemporaryFile
            '' | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules $script:rules -FilePath $testFile.FullName
            
            $findings.Count | Should -Be 0
            
            Remove-Item $testFile -Force
        }
    }
    
    Context 'Large Files' {
        It 'Should handle file with multiple findings' {
            $testFile = New-TemporaryFile
            $content = @'
Invoke-Expression "test1"
$password = "secret123"
ConvertTo-SecureString -String "pwd" -AsPlainText -Force
Import-Clixml -Path "data.xml"
'@
            $content | Out-File $testFile -Encoding UTF8
            
            $parseResult = Get-ASTNodes -FilePath $testFile.FullName
            $findings = Get-SecurityFindings -ParseResult $parseResult -Rules $script:rules -FilePath $testFile.FullName
            
            $findings.Count | Should -BeGreaterThan 0
            
            Remove-Item $testFile -Force
        }
    }
}
