# Security Scanner Tests

## Overview

This directory contains the Pester test suite for the PowerShell Security Scanner. The tests validate scanner functionality, rule loading, pattern matching, and report generation.

## Test File

**File**: `SecurityScanner.Tests.ps1`

**Framework**: Pester 5.x

**Coverage**:

- Scanner initialization
- Rule loading and validation
- PowerShell file parsing
- AST pattern matching
- Context-aware filtering
- Report generation
- Error handling

## Prerequisites

### Install Pester

```powershell
# Install latest Pester version
Install-Module -Name Pester -Force -SkipPublisherCheck

# Verify installation
Get-Module -Name Pester -ListAvailable
```

## Running Tests

### Run All Tests

```powershell
# From repository root
Invoke-Pester -Path .\tests\SecurityScanner.Tests.ps1 -Output Detailed
```

### Run Specific Test Suite

```powershell
# Run only rule loading tests
Invoke-Pester -Path .\tests\SecurityScanner.Tests.ps1 -TagFilter 'RuleLoading' -Output Detailed

# Run only pattern matching tests
Invoke-Pester -Path .\tests\SecurityScanner.Tests.ps1 -TagFilter 'PatternMatching' -Output Detailed
```

### Run with Code Coverage

```powershell
$config = New-PesterConfiguration
$config.Run.Path = '.\tests\SecurityScanner.Tests.ps1'
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = '.\scanner\Invoke-SecurityScan.ps1'
$config.Output.Verbosity = 'Detailed'

Invoke-Pester -Configuration $config
```

## Test Structure

### Test Suites

#### 1. Scanner Initialization

- Tests scanner script exists
- Validates scanner can be loaded
- Checks for required functions

#### 2. Rule Loading

- Validates detection rule file format
- Checks all required rule properties
- Verifies CVSS scores are valid
- Ensures no duplicate rule IDs

#### 3. File Parsing

- Tests PowerShell file AST parsing
- Validates error handling for invalid files
- Checks support for various file types (.ps1, .psm1, .psd1)

#### 4. Pattern Matching

- Tests detection of known vulnerable patterns
- Validates rule matching logic
- Checks severity classification
- Tests pattern-specific rules

#### 5. Context Analysis

- Tests false positive filtering
- Validates PowerShell-specific context awareness
- Checks DSC pattern recognition
- Tests credential handling patterns

#### 6. Report Generation

- Tests report file creation
- Validates report structure
- Checks Markdown formatting
- Verifies finding details are complete

## Test Tags

Tests are tagged for selective execution:

| Tag | Purpose |
|-----|---------|
| `RuleLoading` | Rule file validation tests |
| `PatternMatching` | Detection pattern tests |
| `ContextAnalysis` | Context filtering tests |
| `ReportGeneration` | Report output tests |
| `ErrorHandling` | Error condition tests |
| `Integration` | End-to-end tests |

### Run by Tag

```powershell
# Run only integration tests
Invoke-Pester -Path .\tests\SecurityScanner.Tests.ps1 -TagFilter 'Integration'

# Exclude error handling tests
Invoke-Pester -Path .\tests\SecurityScanner.Tests.ps1 -ExcludeTagFilter 'ErrorHandling'
```

## Test Data

### Sample Files

Tests use inline PowerShell code samples:

```powershell
BeforeAll {
    $vulnerableCode = @'
    function Test-Vulnerable {
        Invoke-Expression $userInput
    }
