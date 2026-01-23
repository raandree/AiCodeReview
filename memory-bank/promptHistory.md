# Prompt History

## 2025-01-23 - Create Changelog Instructions File

**Prompt**: Please add an instruction file that tells the AI how to handle the changelog.md. The instructions should be based on https://keepachangelog.com/en/1.1.0/. Please also do some research for additional sources.

**Action Taken**:
1. Researched Keep a Changelog 1.1.0 from https://keepachangelog.com/en/1.1.0/
2. Researched Common Changelog from https://common-changelog.org/ (stricter subset of Keep a Changelog)
3. Researched CloudBees best practices for changelog management
4. Created comprehensive `.clinerules/instructions/changelog.instructions.md` with:
   - Core principles from Keep a Changelog 1.1.0 and Common Changelog
   - File format requirements (CHANGELOG.md naming, structure)
   - Version entry format with linkable versions
   - Change categories (Added, Changed, Deprecated, Removed, Fixed, Security)
   - Writing guidelines (imperative mood, self-describing entries, references, credits)
   - Unreleased section management
   - Special entries (initial release, yanked releases, notices)
   - What to include/exclude guidance
   - Antipatterns to avoid
   - Integration with semantic versioning
   - Multi-component project strategies
   - CI/CD integration examples
   - Quality checklists and templates
5. Updated `.clinerules/instructions/markdown.instructions.md` to reference the new changelog file instead of duplicating content

**Files Created**:
- `.clinerules/instructions/changelog.instructions.md`

**Files Modified**:
- `.clinerules/instructions/markdown.instructions.md` (removed duplicate changelog section, added reference to new file)

---

This file tracks all prompts and interactions with the AI agent for the AiCodeReview project.

## 2025-12-14 16:47:26 (Europe/Berlin, UTC+1:00)

**User Request**: There are language specific instructions in the folder D:\Git\AiCodeReview\.clinerules\instructions. I want this project to cover c# as well. Please study the memory bank to learn about the project. Then browse the web for coding best practices for c# and store the knowledge in a new instruction file.

**Task Completed**: 
- Read Memory Bank files to understand the project context
- Studied existing PowerShell instruction file format and structure
- Researched C# coding best practices from Microsoft Learn:
  - Secure Coding Guidelines for .NET
  - .NET Coding Conventions for C#
- Searched for additional OWASP security guidelines
- Created comprehensive C# instruction file at `.clinerules/instructions/csharp.instructions.md`

**Key Deliverables**:
1. New file: `.clinerules/instructions/csharp.instructions.md` (comprehensive 1500+ line C# coding standards document)
2. Coverage includes:
   - Naming conventions (PascalCase, camelCase, ALL_CAPS)
   - Code style and formatting (Allman brace style, 4-space indentation)
   - Type usage (language keywords vs. runtime types, var usage)
   - Modern C# features (nullable reference types, pattern matching, records, primary constructors, collection expressions)
   - String handling (interpolation, raw string literals, StringBuilder)
   - Exception handling (try-catch-finally, using statements, exception filters)
   - LINQ and collections
   - Async/await best practices
   - **Security best practices (CRITICAL)**:
     - Input validation
     - SQL injection prevention with parameterized queries
     - XSS prevention with output encoding
     - Secure password hashing (PBKDF2)
     - API key and secret management
     - Deserialization security
     - Path traversal prevention
     - CSRF protection
   - Dependency injection patterns
   - XML documentation comments
   - Testing considerations
   - Performance best practices (Span<T>, avoiding boxing, ValueTask)
   - Code analysis tools and EditorConfig settings
   - Common anti-patterns to avoid
   - File organization standards

**Sources Referenced**:
- Microsoft Learn: Secure Coding Guidelines for .NET
- Microsoft Learn: .NET Coding Conventions
- .NET Runtime coding guidelines (GitHub)
- C# Compiler (Roslyn) guidelines
- OWASP security best practices
- Existing PowerShell instruction file format

**Project Context**: This C# instruction file now extends the AiCodeReview project's capability to assess C# code in addition to PowerShell, following the same comprehensive security-first approach established for PowerShell modules.

**File Structure**: The instruction file follows the exact format pattern of the PowerShell instruction file, with `applyTo: "**/*.cs,**/*.csx"` metadata to target C# files.
