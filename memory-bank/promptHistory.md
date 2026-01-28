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

## Historical Context

This project has evolved through AI-assisted development with GitHub Copilot. Previous sessions established the core scanning framework, detection rules, and reporting system. This session focused on improving onboarding documentation by integrating legacy setup instructions.

## Date: 2026-01-16

### Prompt: Create Technical Writer & Documentation Agent

**Time**: 2026-01-16 11:30 AM (Europe/Berlin)

**User Request**:
> I want to write an Article about automatedlab. In this project are some chatmodes / agent for software development and code reviewing. I need an agent that targets writing articles for newspapers and documentation. It is important that this agent understands a given scope, repository or project, does research autonomously, writes well structured text and refers the sources. Can you create the agent definition, please?

**Context**: User needs a specialized AI agent for creating comprehensive, well-researched articles and documentation with autonomous research capabilities and proper source citation.

**Analysis Performed**:
1. Reviewed existing chatmode patterns (Software Engineer Agent v1, Security & QA Agent v1)
2. Analyzed project requirements for technical writing and journalism
3. Identified need for autonomous research workflow with web fetch capabilities
4. Designed six-phase writing process from research to publication

**Actions Taken**:

1. **Created Technical Writer & Documentation Agent v1.chatmode.md**:
   - Comprehensive agent definition with zero-confirmation autonomous workflow
   - Six-phase writing process:
     - Phase 0: Scope Understanding & Planning
     - Phase 1: Repository & Project Analysis
     - Phase 2: External Research & Verification
     - Phase 3: Outline & Structure Design
     - Phase 4: Content Creation
     - Phase 5: Editing & Quality Assurance
     - Phase 6: Publication & Documentation
   - Multiple article templates (technical blog, API docs, newspaper articles, tutorials)
   - Journalistic integrity with CRAAP source evaluation framework
   - Research best practices with source hierarchy and citation standards
   - Memory Bank integration for knowledge retention
   - Quality gates and pre-publication checklist

2. **Updated .clinerules/chatmodes/README.md**:
   - Added Technical Writer & Documentation Agent v1 to available chat modes
   - Documented agent responsibilities and key features
   - Updated "Future Chat Modes" section (moved Documentation Agent from planned to available)
   - Maintained consistent structure with existing agent documentation

**Key Features Implemented**:
- **Autonomous Research**: Repository analysis, documentation review, code inspection, web research
- **Source Citation**: Mandatory citations for all factual claims with CRAAP evaluation
- **Multiple Templates**: Technical blog posts, API documentation, newspaper articles, tutorials, comparative analysis
- **Journalistic Standards**: Accuracy, objectivity, clarity, attribution, ethics
- **Publication-Ready Output**: Professional quality content requiring no additional editing
- **Memory Bank Integration**: Documents research findings for future reuse

**Outcome**: 
✅ Successfully created a comprehensive Technical Writer & Documentation Agent that can autonomously research projects, write professional articles for various audiences, and maintain journalistic integrity with proper source citations.

**Files Created**:
- `.clinerules/chatmodes/Technical Writer & Documentation Agent v1.chatmode.md` - **NEW** (comprehensive agent definition)

**Files Modified**:
- `.clinerules/chatmodes/README.md` - Added new agent to available modes

**Value Added**:
- Project now has specialized agent for creating high-quality technical articles
- Supports multiple writing formats (newspaper, technical blog, API docs, tutorials)
- Autonomous research capabilities reduce manual research overhead
- Proper source citation ensures credibility and attribution
- Memory Bank integration enables knowledge reuse across articles

### Follow-up Enhancement: Glossary and Reference Resources

**Time**: 2026-01-16 11:37 AM (Europe/Berlin)

**User Request**:
> Perfect. There are some principles and terms that might not be known to a general audience in the Technical Writer & Documentation Agent v1.chatmode. Can you add a glossary and reference section to do help doing research?

**Context**: User requested additional educational content to help users understand technical writing concepts and provide research resources.

**Actions Taken**:

1. **Added Comprehensive Glossary (40+ Terms)**:
   - **Writing and Research Terms**: CRAAP Test, Primary/Secondary/Tertiary Sources, Attribution, Hook, Executive Summary, Progressive Disclosure, Active Voice, Call-to-Action
   - **Technical Writing Terms**: API Documentation, AST, Code Snippet, Syntax Highlighting, Mermaid Diagrams, Markdown, Front Matter, SBOM
   - **Journalistic Terms**: Lead Paragraph, Byline, Dateline, Objectivity, Fact-Checking, Plagiarism
   - **Software Development Terms**: Repository, Pull Request, CI/CD, Module, Dependency, Build System, Version Number, Changelog
   - **Security and Quality Terms**: Vulnerability, CVE, CVSS, Static Analysis, Code Coverage, Technical Debt, Linting
   - **Memory Bank Terms**: Complete definitions for all Memory Bank files

2. **Added Reference Resources Section (25+ Resources)**:
   - **Writing and Style Guides**: AP Stylebook, Chicago Manual of Style, Microsoft Writing Style Guide, Google Developer Documentation Style Guide
   - **Research and Fact-Checking**: CRAAP Test, Purdue OWL, Google Scholar, Archive.org
   - **Technical Documentation**: Write the Docs, Markdown Guide, Mermaid Documentation, DevDocs
   - **Software Development**: GitHub Docs, Stack Overflow, MDN Web Docs
   - **Security Resources**: OWASP, NIST NVD, CWE
   - **Citation and Attribution**: Citation Machine, Zotero, DOI.org
   - **Quality and Accessibility**: Hemingway Editor, Grammarly, WebAIM

3. **Added Usage Guidelines**:
   - **When Researching**: 5 key steps for effective research
   - **When Writing**: 5 best practices for content creation
   - **When Citing**: 5 citation standards and techniques

**Outcome**: 
✅ Successfully enhanced the Technical Writer Agent with comprehensive educational resources. Added 2,800+ words of glossary definitions and reference resources with URLs, descriptions, and usage guidelines.

**Files Modified**:
- `.clinerules/chatmodes/Technical Writer & Documentation Agent v1.chatmode.md` - Enhanced with glossary and references (now ~12,300 words total)

**Value Added**:
- Demystifies technical writing and journalistic concepts for general audiences
- Provides direct links to authoritative resources for research
- Includes tools for grammar checking, readability analysis, and citation management
- Usage guidelines ensure proper application of resources
- Educational content supports both novice and experienced technical writers

**User Feedback**: "excellent"

---

## Notes

- All AI interactions should be logged here with date, prompt, analysis, actions, and outcomes
- This audit trail helps future AI sessions understand project evolution
- Maintains transparency in AI-assisted development process
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
