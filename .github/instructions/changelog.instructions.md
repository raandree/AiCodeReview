---
applyTo: "**/CHANGELOG.md,**/CHANGELOG,**/changelog.md,**/HISTORY.md,**/NEWS.md,**/RELEASES.md"
---

# Changelog Best Practices and Standards

This document provides comprehensive guidelines for creating and maintaining changelogs, based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), [Common Changelog](https://common-changelog.org/), and industry best practices.

## Core Principles

### What is a Changelog?

A changelog is a file containing a curated, chronologically ordered list of notable changes for each version of a project. Its purpose is to make it easier for users and contributors to see precisely what notable changes have been made between each release.

**Key Characteristics:**
- **Human-Readable**: Written for humans, not machines
- **Curated Content**: Notable changes only, not a git log dump
- **Chronological Order**: Latest version first
- **Version-Linked**: Each entry corresponds to a released version
- **Consistent Format**: Follows a standard structure for easy navigation

### Why Keep a Changelog?

- **Communication**: Conveys noteworthy changes to users and contributors
- **Discoverability**: Provides a single location for change information
- **Decision Support**: Helps users decide whether to upgrade
- **Trust Building**: Demonstrates project maturity and professionalism
- **Time Saving**: Saves readers from digging through commits or documentation

### Who Needs a Changelog?

Everyone who uses or contributes to the project:
- **End Users**: To understand what changed and why
- **Developers**: To assess upgrade impact and breaking changes
- **Contributors**: To see their work acknowledged
- **Project Managers**: To track progress and communicate releases
- **Security Teams**: To identify security-related changes

## Guiding Principles

### From Keep a Changelog 1.1.0

1. **Changelogs are for humans, not machines**
2. **There should be an entry for every single version**
3. **The same types of changes should be grouped**
4. **Versions and sections should be linkable**
5. **The latest version comes first**
6. **The release date of each version is displayed**
7. **Mention whether you follow Semantic Versioning**

### From Common Changelog

1. **Communicate the impact of changes**
2. **Sort content by importance**
3. **Skip content that isn't important**
4. **Link each change to further information**
5. **Use imperative mood for change descriptions**

## File Format

### Filename

**MUST** be `CHANGELOG.md` (uppercase, with `.md` extension).

**Alternatives** (less common, avoid if possible):
- `HISTORY.md`
- `NEWS.md`
- `RELEASES.md`
- `changelog.md` (lowercase)

**Rationale**: `CHANGELOG.md` is the most widely recognized convention and easiest for users to find.

### File Structure

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Upcoming feature descriptions

## [1.2.0] - 2025-01-15

### Added
- New feature description

### Fixed
- Bug fix description

## [1.1.0] - 2025-01-01

### Changed
- Changed behavior description

[Unreleased]: https://github.com/owner/repo/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/owner/repo/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/owner/repo/releases/tag/v1.1.0
```

## Version Entry Format

### Version Header

**Format**: `## [VERSION] - DATE`

```markdown
## [1.2.3] - 2025-01-15
```

**Requirements:**
- Version without "v" prefix in changelog (matches semver)
- Date in ISO 8601 format: `YYYY-MM-DD`
- Version should link to release or compare view
- Use reference-style links for cleaner source

**Examples:**
```markdown
## [1.2.3] - 2025-01-15
## [2.0.0] - 2025-02-01
## [1.0.0-rc.1] - 2025-01-10
```

### Linkable Versions

Use reference-style links at the bottom of the file:

```markdown
## [1.2.0] - 2025-01-15

<!-- Content -->

[1.2.0]: https://github.com/owner/repo/releases/tag/v1.2.0
```

**For GitHub Projects:**
- Link to GitHub Releases for full context
- Or link to compare view showing changes since previous version

```markdown
[1.2.0]: https://github.com/owner/repo/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/owner/repo/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/owner/repo/releases/tag/v1.0.0
```

## Change Categories

### Standard Categories (Keep a Changelog)

Use these categories in this order:

| Category | Purpose | Version Impact |
|----------|---------|----------------|
| `Added` | New features | MINOR |
| `Changed` | Changes in existing functionality | MINOR or MAJOR |
| `Deprecated` | Soon-to-be removed features | MINOR |
| `Removed` | Removed features | MAJOR |
| `Fixed` | Bug fixes | PATCH |
| `Security` | Vulnerability fixes | PATCH or MINOR |

### Simplified Categories (Common Changelog)

For stricter changelogs, use only:

| Category | Purpose |
|----------|---------|
| `Changed` | Changes in existing functionality |
| `Added` | New functionality |
| `Removed` | Removed functionality |
| `Fixed` | Bug fixes |

**Note**: Deprecations go under `Changed`, security fixes under `Fixed` with clear labeling.

### Category Best Practices

```markdown
## [2.0.0] - 2025-01-15

### Removed
- **Breaking:** drop support of Node.js 16 ([#123](link))

### Changed
- **Breaking:** change default timeout from 30s to 60s ([#124](link))
- Deprecate `oldMethod()` in favor of `newMethod()` ([#125](link))

### Added
- Add `newFeature()` function for enhanced processing ([#126](link))

### Fixed
- Fix memory leak in long-running processes ([#127](link))
- **Security:** fix SQL injection vulnerability in query builder ([#128](link))
```

## Writing Change Entries

### Use Imperative Mood

Write changes as if giving commands. Start with a present-tense verb.

**Do:**
```markdown
- Add support for OAuth 2.0 authentication
- Fix memory leak in connection pooling
- Remove deprecated `legacyMethod()` function
- Bump minimum Python version to 3.9
```

**Don't:**
```markdown
- Added support for OAuth 2.0 authentication
- Fixed memory leak in connection pooling
- Removed the deprecated legacyMethod() function
- We bumped the minimum Python version to 3.9
```

### Self-Describing Entries

Each entry must be self-describing, as if no category heading exists.

**Do:**
```markdown
### Added
- Add `write()` method for file operations
- Support CentOS 8 as deployment target
- Document the `read()` method parameters
```

**Don't:**
```markdown
### Added
- `write()` method
- Support of CentOS
- Documentation for `read()`
```

### Include References

Always link to commits, issues, or pull requests for context.

**Format**: Change description followed by references in parentheses.

```markdown
- Fix infinite loop in parser ([#194](https://github.com/owner/repo/issues/194))
- Add caching layer for improved performance ([`a1b2c3d`](https://github.com/owner/repo/commit/a1b2c3d))
```

**Reference Types:**

| Type | Format |
|------|--------|
| Issue/PR | `([#123](link))` |
| Commit | `([`a1b2c3d`](link))` |
| External Issue | `([JIRA-456](link))` |
| Multiple | `([#123](link), [#124](link))` |

### Credit Contributors

Acknowledge contributors after references.

```markdown
- Fix memory leak ([#194](link)) (Alice Smith)
- Add OAuth support ([#195](link)) (Bob Jones, Carol White)
```

**With semicolon separator for clarity:**
```markdown
- Fix memory leak ([#194](link), [#195](link); Alice Smith, Bob Jones)
```

### Mark Breaking Changes

Prefix breaking changes with `**Breaking:**` in bold.

```markdown
### Changed
- **Breaking:** rename `userName` parameter to `identity` ([#200](link))
- **Breaking:** change return type from string to object ([#201](link))

### Removed
- **Breaking:** remove deprecated `legacyAuth()` function ([#202](link))
```

**Ordering**: List breaking changes first within each category.

## Unreleased Section

### Purpose

The `[Unreleased]` section tracks changes that will be included in the next release.

**Benefits:**
- Shows users what's coming in upcoming releases
- Simplifies release process (move entries to new version)
- Ensures changes aren't forgotten during release

### Format

```markdown
## [Unreleased]

### Added
- New feature in development

### Fixed
- Bug fix pending release

## [1.0.0] - 2025-01-01
...
```

### Release Process

When releasing a new version:

1. **Rename** `[Unreleased]` to `[VERSION] - DATE`
2. **Create** new empty `[Unreleased]` section
3. **Update** version links
4. **Verify** all entries are complete

**Before:**
```markdown
## [Unreleased]

### Added
- New authentication module
```

**After:**
```markdown
## [Unreleased]

## [2.0.0] - 2025-01-15

### Added
- New authentication module
```

## Special Entries

### Initial Release

For the first release, use a notice:

```markdown
## [1.0.0] - 2025-01-01

_Initial release._
```

Or with content:

```markdown
## [1.0.0] - 2025-01-01

_Initial stable release._

### Added
- Core functionality for user management
- REST API endpoints
- CLI interface
```

### Yanked Releases

For releases that were pulled due to bugs or security issues:

```markdown
## [1.0.5] - 2025-01-10 [YANKED]

_This release was yanked due to a critical security vulnerability. See [#234](link) for details._

### Fixed
- Performance improvements
```

**Alternative (Common Changelog style):**
```markdown
## [1.0.5] - 2025-01-10

_This release was never published to npm due to security issues ([#234](link))._
```

### Notices

Use notices (italicized single sentences) for special circumstances:

```markdown
## [2.0.0] - 2025-01-15

_If you are upgrading: please see [UPGRADING.md](UPGRADING.md)._

### Changed
- **Breaking:** change API authentication method
```

## What to Include

### Always Include

- ✅ New features and functionality
- ✅ Changes to existing behavior
- ✅ Deprecated features (with deprecation warnings)
- ✅ Removed features (especially breaking changes)
- ✅ Bug fixes affecting users
- ✅ Security vulnerability fixes
- ✅ Changes to supported environments (OS, runtime versions)
- ✅ Breaking changes of any kind
- ✅ Significant refactorings (may have side effects)
- ✅ New documentation (if feature was undocumented)

### Never Include

- ❌ Internal code refactoring without user impact
- ❌ Development dependency updates
- ❌ CI/CD configuration changes
- ❌ Code style/formatting changes
- ❌ Comment updates
- ❌ Test-only changes (unless fixing test bugs)
- ❌ Dotfile changes (.gitignore, .editorconfig)
- ❌ Minor documentation typo fixes

### Include with Care

- ⚠️ Dependency updates (only if significant or security-related)
- ⚠️ Performance improvements (only if measurable and notable)
- ⚠️ Documentation improvements (only if substantial)

## Antipatterns to Avoid

### Commit Log Dumps

**Problem**: Using `git log` as a changelog.

**Why It's Bad**:
- Full of noise (merge commits, WIP commits, formatting changes)
- Not curated for user relevance
- Difficult to understand impact
- Commits serve different purpose than changelog entries

**Bad:**
```markdown
- Merge branch 'feature/auth' into develop
- fix typo
- WIP
- Update dependencies
- Fix linting errors
- Add TODO comment
```

**Good:**
```markdown
- Add OAuth 2.0 authentication ([#150](link))
```

### Verbatim PR Titles

**Problem**: Copying Pull Request titles without curation.

**Why It's Bad**:
- PR titles are written for contributors, not users
- Often lack context for external users
- May use internal terminology

**Bad:**
```markdown
- json-parser 8.0.2 is fixed (#295)
- doc: fix dead link to xml-entities (#296)
- Bump actions/checkout from v2.3.3 to v2.3.4 (#293)
```

**Good:**
```markdown
### Changed
- Upgrade `json-parser` to fix parsing edge cases ([#295](link))

### Fixed
- Correct dead link in XML entities documentation ([#296](link))
```

### Ignoring Deprecations

**Problem**: Not documenting deprecations before removals.

**Why It's Bad**:
- Users can't prepare for breaking changes
- Makes upgrades painful and unexpected
- Damages trust in the project

**Good Practice**:
1. Deprecate in version X (MINOR)
2. Document migration path
3. Remove in version X+1 or later (MAJOR)

```markdown
## [1.5.0] - 2025-01-01

### Deprecated
- Deprecate `oldMethod()`, use `newMethod()` instead. Will be removed in 2.0.0.

## [2.0.0] - 2025-06-01

### Removed
- **Breaking:** remove `oldMethod()` (deprecated since 1.5.0)
```

### Confusing Dates

**Problem**: Using regional date formats.

**Why It's Bad**:
- `01/02/2025` means different things in different regions
- Creates ambiguity and confusion

**Always Use**: ISO 8601 format `YYYY-MM-DD`

```markdown
## [1.0.0] - 2025-01-15
```

### Inconsistent Updates

**Problem**: Only documenting some changes.

**Why It's Bad**:
- Users can't trust the changelog as source of truth
- Important changes may be missed
- Creates false sense of completeness

**Solution**: Update changelog for every notable change, every release.

## Integration with Versioning

### Semantic Versioning Alignment

| Change Type | SemVer Impact | Changelog Category |
|-------------|--------------|-------------------|
| Breaking change | MAJOR | Removed, Changed |
| New feature | MINOR | Added |
| Deprecation | MINOR | Deprecated, Changed |
| Bug fix | PATCH | Fixed |
| Security fix | PATCH/MINOR | Security, Fixed |

### Version Synchronization

Ensure consistency across:
- Module manifest version
- Changelog version header
- Git tag
- Release notes

See `versioning.instructions.md` for detailed synchronization requirements.

### Automated Validation

```powershell
# Validate changelog has entry for current version
$manifestVersion = (Import-PowerShellDataFile './Module.psd1').ModuleVersion
$changelogContent = Get-Content './CHANGELOG.md' -Raw

if ($changelogContent -notmatch "\[$manifestVersion\]") {
    Write-Error "CHANGELOG.md missing entry for version $manifestVersion"
    exit 1
}

# Validate Unreleased section exists
if ($changelogContent -notmatch "## \[Unreleased\]") {
    Write-Error "CHANGELOG.md missing [Unreleased] section"
    exit 1
}
```

## Multi-Component Projects

### Single Changelog Strategy

For small to medium projects, keep one `CHANGELOG.md` in the root.

**Pros**:
- Single source of truth
- Easy to find
- Simple maintenance

**Cons**:
- Can become very long
- May mix unrelated changes

### Component Changelogs Strategy

For large projects with distinct components:

```
project/
├── CHANGELOG.md           # High-level project changelog
├── packages/
│   ├── core/
│   │   └── CHANGELOG.md   # Core package changelog
│   └── cli/
│       └── CHANGELOG.md   # CLI package changelog
```

**Pros**:
- Focused, relevant changes per component
- Easier to maintain independently
- Better for monorepos

**Cons**:
- Users must check multiple files
- Risk of inconsistency

### Version-Based Organization

For extremely long histories:

```
docs/
├── changelogs/
│   ├── CHANGELOG-2.x.md
│   ├── CHANGELOG-1.x.md
│   └── CHANGELOG-0.x.md
└── CHANGELOG.md           # Current major version
```

## CI/CD Integration

### Changelog Validation

**GitHub Actions Example:**

```yaml
name: Validate Changelog

on:
  pull_request:
    paths:
      - 'CHANGELOG.md'
      - 'src/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check changelog updated
        run: |
          if ! git diff --name-only origin/main | grep -q "CHANGELOG.md"; then
            echo "Warning: CHANGELOG.md not updated"
            exit 1
          fi
          
      - name: Validate format
        run: |
          if ! grep -q "## \[Unreleased\]" CHANGELOG.md; then
            echo "Error: Missing [Unreleased] section"
            exit 1
          fi
```

### Automated Release Notes

**GitHub Release from Changelog:**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Extract changelog
        id: changelog
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          NOTES=$(sed -n "/## \[$VERSION\]/,/## \[/p" CHANGELOG.md | head -n -1)
          echo "notes<<EOF" >> $GITHUB_OUTPUT
          echo "$NOTES" >> $GITHUB_OUTPUT
          echo "EOF" >> $GITHUB_OUTPUT
          
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          body: ${{ steps.changelog.outputs.notes }}
```

## Quality Checklist

### Before Committing

- [ ] Entry is in the `[Unreleased]` section
- [ ] Correct category used (Added/Changed/Fixed/etc.)
- [ ] Entry uses imperative mood (starts with verb)
- [ ] Entry is self-describing
- [ ] References included (PR, issue, or commit)
- [ ] Breaking changes marked with `**Breaking:**`
- [ ] Contributors credited (if applicable)
- [ ] Entry ends with appropriate punctuation

### Before Release

- [ ] All entries reviewed for clarity
- [ ] Version number matches manifest
- [ ] Date in ISO 8601 format
- [ ] Version links updated
- [ ] No empty categories
- [ ] Breaking changes documented
- [ ] Migration guides linked (for major versions)
- [ ] `[Unreleased]` section moved to new version

### Periodic Review

- [ ] Format consistent throughout file
- [ ] All version links working
- [ ] Categories in correct order
- [ ] No antipatterns present
- [ ] Aligns with semantic versioning
- [ ] Contributors properly credited

## Templates

### Minimal Changelog Template

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - YYYY-MM-DD

_Initial release._

[Unreleased]: https://github.com/OWNER/REPO/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/OWNER/REPO/releases/tag/v1.0.0
```

### Full Changelog Template

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [1.0.0] - YYYY-MM-DD

_Initial release._

### Added
- Feature 1 description ([#1](link))
- Feature 2 description ([#2](link))

[Unreleased]: https://github.com/OWNER/REPO/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/OWNER/REPO/releases/tag/v1.0.0
```

### Release Entry Template

```markdown
## [X.Y.Z] - YYYY-MM-DD

_Optional notice about upgrade guide or special instructions._

### Removed
- **Breaking:** removed feature ([#XXX](link)) (Contributor)

### Changed
- **Breaking:** changed behavior ([#XXX](link))
- Changed feature ([#XXX](link))

### Added
- New feature ([#XXX](link))

### Deprecated
- Deprecated feature ([#XXX](link))

### Fixed
- Bug fix ([#XXX](link))

### Security
- Security fix ([#XXX](link))
```

## Resources and References

### Official Standards

- **Keep a Changelog 1.1.0**: [https://keepachangelog.com/en/1.1.0/](https://keepachangelog.com/en/1.1.0/)
- **Common Changelog**: [https://common-changelog.org/](https://common-changelog.org/)
- **Semantic Versioning 2.0.0**: [https://semver.org/](https://semver.org/)

### Related Tools

- **Conventional Changelog**: [https://github.com/conventional-changelog/conventional-changelog](https://github.com/conventional-changelog/conventional-changelog)
- **Hallmark**: [https://github.com/vweevers/hallmark](https://github.com/vweevers/hallmark)
- **auto-changelog**: [https://github.com/CookPete/auto-changelog](https://github.com/CookPete/auto-changelog)
- **release-please**: [https://github.com/googleapis/release-please](https://github.com/googleapis/release-please)

### Related Instruction Files

- **versioning.instructions.md**: Version synchronization and semantic versioning
- **markdown.instructions.md**: Markdown formatting standards

### Example Changelogs

- **Level**: [https://github.com/Level/level/blob/master/CHANGELOG.md](https://github.com/Level/level/blob/master/CHANGELOG.md)
- **Keep a Changelog**: [https://github.com/olivierlacan/keep-a-changelog/blob/main/CHANGELOG.md](https://github.com/olivierlacan/keep-a-changelog/blob/main/CHANGELOG.md)

---

**Document Version:** 1.0.0  
**Last Updated:** 2025-01-23  
**Based On:** Keep a Changelog 1.1.0, Common Changelog  
**Maintained By:** AI Instruction Framework