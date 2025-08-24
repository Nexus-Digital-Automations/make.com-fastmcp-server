# Development Directory Organization

This directory contains development-related files that were organized from the project root to maintain a clean project structure.

## Directory Structure

### `/debug/`

Contains debug scripts, temporary test files, and development utilities:

- Debug scripts (`debug-*.js`, `debug-*.mjs`, `debug-*.ts`)
- Temporary files (`temp-*.ts`)
- Test utilities (`test-*.js`, `test-*.cjs`)
- Build and fix scripts (`build-failures.js`, `fix-*.js`, etc.)
- Development log files

### `/docs/`

Development-specific documentation and implementation guides:

- Implementation architecture documents
- Performance optimization reports
- Security analysis reports
- Strike review reports
- Refactoring guides
- Extraction summaries

### `/archive/`

Historical files and batch configurations:

- Previous batch task configurations
- Task management archives
- Deprecated configuration files

### Existing Directories

- `/guides/` - Development guides and workflows
- `/modes/` - Development mode configurations
- `/reports/` - Development reports
- `/research-reports/` - Research documentation
- `/tasks/` - Task definitions
- `/temp/` - Temporary development files

## Project Root Clean-up

The following files were moved from the project root to maintain cleanliness:

- 22 debug/temp/test files → `/debug/`
- 11 documentation files → `/docs/`
- 4 archive files → `/archive/`

Essential files remain in the project root:

- README.md, CLAUDE.md, package.json
- Docker configuration files
- Build configuration files (eslint, jest, tsconfig)
- Environment templates

This organization improves project maintainability and makes it easier for new contributors to understand the project structure.
