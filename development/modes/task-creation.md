# TASK CREATION Mode Instructions

You are in TASK CREATION mode, responsible for intelligently analyzing the project and creating new tasks ONLY when necessary.

## CRITICAL REQUIREMENTS

**MINIMUM TASK CREATION**: If the project is not complete, you MUST create at least **4 tasks or subtasks**. If the project needs fewer than 4 tasks to complete, create as many as needed until completion.

**INTELLIGENT DECISION-MAKING**: Don't automatically create tasks. Analyze whether task creation is actually needed based on project state.

## IMMEDIATE ACTIONS

1. **Read TODO.json** from the project root
2. **Analyze project completeness** - assess if the current tasks provide adequate coverage
3. **Determine creation strategy** - decide between new tasks, subtasks, or no action
4. **Apply minimum requirement** - create at least 4 tasks/subtasks if project incomplete

## DECISION FRAMEWORK

### When to Create NEW STANDALONE TASKS
✅ **Create new tasks for:**
- Missing core functionality or features
- Technical debt that needs addressing
- Integration with external systems
- Performance optimization needs
- Security implementations
- Documentation gaps
- Testing coverage improvements
- New requirements or user stories

### When to Create SUBTASKS
✅ **Break existing tasks into subtasks when:**
- Current task is larger than 4 hours
- Task requires multiple skill sets
- Natural decomposition points exist
- Can be parallelized effectively
- Different testing strategies are needed
- Complex integration points exist

### When to CREATE NOTHING
✅ **Skip task creation if:**
- Current tasks adequately cover project scope
- All major functionality is planned
- Project roadmap is complete and well-defined
- No significant gaps or technical debt exist
- Tasks are appropriately sized (2-4 hours each)

### FALLBACK BEHAVIOR
If you determine that NO new tasks or subtasks are needed:
1. **Mark current task as completed** if it's actually done
2. **Proceed to the next pending task** in the TODO.json
3. **Continue normal execution workflow**

## Task Decomposition Strategies

### 1. Vertical Slicing (User Value)
Break features into complete, shippable increments:
```
User Dashboard → Basic layout → Real-time updates → Filtering → Export → Customization
```

### 2. Horizontal Slicing (Technical Layers)
Split by architectural components:
```
API Integration → Research docs → Data models → API client → Caching → Error handling → UI
```

### 3. Risk-First Decomposition
Tackle unknowns first:
```
Payment System → Research providers → Test sandbox → Design architecture → Basic flow → Refunds → Subscriptions
```

## Subtask Guidelines

### Ideal Task Size
- **2-4 hours**: One focused work session
- **Single Responsibility**: Does one thing well
- **Clear Success Criteria**: Measurable outcomes
- **Minimal Dependencies**: Can work in parallel

### Examples
✅ **Good**: "Create login endpoint with JWT generation"
❌ **Too Large**: "Implement entire authentication system"
❌ **Too Small**: "Create a variable"

## PROJECT ANALYSIS GUIDE

### Assess Project Completeness
Before creating tasks, evaluate:
- **Functional Coverage**: Are all core features planned?
- **Technical Debt**: What needs refactoring or improvement?
- **Testing Gaps**: Where is test coverage insufficient?
- **Documentation Needs**: What's missing or outdated?
- **Performance Issues**: Any optimization opportunities?
- **Security Concerns**: What security measures are needed?
- **Integration Points**: Are external system connections handled?

### Identify Task Gaps
Look for missing tasks in these areas:
- **User-facing features** not yet implemented
- **API endpoints** or data models needed
- **Database migrations** or schema changes
- **Authentication/authorization** components
- **Error handling** and logging improvements
- **Deployment and DevOps** requirements
- **Monitoring and observability** setup

## When to Create Tasks

### Create RESEARCH Tasks For:
- Unknown external APIs
- New technologies/frameworks
- Complex architectural decisions
- Performance optimization needs
- Security implementation patterns

### Split Tasks When:
- Different skill sets required
- Can be parallelized
- Natural checkpoint exists
- Different testing strategies needed

### Keep Together When:
- Tightly coupled logic
- Shared context critical
- Overhead exceeds benefit
- Single atomic change required

## Common Templates

### API Integration
1. Research API capabilities and limits
2. Design data model mappings
3. Build authentication flow
4. Create basic CRUD operations
5. Add error handling and retries
6. Implement rate limiting
7. Add caching layer
8. Write integration tests

### UI Feature
1. Design component structure
2. Build static components
3. Add state management
4. Connect to backend
5. Add loading/error states
6. Implement optimistic updates
7. Add animations/transitions
8. Write component tests

## Creating Tasks Using TaskManager CLI

**CRITICAL**: Always use the TaskManager CLI to create tasks via bash commands. Do NOT manually edit TODO.json.

### CLI Command Usage

Create tasks using the `task-cli.js` command-line tool:

```bash
# Create a development task
node task-cli.js create \
  --title "Implement user authentication system" \
  --description "Create login/logout functionality with JWT tokens" \
  --mode "DEVELOPMENT" \
  --priority "high" \
  --dependencies "src/auth/,package.json" \
  --important-files "src/auth/login.js,README.md" \
  --success-criteria "Users can log in,JWT tokens generated,Logout clears session" \
  --estimate "4 hours"
```

### Batch Task Creation

When creating multiple related tasks, create a JSON file and use batch mode:

```bash
# Create batch-tasks.json file
cat > batch-tasks.json << 'EOF'
[
  {
    "title": "Set up test framework",
    "description": "Configure Jest for unit testing",
    "mode": "TESTING",
    "priority": "high",
    "dependencies": ["package.json"],
    "important_files": ["package.json"],
    "success_criteria": ["Jest is configured and running", "Sample test passes"]
  },
  {
    "title": "Write unit tests for auth module",
    "description": "Create comprehensive tests for authentication functions",
    "mode": "TESTING",
    "priority": "high",
    "dependencies": ["src/auth/", "jest.config.js"],
    "important_files": ["src/auth/login.js", "src/auth/middleware.js"],
    "success_criteria": ["95%+ test coverage for auth module", "All tests pass"]
  }
]
EOF

# Create all tasks from the batch file
node task-cli.js batch --file batch-tasks.json
```

### Task Status Management

```bash
# Update task status to in progress
node task-cli.js status task-1 in_progress

# Mark task as completed
node task-cli.js status task-1 completed

# Check current task details
node task-cli.js current

# List all pending tasks
node task-cli.js list --status pending
```

### Review Strike Failure Response

When review strikes fail, use the CLI to create remediation tasks:

#### Strike 1 Failure (Build Issues)
```bash
# Create build setup task
node task-cli.js create \
  --title "Fix build configuration" \
  --description "Resolve build errors and setup proper build process" \
  --mode "DEVELOPMENT" \
  --priority "high" \
  --dependencies "package.json" \
  --important-files "package.json,tsconfig.json" \
  --success-criteria "Project builds without errors,All dependencies installed"

# Create dependency installation task  
node task-cli.js create \
  --title "Install missing dependencies" \
  --description "Add all required project dependencies" \
  --mode "DEVELOPMENT" \
  --priority "high" \
  --dependencies "package.json" \
  --success-criteria "All dependencies in package.json,npm install succeeds"
```

#### Strike 2 Failure (Lint Issues)
```bash
# Create linting setup task
node task-cli.js create \
  --title "Set up linting tools" \
  --description "Install and configure ESLint/Prettier for code quality" \
  --mode "DEVELOPMENT" \
  --priority "high" \
  --dependencies "package.json" \
  --important-files "package.json,.eslintrc" \
  --success-criteria "ESLint configured,Linting rules active,Zero lint errors"

# Create code style fixes task
node task-cli.js create \
  --title "Fix code style violations" \
  --description "Resolve all linting and code style issues" \
  --mode "REFACTORING" \
  --priority "high" \
  --dependencies "src/" \
  --success-criteria "All lint errors resolved,Consistent code formatting"
```

#### Strike 3 Failure (Test Coverage)
```bash
# Create test framework setup
node task-cli.js create \
  --title "Set up Jest testing framework" \
  --description "Install and configure Jest for unit testing" \
  --mode "TESTING" \
  --priority "high" \
  --dependencies "package.json" \
  --important-files "package.json,jest.config.js" \
  --success-criteria "Jest installed,Basic test passes,Coverage reporting enabled"

# Create comprehensive test tasks for each module
node task-cli.js create \
  --title "Write unit tests for taskManager" \
  --description "Create comprehensive tests for lib/taskManager.js" \
  --mode "TESTING" \
  --priority "high" \
  --dependencies "lib/taskManager.js" \
  --important-files "lib/taskManager.js" \
  --success-criteria "95%+ test coverage,All methods tested,Edge cases covered"
```

## JSON Structure for TODO.json

### Task Object Structure
```json
{
  "id": "task_[number]",
  "title": "Brief descriptive title",
  "description": "Detailed explanation of what needs to be done",
  "mode": "DEVELOPMENT|TESTING|RESEARCH|DEBUGGING|REFACTORING",
  "priority": "high|medium|low",
  "status": "pending",
  "success_criteria": [
    "Specific measurable outcome 1",
    "Specific measurable outcome 2"
  ],
  "dependencies": ["config.yaml", "src/api/"],        // Files/dirs needed for context
  "estimate": "2-4 hours",                            // Optional
  "important_files": ["README.md", "src/auth.js"],   // Critical files to read first
  "requires_research": false                          // Optional
}
```

### Understanding Dependencies vs Important Files

**`dependencies`**: Files, directories, or resources that Claude Code needs to understand before starting the task. These provide essential context for the work.

**`important_files`**: Critical files that should be read immediately when the task begins. These are the most essential files for understanding the task requirements.

### Dependencies Parameter Usage

The `dependencies` array should include:

#### Configuration Files
```json
"dependencies": [
  "package.json",        // For Node.js projects
  "requirements.txt",    // For Python projects  
  "Cargo.toml",         // For Rust projects
  "pom.xml",            // For Java projects
  "composer.json"       // For PHP projects
]
```

#### Key Directories
```json
"dependencies": [
  "src/",               // Main source code
  "lib/",               // Library code
  "config/",            // Configuration files
  "docs/",              // Documentation
  "tests/",             // Test files
  "migrations/"         // Database migrations
]
```

#### Related Features/Modules
```json
"dependencies": [
  "src/auth/",          // Authentication module
  "src/api/routes/",    // API routing logic
  "src/components/",    // UI components
  "src/utils/helpers.js" // Utility functions
]
```

### Important Files Parameter Usage

The `important_files` array should contain the most critical files to read first:

#### Project Documentation
```json
"important_files": [
  "README.md",          // Project overview
  "ARCHITECTURE.md",    // System design
  "API.md",            // API documentation
  "DEPLOYMENT.md"      // Deployment guide
]
```

#### Core Implementation Files
```json
"important_files": [
  "src/main.js",        // Application entry point
  "src/app.py",         // Main application file
  "src/server.rs",      // Server implementation
  "src/index.html"      // Main HTML template
]
```

#### Configuration and Setup
```json
"important_files": [
  ".env.example",       // Environment variables
  "docker-compose.yml", // Container setup
  "webpack.config.js",  // Build configuration
  "tsconfig.json"       // TypeScript config
]
```

### Best Practices for File Specifications

#### Use Relative Paths
```json
// ✅ Good
"dependencies": ["src/auth/", "config/database.yml"]

// ❌ Avoid absolute paths
"dependencies": ["/home/user/project/src/auth/"]
```

#### Be Specific When Possible
```json
// ✅ Good - Specific files
"important_files": ["src/auth/login.js", "src/auth/middleware.js"]

// ✅ Also good - Focused directories
"dependencies": ["src/auth/", "src/middleware/"]

// ❌ Too broad
"dependencies": ["src/", "**/*.js"]
```

#### Language-Agnostic Examples
```json
// Python Project
"dependencies": ["requirements.txt", "src/", "tests/"],
"important_files": ["README.md", "main.py", "config.py"]

// Rust Project  
"dependencies": ["Cargo.toml", "src/", "tests/"],
"important_files": ["README.md", "src/main.rs", "src/lib.rs"]

// Go Project
"dependencies": ["go.mod", "cmd/", "internal/"],
"important_files": ["README.md", "main.go", "internal/app/"]

// React Project
"dependencies": ["package.json", "src/", "public/"],
"important_files": ["README.md", "src/App.js", "src/index.js"]
```

### Task Status Updates
- **pending**: Not started
- **in_progress**: Currently working
- **completed**: Finished successfully
- **blocked**: Waiting on dependencies

## Quick Reference

### Priority Matrix
| Priority | Impact | Urgency | Examples |
|----------|--------|---------|----------|
| High | Critical path | Immediate | Security fixes, blocking bugs |
| Medium | Important | Soon | New features, optimizations |
| Low | Nice to have | Eventually | UI polish, minor improvements |

### Dependency Types
- **Technical**: Code/API dependencies
- **Data**: Database schema, migrations
- **Team**: Cross-team handoffs
- **External**: Third-party services

### Success Checklist
Before creating tasks, ensure:
- [ ] Clear acceptance criteria defined
- [ ] Dependencies explicitly mapped
- [ ] 2-4 hour scope maintained
- [ ] Success metrics are measurable
- [ ] Priority aligns with project goals
- [ ] Mode correctly assigned

## Task Creation Mindset

Think strategically about:
- **Value Delivery**: What provides the most user/business value?
- **Risk Mitigation**: What could block progress?
- **Parallelism**: What can teams work on simultaneously?
- **Integration Points**: Where do components connect?
- **Incremental Progress**: How to show continuous improvement?

## Quick CLI Reference for Claude Code

### Most Common Commands
```bash
# Create a basic task
node task-cli.js create --title "Task Title" --description "Description" --mode "DEVELOPMENT" --priority "high"

# Mark task completed  
node task-cli.js status <task-id> completed

# List pending tasks
node task-cli.js list --status pending

# Get current task info
node task-cli.js current

# Show help
node task-cli.js help
```

### Review Strike Response Commands
```bash
# When any strike fails, create remediation tasks:
node task-cli.js create \
  --title "Fix [issue]" \
  --description "Resolve [specific problem]" \
  --mode "DEVELOPMENT|TESTING|REFACTORING" \
  --priority "high" \
  --dependencies "[relevant-files]" \
  --success-criteria "[specific-outcomes]"
```

## FINAL REMINDERS

**MINIMUM REQUIREMENT**: Create at least 4 tasks/subtasks if the project is incomplete. If fewer than 4 tasks are needed to complete the project, create only what's necessary.

**FALLBACK**: If no task creation is needed, proceed to the next pending task in the workflow.

Remember: Create tasks that move the project forward in meaningful, testable increments, but only when actually needed.