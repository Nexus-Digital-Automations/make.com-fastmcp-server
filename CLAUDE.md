# Claude Code Project Assistant - Streamlined Guide

## ⚡⚡⚡ ABSOLUTE CRITICAL MANDATE ⚡⚡⚡

# 🚨🚨🚨 INSTANTLY CREATE TASK FOR ANY USER REQUEST 🚨🚨🚨
# 🚨🚨🚨 NO EXCEPTIONS - NO DELAYS - NO ANALYSIS FIRST 🚨🚨🚨
# 🚨🚨🚨 USER SAYS ANYTHING → CREATE TASK IMMEDIATELY 🚨🚨🚨

**⚡ THE MOMENT USER MAKES ANY REQUEST:**
**⚡ STOP EVERYTHING AND CREATE TASK USING TASKMANAGER API**
**⚡ CATEGORY REQUIRED - USE: research, missing-feature, bug, enhancement, etc.**
**⚡ THEN AND ONLY THEN PROCEED WITH WORK**

## 🚨 CRITICAL COMPLIANCE PROTOCOLS

**PRIORITY ORDER:**
1. **⚡ INSTANT TASK CREATION ⚡** - Create task for ANY user request FIRST
2. **User Instructions** - Direct commands take highest priority  
3. **Hook Feedback** - Address system responses immediately
4. **Linting Error Feedback** - Fix all linting errors before proceeding
5. **TaskManager Integration** - Use TaskManager API for all task operations
6. **Evidence-Based Validation** - Validate all work with concrete evidence

**CORE RULES:**
- **⚡ INSTANTLY CREATE TASK ⚡** for ANY user request using TaskManager API
- **VALIDATE BEFORE COMPLETION** - Provide evidence of all validation checks
- **FIX ERRORS IMMEDIATELY** - Create categorized tasks for all detected issues

## 🚨 ERROR HANDLING PROTOCOL

**MANDATORY ERROR RESPONSE:**
1. **DETECT** any error → **INSTANTLY CREATE CATEGORIZED TASK**:
   - Linter errors → `category: 'linter-error'` 
   - Build failures → `category: 'build-error'`
   - Runtime errors → `category: 'error'`
   - Test failures → `category: 'test-error'`
2. **ATTEMPT IMMEDIATE FIX** (< 2 minutes) OR work on task
3. **VERIFY** fix and document resolution

**FORBIDDEN:** Ignoring errors, suppressing messages, or implementing workarounds

## 🚨🚨🚨 ABSOLUTE MANDATE: NEVER MASK ISSUES 🚨🚨🚨

# ⛔⛔⛔ ZERO TOLERANCE FOR ISSUE MASKING ⛔⛔⛔
# ⛔⛔⛔ NO BYPASSING - NO WORKAROUNDS - NO SUPPRESSION ⛔⛔⛔
# ⛔⛔⛔ ALWAYS FIX ROOT CAUSE - NEVER HIDE PROBLEMS ⛔⛔⛔

**🚨 ABSOLUTE PROHIBITION - NEVER EVER EVER:**
- **❌ MASK validation errors** - Fix the validation logic, don't bypass it
- **❌ SUPPRESS error messages** - Fix the error, don't hide it
- **❌ BYPASS quality checks** - Fix the code to pass checks
- **❌ IMPLEMENT WORKAROUNDS** - Fix the root cause, don't work around it
- **❌ HIDE FAILING TESTS** - Fix the tests or code, don't disable them
- **❌ IGNORE LINTING ERRORS** - Fix the linting violations
- **❌ COMMENT OUT ERROR HANDLING** - Fix the underlying issue
- **❌ ADD try/catch TO SILENCE ERRORS** - Fix what's causing the error
- **❌ DISABLE WARNINGS OR CHECKS** - Address what's causing the warnings

**🚨 MANDATORY ROOT CAUSE ANALYSIS:**
When ANY issue is detected:
1. **IDENTIFY** the true root cause of the problem
2. **ANALYZE** why the issue exists in the first place  
3. **FIX** the underlying architectural or logic problem
4. **VALIDATE** that the fix resolves the core issue
5. **DOCUMENT** what was wrong and how it was properly fixed

**🚨 EXAMPLES OF FORBIDDEN MASKING:**
```bash
# ❌ FORBIDDEN - Masking validation
if (!validationResult.isValid) return { success: true }; // HIDING PROBLEM

# ✅ REQUIRED - Fixing validation
if (!validationResult.isValid) {
    // Fix the root cause that made validation fail
    fixValidationIssue(validationResult.errors);
    // Re-run validation to ensure it passes
}

# ❌ FORBIDDEN - Suppressing errors  
try { riskyOperation(); } catch (e) { /* ignore */ } // HIDING PROBLEM

# ✅ REQUIRED - Handling errors properly
try { 
    riskyOperation(); 
} catch (e) { 
    // Fix what's causing riskyOperation to fail
    fixUnderlyingIssue(e);
    // Re-attempt after fixing root cause
}
```

**🚨 ZERO TOLERANCE ENFORCEMENT:**
- **ANY ATTEMPT TO MASK** = Immediate task creation to fix properly
- **ANY WORKAROUND SUGGESTION** = Must be replaced with root cause fix
- **ANY ERROR SUPPRESSION** = Must be replaced with proper error resolution
- **ANY VALIDATION BYPASS** = Must be replaced with validation fix

**🚨 QUALITY GATE PRINCIPLE:**
Every error, warning, or issue is a **QUALITY GATE** that must be **PROPERLY ADDRESSED**:
- Issues exist to **PROTECT CODE QUALITY**
- Masking issues **DEGRADES SYSTEM RELIABILITY** 
- Root cause fixes **IMPROVE LONG-TERM STABILITY**
- Proper solutions **PREVENT FUTURE PROBLEMS**

**⚡ WHEN ISSUE DETECTED → INSTANT ROOT CAUSE ANALYSIS → PROPER FIX → NEVER MASK**

**🚨 ADDITIONAL MASKING PATTERNS TO AVOID:**
- **❌ SILENT FAILURES** - Never allow operations to fail silently without proper error reporting
- **❌ GENERIC ERROR HANDLING** - Don't catch all errors with generic handlers that obscure root causes  
- **❌ CONFIGURATION BYPASSES** - Don't disable strict mode or safety checks to avoid errors
- **❌ DEPENDENCY DOWNGRADES** - Don't downgrade dependencies to avoid compatibility issues
- **❌ FEATURE FLAGS TO HIDE BUGS** - Don't use feature flags to permanently hide broken functionality
- **❌ DOCUMENTATION WORKAROUNDS** - Don't document known issues as "features" instead of fixing them

**✅ PROPER ISSUE RESOLUTION APPROACH:**
1. **DETECT** → Identify the exact nature and scope of the issue
2. **INVESTIGATE** → Trace the issue to its root cause in the codebase or architecture  
3. **ANALYZE** → Understand why the issue exists and what allows it to occur
4. **DESIGN** → Plan a solution that eliminates the root cause permanently
5. **IMPLEMENT** → Execute the proper fix with appropriate testing
6. **VALIDATE** → Verify the fix resolves the issue without introducing new problems
7. **DOCUMENT** → Record what was wrong, why it occurred, and how it was properly resolved

**🛡️ QUALITY ASSURANCE MANDATE:**
This mandate exists to ensure **SUSTAINABLE CODE QUALITY** and **LONG-TERM SYSTEM RELIABILITY**. Every avoided shortcut and properly fixed issue contributes to a more robust, maintainable, and trustworthy codebase.

## 🚨 MANDATORY THINKING & VALIDATION

**THINKING LEVELS:** Use maximum beneficial thinking for complexity:
- **ULTRATHINK**: System architecture, task planning, priority evaluation
- **THINK HARD**: Complex refactoring, debugging, task management  
- **MANDATORY**: All task operations (creation, categorization, completion)

**VALIDATION PROTOCOL:** Evidence-based completion required:
1. **RUN validation commands** - show all outputs
2. **TEST functionality manually** - demonstrate it works  
3. **VERIFY requirements met** - list each satisfied requirement
4. **PROVIDE EVIDENCE** - paste command outputs proving success

## 🚨 MANDATORY POST-COMPLETION VALIDATION

**ABSOLUTE REQUIREMENT**: IMMEDIATELY run lint and type checks after completing ANY task that modified code files

**🔴 CRITICAL VALIDATION SEQUENCE:**
1. **Complete task implementation**
2. **Run lint and type checks** on modified files/folders  
3. **Fix any errors** before marking task complete
4. **Provide validation evidence** - show command outputs

**🚨 VALIDATION FAILURE PROTOCOL:**
- **Linting errors** → Create `category: 'linter-error'` task IMMEDIATELY
- **Type errors** → Create `category: 'error'` task IMMEDIATELY  
- **DO NOT mark complete** until ALL validation passes


## 🚨 TASK CATEGORY & PRIORITY SYSTEM

**CATEGORY-BASED PRIORITY SYSTEM:**

Tasks are now organized by **specific categories** instead of generic "low", "medium", "high" priorities. The system **automatically sorts** tasks by category urgency:

### 🔴 CRITICAL ERRORS (Rank 1-4) - Highest Priority - Block All Work
1. **🔴 linter-error** - Code style, formatting, or quality issues detected by linters - **HIGHEST PRIORITY**
2. **🔥 build-error** - Compilation, bundling, or build process failures  
3. **⚠️ start-error** - Application startup, initialization, or runtime launch failures
4. **❌ error** - General runtime errors, exceptions, or system failures

### 🟡 IMPLEMENTATION PRIORITY (Rank 5-9) - Core Development Work
5. **🆕 missing-feature** - Required functionality that needs to be implemented
6. **🐛 bug** - Incorrect behavior or functionality that needs fixing
7. **✨ enhancement** - Improvements to existing features or functionality
8. **♻️ refactor** - Code restructuring, optimization, or technical debt reduction
9. **📚 documentation** - Documentation updates, comments, or API documentation

### 🟢 MAINTENANCE PRIORITY (Rank 10) - Administrative Work
10. **🧹 chore** - Maintenance tasks, cleanup, or administrative work

### 🔬 RESEARCH PRIORITY (Rank 11) - Investigation Work
11. **🔬 research** - Investigation, exploration, or learning tasks

### 🔴 LOWEST PRIORITY (Rank 12-18) - All Testing Related - LAST PRIORITY
12. **🧪 missing-test** - Test coverage gaps or missing test cases - **LOWEST PRIORITY**
13. **⚙️ test-setup** - Test environment configuration, test infrastructure setup
14. **🔄 test-refactor** - Refactoring test code, improving test structure
15. **📊 test-performance** - Performance tests, load testing, stress testing
16. **🔍 test-linter-error** - Linting issues specifically in test files - **LOWEST PRIORITY**
17. **🚫 test-error** - Failing tests, test framework issues - **LOWEST PRIORITY** 
18. **🔧 test-feature** - New testing features, test tooling improvements - **LOWEST PRIORITY**

**AVAILABLE CATEGORIES (Must be specified when creating tasks):**
- **linter-error, build-error, start-error, error** (ranks 1-4) - Critical errors (highest priority)
- **missing-feature, bug, enhancement, refactor, documentation** (ranks 5-9) - Implementation work
- **chore** (rank 10) - Maintenance
- **research** (rank 11) - Investigation work
- **missing-test, test-setup, test-refactor, test-performance, test-linter-error, test-error, test-feature** (ranks 12-18) - Testing (lowest priority)

**THREE-LEVEL AUTO-SORTING HIERARCHY:**
1. **PRIMARY: Category Rank** - Linter Errors (1) → Build Errors (2) → Implementation (5-9) → Research (11) → Testing (12-18)
2. **SECONDARY: Priority Value** - Critical (4) → High (3) → Medium (2) → Low (1)
3. **TERTIARY: Creation Time** - Newer tasks first within same category and priority

**CREATING TASKS WITH CATEGORIES (CATEGORY REQUIRED):**
```bash
# Category is MANDATORY - must be specified explicitly
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'Fix ESLint errors', category: 'linter-error', mode: 'DEVELOPMENT'}).then(id => console.log('Created:', id));"

# Research task (after implementation tasks)
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'Research authentication patterns', category: 'research', mode: 'DEVELOPMENT'}).then(id => console.log('Created:', id));"

# Testing task (lowest priority)  
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'Add unit tests', category: 'missing-test', mode: 'DEVELOPMENT'}).then(id => console.log('Created:', id));"

# Bug fix with explicit priority override
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: 'Urgent bug fix', category: 'bug', priority: 'critical', mode: 'DEVELOPMENT'}).then(id => console.log('Created:', id));"
```

## 🚨 TASK MANAGEMENT PROTOCOLS

**INSTANT TASK CREATION - ALWAYS CREATE TASKS FOR:**
- **EVERY USER REQUEST** - no matter how simple or complex
- **EVERY USER INSTRUCTION** - any time user tells you to do something  
- **EVERY ISSUE USER POINTS OUT** - bugs, problems, suggestions, observations
- **ANY opportunity for improvement** discovered during work
- **ALL errors detected** (linting, testing, runtime, build failures)
- **Performance issues** (slow responses, memory leaks)
- **Security vulnerabilities** (auth issues, data exposure)
- **Code quality opportunities** (refactoring needs, missing docs)
- **Missing functionality** (incomplete features, edge cases)
- **Integration issues** (API failures, dependency conflicts)

**🚨 GOLDEN RULE**: User says ANYTHING requiring action OR asks ANY question → **INSTANTLY CREATE TASK THE VERY FIRST SECOND** → Check existing tasks → Modify OR create → Execute

## 🚨 MANDATORY CATEGORY-BASED TASK CREATION PROTOCOL

**🚨 ABSOLUTE MANDATE: CATEGORY DETECTION = IMMEDIATE TASK CREATION**

**THE INSTANT YOU DETECT ANY OF THESE CATEGORIES IN USER COMMUNICATION OR CODE ANALYSIS - CREATE TASK IMMEDIATELY:**

### 🔴 **CRITICAL ERROR CATEGORIES - CREATE TASK IN FIRST SECOND:**
- **🔴 LINTER-ERROR SPOTTED** → INSTANTLY CREATE `category: 'linter-error'` TASK
- **🔥 BUILD-ERROR DETECTED** → INSTANTLY CREATE `category: 'build-error'` TASK  
- **⚠️ START-ERROR FOUND** → INSTANTLY CREATE `category: 'start-error'` TASK
- **❌ RUNTIME ERROR SEEN** → INSTANTLY CREATE `category: 'error'` TASK

### 🔬 **RESEARCH OPPORTUNITIES - CREATE TASK IN FIRST SECOND:**
- **🔬 INVESTIGATION NEEDED** → INSTANTLY CREATE `category: 'research'` TASK (AFTER IMPLEMENTATION)
- **🔍 EXPLORATION REQUIRED** → INSTANTLY CREATE `category: 'research'` TASK (AFTER IMPLEMENTATION)
- **📊 ANALYSIS OPPORTUNITY** → INSTANTLY CREATE `category: 'research'` TASK (AFTER IMPLEMENTATION)
- **🧭 LEARNING REQUIRED** → INSTANTLY CREATE `category: 'research'` TASK (AFTER IMPLEMENTATION)

### 🆕 **FEATURE OPPORTUNITIES - CREATE TASK IN FIRST SECOND:**
- **🆕 MISSING FUNCTIONALITY** → INSTANTLY CREATE `category: 'missing-feature'` TASK
- **✨ ENHANCEMENT SPOTTED** → INSTANTLY CREATE `category: 'enhancement'` TASK
- **🐛 BUG DISCOVERED** → INSTANTLY CREATE `category: 'bug'` TASK

### 🧪 **TESTING OPPORTUNITIES - CREATE TASK IN FIRST SECOND (LOWEST PRIORITY):**
- **🧪 MISSING TESTS** → INSTANTLY CREATE `category: 'missing-test'` TASK
- **🔍 TEST LINTER ERRORS** → INSTANTLY CREATE `category: 'test-linter-error'` TASK
- **🚫 FAILING TESTS** → INSTANTLY CREATE `category: 'test-error'` TASK
- **🔧 TEST IMPROVEMENTS** → INSTANTLY CREATE `category: 'test-feature'` TASK

### 📚 **MAINTENANCE OPPORTUNITIES - CREATE TASK IN FIRST SECOND:**
- **♻️ REFACTORING NEEDED** → INSTANTLY CREATE `category: 'refactor'` TASK
- **📚 DOCUMENTATION GAPS** → INSTANTLY CREATE `category: 'documentation'` TASK
- **🧹 CLEANUP REQUIRED** → INSTANTLY CREATE `category: 'chore'` TASK

**🚨 CATEGORY DETECTION TRIGGERS - NO EXCEPTIONS:**
- User mentions ANY error, issue, or problem → **INSTANT TASK CREATION**
- Code analysis reveals ANY quality issue → **INSTANT TASK CREATION**
- You spot ANY opportunity for improvement → **INSTANT TASK CREATION**
- ANY missing functionality is identified → **INSTANT TASK CREATION**
- ANY research need is discovered → **INSTANT TASK CREATION**
- ANY test coverage gap is found → **INSTANT TASK CREATION**

**🚨 MANDATORY TASK CREATION COMMANDS - USE THESE IMMEDIATELY:**

**⚠️ CRITICAL BASH ESCAPING RULE:**
**ALWAYS USE SINGLE QUOTES FOR NODE -E COMMANDS TO AVOID SHELL ESCAPING ERRORS**

```bash
# ✅ CORRECT - Use single quotes to prevent bash escaping errors
# INSTANT LINTER ERROR TASK
node -e 'const TaskManager = require("./lib/taskManager"); const tm = new TaskManager("./TODO.json"); tm.createTask({title: "Fix [specific linter error]", category: "linter-error", mode: "DEVELOPMENT", priority: "critical"}).then(id => console.log("URGENT LINTER TASK:", id));'

# INSTANT RESEARCH TASK (AFTER IMPLEMENTATION TASKS)
node -e 'const TaskManager = require("./lib/taskManager"); const tm = new TaskManager("./TODO.json"); tm.createTask({title: "Research [specific topic]", category: "research", mode: "DEVELOPMENT", priority: "high"}).then(id => console.log("RESEARCH TASK:", id));'

# INSTANT BUG TASK
node -e 'const TaskManager = require("./lib/taskManager"); const tm = new TaskManager("./TODO.json"); tm.createTask({title: "Fix [specific bug]", category: "bug", mode: "DEVELOPMENT", priority: "high"}).then(id => console.log("URGENT BUG TASK:", id));'

# INSTANT MISSING FEATURE TASK
node -e 'const TaskManager = require("./lib/taskManager"); const tm = new TaskManager("./TODO.json"); tm.createTask({title: "Implement [specific feature]", category: "missing-feature", mode: "DEVELOPMENT", priority: "high"}).then(id => console.log("FEATURE TASK:", id));'
```

**🚨 ZERO DELAY ENFORCEMENT:**
- **NO ANALYSIS PARALYSIS** - Create task FIRST, analyze SECOND
- **NO HESITATION** - Category spotted = Immediate task creation
- **NO WAITING** - User mentions issue = Task created within 1 second
- **NO EXCEPTIONS** - Every category opportunity gets a task

**WORKFLOW:**
1. **INSTANT TASK CREATION** - THE VERY FIRST SECOND you detect ANY category opportunity
2. **EVALUATE EXISTING TASKS** - Check if current tasks can handle the request
3. **MODIFY OR CREATE** - Update existing task (preferred) OR create new categorized task
4. **AUTO-PRIORITIZE** - Category-based sorting handles priority automatically  
5. **EXECUTE** - Begin working with thinking-driven approach

**CONTINUOUS EVALUATION:**
- **MANDATORY THINKING** for all task operations (creation, categorization, reordering, completion)
- **INSTANT CATEGORY ASSESSMENT** - Detect category patterns in real-time
- **AUTOMATIC TASK CREATION** for every category opportunity discovered
- **PROACTIVE SCANNING** - Actively look for category opportunities in all communications

**CATEGORY ASSIGNMENT RULES:**
- **ALWAYS specify category** when creating tasks - NO EXCEPTIONS
- **USE SPECIFIC CATEGORIES** - prefer 'linter-error' over 'error', 'missing-test' over 'test'  
- **CREATE IMMEDIATELY** upon category detection - NO delay, NO analysis first
- **TRUST CATEGORY HIERARCHY** - Let automatic sorting handle prioritization
- **INCLUDE RESEARCH REPORTS** - Always add relevant reports from development/reports/ and development/research-reports/ to important_files

## 🚨 CRITICAL BASH COMMAND ESCAPING PROTOCOL

**🔴 ABSOLUTE RULE: ALWAYS USE SINGLE QUOTES FOR NODE -E COMMANDS**

**BASH ESCAPING ERRORS TO AVOID:**
- **❌ SyntaxError: Unexpected end of input** - caused by improper quote escaping
- **❌ SyntaxError: missing ) after argument list** - caused by shell interfering with JavaScript
- **❌ Unexpected eof** - caused by unmatched quotes in complex commands

**✅ CORRECT BASH ESCAPING PATTERNS:**
```bash
# ✅ ALWAYS USE SINGLE QUOTES FOR OUTER SHELL, DOUBLE QUOTES FOR INNER JavaScript
node -e 'const TaskManager = require("./lib/taskManager"); tm.createTask({title: "Task name"}).then(id => console.log("Created:", id));'

# ✅ ALTERNATIVE: Create temporary script file for complex commands
echo 'console.log("Complex script with quotes");' > temp.js && node temp.js && rm temp.js

# ✅ ALTERNATIVE: Use != instead of !== to avoid bash escaping issues
node -e 'if (value != null) console.log("Safe comparison");'
```

**❌ FORBIDDEN BASH PATTERNS:**
```bash
# ❌ NEVER use double quotes for outer shell with complex JavaScript
node -e "const tm = require('./lib/taskManager'); tm.createTask({title: 'Task'});"

# ❌ NEVER mix quote types that cause shell conflicts
node -e "script with !== operator"  # Bash escapes the ! character
```

**🚨 MANDATORY BASH TROUBLESHOOTING:**
If you encounter syntax errors in node -e commands:
1. **SWITCH TO SINGLE QUOTES** for the outer shell command
2. **USE DOUBLE QUOTES** for all strings inside the JavaScript
3. **CREATE TEMP FILE** if command is too complex for inline execution
4. **VERIFY QUOTE BALANCE** - ensure all quotes are properly paired

## 🚨 MANDATORY CONCURRENT SUBAGENT DEPLOYMENT - NEVER WORK ALONE

# 🔥🔥🔥 ABSOLUTE SUBAGENT DEPLOYMENT MANDATE 🔥🔥🔥
# 🔥🔥🔥 DEPLOY UP TO 10 CONCURRENT SUBAGENTS SIMULTANEOUSLY 🔥🔥🔥  
# 🔥🔥🔥 NEVER WORK WITHOUT MAXIMUM CONCURRENT SUBAGENTS 🔥🔥🔥

**🚨 CRITICAL DEPLOYMENT RULES - NO EXCEPTIONS:**
- **⚡ INSTANTLY DEPLOY UP TO 10 CONCURRENT SUBAGENTS** for ANY task beyond trivial operations
- **⚡ ALL SUBAGENTS WORK SIMULTANEOUSLY** - never sequential, always parallel execution
- **⚡ FAILURE TO USE CONCURRENT SUBAGENTS = INCOMPLETE EXECUTION** 
- **⚡ SINGLE-AGENT WORK IS FORBIDDEN** except for the most trivial tasks

**MANDATORY**: Deploy **UP TO 10 CONCURRENT SUBAGENTS** in parallel for ALL complex work. **ALWAYS USE AS MANY CONCURRENT SUBAGENTS AS POSSIBLE**. **FAILURE TO USE CONCURRENT SUBAGENTS = FAILED EXECUTION**

### 🎯 Synchronized Completion Protocol
**CRITICAL**: All subagents must finish within same timeframe for optimal efficiency

**COMPLETION SYNCHRONIZATION STRATEGY:**
1. **Pre-Flight Load Balancing**: Distribute work complexity evenly across all 10 subagents
2. **Coordinated Start**: All subagents begin execution simultaneously 
3. **Progress Checkpoints**: 25%, 50%, 75% completion status reporting to main agent
4. **Dynamic Rebalancing**: Redistribute workload if any subagent falls behind schedule
5. **Synchronized Quality Gates**: All subagents run validation simultaneously in final phase
6. **Coordinated Completion**: Main agent waits for ALL subagents before marking task complete

### 🚀 Universal Subagent Deployment
**MANDATORY SPECIALIZATIONS BY MODE:**

- **DEVELOPMENT**: Frontend, Backend, Database, DevOps, Security specialists
- **TESTING**: Unit Test, Integration Test, E2E Test, Performance Test, Security Test specialists  
- **RESEARCH**: Technology Evaluator, API Analyst, Performance Researcher, Security Auditor, UX Researcher
- **DEBUGGING**: Error Analysis, Performance Profiling, Security Audit, Code Quality, System Integration specialists
- **REFACTORING**: Architecture, Performance, Code Quality, Documentation, Testing specialists

### 🔄 Coordination & Timing Controls
**LOAD BALANCING STRATEGIES:**
- **Equal Complexity Distribution**: Each subagent receives ~10% of total work complexity (10 subagents)
- **Dependency-Aware Scheduling**: Sequential tasks distributed to maintain parallel execution
- **Failure Recovery**: If any subagent fails, redistribute work to remaining agents
- **Completion Buffer**: Build in 10-15% time buffer for synchronization delays

**INTEGRATION CHECKPOINTS:**
- **Context Sharing**: Critical information passed between subagents at each checkpoint
- **Quality Verification**: Each subagent validates outputs meet perfection standards
- **Conflict Resolution**: Main agent resolves any conflicting recommendations
- **Final Integration**: All subagent outputs merged into cohesive deliverable

**DEPLOYMENT PATTERN:** Think → Map Work Distribution → Balance Complexity → Deploy UP TO 10 Agents Simultaneously → Monitor Progress → Synchronize Completion

**🔥 CONCURRENT SUBAGENT DEPLOYMENT RULES - ABSOLUTE REQUIREMENTS:**
- **⚡ ALWAYS MAXIMIZE CONCURRENT SUBAGENTS**: Use as many subagents as possible up to 10 when appropriate for the task complexity
- **⚡ SCALE BY COMPLEXITY**: More complex tasks = MORE concurrent subagents (up to 10 maximum running simultaneously)
- **⚡ MANDATORY PARALLEL EXECUTION**: ALL subagents work concurrently, NEVER sequential, ALWAYS simultaneous execution
- **⚡ CONCURRENT TASK DISTRIBUTION**: Distribute work across ALL available subagents running at the same time
- **⚡ SIMULTANEOUS COMPLETION TARGET**: All concurrent subagents should finish within similar timeframes
- **⚡ DEPLOY WHEN BENEFICIAL**: Use concurrent subagents when the task can be meaningfully parallelized

## 🚨 CONTEXT MANAGEMENT

**Always check for ABOUT.md files** before editing code (current directory, parent directories, subdirectories)

## 🚨 RESEARCH REPORTS INTEGRATION & DEPENDENCY SYSTEM

**🔴 ABSOLUTE MANDATE: ALWAYS READ RELEVANT RESEARCH REPORTS FIRST**

**MANDATORY**: Always check `development/reports/` and `development/research-reports/` for relevant research reports before starting any task

**CRITICAL PROTOCOL**:
1. **SCAN development/reports/** AND **development/research-reports/** for related reports
2. **ABSOLUTELY REQUIRED**: ADD relevant reports to important_files when creating tasks  
3. **READ reports FIRST** before implementing to leverage existing research
4. **NEVER START IMPLEMENTATION** without reading applicable research reports
5. **INCLUDE REPORTS AS IMPORTANT FILES** in all related TODO.json tasks

**🚨 RESEARCH REPORT REQUIREMENTS:**
- **ALWAYS include relevant research reports** in task important_files
- **READ research reports BEFORE implementation** - never skip this step
- **LEVERAGE existing research** to inform implementation decisions
- **REFERENCE research findings** in implementation approach
- **UPDATE research reports** if new findings discovered during implementation

## 🚨 MANDATORY RESEARCH TASK CREATION FOR COMPLEX WORK

**ABSOLUTE REQUIREMENT**: Create research tasks as dependencies for any complex implementation work

**CREATE RESEARCH TASKS IMMEDIATELY FOR:**
- **🌐 External API integrations** - Research API documentation, authentication, rate limits, best practices
- **🗄️ Database schema changes** - Research data models, migrations, performance implications
- **🔐 Authentication/Security systems** - Research security patterns, encryption, OAuth flows
- **📊 Data processing algorithms** - Research algorithms, performance characteristics, trade-offs  
- **🧩 Complex architectural decisions** - Research design patterns, frameworks, scalability
- **⚡ Performance optimization** - Research profiling techniques, bottlenecks, optimization strategies
- **🔗 Third-party service integrations** - Research service capabilities, limitations, alternatives
- **📱 UI/UX implementations** - Research design patterns, accessibility, user experience best practices

**DEPENDENCY CREATION PROTOCOL:**
```bash
# 1. Create dependency task FIRST (any category)
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: '[Dependency task]', description: '[details]', category: '[any-category]'}).then(id => console.log('Dependency task:', id));"

# 2. Create dependent task with dependency
node -e "const TaskManager = require('./lib/taskManager'); const tm = new TaskManager('./TODO.json'); tm.createTask({title: '[Dependent task]', description: '[implementation description]', category: '[any-category]', dependencies: ['DEPENDENCY_TASK_ID']}).then(id => console.log('Dependent task:', id));"
```

**🚨 DEPENDENCY SYSTEM BEHAVIOR:**
- **Dependencies ALWAYS come first** in task queue regardless of category
- **Any task can depend on any other task** - not limited to research dependencies
- **Dependent tasks are BLOCKED** until all dependencies complete  
- **Task claiming will redirect** to dependency tasks with instructions
- **Use TaskManager API** for automatic dependency detection and guidance

## 🚨 CODING STANDARDS

**MANDATORY**: All agents MUST follow the standardized coding conventions defined in the global CLAUDE.md at `/Users/jeremyparker/.claude/CLAUDE.md`.

These standards ensure consistency across large codebases and multi-agent collaboration, covering:
- **JavaScript/TypeScript**: Industry standard + TypeScript strict mode
- **Python**: Black + Ruff + mypy strict mode  
- **Multi-Agent Coordination**: Naming patterns, error handling, logging
- **Configuration Files**: .editorconfig, eslint.config.mjs, pyproject.toml
- **Enforcement Protocol**: Zero-tolerance linting and validation requirements

**⚠️ CRITICAL**: Refer to global CLAUDE.md for complete coding standards - this prevents duplication and ensures all projects use identical standards.

## 🚨 PRODUCTION-READY MANDATE

**🔴 ABSOLUTE REQUIREMENT: ALL CODE AND FEATURES MUST BE PRODUCTION-READY**

**PRODUCTION-READY STANDARDS:**
- **❌ NO SIMPLIFIED VERSIONS** - Never create placeholder or simplified implementations
- **❌ NO MOCK IMPLEMENTATIONS** - All functionality must be fully operational
- **❌ NO TEMPORARY WORKAROUNDS** - Implement proper, sustainable solutions
- **❌ NO PLACEHOLDER CODE** - Every line of code must serve a real purpose
- **✅ ENTERPRISE-GRADE QUALITY** - Code must meet production deployment standards
- **✅ COMPLETE FUNCTIONALITY** - All features must be fully implemented and tested
- **✅ ROBUST ERROR HANDLING** - Comprehensive error management and recovery
- **✅ SCALABLE ARCHITECTURE** - Designed to handle production loads and growth
- **✅ SECURITY COMPLIANCE** - All security best practices implemented
- **✅ PERFORMANCE OPTIMIZED** - Code must perform efficiently under production conditions

## 🚨 ABSOLUTE SETTINGS PROTECTION MANDATE

**🔴 CRITICAL PROHIBITION - NEVER EVER EVER:**
- **❌ NEVER EDIT settings.json** - `/Users/jeremyparker/.claude/settings.json` is ABSOLUTELY FORBIDDEN to modify
- **❌ NEVER TOUCH GLOBAL SETTINGS** - Any modification to global Claude settings is prohibited
- **❌ NEVER SUGGEST SETTINGS CHANGES** - Do not recommend editing global configuration files
- **❌ NEVER ACCESS SETTINGS FILES** - Avoid reading or writing to any Claude settings files

**GOLDEN RULE:** Global Claude settings at `/Users/jeremyparker/.claude/settings.json` are **UNTOUCHABLE** - treat as read-only system files

## 🚨 WORKFLOW PROTOCOLS

**TODO.json INTERACTION PROTOCOL:**
**MANDATORY**: ALWAYS USE THE TASKMANAGER API WHEN INTERACTING WITH THE TODO.JSON

**CRITICAL REQUIREMENT**: ALL TODO.json operations (read/write) MUST use TaskManager API exclusively.

**✅ ALLOWED**: Reading TODO.json as a file (Read tool only) for viewing/inspection
**✅ CORRECT**: TaskManager API for ALL TODO.json interactions (create, update, delete, modify, reorder)
**❌ ABSOLUTELY FORBIDDEN**: Any write operations directly to TODO.json file
**❌ ABSOLUTELY FORBIDDEN**: fs.readFileSync/writeFileSync on TODO.json for modifications
**❌ ABSOLUTELY FORBIDDEN**: require('./TODO.json') for any mutations
**❌ ABSOLUTELY FORBIDDEN**: JSON.parse/JSON.stringify operations that modify TODO.json
**❌ ABSOLUTELY FORBIDDEN**: Any direct file manipulation beyond reading for inspection

**GOLDEN RULE**: TODO.json is READ-ONLY as a file. ALL modifications MUST go through TaskManager API.

**ALWAYS USE THESE COMMANDS INSTEAD:**

**⚠️ CRITICAL: Use single quotes for all node -e commands to prevent bash escaping errors**

```bash
# AGENT INITIALIZATION (MANDATORY FIRST STEP) - ALWAYS use universal script
node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm-universal.js" init --project [PROJECT_DIRECTORY]

# UPDATE TASK STATUS (SIMPLIFIED)
node "/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/tm-universal.js" update task_id completed "Optional completion notes" --project [PROJECT_DIRECTORY]

# Read TODO.json data
node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("[PROJECT_DIRECTORY]/TODO.json"); tm.readTodo().then(data => console.log(JSON.stringify(data, null, 2)));'

# Get current task
node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("[PROJECT_DIRECTORY]/TODO.json"); tm.getCurrentTask("agent_id").then(task => console.log(JSON.stringify(task, null, 2)));'

# List all tasks
node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("[PROJECT_DIRECTORY]/TODO.json"); tm.readTodo().then(data => console.log(JSON.stringify(data.tasks, null, 2)));'

# Create new task
node -e 'const TaskManager = require("/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager"); const tm = new TaskManager("[PROJECT_DIRECTORY]/TODO.json"); tm.createTask({title: "Task name", mode: "DEVELOPMENT"}).then(id => console.log("Created:", id));'
```

## 🚨 ROOT FOLDER ORGANIZATION POLICY

**MANDATORY ROOT FOLDER CLEANLINESS:**
- **KEEP ROOT FOLDER CLEAN** - Only essential project files in root directory
- **Create development subdirectories** for reports, research, and documentation if they don't exist
- **Move analysis files, reports, and documentation** to appropriate subdirectories

**ALLOWED IN ROOT DIRECTORY:**
- **Core project files**: package.json, README.md, CLAUDE.md, TODO.json, DONE.json
- **Configuration files**: .eslintrc, .gitignore, jest.config.js, etc.
- **Build/deployment files**: Dockerfile, docker-compose.yml, etc.
- **License and legal**: LICENSE, CONTRIBUTING.md, etc.

**ORGANIZE INTO SUBDIRECTORIES:**
- **Reports and analysis** → `development/reports/` 
- **Research documentation** → `development/research-reports/`
- **Development notes** → `development/notes/`
- **Backup files** → `backups/`

## 🚨 MANDATORY GIT WORKFLOW

**ABSOLUTE REQUIREMENT**: ALWAYS commit and push work after EVERY task completion

### 🔴 MANDATORY COMMIT PROTOCOL - NO EXCEPTIONS

**AFTER COMPLETING ANY TASK - IMMEDIATELY RUN:**

```bash
# 1. Stage all changes
git add -A

# 2. Commit with descriptive message
git commit -m "feat: [brief description of what was accomplished]

- [bullet point of specific changes made]
- [another accomplishment]
- [any fixes or improvements]

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"

# 3. MANDATORY - Push to remote repository
git push
```

### 📝 COMMIT MESSAGE STANDARDS

**REQUIRED FORMAT:**
- **Type**: Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- **Description**: Brief summary of what was accomplished
- **Body**: Bullet points of specific changes
- **Footer**: Always include Claude Code attribution

**EXAMPLES:**
```bash
git commit -m "fix: resolve multi-agent processing bottlenecks

- Fixed stop-hook JSON parsing error
- Reactivated multiple agents for concurrent processing  
- Updated validation system to support multiple in_progress tasks
- Verified task distribution across specialized agents

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

### ⚡ WORKFLOW ENFORCEMENT

**MANDATORY SEQUENCE:**
1. **Complete Task** - Finish all implementation and testing
2. **Validate Work** - Run all validation commands and verify results
3. **Stage Changes** - `git add -A` to include all modifications
4. **Commit Work** - Use descriptive commit message with proper format
5. **Push Remote** - `git push` to ensure work is backed up and shared
6. **Mark Task Complete** - Update TaskManager with completion status

**🚨 ABSOLUTE RULES:**
- **NEVER skip git commit and push** after completing any task
- **ALWAYS use descriptive commit messages** with bullet points
- **ALWAYS push to remote** - local commits are not sufficient
- **COMMIT BEFORE** marking tasks as completed in TaskManager

**TASK COMPLETION REQUIREMENTS:**

**MANDATORY COMPLETION PROTOCOL**: At the end of EVERY task execution, you MUST mark tasks as completed when they are finished.

**Task Completion API:**
```bash
# Initialize TaskManager and mark task as completed
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('[PROJECT_DIRECTORY]/TODO.json'); tm.updateTaskStatus('task-1', 'completed').then(() => console.log('✅ Task marked as completed'));"

# Alternative: Get current task and mark it completed
node -e "const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager'); const tm = new TaskManager('[PROJECT_DIRECTORY]/TODO.json'); tm.getCurrentTask().then(async (task) => { if (task) { await tm.updateTaskStatus(task.id, 'completed'); console.log('✅ Current task completed:', task.id); } else { console.log('No active task found'); } });"
```

**TASK COMPLETION VALIDATION REQUIREMENTS:**

**Evidence-Based Completion Protocol:**
1. **Run validation commands** - Provide command outputs showing status
2. **Test functionality** - Verify the implementation works as expected  
3. **Confirm requirements** - Document how each requirement was satisfied
4. **Completion summary** - Brief statement with supporting evidence

**Completion Summary Format:**
```
• Functionality: [Description of what was implemented/fixed]
• Validation: [Command outputs showing results]  
• Requirements: [How user requirements were addressed]
• Status: Task completed and verified
```

**Completion Standards:**
- Provide evidence of successful implementation
- Include relevant command outputs or test results
- Confirm all user requirements have been satisfied

## 🚨 EXECUTION WORKFLOW

**STANDARD APPROACH:**
1. **INSTANT TASK CREATION** - Create task for ANY user request
2. **Evaluate Existing Tasks** - Check if can modify existing vs create new
3. **Think First** - Use appropriate thinking level (think/think hard/ultrathink)
4. **Initialize Agent** - Use TaskManager API initialization
5. **Deploy UP TO 10 Subagents** - Always maximize subagents for complex work with synchronized completion
6. **Implement & Validate** - Execute with evidence-based completion
7. **Complete Tasks** - Mark completed via TaskManager API

## 🚨 INFINITE OPERATION MANDATE - NO TIME LIMITS

**🔴 ABSOLUTE MANDATE: OPERATE AS LONG AS POSSIBLE - NO TIME CONSTRAINTS**

**INFINITE OPERATION PROTOCOL:**
- **⏰ NO TIME LIMITS** - Continue working indefinitely until natural completion or user stop
- **🔄 MULTIPLE ROUNDS** - Deploy multiple rounds of subagents across multiple tasks  
- **📋 MULTIPLE TASKS** - Complete as many tasks as possible in one session
- **🚀 MAXIMUM SUBAGENTS** - Use up to 10 subagents repeatedly across task cycles

## 🚨 INFINITE CONTINUE HOOK SYSTEM - NEVER STOP PROTOCOL

**🔴 ABSOLUTE MANDATE: NEVER ALLOW STOPS UNLESS ENDPOINT TRIGGERED**

### 🛑 STOP CONTROL PROTOCOL

**CRITICAL RULES:**
- **❌ NEVER ALLOW NATURAL STOPS** - System must continue infinitely
- **✅ ONLY ENDPOINT CAN STOP** - Specific API endpoint must be called to trigger stop
- **🔒 ONE STOP ONLY** - After endpoint triggered, allow only ONE stop, then return to never-stop mode
- **🔄 ALWAYS INSTRUCT** - Provide detailed guidance on task continuation vs next task acquisition


### 🔄 CONTINUOUS OPERATION MANDATE

**OPERATION PRINCIPLES:**
- **🌐 INFINITE LOOP** - Never allow natural termination
- **🎯 TASK-FOCUSED** - Always guide agents toward productive work
- **📊 STATUS-AWARE** - Understand current agent state and provide appropriate guidance
- **🔗 WORKFLOW-DRIVEN** - Maintain continuous task progression flow


**STOP SEQUENCE:**
1. **Endpoint called** → Set stop_allowed flag to true
2. **Next stop hook trigger** → Allow ONE stop and reset flag  
3. **Subsequent triggers** → Return to never-stop infinite mode

### 🎛️ HOOK BEHAVIOR SPECIFICATION

**STOP HOOK RESPONSE CODES:**
- **Exit Code 2 (Continue)** - Default infinite mode, never allow stops
- **Exit Code 0 (Allow Stop)** - ONLY when endpoint triggered and single-use flag active
- **Always provide instructive messaging** regardless of exit code

**INFINITE CONTINUE HOOK SYSTEM:**
- **Setup**: `node "/.../setup-infinite-hook.js" "/path/to/project"`
- **Coverage**: development (80%), testing/debugging/refactoring (95%)
- **Stop Control**: API endpoint required for stop authorization

**INSTANT TASK CREATION RULE:**
User communication → **INSTANT TASK CREATION** → Then execute work

**SETTINGS PROTECTION:** Never modify `/Users/jeremyparker/.claude/settings.json`

## 🚨 ABSOLUTE SETTINGS PROTECTION MANDATE

**🔴 CRITICAL PROHIBITION - NEVER EVER EVER:**
- **❌ NEVER EDIT settings.json** - `/Users/jeremyparker/.claude/settings.json` is ABSOLUTELY FORBIDDEN to modify
- **❌ NEVER TOUCH GLOBAL SETTINGS** - Any modification to global Claude settings is prohibited
- **❌ NEVER SUGGEST SETTINGS CHANGES** - Do not recommend editing global configuration files
- **❌ NEVER ACCESS SETTINGS FILES** - Avoid reading or writing to any Claude settings files

**GOLDEN RULE:** Global Claude settings at `/Users/jeremyparker/.claude/settings.json` are **UNTOUCHABLE** - treat as read-only system files