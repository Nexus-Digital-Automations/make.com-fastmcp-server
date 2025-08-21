#!/usr/bin/env node

/**
 * Mark review-strike-2 task as completed after creating remediation tasks
 * Fixed to use TaskManager API instead of direct file manipulation
 */

import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import TaskManager with proper CommonJS handling
async function loadTaskManager() {
    try {
        // For environments where require is available
        if (typeof require !== 'undefined') {
            const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager');
            return TaskManager;
        } else {
            // Fallback for pure ES modules
            const { createRequire } = await import('module');
            const require = createRequire(import.meta.url);
            const TaskManager = require('/Users/jeremyparker/Desktop/Claude Coding Projects/infinite-continue-stop-hook/lib/taskManager');
            return TaskManager;
        }
    } catch (error) {
        console.error('❌ Failed to load TaskManager:', error.message);
        process.exit(1);
    }
}

async function main() {
    const TaskManager = await loadTaskManager();
    const todoPath = path.join(__dirname, 'TODO.json');
    const tm = new TaskManager(todoPath);

    const taskId = 'review-strike-2';
    
    try {
        // Read current TODO data using TaskManager API
        const todoData = await tm.readTodo();
        const task = todoData.tasks.find(t => t.id === taskId);

        if (!task) {
            console.error(`❌ Task ${taskId} not found in TODO.json`);
            process.exit(1);
        }

        // Prepare review result data
        const reviewResult = {
            status: 'FAILED',
            criteria: 'Lint Verification',
            critical_failure: 'ESLint configuration error prevents lint execution',
            error_details: {
                configuration_error: 'ESLint couldn\'t find the config "@typescript-eslint/recommended" to extend from',
                root_cause: 'Invalid extends reference in .eslintrc.json',
                required_fix: 'Update extends to "@typescript-eslint/eslint-plugin/recommended"'
            },
            dependencies_status: {
                typescript_eslint_plugin: 'INSTALLED (v6.21.0)',
                typescript_eslint_parser: 'INSTALLED (v6.21.0)', 
                eslint: 'INSTALLED (v8.57.1)',
                node_modules_structure: 'VALID'
            },
            remediation_tasks_created: [
                'fix-eslint-typescript-config',
                'resolve-all-lint-errors'
            ],
            next_action: 'Complete ESLint configuration fix before re-running Strike 2'
        };

        // Update task status using TaskManager API
        const completionNotes = `Strike 2 Review completed with FAILED status. Review results: ${JSON.stringify(reviewResult)}`;
        await tm.updateTaskStatus(taskId, 'completed', completionNotes);
        
        console.log(`✅ Task ${taskId} marked as completed using TaskManager API`);
        
        // Show completion details
        console.log('\n📋 Strike 2 Review Summary:');
        console.log(`- Task ID: ${taskId}`);
        console.log(`- Status: completed (Review conducted, remediation tasks created)`);
        console.log(`- Review Result: FAILED - ESLint configuration error`);
        console.log(`- Critical Issue: Configuration prevents lint execution`);
        console.log(`- Completed At: ${new Date().toISOString()}`);
        
        console.log('\n🔴 CRITICAL: Strike 2 Review Failed');
        console.log('✅ Review task completed (remediation tasks created)');
        console.log('📋 2 remediation tasks created with high priority');
        console.log('⚠️  ESLint configuration must be fixed before Strike 2 can pass');
        console.log('\n📄 Detailed report: STRIKE_2_REVIEW_REPORT.md');
        
    } catch (error) {
        console.error('❌ Failed to update task status:', error.message);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

// Run main function
main().catch(error => {
    console.error('❌ Script failed:', error.message);
    process.exit(1);
});