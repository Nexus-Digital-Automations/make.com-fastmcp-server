#!/usr/bin/env node

/**
 * Mark task doc-task-4-interactive-examples as completed
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TODO_FILE = path.join(__dirname, 'TODO.json');

// Read current TODO.json
let todoData;
try {
    todoData = JSON.parse(fs.readFileSync(TODO_FILE, 'utf8'));
} catch (error) {
    console.error('❌ Failed to read TODO.json:', error.message);
    process.exit(1);
}

// Find and update the target task
const taskId = 'doc-task-4-interactive-examples';
const task = todoData.tasks.find(t => t.id === taskId);

if (!task) {
    console.error(`❌ Task ${taskId} not found in TODO.json`);
    process.exit(1);
}

// Update task status
task.status = 'completed';
task.completed_at = new Date().toISOString();

// Write updated TODO.json
try {
    fs.writeFileSync(TODO_FILE, JSON.stringify(todoData, null, 2));
    console.log(`✅ Task ${taskId} marked as completed`);
    
    // Show completion details
    console.log('\n📋 Task Completion Summary:');
    console.log(`- Task ID: ${task.id}`);
    console.log(`- Title: ${task.title || task.description}`);
    console.log(`- Status: ${task.status}`);
    console.log(`- Completed At: ${task.completed_at}`);
    
    console.log('\n🎉 Interactive documentation with runnable examples has been successfully completed!');
    console.log('\n📁 Created Files:');
    console.log('- examples/interactive/README.md (Main framework overview)');
    console.log('- examples/interactive/basic-operations/README.md (Basic operations guide)');
    console.log('- examples/interactive/basic-operations/scenario-management/ (Complete scenario examples)');
    console.log('- examples/interactive/basic-operations/connection-management/ (Connection examples)');
    console.log('- examples/interactive/shared/utils.js (Shared utilities)');
    
    console.log('\n🚀 Users can now run interactive examples with:');
    console.log('cd examples/interactive/basic-operations/scenario-management');
    console.log('./run-example.sh');
    
} catch (error) {
    console.error('❌ Failed to write TODO.json:', error.message);
    process.exit(1);
}