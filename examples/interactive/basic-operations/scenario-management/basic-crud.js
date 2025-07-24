#!/usr/bin/env node

/**
 * Basic CRUD Operations Demo for Make.com FastMCP Server
 * 
 * This script demonstrates fundamental scenario management operations:
 * - Create: Build new scenarios with blueprints
 * - Read: List and retrieve scenario details
 * - Update: Modify scenario properties
 * - Delete: Remove scenarios safely
 * 
 * Usage:
 *   node basic-crud.js
 *   node basic-crud.js --operation list
 *   node basic-crud.js --operation create --name "My Scenario"
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// Configuration
const CONFIG = {
    mcpServer: process.env.MCP_SERVER || 'localhost:3000',
    demoDataFile: path.join(__dirname, 'demo-data.json'),
    logFile: path.join(__dirname, 'basic-crud.log'),
    timeout: 30000
};

// Load demo data
let demoData;
try {
    demoData = JSON.parse(fs.readFileSync(CONFIG.demoDataFile, 'utf8'));
} catch (error) {
    console.error('❌ Failed to load demo data:', error.message);
    process.exit(1);
}

// Utility functions
const log = (message, level = 'info') => {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${level.toUpperCase()}: ${message}\n`;
    
    // Write to log file
    fs.appendFileSync(CONFIG.logFile, logEntry);
    
    // Console output with colors
    const colors = {
        info: '\x1b[36m',    // Cyan
        success: '\x1b[32m', // Green
        warn: '\x1b[33m',    // Yellow
        error: '\x1b[31m',   // Red
        reset: '\x1b[0m'     // Reset
    };
    
    console.log(`${colors[level] || colors.info}${message}${colors.reset}`);
};

const success = (message) => log(`✓ ${message}`, 'success');
const error = (message) => log(`✗ ${message}`, 'error');
const warn = (message) => log(`⚠ ${message}`, 'warn');
const info = (message) => log(`ℹ ${message}`, 'info');

// Execute MCP command
const executeMCP = async (toolName, params, description) => {
    return new Promise((resolve, reject) => {
        info(`Executing: ${description}`);
        
        const request = {
            method: 'tools/call',
            params: {
                name: toolName,
                arguments: params
            }
        };
        
        const child = spawn('npx', ['@modelcontextprotocol/cli', 'chat'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        let stdout = '';
        let stderr = '';
        
        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        
        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        child.on('close', (code) => {
            if (code === 0) {
                try {
                    const result = JSON.parse(stdout);
                    success(`${description} completed`);
                    resolve(result);
                } catch (parseError) {
                    error(`Failed to parse response: ${parseError.message}`);
                    reject(parseError);
                }
            } else {
                error(`${description} failed: ${stderr}`);
                reject(new Error(stderr || `Process exited with code ${code}`));
            }
        });
        
        // Send request
        child.stdin.write(JSON.stringify(request));
        child.stdin.end();
        
        // Set timeout
        setTimeout(() => {
            child.kill();
            reject(new Error(`Operation timed out after ${CONFIG.timeout}ms`));
        }, CONFIG.timeout);
    });
};

// Demo operations
const demoOperations = {
    
    /**
     * List scenarios with various filtering options
     */
    async list(options = {}) {
        info('📋 Starting scenario listing demo...');
        
        const filters = [
            { ...demoData.filters.activeScenarios, ...options },
            demoData.filters.teamScenarios,
            demoData.filters.searchExample,
            demoData.filters.folderScenarios
        ];
        
        const descriptions = [
            'Active scenarios only',
            'Team-specific scenarios',
            'Search scenarios by name',
            'Folder-organized scenarios'
        ];
        
        for (let i = 0; i < filters.length; i++) {
            try {
                info(`${i + 1}. ${descriptions[i]}`);
                const result = await executeMCP('list-scenarios', filters[i], descriptions[i]);
                
                if (result.result) {
                    const data = JSON.parse(result.result);
                    console.log(`   Found ${data.scenarios?.length || 0} scenarios`);
                    console.log(`   Total: ${data.pagination?.total || 0}`);
                    
                    // Show first few scenarios
                    if (data.scenarios && data.scenarios.length > 0) {
                        console.log('   Sample scenarios:');
                        data.scenarios.slice(0, 3).forEach(scenario => {
                            console.log(`   - ID: ${scenario.id}, Name: ${scenario.name}, Active: ${scenario.isActive}`);
                        });
                    }
                }
                
                console.log(''); // Empty line for readability
            } catch (err) {
                error(`Failed to list scenarios with filter ${i + 1}: ${err.message}`);
            }
        }
        
        success('Scenario listing demo completed');
    },
    
    /**
     * Retrieve detailed scenario information
     */
    async get(scenarioId = '2001') {
        info(`🔍 Getting detailed information for scenario ${scenarioId}...`);
        
        try {
            const params = {
                scenarioId: scenarioId,
                includeBlueprint: true,
                includeExecutions: true
            };
            
            const result = await executeMCP('get-scenario', params, `Get scenario ${scenarioId} details`);
            
            if (result.result) {
                const data = JSON.parse(result.result);
                
                console.log('📊 Scenario Details:');
                console.log(`   ID: ${data.scenario?.id}`);
                console.log(`   Name: ${data.scenario?.name}`);
                console.log(`   Team ID: ${data.scenario?.teamId}`);
                console.log(`   Active: ${data.scenario?.isActive}`);
                console.log(`   Created: ${data.scenario?.createdAt}`);
                console.log(`   Updated: ${data.scenario?.updatedAt}`);
                
                if (data.blueprint) {
                    console.log(`   Blueprint modules: ${data.blueprint.flow?.length || 0}`);
                }
                
                if (data.recentExecutions) {
                    console.log(`   Recent executions: ${data.recentExecutions.length}`);
                }
            }
            
        } catch (err) {
            error(`Failed to get scenario details: ${err.message}`);
        }
    },
    
    /**
     * Create new scenarios with different configurations
     */
    async create(scenarioName) {
        info('🆕 Starting scenario creation demo...');
        
        const scenarioTypes = [
            {
                name: scenarioName || `Basic Demo ${Date.now()}`,
                data: demoData.scenarios.basic,
                description: 'Basic webhook-to-email scenario'
            },
            {
                name: `Advanced Demo ${Date.now()}`,
                data: demoData.scenarios.advanced,
                description: 'Advanced scheduled workflow'
            },
            {
                name: `E-commerce Demo ${Date.now()}`,
                data: demoData.scenarios.ecommerce,
                description: 'E-commerce order processing'
            }
        ];
        
        for (const scenarioType of scenarioTypes) {
            try {
                info(`Creating: ${scenarioType.description}`);
                
                const params = {
                    name: scenarioType.name,
                    teamId: scenarioType.data.teamId,
                    folderId: scenarioType.data.folderId,
                    blueprint: scenarioType.data.blueprint,
                    scheduling: scenarioType.data.scheduling
                };
                
                const result = await executeMCP('create-scenario', params, scenarioType.description);
                
                if (result.result) {
                    const data = JSON.parse(result.result);
                    console.log(`   ✓ Created scenario: ${data.scenario?.name}`);
                    console.log(`   ✓ Scenario ID: ${data.scenario?.id}`);
                    console.log(`   ✓ Team ID: ${data.scenario?.teamId}`);
                    console.log(`   ✓ Active: ${data.scenario?.isActive}`);
                }
                
                console.log(''); // Empty line
                
            } catch (err) {
                error(`Failed to create ${scenarioType.description}: ${err.message}`);
            }
        }
        
        success('Scenario creation demo completed');
    },
    
    /**
     * Update scenario properties and configuration
     */
    async update(scenarioId = '2001') {
        info(`🔄 Starting scenario update demo for scenario ${scenarioId}...`);
        
        const updates = [
            {
                data: demoData.updates.activateScenario,
                description: 'Activate scenario'
            },
            {
                data: demoData.updates.updateName,
                description: 'Update scenario name'
            },
            {
                data: demoData.updates.updateScheduling,
                description: 'Update scheduling configuration'
            }
        ];
        
        for (const update of updates) {
            try {
                info(`Applying: ${update.description}`);
                
                const params = {
                    scenarioId: scenarioId,
                    ...update.data
                };
                
                const result = await executeMCP('update-scenario', params, update.description);
                
                if (result.result) {
                    const data = JSON.parse(result.result);
                    console.log(`   ✓ Update applied successfully`);
                    console.log(`   ✓ Scenario: ${data.scenario?.name}`);
                    console.log(`   ✓ Updated fields: ${Object.keys(update.data).join(', ')}`);
                }
                
                console.log(''); // Empty line
                
            } catch (err) {
                error(`Failed to apply ${update.description}: ${err.message}`);
            }
        }
        
        success('Scenario update demo completed');
    },
    
    /**
     * Clone scenarios with different configurations
     */
    async clone(sourceId = '2001') {
        info(`📋 Starting scenario cloning demo from scenario ${sourceId}...`);
        
        const cloneConfigs = [
            {
                ...demoData.cloning.basicClone,
                name: `${demoData.cloning.basicClone.name} ${Date.now()}`,
                description: 'Basic clone in same team'
            },
            {
                ...demoData.cloning.crossTeamClone,
                name: `${demoData.cloning.crossTeamClone.name} ${Date.now()}`,
                description: 'Cross-team clone'
            }
        ];
        
        for (const config of cloneConfigs) {
            try {
                info(`Creating: ${config.description}`);
                
                const params = {
                    scenarioId: sourceId,
                    name: config.name,
                    teamId: config.teamId,
                    folderId: config.folderId,
                    active: config.active
                };
                
                const result = await executeMCP('clone-scenario', params, config.description);
                
                if (result.result) {
                    const data = JSON.parse(result.result);
                    console.log(`   ✓ Cloned scenario: ${data.clonedScenario?.name}`);
                    console.log(`   ✓ New ID: ${data.clonedScenario?.id}`);
                    console.log(`   ✓ Source ID: ${data.originalScenarioId}`);
                    console.log(`   ✓ Active: ${data.clonedScenario?.isActive}`);
                }
                
                console.log(''); // Empty line
                
            } catch (err) {
                error(`Failed to create ${config.description}: ${err.message}`);
            }
        }
        
        success('Scenario cloning demo completed');
    },
    
    /**
     * Delete scenarios with safety checks
     */
    async delete(scenarioId = '2002') {
        info(`🗑️  Starting scenario deletion demo for scenario ${scenarioId}...`);
        
        try {
            // First try to delete without force (should fail if active)
            info('Attempting safe deletion...');
            
            const params = {
                scenarioId: scenarioId,
                force: false
            };
            
            const result = await executeMCP('delete-scenario', params, 'Safe deletion attempt');
            
            if (result.result) {
                const data = JSON.parse(result.result);
                console.log(`   ✓ Scenario deleted: ${data.scenarioId}`);
                console.log(`   ✓ Force used: ${data.force}`);
            }
            
        } catch (err) {
            warn(`Safe deletion failed (expected if scenario is active): ${err.message}`);
            
            // Try with force flag
            try {
                info('Attempting force deletion...');
                
                const forceParams = {
                    scenarioId: scenarioId,
                    force: true
                };
                
                const forceResult = await executeMCP('delete-scenario', forceParams, 'Force deletion');
                
                if (forceResult.result) {
                    const data = JSON.parse(forceResult.result);
                    console.log(`   ✓ Force deletion successful: ${data.scenarioId}`);
                }
                
            } catch (forceErr) {
                error(`Force deletion also failed: ${forceErr.message}`);
            }
        }
        
        success('Scenario deletion demo completed');
    },
    
    /**
     * Run all CRUD operations in sequence
     */
    async all() {
        info('🚀 Starting complete CRUD operations demo...');
        console.log('');
        
        try {
            // List existing scenarios
            await this.list();
            console.log('─'.repeat(60));
            
            // Get scenario details
            await this.get();
            console.log('─'.repeat(60));
            
            // Create new scenarios
            await this.create();
            console.log('─'.repeat(60));
            
            // Update scenario
            await this.update();
            console.log('─'.repeat(60));
            
            // Clone scenario
            await this.clone();
            console.log('─'.repeat(60));
            
            // Note: Skipping delete in 'all' demo to avoid removing test data
            info('💡 Skipping deletion demo in full run to preserve test scenarios');
            
            success('🎉 Complete CRUD operations demo finished successfully!');
            
        } catch (err) {
            error(`CRUD demo failed: ${err.message}`);
        }
    }
};

// Main execution
async function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    let operation = 'all';
    let options = {};
    
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--operation':
                operation = args[++i];
                break;
            case '--name':
                options.name = args[++i];
                break;
            case '--scenarioId':
                options.scenarioId = args[++i];
                break;
            case '--limit':
                options.limit = parseInt(args[++i]);
                break;
            case '--help':
                console.log(`
Make.com FastMCP Server - Basic CRUD Operations Demo

Usage: node basic-crud.js [options]

Operations:
  --operation OPERATION    Run specific operation (list|get|create|update|clone|delete|all)
  
Options:
  --name NAME             Scenario name for create operation
  --scenarioId ID         Target scenario ID for get/update/delete operations
  --limit NUMBER          Limit for list operation
  --help                  Show this help message

Examples:
  node basic-crud.js                           # Run all operations
  node basic-crud.js --operation list          # List scenarios
  node basic-crud.js --operation create --name "My Demo"
  node basic-crud.js --operation get --scenarioId "2001"
                `);
                return;
            default:
                if (args[i].startsWith('--')) {
                    error(`Unknown option: ${args[i]}`);
                    process.exit(1);
                }
        }
    }
    
    // Initialize log
    const startTime = new Date();
    fs.writeFileSync(CONFIG.logFile, `Make.com FastMCP Basic CRUD Demo - ${startTime.toISOString()}\n`);
    
    info('Make.com FastMCP Server - Basic CRUD Operations Demo');
    info(`Operation: ${operation}`);
    info(`Server: ${CONFIG.mcpServer}`);
    info(`Log file: ${CONFIG.logFile}`);
    console.log('');
    
    // Execute operation
    try {
        if (demoOperations[operation]) {
            await demoOperations[operation](
                options.scenarioId,
                options.name,
                options
            );
        } else {
            error(`Unknown operation: ${operation}`);
            error('Available operations: list, get, create, update, clone, delete, all');
            process.exit(1);
        }
        
        const endTime = new Date();
        const duration = endTime - startTime;
        success(`Demo completed in ${duration}ms`);
        
    } catch (err) {
        error(`Demo failed: ${err.message}`);
        process.exit(1);
    }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    error(`Unhandled Rejection at: ${promise}, reason: ${reason}`);
    process.exit(1);
});

// Run main function
if (require.main === module) {
    main();
}

module.exports = { demoOperations, executeMCP };