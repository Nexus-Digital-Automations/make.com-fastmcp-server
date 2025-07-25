/**
 * Shared utilities for Make.com FastMCP Server interactive examples
 * 
 * This module provides common functionality used across all example demos including:
 * - MCP command execution
 * - Output formatting
 * - Error handling
 * - Logging utilities
 * - Configuration management
 */

const fs = require('fs');
const _path = require('path');
const { spawn } = require('child_process');

// Configuration constants
const CONFIG = {
    mcpServer: process.env.MCP_SERVER || 'localhost:3000',
    timeout: parseInt(process.env.MCP_TIMEOUT) || 30000,
    retries: parseInt(process.env.MCP_RETRIES) || 3,
    retryDelay: parseInt(process.env.MCP_RETRY_DELAY) || 1000,
    logLevel: process.env.LOG_LEVEL || 'info'
};

// Color constants for console output
const COLORS = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    reset: '\x1b[0m'
};

/**
 * Logger utility with different levels and file output
 */
class Logger {
    constructor(logFile = null) {
        this.logFile = logFile;
        this.levels = {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3
        };
        this.currentLevel = this.levels[CONFIG.logLevel] || this.levels.info;
    }

    _writeLog(level, message, data = null) {
        if (this.levels[level] > this.currentLevel) return;

        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level: level.toUpperCase(),
            message,
            data
        };

        // Write to file if specified
        if (this.logFile) {
            const logLine = `[${timestamp}] ${level.toUpperCase()}: ${message}`;
            const fullLogLine = data ? `${logLine} ${JSON.stringify(data)}` : logLine;
            fs.appendFileSync(this.logFile, fullLogLine + '\n');
        }

        return logEntry;
    }

    _colorize(text, color) {
        return `${COLORS[color] || ''}${text}${COLORS.reset}`;
    }

    error(message, data = null) {
        this._writeLog('error', message, data);
        console.error(this._colorize(`❌ ${message}`, 'red'));
        if (data && this.currentLevel >= this.levels.debug) {
            console.error(this._colorize(JSON.stringify(data, null, 2), 'dim'));
        }
    }

    warn(message, data = null) {
        this._writeLog('warn', message, data);
        console.warn(this._colorize(`⚠️  ${message}`, 'yellow'));
        if (data && this.currentLevel >= this.levels.debug) {
            console.warn(this._colorize(JSON.stringify(data, null, 2), 'dim'));
        }
    }

    info(message, data = null) {
        this._writeLog('info', message, data);
        console.log(this._colorize(`ℹ️  ${message}`, 'cyan'));
        if (data && this.currentLevel >= this.levels.debug) {
            console.log(this._colorize(JSON.stringify(data, null, 2), 'dim'));
        }
    }

    success(message, data = null) {
        this._writeLog('info', message, data);
        console.log(this._colorize(`✅ ${message}`, 'green'));
        if (data && this.currentLevel >= this.levels.debug) {
            console.log(this._colorize(JSON.stringify(data, null, 2), 'dim'));
        }
    }

    debug(message, data = null) {
        this._writeLog('debug', message, data);
        if (this.currentLevel >= this.levels.debug) {
            console.log(this._colorize(`🔍 ${message}`, 'dim'));
            if (data) {
                console.log(this._colorize(JSON.stringify(data, null, 2), 'dim'));
            }
        }
    }
}

/**
 * Execute MCP command with retry logic and error handling
 */
class MCPExecutor {
    constructor(logger = null) {
        this.logger = logger || new Logger();
    }

    async execute(toolName, params, description = '') {
        const startTime = Date.now();
        let lastError = null;

        for (let attempt = 1; attempt <= CONFIG.retries; attempt++) {
            try {
                this.logger.debug(`Attempt ${attempt}/${CONFIG.retries}: ${description || toolName}`, {
                    tool: toolName,
                    params: typeof params === 'object' ? Object.keys(params) : params
                });

                const result = await this._executeSingle(toolName, params, description);
                const duration = Date.now() - startTime;
                
                this.logger.success(`${description || toolName} completed in ${duration}ms`);
                return result;

            } catch (error) {
                lastError = error;
                this.logger.warn(`Attempt ${attempt} failed: ${error.message}`);

                if (attempt < CONFIG.retries) {
                    const delay = CONFIG.retryDelay * attempt; // Exponential backoff
                    this.logger.debug(`Retrying in ${delay}ms...`);
                    await this._sleep(delay);
                }
            }
        }

        this.logger.error(`All ${CONFIG.retries} attempts failed for ${toolName}`, lastError);
        throw lastError;
    }

    async _executeSingle(toolName, params, _description) {
        return new Promise((resolve, reject) => {
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
                        resolve(result);
                    } catch (parseError) {
                        reject(new Error(`Failed to parse MCP response: ${parseError.message}`));
                    }
                } else {
                    reject(new Error(`MCP command failed (exit code ${code}): ${stderr || 'Unknown error'}`));
                }
            });

            child.on('error', (error) => {
                reject(new Error(`Failed to spawn MCP process: ${error.message}`));
            });

            // Send request
            child.stdin.write(JSON.stringify(request));
            child.stdin.end();

            // Set timeout
            setTimeout(() => {
                child.kill();
                reject(new Error(`MCP command timed out after ${CONFIG.timeout}ms`));
            }, CONFIG.timeout);
        });
    }

    _sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

/**
 * Output formatters for different display modes
 */
class OutputFormatter {
    constructor(format = 'json') {
        this.format = format;
    }

    format(data, title = null) {
        switch (this.format) {
            case 'table':
                return this._formatTable(data, title);
            case 'detailed':
                return this._formatDetailed(data, title);
            case 'summary':
                return this._formatSummary(data, title);
            case 'json':
            default:
                return this._formatJSON(data, title);
        }
    }

    _formatJSON(data, title) {
        const output = [];
        if (title) {
            output.push(`\n${COLORS.bright}${title}${COLORS.reset}`);
            output.push('─'.repeat(title.length));
        }
        
        if (typeof data === 'string') {
            try {
                data = JSON.parse(data);
            } catch (e) {
                output.push(data);
                return output.join('\n');
            }
        }

        output.push(JSON.stringify(data, null, 2));
        return output.join('\n');
    }

    _formatTable(data, title) {
        const output = [];
        if (title) {
            output.push(`\n${COLORS.bright}${title}${COLORS.reset}`);
        }

        if (typeof data === 'string') {
            try {
                data = JSON.parse(data);
            } catch (e) {
                output.push(data);
                return output.join('\n');
            }
        }

        // Handle different data structures
        if (data.scenarios) {
            output.push(this._createTable(data.scenarios, ['id', 'name', 'isActive', 'createdAt']));
        } else if (data.connections) {
            output.push(this._createTable(data.connections, ['id', 'name', 'service', 'isValid', 'createdAt']));
        } else if (data.users) {
            output.push(this._createTable(data.users, ['id', 'name', 'email', 'role', 'isActive']));
        } else if (Array.isArray(data)) {
            const keys = data.length > 0 ? Object.keys(data[0]) : [];
            output.push(this._createTable(data, keys.slice(0, 5))); // Limit columns
        } else if (typeof data === 'object') {
            output.push(this._createKeyValueTable(data));
        } else {
            output.push(String(data));
        }

        return output.join('\n');
    }

    _formatDetailed(data, title) {
        const output = [];
        if (title) {
            output.push(`\n${COLORS.bright}${title}${COLORS.reset}`);
            output.push('━'.repeat(50));
        }

        if (typeof data === 'string') {
            try {
                data = JSON.parse(data);
            } catch (e) {
                output.push(data);
                return output.join('\n');
            }
        }

        output.push(`Timestamp: ${new Date().toISOString()}`);
        output.push('');

        this._addDetailedSection(output, data, '');
        
        return output.join('\n');
    }

    _formatSummary(data, title) {
        const output = [];
        if (title) {
            output.push(`\n${COLORS.bright}${title}${COLORS.reset}`);
        }

        if (typeof data === 'string') {
            try {
                data = JSON.parse(data);
            } catch (e) {
                output.push(data);
                return output.join('\n');
            }
        }

        // Generate summary based on data type
        if (data.scenarios) {
            const total = data.scenarios.length;
            const active = data.scenarios.filter(s => s.isActive).length;
            output.push(`📊 Scenarios: ${total} total, ${active} active`);
        } else if (data.connections) {
            const total = data.connections.length;
            const valid = data.connections.filter(c => c.isValid).length;
            output.push(`🔌 Connections: ${total} total, ${valid} valid`);
        } else if (data.scenario) {
            output.push(`📋 Scenario: ${data.scenario.name} (${data.scenario.isActive ? 'Active' : 'Inactive'})`);
        } else if (data.connection) {
            output.push(`🔌 Connection: ${data.connection.name} - ${data.connection.service} (${data.connection.isValid ? 'Valid' : 'Invalid'})`);
        } else {
            output.push(`📄 Data: ${typeof data} with ${Object.keys(data).length} properties`);
        }

        return output.join('\n');
    }

    _createTable(data, columns) {
        if (!Array.isArray(data) || data.length === 0) {
            return 'No data available';
        }

        const rows = [columns.map(col => col.toUpperCase())];
        
        data.forEach(item => {
            const row = columns.map(col => {
                const value = item[col];
                if (value === null || value === undefined) return '';
                if (typeof value === 'boolean') return value ? 'Yes' : 'No';
                if (typeof value === 'string' && value.length > 30) {
                    return value.substring(0, 27) + '...';
                }
                return String(value);
            });
            rows.push(row);
        });

        return this._formatTableRows(rows);
    }

    _createKeyValueTable(obj) {
        const rows = [['PROPERTY', 'VALUE']];
        
        Object.entries(obj).forEach(([key, value]) => {
            if (typeof value === 'object' && value !== null) {
                rows.push([key, JSON.stringify(value)]);
            } else {
                rows.push([key, String(value)]);
            }
        });

        return this._formatTableRows(rows);
    }

    _formatTableRows(rows) {
        if (rows.length === 0) return '';

        // Calculate column widths
        const columnWidths = rows[0].map((_, colIndex) => 
            Math.max(...rows.map(row => String(row[colIndex] || '').length))
        );

        const output = [];
        
        rows.forEach((row, rowIndex) => {
            const formattedRow = row.map((cell, colIndex) => 
                String(cell || '').padEnd(columnWidths[colIndex])
            ).join(' | ');
            
            output.push(formattedRow);
            
            // Add separator after header
            if (rowIndex === 0) {
                const separator = columnWidths.map(width => '-'.repeat(width)).join('-+-');
                output.push(separator);
            }
        });

        return output.join('\n');
    }

    _addDetailedSection(output, obj, prefix) {
        if (typeof obj !== 'object' || obj === null) {
            output.push(`${prefix}${obj}`);
            return;
        }

        Object.entries(obj).forEach(([key, value]) => {
            const fullKey = prefix ? `${prefix}.${key}` : key;
            
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                output.push(`${COLORS.bright}${fullKey}:${COLORS.reset}`);
                this._addDetailedSection(output, value, '  ');
            } else {
                const displayValue = Array.isArray(value) 
                    ? `[${value.length} items]` 
                    : String(value);
                output.push(`  ${key}: ${displayValue}`);
            }
        });
    }
}

/**
 * Configuration manager for examples
 */
class ConfigManager {
    constructor(configFile = null) {
        this.config = { ...CONFIG };
        if (configFile && fs.existsSync(configFile)) {
            try {
                const fileConfig = JSON.parse(fs.readFileSync(configFile, 'utf8'));
                this.config = { ...this.config, ...fileConfig };
            } catch (error) {
                console.warn(`Failed to load config file ${configFile}: ${error.message}`);
            }
        }
    }

    get(key, defaultValue = null) {
        return this.config[key] !== undefined ? this.config[key] : defaultValue;
    }

    set(key, value) {
        this.config[key] = value;
    }

    getAll() {
        return { ...this.config };
    }
}

/**
 * Test data loader and generator
 */
class TestDataManager {
    constructor(dataFile = null) {
        this.data = {};
        if (dataFile && fs.existsSync(dataFile)) {
            try {
                this.data = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
            } catch (error) {
                console.warn(`Failed to load test data ${dataFile}: ${error.message}`);
            }
        }
    }

    get(path, defaultValue = null) {
        const keys = path.split('.');
        let current = this.data;
        
        for (const key of keys) {
            if (current && typeof current === 'object' && key in current) {
                current = current[key];
            } else {
                return defaultValue;
            }
        }
        
        return current;
    }

    generateId() {
        return Date.now() + Math.floor(Math.random() * 1000);
    }

    generateTestScenario(overrides = {}) {
        const base = this.get('scenarios.basic', {});
        return {
            ...base,
            id: this.generateId(),
            name: `Test Scenario ${this.generateId()}`,
            createdAt: new Date().toISOString(),
            ...overrides
        };
    }

    generateTestConnection(service = 'gmail', overrides = {}) {
        const base = this.get(`connections.${service}`, {});
        return {
            ...base,
            id: this.generateId(),
            name: `Test ${service} Connection ${this.generateId()}`,
            createdAt: new Date().toISOString(),
            ...overrides
        };
    }
}

/**
 * Performance monitor for tracking operation metrics
 */
class PerformanceMonitor {
    constructor() {
        this.metrics = new Map();
    }

    startTimer(operation) {
        this.metrics.set(operation, {
            startTime: Date.now(),
            endTime: null,
            duration: null
        });
    }

    endTimer(operation) {
        const metric = this.metrics.get(operation);
        if (metric) {
            metric.endTime = Date.now();
            metric.duration = metric.endTime - metric.startTime;
        }
        return metric;
    }

    getMetrics() {
        const results = {};
        this.metrics.forEach((metric, operation) => {
            results[operation] = {
                duration: metric.duration,
                startTime: metric.startTime,
                endTime: metric.endTime
            };
        });
        return results;
    }

    getSummary() {
        const metrics = this.getMetrics();
        const operations = Object.keys(metrics);
        
        if (operations.length === 0) {
            return { totalOperations: 0, totalTime: 0, averageTime: 0 };
        }

        const totalTime = operations.reduce((sum, op) => sum + (metrics[op].duration || 0), 0);
        const completedOps = operations.filter(op => metrics[op].duration !== null);
        
        return {
            totalOperations: operations.length,
            completedOperations: completedOps.length,
            totalTime,
            averageTime: completedOps.length > 0 ? totalTime / completedOps.length : 0,
            operations: metrics
        };
    }
}

// Utility functions
const utils = {
    sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
    
    formatBytes: (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    formatDuration: (ms) => {
        if (ms < 1000) return `${ms}ms`;
        if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
        return `${(ms / 60000).toFixed(1)}m`;
    },
    
    truncateString: (str, length = 50) => {
        if (str.length <= length) return str;
        return str.substring(0, length - 3) + '...';
    },
    
    isValidUrl: (url) => {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    },
    
    deepMerge: (target, source) => {
        const result = { ...target };
        
        for (const key in source) {
            if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                result[key] = utils.deepMerge(result[key] || {}, source[key]);
            } else {
                result[key] = source[key];
            }
        }
        
        return result;
    }
};

module.exports = {
    Logger,
    MCPExecutor,
    OutputFormatter,
    ConfigManager,
    TestDataManager,
    PerformanceMonitor,
    CONFIG,
    COLORS,
    utils
};