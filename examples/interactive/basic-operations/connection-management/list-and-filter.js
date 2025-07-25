#!/usr/bin/env node

/**
 * Connection List and Filter Demo for Make.com FastMCP Server
 * 
 * This script demonstrates connection discovery and filtering operations:
 * - List all connections with various filters
 * - Service-based filtering (gmail, slack, database, etc.)
 * - Status filtering (valid, invalid, all)
 * - Text search across connection names
 * - Pagination support for large datasets
 * 
 * Usage:
 *   node list-and-filter.js
 *   node list-and-filter.js --service gmail
 *   node list-and-filter.js --status valid --limit 20
 */

const fs = require('fs');
const path = require('path');
const { Logger, MCPExecutor, OutputFormatter, TestDataManager: _TestDataManager, PerformanceMonitor } = require('../../shared/utils.js');

// Configuration
const CONFIG = {
    demoDataFile: path.join(__dirname, '..', '..', '..', 'tests', 'fixtures', 'test-data.ts'),
    logFile: path.join(__dirname, 'connection-filter.log'),
    outputFormat: 'json'
};

// Initialize utilities
const logger = new Logger(CONFIG.logFile);
const mcpExecutor = new MCPExecutor(logger);
const performanceMonitor = new PerformanceMonitor();

/**
 * Connection filtering demonstrations
 */
class ConnectionFilterDemo {
    constructor(outputFormat = 'json') {
        this.formatter = new OutputFormatter(outputFormat);
        this.testData = this._loadTestData();
    }

    _loadTestData() {
        try {
            // Load test connections data from fixtures
            const testConnections = {
                gmail: {
                    id: 4001,
                    name: 'Gmail Test Connection',
                    accountName: 'test@gmail.com',
                    service: 'gmail',
                    isValid: true,
                    createdAt: '2024-01-01T10:00:00Z'
                },
                slack: {
                    id: 4002,
                    name: 'Slack Team Connection',
                    accountName: 'team-workspace',
                    service: 'slack',
                    isValid: true,
                    createdAt: '2024-01-01T11:00:00Z'
                },
                mysql: {
                    id: 4003,
                    name: 'MySQL Test Connection',
                    accountName: 'test_db',
                    service: 'mysql',
                    isValid: false,
                    createdAt: '2024-01-01T12:00:00Z'
                },
                api: {
                    id: 4004,
                    name: 'Custom API Connection',
                    accountName: 'api.example.com',
                    service: 'custom_api',
                    isValid: true,
                    createdAt: '2024-01-02T09:00:00Z'
                }
            };

            return { connections: testConnections };
        } catch (error) {
            logger.warn('Could not load test data, using defaults', error);
            return { connections: {} };
        }
    }

    /**
     * Demonstrate basic connection listing
     */
    async demonstrateBasicListing() {
        logger.info('🔍 Demonstrating basic connection listing...');
        
        performanceMonitor.startTimer('basic-list');
        
        try {
            const filters = {
                limit: 20,
                offset: 0
            };

            const result = await mcpExecutor.execute(
                'list-connections',
                filters,
                'List all connections'
            );

            performanceMonitor.endTimer('basic-list');

            if (result.result) {
                const data = JSON.parse(result.result);
                console.log(this.formatter.format(data, '📋 All Connections'));
                
                logger.success(`Found ${data.connections?.length || 0} connections`);
                
                if (data.pagination) {
                    logger.info(`Total available: ${data.pagination.total}, Showing: ${data.connections?.length || 0}`);
                }
            }

            return result;

        } catch (error) {
            logger.error('Failed to list connections', error);
            throw error;
        }
    }

    /**
     * Demonstrate service-based filtering
     */
    async demonstrateServiceFiltering() {
        logger.info('🔧 Demonstrating service-based filtering...');

        const services = ['gmail', 'slack', 'mysql', 'custom_api'];
        const results = {};

        for (const service of services) {
            try {
                logger.info(`Filtering connections for service: ${service}`);
                
                performanceMonitor.startTimer(`service-${service}`);
                
                const filters = {
                    service: service,
                    limit: 10,
                    offset: 0,
                    status: 'all'
                };

                const result = await mcpExecutor.execute(
                    'list-connections',
                    filters,
                    `List ${service} connections`
                );

                performanceMonitor.endTimer(`service-${service}`);

                if (result.result) {
                    const data = JSON.parse(result.result);
                    results[service] = data;
                    
                    console.log(this.formatter.format(data, `🔌 ${service.toUpperCase()} Connections`));
                    
                    const count = data.connections?.length || 0;
                    logger.success(`Found ${count} ${service} connections`);
                }

            } catch (error) {
                logger.error(`Failed to filter ${service} connections`, error);
                results[service] = { error: error.message };
            }
        }

        return results;
    }

    /**
     * Demonstrate status-based filtering
     */
    async demonstrateStatusFiltering() {
        logger.info('📊 Demonstrating status-based filtering...');

        const statuses = ['valid', 'invalid', 'all'];
        const results = {};

        for (const status of statuses) {
            try {
                logger.info(`Filtering connections by status: ${status}`);
                
                performanceMonitor.startTimer(`status-${status}`);
                
                const filters = {
                    status: status,
                    limit: 15,
                    offset: 0
                };

                const result = await mcpExecutor.execute(
                    'list-connections',
                    filters,
                    `List ${status} connections`
                );

                performanceMonitor.endTimer(`status-${status}`);

                if (result.result) {
                    const data = JSON.parse(result.result);
                    results[status] = data;
                    
                    console.log(this.formatter.format(data, `${status === 'valid' ? '✅' : status === 'invalid' ? '❌' : '📋'} ${status.toUpperCase()} Connections`));
                    
                    const count = data.connections?.length || 0;
                    logger.success(`Found ${count} ${status} connections`);
                }

            } catch (error) {
                logger.error(`Failed to filter ${status} connections`, error);
                results[status] = { error: error.message };
            }
        }

        return results;
    }

    /**
     * Demonstrate text search functionality
     */
    async demonstrateTextSearch() {
        logger.info('🔍 Demonstrating text search functionality...');

        const searchTerms = ['test', 'gmail', 'api', 'production'];
        const results = {};

        for (const term of searchTerms) {
            try {
                logger.info(`Searching connections for term: "${term}"`);
                
                performanceMonitor.startTimer(`search-${term}`);
                
                const filters = {
                    search: term,
                    limit: 10,
                    offset: 0,
                    status: 'all'
                };

                const result = await mcpExecutor.execute(
                    'list-connections',
                    filters,
                    `Search connections for "${term}"`
                );

                performanceMonitor.endTimer(`search-${term}`);

                if (result.result) {
                    const data = JSON.parse(result.result);
                    results[term] = data;
                    
                    console.log(this.formatter.format(data, `🔍 Search Results for "${term}"`));
                    
                    const count = data.connections?.length || 0;
                    logger.success(`Found ${count} connections matching "${term}"`);
                    
                    // Show matching details
                    if (data.connections && data.connections.length > 0) {
                        data.connections.forEach(conn => {
                            const matchFields = [];
                            if (conn.name && conn.name.toLowerCase().includes(term.toLowerCase())) {
                                matchFields.push('name');
                            }
                            if (conn.service && conn.service.toLowerCase().includes(term.toLowerCase())) {
                                matchFields.push('service');
                            }
                            if (conn.accountName && conn.accountName.toLowerCase().includes(term.toLowerCase())) {
                                matchFields.push('accountName');
                            }
                            
                            logger.debug(`  - ${conn.name} (matches in: ${matchFields.join(', ')})`);
                        });
                    }
                }

            } catch (error) {
                logger.error(`Failed to search for "${term}"`, error);
                results[term] = { error: error.message };
            }
        }

        return results;
    }

    /**
     * Demonstrate pagination functionality
     */
    async demonstratePagination() {
        logger.info('📄 Demonstrating pagination functionality...');

        const pageSize = 5;
        const maxPages = 3;
        const results = [];

        for (let page = 0; page < maxPages; page++) {
            try {
                const offset = page * pageSize;
                logger.info(`Fetching page ${page + 1} (offset: ${offset}, limit: ${pageSize})`);
                
                performanceMonitor.startTimer(`page-${page + 1}`);
                
                const filters = {
                    limit: pageSize,
                    offset: offset,
                    status: 'all'
                };

                const result = await mcpExecutor.execute(
                    'list-connections',
                    filters,
                    `Fetch page ${page + 1}`
                );

                performanceMonitor.endTimer(`page-${page + 1}`);

                if (result.result) {
                    const data = JSON.parse(result.result);
                    results.push(data);
                    
                    console.log(this.formatter.format(data, `📄 Page ${page + 1} of Connections`));
                    
                    const count = data.connections?.length || 0;
                    logger.success(`Page ${page + 1}: ${count} connections`);
                    
                    if (data.pagination) {
                        logger.info(`Progress: ${offset + count}/${data.pagination.total} connections`);
                        
                        // Stop if we've reached the end
                        if (!data.pagination.hasMore) {
                            logger.info('Reached end of results');
                            break;
                        }
                    }
                    
                    // Stop if no more connections
                    if (count === 0) {
                        logger.info('No more connections found');
                        break;
                    }
                }

            } catch (error) {
                logger.error(`Failed to fetch page ${page + 1}`, error);
                results.push({ error: error.message, page: page + 1 });
            }
        }

        return results;
    }

    /**
     * Demonstrate advanced filtering combinations
     */
    async demonstrateAdvancedFiltering() {
        logger.info('🎯 Demonstrating advanced filtering combinations...');

        const advancedFilters = [
            {
                name: 'Valid Gmail connections',
                filters: {
                    service: 'gmail',
                    status: 'valid',
                    limit: 10
                }
            },
            {
                name: 'Invalid connections with search',
                filters: {
                    status: 'invalid',
                    search: 'test',
                    limit: 10
                }
            },
            {
                name: 'API connections only',
                filters: {
                    search: 'api',
                    status: 'all',
                    limit: 5
                }
            },
            {
                name: 'Recent connections (limited)',
                filters: {
                    limit: 3,
                    offset: 0,
                    status: 'all'
                }
            }
        ];

        const results = {};

        for (const config of advancedFilters) {
            try {
                logger.info(`Testing: ${config.name}`);
                
                performanceMonitor.startTimer(`advanced-${config.name.replace(/\s+/g, '-').toLowerCase()}`);
                
                const result = await mcpExecutor.execute(
                    'list-connections',
                    config.filters,
                    config.name
                );

                performanceMonitor.endTimer(`advanced-${config.name.replace(/\s+/g, '-').toLowerCase()}`);

                if (result.result) {
                    const data = JSON.parse(result.result);
                    results[config.name] = data;
                    
                    console.log(this.formatter.format(data, `🎯 ${config.name}`));
                    
                    const count = data.connections?.length || 0;
                    logger.success(`${config.name}: ${count} connections found`);
                    
                    // Show filter effectiveness
                    logger.debug(`Filters applied: ${JSON.stringify(config.filters)}`);
                }

            } catch (error) {
                logger.error(`Failed advanced filter: ${config.name}`, error);
                results[config.name] = { error: error.message };
            }
        }

        return results;
    }

    /**
     * Run all demonstrations
     */
    async runAllDemonstrations() {
        logger.info('🚀 Starting comprehensive connection filtering demonstration...');
        
        const results = {
            basic: null,
            serviceFiltering: null,
            statusFiltering: null,
            textSearch: null,
            pagination: null,
            advancedFiltering: null
        };

        try {
            // Basic listing
            results.basic = await this.demonstrateBasicListing();
            console.log('\n' + '─'.repeat(60) + '\n');

            // Service filtering
            results.serviceFiltering = await this.demonstrateServiceFiltering();
            console.log('\n' + '─'.repeat(60) + '\n');

            // Status filtering
            results.statusFiltering = await this.demonstrateStatusFiltering();
            console.log('\n' + '─'.repeat(60) + '\n');

            // Text search
            results.textSearch = await this.demonstrateTextSearch();
            console.log('\n' + '─'.repeat(60) + '\n');

            // Pagination
            results.pagination = await this.demonstratePagination();
            console.log('\n' + '─'.repeat(60) + '\n');

            // Advanced filtering
            results.advancedFiltering = await this.demonstrateAdvancedFiltering();

            // Performance summary
            const perfSummary = performanceMonitor.getSummary();
            console.log('\n' + '═'.repeat(60));
            console.log('📊 PERFORMANCE SUMMARY');
            console.log('═'.repeat(60));
            console.log(`Total Operations: ${perfSummary.totalOperations}`);
            console.log(`Completed Operations: ${perfSummary.completedOperations}`);
            console.log(`Total Time: ${perfSummary.totalTime}ms`);
            console.log(`Average Time: ${Math.round(perfSummary.averageTime)}ms`);
            
            logger.success('🎉 All demonstrations completed successfully!');

        } catch (error) {
            logger.error('Demonstration failed', error);
            throw error;
        }

        return results;
    }
}

/**
 * Main execution function
 */
async function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    let operation = 'all';
    const options = {
        service: null,
        status: 'all',
        search: null,
        limit: 10,
        offset: 0,
        format: 'json'
    };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--operation':
                operation = args[++i];
                break;
            case '--service':
                options.service = args[++i];
                break;
            case '--status':
                options.status = args[++i];
                break;
            case '--search':
                options.search = args[++i];
                break;
            case '--limit':
                options.limit = parseInt(args[++i]);
                break;
            case '--offset':
                options.offset = parseInt(args[++i]);
                break;
            case '--format':
                options.format = args[++i];
                break;
            case '--help':
                console.log(`
Make.com FastMCP Server - Connection List and Filter Demo

Usage: node list-and-filter.js [options]

Operations:
  --operation OPERATION    Run specific demo (basic|service|status|search|pagination|advanced|all)
  
Filters:
  --service SERVICE        Filter by service type (gmail|slack|mysql|custom_api)
  --status STATUS          Filter by status (valid|invalid|all)
  --search TERM           Search connections by name/service
  --limit NUMBER          Maximum connections to return
  --offset NUMBER         Number of connections to skip
  
Output:
  --format FORMAT         Output format (json|table|detailed|summary)
  --help                  Show this help message

Examples:
  node list-and-filter.js                                    # Run all demos
  node list-and-filter.js --operation service               # Service filtering demo
  node list-and-filter.js --service gmail --status valid    # Custom filter
  node list-and-filter.js --search test --format table      # Search with table output
                `);
                return;
            default:
                if (args[i].startsWith('--')) {
                    logger.error(`Unknown option: ${args[i]}`);
                    process.exit(1);
                }
        }
    }

    // Initialize demo
    const startTime = new Date();
    fs.writeFileSync(CONFIG.logFile, `Make.com FastMCP Connection Filter Demo - ${startTime.toISOString()}\n`);

    logger.info('Make.com FastMCP Server - Connection List and Filter Demo');
    logger.info(`Operation: ${operation}`);
    logger.info(`Options: ${JSON.stringify(options)}`);
    logger.info(`Log file: ${CONFIG.logFile}`);
    console.log('');

    const demo = new ConnectionFilterDemo(options.format);

    try {
        let result;

        switch (operation) {
            case 'basic':
                result = await demo.demonstrateBasicListing();
                break;
            case 'service':
                result = await demo.demonstrateServiceFiltering();
                break;
            case 'status':
                result = await demo.demonstrateStatusFiltering();
                break;
            case 'search':
                result = await demo.demonstrateTextSearch();
                break;
            case 'pagination':
                result = await demo.demonstratePagination();
                break;
            case 'advanced':
                result = await demo.demonstrateAdvancedFiltering();
                break;
            case 'custom': {
                // Run custom filter with provided options
                const filters = {};
                if (options.service) filters.service = options.service;
                if (options.status !== 'all') filters.status = options.status;
                if (options.search) filters.search = options.search;
                filters.limit = options.limit;
                filters.offset = options.offset;

                logger.info('🎯 Running custom filter...');
                const customResult = await mcpExecutor.execute(
                    'list-connections',
                    filters,
                    'Custom connection filter'
                );

                if (customResult.result) {
                    const data = JSON.parse(customResult.result);
                    console.log(demo.formatter.format(data, '🎯 Custom Filter Results'));
                }
                result = customResult;
                break;
            }
            case 'all':
            default:
                result = await demo.runAllDemonstrations();
                break;
        }

        const endTime = new Date();
        const duration = endTime - startTime;
        logger.success(`Demo completed successfully in ${duration}ms`);

        return result;

    } catch (error) {
        logger.error(`Demo failed: ${error.message}`);
        process.exit(1);
    }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, _promise) => {
    logger.error(`Unhandled Rejection: ${reason}`);
    process.exit(1);
});

// Run main function if script is executed directly
if (require.main === module) {
    main();
}

module.exports = { ConnectionFilterDemo };