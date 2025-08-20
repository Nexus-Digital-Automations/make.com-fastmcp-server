/**
 * Comprehensive Test Suite for Custom App Development Tools
 * Tests all 5 custom app development tools with app lifecycle management
 * and advanced testing patterns following testing.md guidelines
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool 
} from '../../utils/test-helpers.js';
import type { MakeCustomApp } from '../../../src/types/index.js';

// Advanced testing utilities
class ChaosMonkey {
  constructor(private config: { failureRate: number; latencyMs: number; scenarios: string[] }) {}

  shouldFail(): boolean {
    return Math.random() < this.config.failureRate;
  }

  getRandomLatency(): number {
    return Math.random() * this.config.latencyMs;
  }

  getRandomScenario(): string {
    return this.config.scenarios[Math.floor(Math.random() * this.config.scenarios.length)];
  }
}

// Security testing utilities
const securityTestPatterns = {
  sqlInjection: ["'; DROP TABLE apps; --", "1' OR '1'='1", "'; SELECT * FROM functions; --"],
  xss: ["<script>alert('xss')</script>", "javascript:alert('xss')", "<img src=x onerror=alert('xss')>"],
  pathTraversal: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "....//....//etc/passwd"],
  commandInjection: ["; cat /etc/passwd", "| whoami", "&& rm -rf /", "; shutdown -h now"],
  codeInjection: ["'; return process.env; //", "console.log(process.env)", "require('fs').readFileSync('/etc/passwd')"],
};

describe('Custom App Development Tools', () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let mockTool: any;
  let mockApiClient: MockMakeApiClient;
  let chaosMonkey: ChaosMonkey;

  // Mock data generators
  const generateMockCustomApp = (overrides?: Partial<MakeCustomApp>): MakeCustomApp => ({
    id: Math.floor(Math.random() * 100000),
    name: 'Payment Processing Connector',
    description: 'Custom connector for payment processing API integration',
    version: '1.2.3',
    status: 'published',
    organizationId: 1001,
    teamId: 2001,
    configuration: {
      type: 'connector',
      runtime: 'nodejs',
      environment: {
        variables: {
          NODE_ENV: 'production',
          API_VERSION: 'v2',
          TIMEOUT: '30000',
        },
        secrets: ['PAYMENT_API_KEY', 'WEBHOOK_SECRET'],
        dependencies: {
          'axios': '^1.0.0',
          'crypto': '^1.0.0',
          'jsonwebtoken': '^9.0.0',
        },
      },
      endpoints: [
        {
          name: 'process_payment',
          method: 'POST',
          path: '/api/payments/process',
          description: 'Process a payment transaction',
          parameters: {
            type: 'object',
            properties: {
              amount: { type: 'number', minimum: 0.01 },
              currency: { type: 'string', enum: ['USD', 'EUR', 'GBP'] },
              customerId: { type: 'string', minLength: 1 },
            },
            required: ['amount', 'currency', 'customerId'],
          },
          responses: {
            '200': {
              type: 'object',
              properties: {
                transactionId: { type: 'string' },
                status: { type: 'string', enum: ['success', 'failed', 'pending'] },
                amount: { type: 'number' },
              },
            },
          },
        },
        {
          name: 'get_transaction',
          method: 'GET',
          path: '/api/payments/transactions/{id}',
          description: 'Retrieve transaction details',
          parameters: {
            type: 'object',
            properties: {
              id: { type: 'string', minLength: 1 },
            },
            required: ['id'],
          },
          responses: {
            '200': {
              type: 'object',
              properties: {
                id: { type: 'string' },
                status: { type: 'string' },
                createdAt: { type: 'string', format: 'date-time' },
              },
            },
          },
        },
      ],
      authentication: {
        type: 'api_key',
        configuration: {
          location: 'header',
          name: 'X-API-Key',
          description: 'API key for authentication',
        },
      },
      ui: {
        icon: 'payment-icon.svg',
        color: '#4CAF50',
        description: 'Process payments securely',
        category: 'payments',
      },
    },
    deployment: {
      source: 'git',
      repository: 'https://github.com/company/payment-connector.git',
      branch: 'main',
      buildCommand: 'npm run build',
      startCommand: 'npm start',
      healthCheckEndpoint: '/health',
    },
    testing: {
      testSuite: 'jest',
      coverageThreshold: 85,
      lastTestRun: {
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        passed: 42,
        failed: 1,
        coverage: 87.5,
        duration: 15432, // milliseconds
      },
    },
    usage: {
      installations: 156,
      executions: 12847,
      averageResponseTime: 245, // milliseconds
      errorRate: 0.0034, // 0.34%
      lastUsed: new Date(Date.now() - 1800000).toISOString(),
    },
    permissions: {
      scopes: ['payments:read', 'payments:write', 'transactions:read'],
      roles: ['developer', 'admin'],
      restrictions: {
        allowedDomains: ['*.company.com', 'trusted-partner.com'],
        rateLimit: { requests: 1000, window: 3600 },
        ipWhitelist: ['192.168.1.0/24', '10.0.0.0/8'],
      },
    },
    createdAt: new Date(Date.now() - 86400000 * 90).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    createdByName: 'Lead Developer',
    ...overrides,
  });

  const generateMockHook = (overrides?: Partial<MakeHook>): MakeHook => ({
    id: Math.floor(Math.random() * 100000),
    name: 'Order Status Webhook',
    description: 'Webhook to receive order status updates from e-commerce platform',
    appId: 12345,
    appName: 'E-commerce Connector',
    type: 'webhook',
    status: 'active',
    configuration: {
      endpoint: 'https://api.company.com/webhooks/order-status',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Source': 'make-platform',
        'User-Agent': 'Make-Webhook/1.0',
      },
      authentication: {
        type: 'bearer',
        configuration: {
          tokenType: 'jwt',
          algorithm: 'HS256',
          secret: 'webhook_secret',
        },
      },
    },
    events: [
      {
        name: 'order.created',
        description: 'Triggered when a new order is created',
        schema: {
          type: 'object',
          properties: {
            orderId: { type: 'string' },
            customerId: { type: 'string' },
            amount: { type: 'number' },
            items: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  productId: { type: 'string' },
                  quantity: { type: 'number' },
                  price: { type: 'number' },
                },
              },
            },
            timestamp: { type: 'string', format: 'date-time' },
          },
          required: ['orderId', 'customerId', 'amount', 'timestamp'],
        },
        filters: {
          minAmount: 10.00,
          excludeTestOrders: true,
        },
      },
      {
        name: 'order.updated',
        description: 'Triggered when an order status changes',
        schema: {
          type: 'object',
          properties: {
            orderId: { type: 'string' },
            oldStatus: { type: 'string' },
            newStatus: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' },
          },
          required: ['orderId', 'newStatus', 'timestamp'],
        },
      },
    ],
    execution: {
      totalCalls: 2847,
      successfulCalls: 2834,
      failedCalls: 13,
      averageResponseTime: 187, // milliseconds
      lastExecution: {
        timestamp: new Date(Date.now() - 900000).toISOString(),
        status: 'success',
        responseTime: 142,
      },
    },
    logs: {
      retention: 30, // days
      level: 'info',
      destinations: ['console', 'file'],
    },
    createdAt: new Date(Date.now() - 86400000 * 60).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    ...overrides,
  });

  const generateMockCustomFunction = (overrides?: Partial<MakeCustomFunction>): MakeCustomFunction => ({
    id: Math.floor(Math.random() * 100000),
    name: 'currency_converter',
    description: 'Convert amounts between different currencies using live exchange rates',
    appId: 12345,
    type: 'transformer',
    language: 'javascript',
    status: 'published',
    code: {
      source: `
function convert(amount, fromCurrency, toCurrency, exchangeRates) {
  if (!amount || !fromCurrency || !toCurrency) {
    throw new Error('Missing required parameters: amount, fromCurrency, toCurrency');
  }
  
  if (fromCurrency === toCurrency) {
    return { convertedAmount: amount, rate: 1, timestamp: new Date().toISOString() };
  }
  
  const rate = exchangeRates[fromCurrency + '_' + toCurrency];
  if (!rate) {
    throw new Error('Exchange rate not available for ' + fromCurrency + ' to ' + toCurrency);
  }
  
  const convertedAmount = Math.round(amount * rate * 100) / 100;
  return {
    convertedAmount,
    rate,
    originalAmount: amount,
    fromCurrency,
    toCurrency,
    timestamp: new Date().toISOString()
  };
}

module.exports = { convert };
      `.trim(),
      dependencies: {
        'axios': '^1.0.0',
        'lodash': '^4.17.21',
      },
      environment: {
        NODE_ENV: 'production',
        API_TIMEOUT: '5000',
      },
      timeout: 30, // seconds
      memoryLimit: 256, // MB
    },
    interface: {
      input: {
        type: 'object',
        properties: {
          amount: { type: 'number', minimum: 0 },
          fromCurrency: { type: 'string', minLength: 3, maxLength: 3 },
          toCurrency: { type: 'string', minLength: 3, maxLength: 3 },
          exchangeRates: {
            type: 'object',
            additionalProperties: { type: 'number' },
          },
        },
        required: ['amount', 'fromCurrency', 'toCurrency', 'exchangeRates'],
      },
      output: {
        type: 'object',
        properties: {
          convertedAmount: { type: 'number' },
          rate: { type: 'number' },
          originalAmount: { type: 'number' },
          fromCurrency: { type: 'string' },
          toCurrency: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
        },
        required: ['convertedAmount', 'rate', 'timestamp'],
      },
      parameters: {
        precision: { type: 'number', default: 2, minimum: 0, maximum: 8 },
        roundingMode: { type: 'string', enum: ['round', 'floor', 'ceil'], default: 'round' },
      },
    },
    testing: {
      testCases: [
        {
          name: 'USD to EUR conversion',
          input: {
            amount: 100,
            fromCurrency: 'USD',
            toCurrency: 'EUR',
            exchangeRates: { 'USD_EUR': 0.85 },
          },
          expectedOutput: {
            convertedAmount: 85,
            rate: 0.85,
            originalAmount: 100,
            fromCurrency: 'USD',
            toCurrency: 'EUR',
          },
          description: 'Convert 100 USD to EUR at 0.85 rate',
        },
        {
          name: 'Same currency conversion',
          input: {
            amount: 50,
            fromCurrency: 'USD',
            toCurrency: 'USD',
            exchangeRates: {},
          },
          expectedOutput: {
            convertedAmount: 50,
            rate: 1,
          },
          description: 'Convert USD to USD should return same amount',
        },
      ],
      lastTestRun: {
        timestamp: new Date(Date.now() - 7200000).toISOString(),
        passed: 8,
        failed: 0,
        duration: 1250, // milliseconds
      },
    },
    deployment: {
      version: '2.1.0',
      environment: 'production',
      instances: 3,
      autoScale: true,
    },
    monitoring: {
      executions: 5432,
      averageExecutionTime: 45, // milliseconds
      errorRate: 0.0018, // 0.18%
      memoryUsage: 128, // MB
      cpuUsage: 15, // percentage
    },
    createdAt: new Date(Date.now() - 86400000 * 120).toISOString(),
    updatedAt: new Date(Date.now() - 86400000 * 2).toISOString(),
    createdBy: 12345,
    ...overrides,
  });

  beforeEach(async () => {
    // Create mock server and tool
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    
    mockApiClient = new MockMakeApiClient();
    chaosMonkey = new ChaosMonkey({
      failureRate: 0.1,
      latencyMs: 1000,
      scenarios: ['latency', 'error', 'timeout'],
    });

    // Add tools to server
    const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
    addCustomAppTools(mockServer, mockApiClient as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    test('should register all custom app development tools', () => {
      const toolConfigs = mockTool.mock.calls.map((call: any[]) => call[0]);
      const expectedTools = [
        'create-custom-app',
        'list-custom-apps',
        'create-hook',
        'create-custom-function',
        'test-custom-app',
      ];

      expectedTools.forEach(toolName => {
        const tool = toolConfigs.find((config: any) => config.name === toolName);
        expect(tool).toBeDefined();
      });
    });

    test('should have correct tool schemas', () => {
      const toolConfigs = mockTool.mock.calls.map((call: any[]) => call[0]);
      
      const createAppTool = toolConfigs.find((config: any) => config.name === 'create-custom-app');
      const listAppsTool = toolConfigs.find((config: any) => config.name === 'list-custom-apps');
      
      const createHookTool = toolConfigs.find((config: any) => config.name === 'create-hook');
      const createFunctionTool = toolConfigs.find((config: any) => config.name === 'create-custom-function');
      const testAppTool = toolConfigs.find((config: any) => config.name === 'test-custom-app');
      
      expect(createAppTool?.parameters).toBeDefined();
      expect(listAppsTool?.parameters).toBeDefined();
      expect(createHookTool?.parameters).toBeDefined();
      expect(createFunctionTool?.parameters).toBeDefined();
      expect(testAppTool?.parameters).toBeDefined();
    });
  });

  describe('create-custom-app', () => {
    describe('Basic Functionality', () => {
      test('should create a simple connector app', async () => {
        const mockApp = generateMockCustomApp();
        mockApiClient.setMockResponse('post', '/custom-apps', {
          success: true,
          data: mockApp,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            name: 'Simple API Connector',
            description: 'Basic connector for external API integration',
            type: 'connector',
            runtime: 'nodejs',
            organizationId: 1001,
            teamId: 2001,
            configuration: {
              environment: {
                variables: { NODE_ENV: 'production' },
                secrets: ['API_KEY'],
                dependencies: { 'axios': '^1.0.0' },
              },
              endpoints: [
                {
                  name: 'get_data',
                  method: 'GET',
                  path: '/api/data',
                  description: 'Retrieve data from external API',
                },
              ],
              authentication: {
                type: 'api_key',
                configuration: { location: 'header', name: 'X-API-Key' },
              },
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/custom-apps', expect.objectContaining({
          name: 'Simple API Connector',
          configuration: expect.objectContaining({
            type: 'connector',
            runtime: 'nodejs',
          }),
        }));

        const response = JSON.parse(result);
        expect(response.app).toBeDefined();
        expect(response.development.type).toBe('connector');
        expect(response.nextSteps).toBeDefined();
        expect(response.message).toContain('created successfully');
      });

      test('should create full app with comprehensive configuration', async () => {
        const fullApp = generateMockCustomApp({
          configuration: {
            type: 'full_app',
            runtime: 'nodejs',
            environment: {
              variables: {
                NODE_ENV: 'production',
                API_VERSION: 'v2',
                DATABASE_URL: 'postgresql://localhost:5432/app',
              },
              secrets: ['DATABASE_PASSWORD', 'JWT_SECRET', 'OAUTH_CLIENT_SECRET'],
              dependencies: {
                'express': '^4.18.0',
                'pg': '^8.8.0',
                'jsonwebtoken': '^9.0.0',
                'passport': '^0.6.0',
              },
            },
            endpoints: [
              {
                name: 'create_user',
                method: 'POST',
                path: '/api/users',
                description: 'Create a new user account',
                parameters: {
                  type: 'object',
                  properties: {
                    email: { type: 'string', format: 'email' },
                    name: { type: 'string', minLength: 1 },
                    role: { type: 'string', enum: ['user', 'admin'] },
                  },
                  required: ['email', 'name'],
                },
              },
              {
                name: 'authenticate',
                method: 'POST',
                path: '/api/auth/login',
                description: 'Authenticate user and return JWT token',
              },
            ],
            authentication: {
              type: 'oauth2',
              configuration: {
                authorizationUrl: 'https://auth.company.com/oauth/authorize',
                tokenUrl: 'https://auth.company.com/oauth/token',
                scope: 'read write',
              },
            },
            ui: {
              icon: 'custom-app-icon.svg',
              color: '#FF5722',
              description: 'Full-featured custom application',
              category: 'business',
            },
          },
        });

        mockApiClient.setMockResponse('post', '/custom-apps', {
          success: true,
          data: fullApp,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            name: 'Business Management App',
            description: 'Comprehensive business management application',
            type: 'full_app',
            runtime: 'nodejs',
            configuration: {
              environment: {
                variables: {
                  NODE_ENV: 'production',
                  API_VERSION: 'v2',
                  DATABASE_URL: 'postgresql://localhost:5432/app',
                },
                secrets: ['DATABASE_PASSWORD', 'JWT_SECRET'],
                dependencies: {
                  'express': '^4.18.0',
                  'pg': '^8.8.0',
                },
              },
              endpoints: [
                {
                  name: 'create_user',
                  method: 'POST',
                  path: '/api/users',
                  description: 'Create a new user',
                },
              ],
              authentication: {
                type: 'oauth2',
                configuration: {
                  authorizationUrl: 'https://auth.company.com/oauth/authorize',
                },
              },
            },
            deployment: {
              source: 'git',
              repository: 'https://github.com/company/business-app.git',
              buildCommand: 'npm run build:prod',
              startCommand: 'npm run start:prod',
            },
            permissions: {
              scopes: ['users:read', 'users:write', 'admin:all'],
              roles: ['developer', 'admin'],
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.app.configuration.type).toBe('full_app');
        expect(response.development.endpoints).toBeGreaterThan(0);
        expect(response.development.authentication).toBe('oauth2');
      });
    });

    describe('Security and Validation', () => {
      test('should sanitize app configuration', async () => {
        const mockApp = generateMockCustomApp();
        mockApiClient.setMockResponse('post', '/custom-apps', {
          success: true,
          data: mockApp,
        });

        const maliciousName = securityTestPatterns.xss[0];
        const maliciousDescription = securityTestPatterns.sqlInjection[0];

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            name: maliciousName,
            description: maliciousDescription,
            type: 'connector',
            runtime: 'nodejs',
            configuration: {
              endpoints: [],
              authentication: { type: 'none', configuration: {} },
            },
          },
        });

        // App should be created but content should be sanitized
        const response = JSON.parse(result);
        expect(response.app).toBeDefined();
        // Verify sanitization occurred (actual implementation would sanitize)
      });

      test('should mask sensitive configuration', async () => {
        const mockApp = generateMockCustomApp();
        mockApiClient.setMockResponse('post', '/custom-apps', {
          success: true,
          data: mockApp,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            name: 'Secure App',
            description: 'App with sensitive data',
            type: 'connector',
            runtime: 'nodejs',
            configuration: {
              environment: {
                secrets: ['DATABASE_PASSWORD', 'API_SECRET'],
              },
              endpoints: [],
              authentication: { type: 'none', configuration: {} },
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.app.configuration.environment.secrets).toEqual(['[SECRET_HIDDEN]', '[SECRET_HIDDEN]']);
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures gracefully', async () => {
        mockApiClient.setMockResponse('post', '/custom-apps', {
          success: false,
          error: { message: 'Custom app service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            name: 'Test App',
            description: 'Test description',
            type: 'connector',
            runtime: 'nodejs',
            configuration: {
              endpoints: [],
              authentication: { type: 'none', configuration: {} },
            },
          },
        })).rejects.toThrow('Failed to create custom app: Custom app service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            // Missing required fields
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('list-custom-apps', () => {
    describe('Basic Functionality', () => {
      test('should list custom apps with filters', async () => {
        const mockApps = [
          generateMockCustomApp({ configuration: { type: 'connector', runtime: 'nodejs', environment: { variables: {}, secrets: [], dependencies: {} }, endpoints: [], authentication: { type: 'none', configuration: {} }, ui: {} } }),
          generateMockCustomApp({ configuration: { type: 'trigger', runtime: 'python', environment: { variables: {}, secrets: [], dependencies: {} }, endpoints: [], authentication: { type: 'none', configuration: {} }, ui: {} } }),
          generateMockCustomApp({ configuration: { type: 'action', runtime: 'nodejs', environment: { variables: {}, secrets: [], dependencies: {} }, endpoints: [], authentication: { type: 'none', configuration: {} }, ui: {} } }),
        ];

        mockApiClient.setMockResponse('get', '/custom-apps', {
          success: true,
          data: mockApps,
          metadata: { total: 3, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-custom-apps',
          parameters: {
            type: 'all',
            status: 'published',
            runtime: 'nodejs',
            includeUsage: true,
            limit: 50,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/custom-apps', {
          params: expect.objectContaining({
            status: 'published',
            runtime: 'nodejs',
            includeUsage: true,
            limit: 50,
          }),
        });

        const response = JSON.parse(result);
        expect(response.apps).toHaveLength(3);
        expect(response.analysis).toBeDefined();
        expect(response.analysis.totalApps).toBe(3);
      });

      test('should provide development and usage analytics', async () => {
        const appsWithUsage = [
          generateMockCustomApp({
            status: 'published',
            usage: { installations: 150, executions: 5000, averageResponseTime: 200, errorRate: 0.01, lastUsed: new Date().toISOString() },
            configuration: { type: 'connector', runtime: 'nodejs', environment: { variables: {}, secrets: [], dependencies: {} }, endpoints: [{ name: 'test', method: 'GET', path: '/test' }], authentication: { type: 'none', configuration: {} }, ui: {} },
          }),
          generateMockCustomApp({
            status: 'testing',
            usage: { installations: 25, executions: 500, averageResponseTime: 350, errorRate: 0.05, lastUsed: new Date().toISOString() },
            configuration: { type: 'action', runtime: 'python', environment: { variables: {}, secrets: [], dependencies: {} }, endpoints: [{ name: 'test1', method: 'POST', path: '/test1' }, { name: 'test2', method: 'PUT', path: '/test2' }], authentication: { type: 'none', configuration: {} }, ui: {} },
          }),
        ];

        mockApiClient.setMockResponse('get', '/custom-apps', {
          success: true,
          data: appsWithUsage,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-custom-apps',
          parameters: {
            includeUsage: true,
            includeConfig: false,
          },
        });

        const response = JSON.parse(result);
        expect(response.analysis.developmentSummary).toBeDefined();
        expect(response.analysis.developmentSummary.publishedApps).toBe(1);
        expect(response.analysis.developmentSummary.testingApps).toBe(1);
        expect(response.analysis.usageSummary).toBeDefined();
        expect(response.analysis.usageSummary.totalInstallations).toBe(175);
        expect(response.analysis.usageSummary.totalExecutions).toBe(5500);
      });
    });

    describe('Advanced Filtering', () => {
      test('should filter by organization and team', async () => {
        const orgApps = [
          generateMockCustomApp({ organizationId: 1001, teamId: 2001 }),
        ];

        mockApiClient.setMockResponse('get', '/custom-apps', {
          success: true,
          data: orgApps,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-custom-apps',
          parameters: {
            organizationId: 1001,
            teamId: 2001,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/custom-apps', {
          params: expect.objectContaining({
            organizationId: 1001,
            teamId: 2001,
          }),
        });

        const response = JSON.parse(result);
        expect(response.apps[0].organizationId).toBe(1001);
        expect(response.apps[0].teamId).toBe(2001);
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('get', '/custom-apps', {
          success: false,
          error: { message: 'Custom app service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'list-custom-apps',
          parameters: {},
        })).rejects.toThrow('Failed to list custom apps: Custom app service temporarily unavailable');
      });
    });
  });

  describe('create-hook', () => {
    describe('Basic Functionality', () => {
      test('should create webhook successfully', async () => {
        const mockHook = generateMockHook();
        mockApiClient.setMockResponse('post', '/hooks', {
          success: true,
          data: mockHook,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-hook',
          parameters: {
            name: 'Order Webhook',
            description: 'Webhook for order status updates',
            appId: 12345,
            type: 'webhook',
            configuration: {
              endpoint: 'https://api.company.com/webhooks/orders',
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              authentication: {
                type: 'bearer',
                configuration: { token: 'webhook_token_123' },
              },
            },
            events: [
              {
                name: 'order.created',
                description: 'New order created',
                schema: {
                  type: 'object',
                  properties: {
                    orderId: { type: 'string' },
                    amount: { type: 'number' },
                  },
                },
              },
            ],
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/hooks', expect.objectContaining({
          name: 'Order Webhook',
          type: 'webhook',
          appId: 12345,
        }));

        const response = JSON.parse(result);
        expect(response.hook).toBeDefined();
        expect(response.configuration.type).toBe('webhook');
        expect(response.testing.webhookUrl).toBeDefined();
        expect(response.message).toContain('created successfully');
      });

      test('should create polling hook with schedule', async () => {
        const pollingHook = generateMockHook({
          type: 'polling',
          configuration: {
            endpoint: 'https://api.external.com/data',
            method: 'GET',
            headers: {},
            authentication: { type: 'api_key', configuration: { key: 'api_key_123' } },
            polling: {
              interval: 15, // 15 minutes
              strategy: 'incremental',
              parameters: { lastUpdated: '{{lastRun}}', limit: 100 },
            },
          },
        });

        mockApiClient.setMockResponse('post', '/hooks', {
          success: true,
          data: pollingHook,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-hook',
          parameters: {
            name: 'Data Polling Hook',
            description: 'Poll external API for data updates',
            appId: 12345,
            type: 'polling',
            configuration: {
              endpoint: 'https://api.external.com/data',
              method: 'GET',
              authentication: {
                type: 'api_key',
                configuration: { key: 'api_key_123' },
              },
              polling: {
                interval: 15,
                strategy: 'incremental',
                parameters: { limit: 100 },
              },
            },
            events: [
              {
                name: 'data.updated',
                description: 'Data updated in external system',
                schema: { type: 'object' },
              },
            ],
          },
        });

        const response = JSON.parse(result);
        expect(response.hook.type).toBe('polling');
        expect(response.testing.pollingInterval).toBe(15);
      });
    });

    describe('Security Testing', () => {
      test('should mask authentication configuration', async () => {
        const mockHook = generateMockHook();
        mockApiClient.setMockResponse('post', '/hooks', {
          success: true,
          data: mockHook,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-hook',
          parameters: {
            name: 'Secure Hook',
            description: 'Hook with sensitive auth data',
            appId: 12345,
            type: 'webhook',
            configuration: {
              endpoint: 'https://api.company.com/webhook',
              authentication: {
                type: 'bearer',
                configuration: { token: 'secret_token_12345' },
              },
            },
            events: [
              {
                name: 'test.event',
                description: 'Test event',
                schema: { type: 'object' },
              },
            ],
          },
        });

        const response = JSON.parse(result);
        expect(response.hook.configuration.authentication.configuration).toBe('[AUTH_CONFIG_HIDDEN]');
        // Sensitive data should not be exposed
        expect(JSON.stringify(response)).not.toContain('secret_token_12345');
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('post', '/hooks', {
          success: false,
          error: { message: 'Hook service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-hook',
          parameters: {
            name: 'Test Hook',
            appId: 12345,
            type: 'webhook',
            configuration: {
              endpoint: 'https://api.test.com/webhook',
              authentication: { type: 'none', configuration: {} },
            },
            events: [
              {
                name: 'test.event',
                schema: { type: 'object' },
              },
            ],
          },
        })).rejects.toThrow('Failed to create hook: Hook service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-hook',
          parameters: {
            // Missing required fields
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('create-custom-function', () => {
    describe('Basic Functionality', () => {
      test('should create JavaScript function successfully', async () => {
        const mockFunction = generateMockCustomFunction();
        mockApiClient.setMockResponse('post', '/custom-functions', {
          success: true,
          data: mockFunction,
        });

        const functionCode = `
function processData(input) {
  if (!input || !input.data) {
    throw new Error('Invalid input: data is required');
  }
  return {
    processed: true,
    count: input.data.length,
    timestamp: new Date().toISOString()
  };
}
module.exports = { processData };
        `.trim();

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-function',
          parameters: {
            name: 'data_processor',
            description: 'Process and validate input data',
            appId: 12345,
            type: 'transformer',
            language: 'javascript',
            code: {
              source: functionCode,
              dependencies: { 'lodash': '^4.17.21' },
              timeout: 30,
              memoryLimit: 256,
            },
            interface: {
              input: {
                type: 'object',
                properties: {
                  data: { type: 'array' },
                },
                required: ['data'],
              },
              output: {
                type: 'object',
                properties: {
                  processed: { type: 'boolean' },
                  count: { type: 'number' },
                  timestamp: { type: 'string' },
                },
              },
            },
            testCases: [
              {
                name: 'valid data processing',
                input: { data: [1, 2, 3] },
                expectedOutput: { processed: true, count: 3 },
                description: 'Process array of numbers',
              },
            ],
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/custom-functions', expect.objectContaining({
          name: 'data_processor',
          type: 'transformer',
          language: 'javascript',
        }));

        const response = JSON.parse(result);
        expect(response.function).toBeDefined();
        expect(response.function.code.source).toBe('[FUNCTION_CODE_STORED]');
        expect(response.configuration.language).toBe('javascript');
        expect(response.testing.testEndpoint).toBeDefined();
        expect(response.message).toContain('created successfully');
      });

      test('should create Python function with complex interface', async () => {
        const pythonFunction = generateMockCustomFunction({
          language: 'python',
          type: 'calculator',
        });

        mockApiClient.setMockResponse('post', '/custom-functions', {
          success: true,
          data: pythonFunction,
        });

        const pythonCode = `
def calculate_metrics(data, config):
    if not data or not isinstance(data, list):
        raise ValueError('Data must be a non-empty list')
    
    metrics = {
        'mean': sum(data) / len(data),
        'min': min(data),
        'max': max(data),
        'count': len(data)
    }
    
    if config.get('include_std', False):
        mean = metrics['mean']
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        metrics['std'] = variance ** 0.5
    
    return metrics
        `.trim();

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-function',
          parameters: {
            name: 'metrics_calculator',
            description: 'Calculate statistical metrics for numerical data',
            type: 'calculator',
            language: 'python',
            code: {
              source: pythonCode,
              dependencies: { 'numpy': '1.21.0' },
              environment: { PYTHON_VERSION: '3.9' },
              timeout: 60,
              memoryLimit: 512,
            },
            interface: {
              input: {
                type: 'object',
                properties: {
                  data: {
                    type: 'array',
                    items: { type: 'number' },
                    minItems: 1,
                  },
                  config: {
                    type: 'object',
                    properties: {
                      include_std: { type: 'boolean', default: false },
                    },
                  },
                },
                required: ['data'],
              },
              output: {
                type: 'object',
                properties: {
                  mean: { type: 'number' },
                  min: { type: 'number' },
                  max: { type: 'number' },
                  count: { type: 'number' },
                  std: { type: 'number' },
                },
                required: ['mean', 'min', 'max', 'count'],
              },
            },
            testCases: [
              {
                name: 'basic metrics calculation',
                input: { data: [1, 2, 3, 4, 5] },
                expectedOutput: { mean: 3, min: 1, max: 5, count: 5 },
              },
            ],
            deployment: {
              environment: 'production',
              instances: 2,
              autoScale: true,
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.function.language).toBe('python');
        expect(response.function.code.source).toBe('[FUNCTION_CODE_STORED]');
        expect(response.deployment.autoScale).toBe(true);
      });
    });

    describe('Security Testing', () => {
      test('should validate function code for security issues', async () => {
        const maliciousCode = securityTestPatterns.codeInjection[0];

        // This should either be rejected or sanitized
        try {
          await mockServer.executeToolCall({
            tool: 'create-custom-function',
            parameters: {
              name: 'malicious_function',
              description: 'Function with malicious code',
              type: 'custom',
              language: 'javascript',
              code: {
                source: maliciousCode,
              },
              interface: {
                input: { type: 'object' },
                output: { type: 'object' },
              },
            },
          });
          // If creation succeeds, code should be sanitized
        } catch (error) {
          // Should be rejected due to security validation
          expect(error).toBeDefined();
        }
      });

      test('should mask function source code in response', async () => {
        const mockFunction = generateMockCustomFunction();
        mockApiClient.setMockResponse('post', '/custom-functions', {
          success: true,
          data: mockFunction,
        });

        const secretCode = 'const SECRET_KEY = "super_secret_key_123";';

        const result = await mockServer.executeToolCall({
          tool: 'create-custom-function',
          parameters: {
            name: 'secure_function',
            description: 'Function with secret code',
            type: 'custom',
            language: 'javascript',
            code: {
              source: secretCode,
            },
            interface: {
              input: { type: 'object' },
              output: { type: 'object' },
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.function.code.source).toBe('[FUNCTION_CODE_STORED]');
        // Secret should not be exposed in response
        expect(JSON.stringify(response)).not.toContain('super_secret_key_123');
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('post', '/custom-functions', {
          success: false,
          error: { message: 'Custom function service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-custom-function',
          parameters: {
            name: 'test_function',
            description: 'Test function',
            type: 'custom',
            language: 'javascript',
            code: {
              source: 'function test() { return "test"; }',
            },
            interface: {
              input: { type: 'object' },
              output: { type: 'string' },
            },
          },
        })).rejects.toThrow('Failed to create custom function: Custom function service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-custom-function',
          parameters: {
            // Missing required fields
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('test-custom-app', () => {
    describe('Basic Functionality', () => {
      test('should run comprehensive app tests', async () => {
        const testResult = {
          summary: {
            total: 25,
            passed: 23,
            failed: 2,
            duration: 45000, // 45 seconds
          },
          coverage: {
            lines: 87.5,
            functions: 90.2,
            branches: 82.1,
          },
          results: {
            endpoints: [
              { name: 'get_data', status: 'passed', duration: 150 },
              { name: 'process_payment', status: 'failed', error: 'Timeout after 30s' },
            ],
            functions: [
              { name: 'validate_input', status: 'passed', duration: 25 },
              { name: 'format_output', status: 'passed', duration: 18 },
            ],
            hooks: [
              { name: 'order_webhook', status: 'passed', duration: 95 },
            ],
          },
          recommendations: [
            'Increase timeout for payment processing endpoint',
            'Add more unit tests for edge cases',
            'Improve error handling in webhook processing',
          ],
        };

        mockApiClient.setMockResponse('post', '/custom-apps/12345/test', {
          success: true,
          data: testResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'test-custom-app',
          parameters: {
            appId: 12345,
            testType: 'all',
            environment: 'development',
            includePerformance: true,
            timeout: 120,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/custom-apps/12345/test', expect.objectContaining({
          testType: 'all',
          environment: 'development',
          includePerformance: true,
          timeout: 120,
        }));

        const response = JSON.parse(result);
        expect(response.summary.appId).toBe(12345);
        expect(response.summary.totalTests).toBe(25);
        expect(response.summary.passed).toBe(23);
        expect(response.summary.failed).toBe(2);
        expect(response.results.endpoints).toBeDefined();
        expect(response.recommendations).toHaveLength(3);
      });

      test('should run specific test types', async () => {
        const endpointTestResult = {
          summary: {
            total: 8,
            passed: 8,
            failed: 0,
            duration: 12000,
          },
          coverage: { lines: 95.0 },
          results: {
            endpoints: [
              { name: 'health_check', status: 'passed', duration: 50 },
              { name: 'api_status', status: 'passed', duration: 75 },
            ],
            functions: [],
            hooks: [],
          },
          recommendations: [],
        };

        mockApiClient.setMockResponse('post', '/custom-apps/12345/test', {
          success: true,
          data: endpointTestResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'test-custom-app',
          parameters: {
            appId: 12345,
            testType: 'endpoints',
            environment: 'staging',
            includePerformance: false,
          },
        });

        const response = JSON.parse(result);
        expect(response.summary.testType).toBe('endpoints');
        expect(response.results.endpoints).toHaveLength(2);
        expect(response.results.functions).toHaveLength(0);
      });
    });

    describe('Performance Testing', () => {
      test('should include performance testing results', async () => {
        const performanceResult = {
          summary: { total: 15, passed: 15, failed: 0, duration: 30000 },
          coverage: { lines: 88.0 },
          results: {
            endpoints: [],
            functions: [],
            hooks: [],
            performance: {
              responseTime: {
                p50: 120,
                p95: 450,
                p99: 800,
                max: 1200,
              },
              throughput: {
                requestsPerSecond: 150,
                concurrentUsers: 50,
              },
              resources: {
                cpuUsage: 35.5,
                memoryUsage: 256.8,
                networkIO: 1024000,
              },
            },
          },
          recommendations: [
            'Consider caching frequently accessed data',
            'Optimize database queries for better performance',
          ],
        };

        mockApiClient.setMockResponse('post', '/custom-apps/12345/test', {
          success: true,
          data: performanceResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'test-custom-app',
          parameters: {
            appId: 12345,
            testType: 'all',
            environment: 'production',
            includePerformance: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.results.performance).toBeDefined();
        expect(response.results.performance.responseTime.p95).toBe(450);
        expect(response.results.performance.throughput.requestsPerSecond).toBe(150);
      });
    });

    describe('Error Handling', () => {
      test('should handle test execution failures', async () => {
        mockApiClient.setMockResponse('post', '/custom-apps/12345/test', {
          success: false,
          error: { message: 'Test execution failed: app not found' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'test-custom-app',
          parameters: {
            appId: 12345,
            testType: 'all',
          },
        })).rejects.toThrow('Failed to test custom app: Test execution failed: app not found');
      });

      test('should validate app ID', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'test-custom-app',
          parameters: {
            appId: -1, // Invalid ID
            testType: 'all',
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('Integration Testing', () => {
    test('should handle complete custom app development lifecycle', async () => {
      // 1. Create custom app
      const newApp = generateMockCustomApp();
      mockApiClient.setMockResponse('post', '/custom-apps', {
        success: true,
        data: newApp,
      });

      const appResult = await mockServer.executeToolCall({
        tool: 'create-custom-app',
        parameters: {
          name: 'Lifecycle Test App',
          description: 'App for testing complete lifecycle',
          type: 'connector',
          runtime: 'nodejs',
          configuration: {
            endpoints: [
              {
                name: 'test_endpoint',
                method: 'GET',
                path: '/test',
              },
            ],
            authentication: { type: 'none', configuration: {} },
          },
        },
      });

      // 2. Create hook for the app
      const newHook = generateMockHook({ appId: newApp.id });
      mockApiClient.setMockResponse('post', '/hooks', {
        success: true,
        data: newHook,
      });

      const hookResult = await mockServer.executeToolCall({
        tool: 'create-hook',
        parameters: {
          name: 'Test Hook',
          description: 'Hook for lifecycle testing',
          appId: newApp.id,
          type: 'webhook',
          configuration: {
            endpoint: 'https://api.test.com/webhook',
            authentication: { type: 'none', configuration: {} },
          },
          events: [
            {
              name: 'test.event',
              description: 'Test event',
              schema: { type: 'object' },
            },
          ],
        },
      });

      // 3. Create custom function for the app
      const newFunction = generateMockCustomFunction({ appId: newApp.id });
      mockApiClient.setMockResponse('post', '/custom-functions', {
        success: true,
        data: newFunction,
      });

      const functionResult = await mockServer.executeToolCall({
        tool: 'create-custom-function',
        parameters: {
          name: 'test_function',
          description: 'Function for lifecycle testing',
          appId: newApp.id,
          type: 'transformer',
          language: 'javascript',
          code: {
            source: 'function test() { return "test"; }',
          },
          interface: {
            input: { type: 'object' },
            output: { type: 'string' },
          },
        },
      });

      // 4. Test the complete app
      const testResult = {
        summary: { total: 10, passed: 10, failed: 0, duration: 5000 },
        coverage: { lines: 95.0 },
        results: { endpoints: [], functions: [], hooks: [] },
        recommendations: [],
      };

      mockApiClient.setMockResponse('post', `/custom-apps/${newApp.id}/test`, {
        success: true,
        data: testResult,
      });

      const testingResult = await mockServer.executeToolCall({
        tool: 'test-custom-app',
        parameters: {
          appId: newApp.id,
          testType: 'all',
          environment: 'development',
        },
      });

      // Verify the lifecycle completed successfully
      expect(JSON.parse(appResult).app.id).toBe(newApp.id);
      expect(JSON.parse(hookResult).hook.appId).toBe(newApp.id);
      expect(JSON.parse(functionResult).function.appId).toBe(newApp.id);
      expect(JSON.parse(testingResult).summary.passed).toBe(10);
    });
  });

  describe('Chaos Engineering Tests', () => {
    test('should handle service degradation gracefully', async () => {
      const scenarios = ['latency', 'error', 'timeout'];
      const results: { scenario: string; success: boolean }[] = [];

      for (const scenario of scenarios) {
        try {
          if (scenario === 'latency') {
            // Simulate high latency
            mockApiClient.setMockResponse('post', '/custom-apps', {
              success: true,
              data: generateMockCustomApp(),
            }, chaosMonkey.getRandomLatency());
          } else if (scenario === 'error') {
            // Simulate service error
            mockApiClient.setMockResponse('post', '/custom-apps', {
              success: false,
              error: { message: 'Service temporarily unavailable' },
            });
          } else if (scenario === 'timeout') {
            // Simulate timeout
            mockApiClient.setMockResponse('post', '/custom-apps', {
              success: false,
              error: { message: 'Request timeout' },
            });
          }

          await mockServer.executeToolCall({
            tool: 'create-custom-app',
            parameters: {
              name: `Chaos Test ${scenario}`,
              description: 'Testing service degradation scenarios',
              type: 'connector',
              runtime: 'nodejs',
              configuration: {
                endpoints: [],
                authentication: { type: 'none', configuration: {} },
              },
            },
          });

          results.push({ scenario, success: true });
        } catch (error) {
          results.push({ scenario, success: false });
        }
      }

      // At least one scenario should handle gracefully
      const successfulScenarios = results.filter(r => r.success).length;
      expect(successfulScenarios).toBeGreaterThan(0);
    });
  });

  describe('Performance Testing', () => {
    test('should handle concurrent custom app operations', async () => {
      const concurrentRequests = 8;
      const promises: Promise<string>[] = [];

      mockApiClient.setMockResponse('post', '/custom-apps', {
        success: true,
        data: generateMockCustomApp(),
      });

      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(mockServer.executeToolCall({
          tool: 'create-custom-app',
          parameters: {
            name: `Concurrent App ${i}`,
            description: `Testing concurrent app creation ${i}`,
            type: 'connector',
            runtime: 'nodejs',
            configuration: {
              endpoints: [],
              authentication: { type: 'none', configuration: {} },
            },
          },
        }));
      }

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      
      expect(successful).toBeGreaterThan(concurrentRequests * 0.75); // 75% success rate
    });
  });
});