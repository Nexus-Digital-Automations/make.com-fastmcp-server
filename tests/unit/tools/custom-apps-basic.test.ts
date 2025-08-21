/**
 * Basic Test Suite for Custom App Development Tools
 * Tests core functionality of custom app creation, management, and lifecycle tools
 * Covers app creation, hooks, functions, testing, and comprehensive validation
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';

// Import types from custom-apps.ts
import type { 
  MakeCustomApp,
  MakeHook,
  MakeCustomFunction 
} from '../../../src/tools/custom-apps.js';

describe('Custom App Development Tools - Basic Tests', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;
  let mockReportProgress: jest.MockedFunction<any>;

  // Test data for custom apps
  const testCustomApp: MakeCustomApp = {
    id: 1,
    name: 'E-commerce Connector',
    description: 'Advanced connector for e-commerce platforms',
    version: '1.0.0',
    status: 'draft',
    organizationId: 123,
    teamId: 456,
    configuration: {
      type: 'connector',
      runtime: 'nodejs',
      environment: {
        variables: {
          API_VERSION: 'v2',
          TIMEOUT: '30000'
        },
        secrets: ['API_KEY', 'SECRET_TOKEN'],
        dependencies: {
          'axios': '^1.6.0',
          'lodash': '^4.17.21'
        }
      },
      endpoints: [
        {
          name: 'getProducts',
          method: 'GET',
          path: '/products',
          description: 'Retrieve product list',
          parameters: {
            type: 'object',
            properties: {
              limit: { type: 'number', default: 10 },
              offset: { type: 'number', default: 0 }
            }
          },
          responses: {
            '200': {
              type: 'object',
              properties: {
                products: { type: 'array' },
                total: { type: 'number' }
              }
            }
          }
        },
        {
          name: 'createOrder',
          method: 'POST',
          path: '/orders',
          description: 'Create new order',
          parameters: {
            type: 'object',
            properties: {
              customerId: { type: 'string', required: true },
              items: { type: 'array', required: true }
            }
          },
          responses: {
            '201': {
              type: 'object',
              properties: {
                orderId: { type: 'string' },
                status: { type: 'string' }
              }
            }
          }
        }
      ],
      authentication: {
        type: 'oauth2',
        configuration: {
          authUrl: 'https://api.example.com/oauth/authorize',
          tokenUrl: 'https://api.example.com/oauth/token',
          scopes: ['read:products', 'write:orders']
        }
      },
      ui: {
        icon: 'https://cdn.example.com/icon.png',
        color: '#007bff',
        description: 'Connect to e-commerce platforms',
        category: 'commerce'
      }
    },
    deployment: {
      source: 'git',
      repository: 'https://github.com/company/ecommerce-connector.git',
      branch: 'main',
      buildCommand: 'npm run build',
      startCommand: 'npm start',
      healthCheckEndpoint: '/health'
    },
    testing: {
      testSuite: 'jest',
      coverageThreshold: 80,
      lastTestRun: {
        timestamp: '2024-01-15T14:30:00Z',
        passed: 45,
        failed: 2,
        coverage: 85,
        duration: 120
      }
    },
    usage: {
      installations: 25,
      executions: 15000,
      averageResponseTime: 250,
      errorRate: 1.2,
      lastUsed: '2024-01-15T16:00:00Z'
    },
    permissions: {
      scopes: ['read:products', 'write:orders', 'read:customers'],
      roles: ['developer', 'admin'],
      restrictions: {
        ipWhitelist: ['192.168.1.0/24'],
        timeRestrictions: false
      }
    },
    createdAt: '2024-01-01T10:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
    createdBy: 1,
    createdByName: 'John Developer'
  };

  const testHook: MakeHook = {
    id: 1,
    name: 'Order Status Hook',
    description: 'Webhook for order status updates',
    appId: 1,
    appName: 'E-commerce Connector',
    type: 'webhook',
    status: 'active',
    configuration: {
      endpoint: 'https://api.company.com/webhooks/orders',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {{token}}'
      },
      authentication: {
        type: 'bearer',
        configuration: {
          token: 'secret-webhook-token'
        }
      }
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
            amount: { type: 'number' }
          }
        }
      },
      {
        name: 'order.updated',
        description: 'Triggered when order status changes',
        schema: {
          type: 'object',
          properties: {
            orderId: { type: 'string' },
            status: { type: 'string' },
            updatedAt: { type: 'string' }
          }
        },
        filters: {
          status: ['pending', 'shipped', 'delivered', 'cancelled']
        }
      }
    ],
    execution: {
      totalCalls: 1500,
      successfulCalls: 1485,
      failedCalls: 15,
      averageResponseTime: 180,
      lastExecution: {
        timestamp: '2024-01-15T15:30:00Z',
        status: 'success',
        responseTime: 165
      }
    },
    logs: {
      retention: 30,
      level: 'info',
      destinations: ['console', 'file']
    },
    createdAt: '2024-01-05T10:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
    createdBy: 1
  };

  const testPollingHook: MakeHook = {
    id: 2,
    name: 'Product Sync Hook',
    description: 'Polling hook for product updates',
    appId: 1,
    appName: 'E-commerce Connector',
    type: 'polling',
    status: 'active',
    configuration: {
      endpoint: 'https://api.example.com/products/updated',
      method: 'GET',
      headers: {
        'Authorization': 'Bearer {{api_key}}'
      },
      authentication: {
        type: 'api_key',
        configuration: {
          key: 'api_key',
          location: 'header'
        }
      },
      polling: {
        interval: 15,
        strategy: 'timestamp_based',
        parameters: {
          lastModifiedField: 'updatedAt',
          sortOrder: 'desc'
        }
      }
    },
    events: [
      {
        name: 'product.updated',
        description: 'Product information has been updated',
        schema: {
          type: 'object',
          properties: {
            productId: { type: 'string' },
            name: { type: 'string' },
            price: { type: 'number' },
            updatedAt: { type: 'string' }
          }
        }
      }
    ],
    execution: {
      totalCalls: 2880,
      successfulCalls: 2850,
      failedCalls: 30,
      averageResponseTime: 450
    },
    logs: {
      retention: 15,
      level: 'warn',
      destinations: ['console', 'webhook']
    },
    createdAt: '2024-01-08T10:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
    createdBy: 1
  };

  const testCustomFunction: MakeCustomFunction = {
    id: 1,
    name: 'Price Calculator',
    description: 'Calculate final price with taxes and discounts',
    appId: 1,
    type: 'calculator',
    language: 'javascript',
    status: 'published',
    code: {
      source: `
        function calculatePrice(basePrice, taxRate, discount) {
          const discountAmount = basePrice * (discount / 100);
          const priceAfterDiscount = basePrice - discountAmount;
          const taxAmount = priceAfterDiscount * (taxRate / 100);
          return {
            basePrice,
            discount: discountAmount,
            taxAmount,
            finalPrice: priceAfterDiscount + taxAmount
          };
        }
        
        module.exports = { calculatePrice };
      `,
      dependencies: {
        'decimal.js': '^10.4.3'
      },
      environment: {
        NODE_ENV: 'production'
      },
      timeout: 10,
      memoryLimit: 128
    },
    interface: {
      input: {
        type: 'object',
        properties: {
          basePrice: { type: 'number', minimum: 0 },
          taxRate: { type: 'number', minimum: 0, maximum: 100 },
          discount: { type: 'number', minimum: 0, maximum: 100, default: 0 }
        },
        required: ['basePrice', 'taxRate']
      },
      output: {
        type: 'object',
        properties: {
          basePrice: { type: 'number' },
          discount: { type: 'number' },
          taxAmount: { type: 'number' },
          finalPrice: { type: 'number' }
        }
      },
      parameters: {}
    },
    testing: {
      testCases: [
        {
          name: 'Basic calculation',
          input: { basePrice: 100, taxRate: 10, discount: 5 },
          expectedOutput: { basePrice: 100, discount: 5, taxAmount: 9.5, finalPrice: 104.5 },
          description: 'Test basic price calculation with tax and discount'
        },
        {
          name: 'No discount',
          input: { basePrice: 50, taxRate: 8 },
          expectedOutput: { basePrice: 50, discount: 0, taxAmount: 4, finalPrice: 54 },
          description: 'Test calculation without discount'
        }
      ],
      lastTestRun: {
        timestamp: '2024-01-15T12:00:00Z',
        passed: 2,
        failed: 0,
        duration: 850
      }
    },
    deployment: {
      version: '1.2.0',
      environment: 'production',
      instances: 3,
      autoScale: true
    },
    monitoring: {
      executions: 50000,
      averageExecutionTime: 45,
      errorRate: 0.8,
      memoryUsage: 85,
      cpuUsage: 15
    },
    createdAt: '2024-01-03T10:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
    createdBy: 1
  };

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    };
    mockReportProgress = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Import Validation', () => {
    it('should import custom apps tools module without errors', async () => {
      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      expect(addCustomAppTools).toBeDefined();
      expect(typeof addCustomAppTools).toBe('function');
    });

    it('should register all 5 custom app tools', async () => {
      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-custom-app',
        'list-custom-apps',
        'create-hook',
        'create-custom-function',
        'test-custom-app'
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });

      // Verify we have all 5 tools
      expect(mockTool.mock.calls).toHaveLength(5);
    });

    it('should have proper tool configuration for app lifecycle tools', async () => {
      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const coreTools = [
        'create-custom-app',
        'list-custom-apps',
        'test-custom-app'
      ];
      
      coreTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/custom app/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should have proper tool configuration for development tools', async () => {
      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const devTools = [
        'create-hook',
        'create-custom-function'
      ];
      
      devTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/(hook|function)/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });
  });

  describe('Custom App Creation and Management', () => {
    describe('create-custom-app tool', () => {
      it('should create basic connector app', async () => {
        mockApiClient.mockResponse('POST', '/custom-apps', {
          success: true,
          data: testCustomApp
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-app');
        const result = await executeTool(tool, {
          name: 'E-commerce Connector',
          description: 'Advanced connector for e-commerce platforms',
          type: 'connector',
          runtime: 'nodejs',
          configuration: {
            environment: {
              variables: { API_VERSION: 'v2' },
              secrets: ['API_KEY'],
              dependencies: { 'axios': '^1.6.0' }
            },
            endpoints: [
              {
                name: 'getProducts',
                method: 'GET',
                path: '/products',
                description: 'Retrieve product list'
              }
            ],
            authentication: {
              type: 'oauth2',
              configuration: {
                authUrl: 'https://api.example.com/oauth/authorize'
              }
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('E-commerce Connector');
        expect(result).toContain('created successfully');
        expect(result).toContain('"status": "draft"');
        expect(result).toContain('nextSteps');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/custom-apps');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('E-commerce Connector');
        expect(calls[0].data.configuration.type).toBe('connector');
        expect(calls[0].data.configuration.runtime).toBe('nodejs');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create organization-scoped app', async () => {
        const orgApp = { ...testCustomApp, organizationId: 789, teamId: undefined };
        mockApiClient.mockResponse('POST', '/organizations/789/custom-apps', {
          success: true,
          data: orgApp
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-app');
        await executeTool(tool, {
          name: 'Org Analytics App',
          type: 'full_app',
          runtime: 'python',
          organizationId: 789,
          configuration: {
            endpoints: [],
            authentication: { type: 'none', configuration: {} }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/789/custom-apps');
        expect(calls[0].data.organizationId).toBe(789);
      });

      it('should create team-scoped app', async () => {
        const teamApp = { ...testCustomApp, teamId: 456 };
        mockApiClient.mockResponse('POST', '/teams/456/custom-apps', {
          success: true,
          data: teamApp
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-app');
        await executeTool(tool, {
          name: 'Team Workflow App',
          type: 'action',
          teamId: 456,
          configuration: {
            endpoints: [],
            authentication: { type: 'api_key', configuration: {} }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/teams/456/custom-apps');
        expect(calls[0].data.teamId).toBe(456);
      });

      it('should create app with comprehensive configuration', async () => {
        mockApiClient.mockResponse('POST', '/custom-apps', {
          success: true,
          data: testCustomApp
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-app');
        await executeTool(tool, {
          name: 'Advanced E-commerce Connector',
          description: 'Full-featured e-commerce integration',
          type: 'connector',
          runtime: 'nodejs',
          configuration: {
            environment: {
              variables: {
                API_VERSION: 'v2',
                TIMEOUT: '30000',
                RETRY_COUNT: '3'
              },
              secrets: ['API_KEY', 'SECRET_TOKEN', 'WEBHOOK_SECRET'],
              dependencies: {
                'axios': '^1.6.0',
                'lodash': '^4.17.21',
                'moment': '^2.29.0'
              }
            },
            endpoints: [
              {
                name: 'listProducts',
                method: 'GET',
                path: '/products',
                description: 'List all products',
                parameters: {
                  type: 'object',
                  properties: {
                    page: { type: 'number', default: 1 },
                    limit: { type: 'number', default: 10 }
                  }
                }
              },
              {
                name: 'createOrder',
                method: 'POST',
                path: '/orders',
                description: 'Create new order',
                parameters: {
                  type: 'object',
                  properties: {
                    items: { type: 'array' },
                    customer: { type: 'object' }
                  }
                }
              }
            ],
            authentication: {
              type: 'oauth2',
              configuration: {
                authUrl: 'https://api.example.com/oauth/authorize',
                tokenUrl: 'https://api.example.com/oauth/token',
                scopes: ['read:products', 'write:orders']
              }
            },
            ui: {
              icon: 'https://cdn.example.com/icon.png',
              color: '#00a86b',
              description: 'Connect to your e-commerce platform',
              category: 'e-commerce'
            }
          },
          deployment: {
            source: 'git',
            repository: 'https://github.com/company/ecommerce-app.git',
            branch: 'main',
            buildCommand: 'npm run build:prod',
            startCommand: 'npm start',
            healthCheckEndpoint: '/health'
          },
          permissions: {
            scopes: ['read:products', 'write:orders', 'read:customers'],
            roles: ['developer', 'admin'],
            restrictions: {
              ipWhitelist: ['10.0.0.0/8'],
              timeRestrictions: false
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        const requestData = calls[0].data;
        expect(requestData.configuration.environment.variables.API_VERSION).toBe('v2');
        expect(requestData.configuration.environment.secrets).toContain('API_KEY');
        expect(requestData.configuration.endpoints).toHaveLength(2);
        expect(requestData.configuration.authentication.type).toBe('oauth2');
        expect(requestData.deployment.source).toBe('git');
        expect(requestData.permissions.scopes).toContain('read:products');
      });

      it('should validate app creation parameters', async () => {
        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-app');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          name: 'Test App',
          type: 'connector',
          configuration: {
            endpoints: [],
            authentication: { type: 'none', configuration: {} }
          }
        });
        
        // Test invalid name (empty)
        expectInvalidZodParse(tool.parameters, {
          name: '',
          type: 'connector',
          configuration: { endpoints: [], authentication: { type: 'none', configuration: {} } }
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          name: 'Test App',
          type: 'invalid-type',
          configuration: { endpoints: [], authentication: { type: 'none', configuration: {} } }
        });
        
        // Test invalid runtime
        expectInvalidZodParse(tool.parameters, {
          name: 'Test App',
          type: 'connector',
          runtime: 'invalid-runtime',
          configuration: { endpoints: [], authentication: { type: 'none', configuration: {} } }
        });
      });

      it('should handle app creation errors', async () => {
        mockApiClient.mockResponse('POST', '/custom-apps', {
          success: false,
          error: { message: 'App name already exists' }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-app');
        
        await expect(executeTool(tool, {
          name: 'Existing App',
          type: 'connector',
          configuration: {
            endpoints: [],
            authentication: { type: 'none', configuration: {} }
          }
        }, { log: mockLog })).rejects.toThrow('App name already exists');
      });
    });

    describe('list-custom-apps tool', () => {
      it('should list apps with default parameters', async () => {
        const appsList = [testCustomApp, { ...testCustomApp, id: 2, name: 'Payment Processor', status: 'published' }];
        mockApiClient.mockResponse('GET', '/custom-apps', {
          success: true,
          data: appsList,
          metadata: { total: 2 }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-apps');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('E-commerce Connector');
        expect(result).toContain('Payment Processor');
        expect(result).toContain('"totalApps": 2');
        expect(result).toContain('typeBreakdown');
        expect(result).toContain('statusBreakdown');
        expect(result).toContain('developmentSummary');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.apps).toHaveLength(2);
        expect(parsedResult.analysis.statusBreakdown).toHaveProperty('draft');
        expect(parsedResult.analysis.statusBreakdown).toHaveProperty('published');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/custom-apps');
        expect(calls[0].method).toBe('GET');
      });

      it('should filter apps by type and status', async () => {
        const connectorApps = [testCustomApp];
        mockApiClient.mockResponse('GET', '/custom-apps', {
          success: true,
          data: connectorApps,
          metadata: { total: 1 }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-apps');
        await executeTool(tool, {
          type: 'connector',
          status: 'draft',
          runtime: 'nodejs',
          includeUsage: true,
          includeConfig: false,
          limit: 50,
          sortBy: 'usage',
          sortOrder: 'desc'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.type).toBe('connector');
        expect(calls[0].data.status).toBe('draft');
        expect(calls[0].data.runtime).toBe('nodejs');
        expect(calls[0].data.includeUsage).toBe(true);
        expect(calls[0].data.includeConfig).toBe(false);
        expect(calls[0].data.limit).toBe(50);
        expect(calls[0].data.sortBy).toBe('usage');
        expect(calls[0].data.sortOrder).toBe('desc');
      });

      it('should list organization apps with usage analysis', async () => {
        const orgApps = [
          { ...testCustomApp, organizationId: 789, usage: { ...testCustomApp.usage, installations: 100, executions: 50000 } }
        ];
        mockApiClient.mockResponse('GET', '/custom-apps', {
          success: true,
          data: orgApps,
          metadata: { total: 1 }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-apps');
        const result = await executeTool(tool, {
          organizationId: 789,
          includeUsage: true
        }, { log: mockLog });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.analysis.usageSummary).toBeDefined();
        expect(parsedResult.analysis.usageSummary.totalInstallations).toBe(100);
        expect(parsedResult.analysis.usageSummary.totalExecutions).toBe(50000);
        expect(parsedResult.analysis.usageSummary.mostUsedApps).toBeDefined();
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.organizationId).toBe(789);
      });

      it('should validate list apps parameters', async () => {
        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-apps');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, { type: 'connector', status: 'published' });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, { type: 'invalid-type' });
        
        // Test invalid status
        expectInvalidZodParse(tool.parameters, { status: 'invalid-status' });
        
        // Test invalid limit
        expectInvalidZodParse(tool.parameters, { limit: 0 });
        expectInvalidZodParse(tool.parameters, { limit: 1001 });
        
        // Test invalid offset
        expectInvalidZodParse(tool.parameters, { offset: -1 });
      });

      it('should handle empty app list', async () => {
        mockApiClient.mockResponse('GET', '/custom-apps', {
          success: true,
          data: [],
          metadata: { total: 0 }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-apps');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.apps).toHaveLength(0);
        expect(parsedResult.analysis.totalApps).toBe(0);
      });
    });
  });

  describe('Hook Creation and Management', () => {
    describe('create-hook tool', () => {
      it('should create webhook hook', async () => {
        mockApiClient.mockResponse('POST', '/hooks', {
          success: true,
          data: testHook
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-hook');
        const result = await executeTool(tool, {
          name: 'Order Status Hook',
          description: 'Webhook for order status updates',
          appId: 1,
          type: 'webhook',
          configuration: {
            endpoint: 'https://api.company.com/webhooks/orders',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            authentication: {
              type: 'bearer',
              configuration: { token: 'secret-token' }
            }
          },
          events: [
            {
              name: 'order.created',
              description: 'New order created',
              schema: {
                type: 'object',
                properties: {
                  orderId: { type: 'string' },
                  amount: { type: 'number' }
                }
              }
            }
          ]
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Order Status Hook');
        expect(result).toContain('created successfully');
        expect(result).toContain('"type": "webhook"');
        expect(result).toContain('testing');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/hooks');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('Order Status Hook');
        expect(calls[0].data.type).toBe('webhook');
        expect(calls[0].data.configuration.endpoint).toBe('https://api.company.com/webhooks/orders');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create polling hook with interval configuration', async () => {
        mockApiClient.mockResponse('POST', '/hooks', {
          success: true,
          data: testPollingHook
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-hook');
        const result = await executeTool(tool, {
          name: 'Product Sync Hook',
          appId: 1,
          type: 'polling',
          configuration: {
            endpoint: 'https://api.example.com/products/updated',
            method: 'GET',
            authentication: {
              type: 'api_key',
              configuration: { key: 'api_key', location: 'header' }
            },
            polling: {
              interval: 15,
              strategy: 'timestamp_based',
              parameters: { lastModifiedField: 'updatedAt' }
            }
          },
          events: [
            {
              name: 'product.updated',
              schema: { type: 'object', properties: { productId: { type: 'string' } } }
            }
          ]
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Product Sync Hook');
        expect(result).toContain('pollingInterval');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.type).toBe('polling');
        expect(calls[0].data.configuration.polling.interval).toBe(15);
        expect(calls[0].data.configuration.polling.strategy).toBe('timestamp_based');
      });

      it('should create hook with custom logging configuration', async () => {
        const customHook = {
          ...testHook,
          logs: {
            retention: 60,
            level: 'debug',
            destinations: ['console', 'file', 'webhook']
          }
        };

        mockApiClient.mockResponse('POST', '/hooks', {
          success: true,
          data: customHook
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-hook');
        await executeTool(tool, {
          name: 'Debug Hook',
          appId: 1,
          type: 'instant',
          configuration: {
            endpoint: 'https://api.example.com/instant',
            authentication: { type: 'none', configuration: {} }
          },
          events: [
            { name: 'test.event', schema: { type: 'object' } }
          ],
          logs: {
            retention: 60,
            level: 'debug',
            destinations: ['console', 'file', 'webhook']
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.logs.retention).toBe(60);
        expect(calls[0].data.logs.level).toBe('debug');
        expect(calls[0].data.logs.destinations).toEqual(['console', 'file', 'webhook']);
      });

      it('should validate hook creation parameters', async () => {
        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-hook');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          name: 'Test Hook',
          appId: 1,
          type: 'webhook',
          configuration: {
            endpoint: 'https://api.example.com/webhook',
            authentication: { type: 'none', configuration: {} }
          },
          events: [
            { name: 'test.event', schema: { type: 'object' } }
          ]
        });
        
        // Test invalid name (empty)
        expectInvalidZodParse(tool.parameters, {
          name: '',
          appId: 1,
          type: 'webhook',
          configuration: { endpoint: 'https://api.example.com', authentication: { type: 'none', configuration: {} } },
          events: [{ name: 'test', schema: {} }]
        });
        
        // Test invalid appId
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Hook',
          appId: 0,
          type: 'webhook',
          configuration: { endpoint: 'https://api.example.com', authentication: { type: 'none', configuration: {} } },
          events: [{ name: 'test', schema: {} }]
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Hook',
          appId: 1,
          type: 'invalid-type',
          configuration: { endpoint: 'https://api.example.com', authentication: { type: 'none', configuration: {} } },
          events: [{ name: 'test', schema: {} }]
        });
        
        // Test invalid endpoint URL
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Hook',
          appId: 1,
          type: 'webhook',
          configuration: { endpoint: 'invalid-url', authentication: { type: 'none', configuration: {} } },
          events: [{ name: 'test', schema: {} }]
        });
        
        // Test empty events array
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Hook',
          appId: 1,
          type: 'webhook',
          configuration: { endpoint: 'https://api.example.com', authentication: { type: 'none', configuration: {} } },
          events: []
        });
      });

      it('should handle hook creation errors', async () => {
        mockApiClient.mockResponse('POST', '/hooks', {
          success: false,
          error: { message: 'Invalid app ID' }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-hook');
        
        await expect(executeTool(tool, {
          name: 'Invalid Hook',
          appId: 999,
          type: 'webhook',
          configuration: {
            endpoint: 'https://api.example.com/webhook',
            authentication: { type: 'none', configuration: {} }
          },
          events: [{ name: 'test.event', schema: { type: 'object' } }]
        }, { log: mockLog })).rejects.toThrow('Invalid app ID');
      });
    });
  });

  describe('Custom Function Creation and Management', () => {
    describe('create-custom-function tool', () => {
      it('should create JavaScript transformer function', async () => {
        mockApiClient.mockResponse('POST', '/custom-functions', {
          success: true,
          data: testCustomFunction
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-function');
        const result = await executeTool(tool, {
          name: 'Price Calculator',
          description: 'Calculate final price with taxes and discounts',
          appId: 1,
          type: 'calculator',
          language: 'javascript',
          code: {
            source: `
              function calculatePrice(basePrice, taxRate, discount = 0) {
                const discountAmount = basePrice * (discount / 100);
                const priceAfterDiscount = basePrice - discountAmount;
                const taxAmount = priceAfterDiscount * (taxRate / 100);
                return {
                  basePrice,
                  discount: discountAmount,
                  taxAmount,
                  finalPrice: priceAfterDiscount + taxAmount
                };
              }
              module.exports = { calculatePrice };
            `,
            dependencies: { 'decimal.js': '^10.4.3' },
            environment: { NODE_ENV: 'production' },
            timeout: 10,
            memoryLimit: 128
          },
          interface: {
            input: {
              type: 'object',
              properties: {
                basePrice: { type: 'number', minimum: 0 },
                taxRate: { type: 'number', minimum: 0, maximum: 100 },
                discount: { type: 'number', minimum: 0, maximum: 100, default: 0 }
              },
              required: ['basePrice', 'taxRate']
            },
            output: {
              type: 'object',
              properties: {
                basePrice: { type: 'number' },
                discount: { type: 'number' },
                taxAmount: { type: 'number' },
                finalPrice: { type: 'number' }
              }
            }
          },
          testCases: [
            {
              name: 'Basic calculation',
              input: { basePrice: 100, taxRate: 10, discount: 5 },
              expectedOutput: { basePrice: 100, discount: 5, taxAmount: 9.5, finalPrice: 104.5 }
            }
          ]
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Price Calculator');
        expect(result).toContain('created successfully');
        expect(result).toContain('"language": "javascript"');
        expect(result).toContain('testEndpoint');
        expect(result).toContain('deployEndpoint');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/custom-functions');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('Price Calculator');
        expect(calls[0].data.type).toBe('calculator');
        expect(calls[0].data.language).toBe('javascript');
        expect(calls[0].data.code.timeout).toBe(10);
        expect(calls[0].data.testing.testCases).toHaveLength(1);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create Python validator function', async () => {
        const pythonFunction = {
          ...testCustomFunction,
          id: 2,
          name: 'Email Validator',
          type: 'validator',
          language: 'python',
          code: {
            source: `
import re
import email_validator

def validate_email(email_address):
    try:
        valid = email_validator.validate_email(email_address)
        return {
            'isValid': True,
            'email': valid.email,
            'domain': valid.domain
        }
    except email_validator.EmailNotValidError:
        return {
            'isValid': False,
            'error': 'Invalid email format'
        }
            `,
            dependencies: { 'email-validator': '^2.0.0' },
            environment: { PYTHON_ENV: 'production' },
            timeout: 5,
            memoryLimit: 64
          }
        };

        mockApiClient.mockResponse('POST', '/custom-functions', {
          success: true,
          data: pythonFunction
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-function');
        await executeTool(tool, {
          name: 'Email Validator',
          type: 'validator',
          language: 'python',
          code: {
            source: pythonFunction.code.source,
            dependencies: { 'email-validator': '^2.0.0' },
            timeout: 5,
            memoryLimit: 64
          },
          interface: {
            input: {
              type: 'object',
              properties: { email: { type: 'string' } }
            },
            output: {
              type: 'object',
              properties: {
                isValid: { type: 'boolean' },
                email: { type: 'string' }
              }
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.language).toBe('python');
        expect(calls[0].data.type).toBe('validator');
        expect(calls[0].data.code.dependencies['email-validator']).toBe('^2.0.0');
      });

      it('should create function with deployment configuration', async () => {
        const deployedFunction = {
          ...testCustomFunction,
          deployment: {
            version: '2.0.0',
            environment: 'staging',
            instances: 5,
            autoScale: true
          }
        };

        mockApiClient.mockResponse('POST', '/custom-functions', {
          success: true,
          data: deployedFunction
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-function');
        await executeTool(tool, {
          name: 'Scalable Formatter',
          type: 'formatter',
          language: 'javascript',
          code: {
            source: 'function format(data) { return JSON.stringify(data); }',
            timeout: 15
          },
          interface: {
            input: { type: 'any' },
            output: { type: 'string' }
          },
          deployment: {
            environment: 'staging',
            instances: 5,
            autoScale: true
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.deployment.environment).toBe('staging');
        expect(calls[0].data.deployment.instances).toBe(5);
        expect(calls[0].data.deployment.autoScale).toBe(true);
      });

      it('should validate custom function parameters', async () => {
        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-function');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          name: 'Test Function',
          type: 'transformer',
          language: 'javascript',
          code: {
            source: 'function test() { return {}; }'
          },
          interface: {
            input: { type: 'object' },
            output: { type: 'object' }
          }
        });
        
        // Test invalid name (empty)
        expectInvalidZodParse(tool.parameters, {
          name: '',
          type: 'transformer',
          language: 'javascript',
          code: { source: 'function test() {}' },
          interface: { input: {}, output: {} }
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Function',
          type: 'invalid-type',
          language: 'javascript',
          code: { source: 'function test() {}' },
          interface: { input: {}, output: {} }
        });
        
        // Test invalid language
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Function',
          type: 'transformer',
          language: 'invalid-language',
          code: { source: 'function test() {}' },
          interface: { input: {}, output: {} }
        });
        
        // Test empty source code
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Function',
          type: 'transformer',
          language: 'javascript',
          code: { source: '' },
          interface: { input: {}, output: {} }
        });
        
        // Test invalid timeout
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Function',
          type: 'transformer',
          language: 'javascript',
          code: { source: 'test', timeout: 0 },
          interface: { input: {}, output: {} }
        });
        
        // Test invalid memory limit
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Function',
          type: 'transformer',
          language: 'javascript',
          code: { source: 'test', memoryLimit: 32 },
          interface: { input: {}, output: {} }
        });
      });

      it('should handle function creation errors', async () => {
        mockApiClient.mockResponse('POST', '/custom-functions', {
          success: false,
          error: { message: 'Invalid function syntax' }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-function');
        
        await expect(executeTool(tool, {
          name: 'Invalid Function',
          type: 'transformer',
          language: 'javascript',
          code: {
            source: 'invalid javascript syntax {'
          },
          interface: {
            input: { type: 'object' },
            output: { type: 'object' }
          }
        }, { log: mockLog })).rejects.toThrow('Invalid function syntax');
      });
    });
  });

  describe('Custom App Testing', () => {
    describe('test-custom-app tool', () => {
      it('should run comprehensive app tests', async () => {
        const testResult = {
          summary: {
            total: 25,
            passed: 23,
            failed: 2,
            duration: 180,
            coverage: 85.5
          },
          results: {
            endpoints: [
              {
                name: 'getProducts',
                status: 'passed',
                responseTime: 120,
                tests: {
                  passed: 8,
                  failed: 0
                }
              },
              {
                name: 'createOrder',
                status: 'failed',
                responseTime: 0,
                error: 'Connection timeout',
                tests: {
                  passed: 5,
                  failed: 2
                }
              }
            ],
            functions: [
              {
                name: 'Price Calculator',
                status: 'passed',
                executionTime: 45,
                tests: {
                  passed: 10,
                  failed: 0
                }
              }
            ],
            hooks: [
              {
                name: 'Order Status Hook',
                status: 'passed',
                responseTime: 95
              }
            ]
          },
          recommendations: [
            'Optimize createOrder endpoint timeout settings',
            'Add error handling for connection failures'
          ],
          coverage: {
            statements: 85.5,
            branches: 78.2,
            functions: 92.1,
            lines: 84.8
          }
        };

        mockApiClient.mockResponse('POST', '/custom-apps/1/test', {
          success: true,
          data: testResult
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-custom-app');
        const result = await executeTool(tool, {
          appId: 1,
          testType: 'all',
          environment: 'development',
          includePerformance: true,
          timeout: 180
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Custom app 1 testing completed');
        expect(result).toContain('"passed": 23');
        expect(result).toContain('"failed": 2');
        expect(result).toContain('recommendations');
        expect(result).toContain('coverage');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.summary.totalTests).toBe(25);
        expect(parsedResult.summary.passed).toBe(23);
        expect(parsedResult.summary.failed).toBe(2);
        expect(parsedResult.results.endpoints).toHaveLength(2);
        expect(parsedResult.results.functions).toHaveLength(1);
        expect(parsedResult.recommendations).toHaveLength(2);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/custom-apps/1/test');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.testType).toBe('all');
        expect(calls[0].data.environment).toBe('development');
        expect(calls[0].data.includePerformance).toBe(true);
        expect(calls[0].data.timeout).toBe(180);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should run specific test types', async () => {
        const endpointTestResult = {
          summary: { total: 8, passed: 8, failed: 0, duration: 45 },
          results: {
            endpoints: [
              {
                name: 'getProducts',
                status: 'passed',
                responseTime: 95,
                tests: { passed: 4, failed: 0 }
              },
              {
                name: 'createOrder',
                status: 'passed',
                responseTime: 110,
                tests: { passed: 4, failed: 0 }
              }
            ]
          }
        };

        mockApiClient.mockResponse('POST', '/custom-apps/1/test', {
          success: true,
          data: endpointTestResult
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-custom-app');
        await executeTool(tool, {
          appId: 1,
          testType: 'endpoints',
          environment: 'staging'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.testType).toBe('endpoints');
        expect(calls[0].data.environment).toBe('staging');
      });

      it('should run performance tests', async () => {
        const performanceResult = {
          summary: { total: 15, passed: 14, failed: 1, duration: 300 },
          results: {
            performance: {
              loadTest: {
                concurrent_users: 100,
                duration: 60,
                requests_per_second: 250,
                average_response_time: 180,
                error_rate: 2.1
              },
              stressTest: {
                peak_load: 500,
                breaking_point: 450,
                memory_usage: 85,
                cpu_usage: 75
              }
            }
          }
        };

        mockApiClient.mockResponse('POST', '/custom-apps/1/test', {
          success: true,
          data: performanceResult
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-custom-app');
        const result = await executeTool(tool, {
          appId: 1,
          testType: 'integration',
          environment: 'production',
          includePerformance: true,
          timeout: 300
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.results.performance).toBeDefined();
        expect(parsedResult.results.performance.loadTest.concurrent_users).toBe(100);
        expect(parsedResult.results.performance.stressTest.breaking_point).toBe(450);
      });

      it('should validate test app parameters', async () => {
        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-custom-app');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, { appId: 1 });
        expectValidZodParse(tool.parameters, { appId: 1, testType: 'unit', environment: 'staging' });
        
        // Test invalid appId
        expectInvalidZodParse(tool.parameters, { appId: 0 });
        expectInvalidZodParse(tool.parameters, { appId: -1 });
        
        // Test invalid testType
        expectInvalidZodParse(tool.parameters, { appId: 1, testType: 'invalid-type' });
        
        // Test invalid environment
        expectInvalidZodParse(tool.parameters, { appId: 1, environment: 'invalid-env' });
        
        // Test invalid timeout
        expectInvalidZodParse(tool.parameters, { appId: 1, timeout: 29 });
        expectInvalidZodParse(tool.parameters, { appId: 1, timeout: 601 });
      });

      it('should handle test execution errors', async () => {
        mockApiClient.mockResponse('POST', '/custom-apps/999/test', {
          success: false,
          error: { message: 'App not found' }
        });

        const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
        addCustomAppTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-custom-app');
        
        await expect(executeTool(tool, {
          appId: 999,
          testType: 'all'
        }, { log: mockLog })).rejects.toThrow('App not found');
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully', async () => {
      mockApiClient.mockResponse('POST', '/custom-apps', {
        success: false,
        error: { message: 'Insufficient permissions' }
      });

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-app');
      
      await expect(executeTool(tool, {
        name: 'Permission Test App',
        type: 'connector',
        configuration: {
          endpoints: [],
          authentication: { type: 'none', configuration: {} }
        }
      }, { log: mockLog })).rejects.toThrow('Insufficient permissions');
    });

    it('should handle network timeouts', async () => {
      mockApiClient.mockError('GET', '/custom-apps', new Error('Request timeout'));

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-custom-apps');
      
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Request timeout');
    });

    it('should handle invalid responses', async () => {
      mockApiClient.mockResponse('POST', '/custom-apps', {
        success: true,
        data: null
      });

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-app');
      
      await expect(executeTool(tool, {
        name: 'Test App',
        type: 'connector',
        configuration: {
          endpoints: [],
          authentication: { type: 'none', configuration: {} }
        }
      }, { log: mockLog })).rejects.toThrow('Custom app creation failed - no data returned');
    });

    it('should handle empty app lists', async () => {
      mockApiClient.mockResponse('GET', '/custom-apps', {
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-custom-apps');
      const result = await executeTool(tool, {}, { log: mockLog });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.apps).toHaveLength(0);
      expect(parsedResult.analysis.totalApps).toBe(0);
    });

    it('should handle malformed hook data', async () => {
      mockApiClient.mockResponse('POST', '/hooks', {
        success: true,
        data: null
      });

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-hook');
      
      await expect(executeTool(tool, {
        name: 'Test Hook',
        appId: 1,
        type: 'webhook',
        configuration: {
          endpoint: 'https://api.example.com/webhook',
          authentication: { type: 'none', configuration: {} }
        },
        events: [{ name: 'test.event', schema: { type: 'object' } }]
      }, { log: mockLog })).rejects.toThrow('Hook creation failed - no data returned');
    });

    it('should handle function creation with invalid response', async () => {
      mockApiClient.mockResponse('POST', '/custom-functions', {
        success: true,
        data: null
      });

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-function');
      
      await expect(executeTool(tool, {
        name: 'Test Function',
        type: 'transformer',
        language: 'javascript',
        code: {
          source: 'function test() { return {}; }'
        },
        interface: {
          input: { type: 'object' },
          output: { type: 'object' }
        }
      }, { log: mockLog })).rejects.toThrow('Custom function creation failed - no data returned');
    });
  });

  describe('Integration and End-to-End Scenarios', () => {
    it('should handle complete app development lifecycle', async () => {
      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);

      // 1. Create app
      mockApiClient.mockResponse('POST', '/custom-apps', {
        success: true,
        data: testCustomApp
      });

      const createAppTool = findTool(mockTool, 'create-custom-app');
      await executeTool(createAppTool, {
        name: 'E-commerce Connector',
        type: 'connector',
        configuration: {
          endpoints: [],
          authentication: { type: 'oauth2', configuration: {} }
        }
      }, { log: mockLog, reportProgress: mockReportProgress });

      // 2. Create hook for the app
      mockApiClient.mockResponse('POST', '/hooks', {
        success: true,
        data: testHook
      });

      const createHookTool = findTool(mockTool, 'create-hook');
      await executeTool(createHookTool, {
        name: 'Order Status Hook',
        appId: 1,
        type: 'webhook',
        configuration: {
          endpoint: 'https://api.company.com/webhooks/orders',
          authentication: { type: 'bearer', configuration: {} }
        },
        events: [
          { name: 'order.created', schema: { type: 'object' } }
        ]
      }, { log: mockLog, reportProgress: mockReportProgress });

      // 3. Create custom function for the app
      mockApiClient.mockResponse('POST', '/custom-functions', {
        success: true,
        data: testCustomFunction
      });

      const createFunctionTool = findTool(mockTool, 'create-custom-function');
      await executeTool(createFunctionTool, {
        name: 'Price Calculator',
        appId: 1,
        type: 'calculator',
        language: 'javascript',
        code: {
          source: 'function calculatePrice() { return {}; }'
        },
        interface: {
          input: { type: 'object' },
          output: { type: 'object' }
        }
      }, { log: mockLog, reportProgress: mockReportProgress });

      // 4. Test the complete app
      mockApiClient.mockResponse('POST', '/custom-apps/1/test', {
        success: true,
        data: {
          summary: { total: 15, passed: 14, failed: 1, duration: 120 },
          results: {
            endpoints: [{ name: 'getProducts', status: 'passed' }],
            functions: [{ name: 'Price Calculator', status: 'passed' }],
            hooks: [{ name: 'Order Status Hook', status: 'passed' }]
          }
        }
      });

      const testAppTool = findTool(mockTool, 'test-custom-app');
      await executeTool(testAppTool, {
        appId: 1,
        testType: 'all'
      }, { log: mockLog, reportProgress: mockReportProgress });

      // 5. List apps to verify everything exists
      mockApiClient.mockResponse('GET', '/custom-apps', {
        success: true,
        data: [testCustomApp],
        metadata: { total: 1 }
      });

      const listAppsTool = findTool(mockTool, 'list-custom-apps');
      await executeTool(listAppsTool, {}, { log: mockLog });

      expect(mockApiClient.getCallLog()).toHaveLength(5); // CREATE APP, CREATE HOOK, CREATE FUNCTION, TEST APP, LIST APPS
    });

    it('should handle app development with multiple environments', async () => {
      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);

      // Create app for development
      mockApiClient.mockResponse('POST', '/custom-apps', {
        success: true,
        data: { ...testCustomApp, status: 'draft' }
      });

      const tool = findTool(mockTool, 'create-custom-app');
      await executeTool(tool, {
        name: 'Multi-Env App',
        type: 'full_app',
        configuration: {
          endpoints: [],
          authentication: { type: 'none', configuration: {} }
        }
      }, { log: mockLog, reportProgress: mockReportProgress });

      // Test in development
      mockApiClient.mockResponse('POST', '/custom-apps/1/test', {
        success: true,
        data: { summary: { total: 10, passed: 10, failed: 0 } }
      });

      const testTool = findTool(mockTool, 'test-custom-app');
      await executeTool(testTool, {
        appId: 1,
        testType: 'all',
        environment: 'development'
      }, { log: mockLog, reportProgress: mockReportProgress });

      // Test in staging
      mockApiClient.mockResponse('POST', '/custom-apps/1/test', {
        success: true,
        data: { summary: { total: 15, passed: 14, failed: 1 } }
      });

      await executeTool(testTool, {
        appId: 1,
        testType: 'integration',
        environment: 'staging'
      }, { log: mockLog, reportProgress: mockReportProgress });

      expect(mockApiClient.getCallLog()).toHaveLength(3);
      expect(mockApiClient.getCallLog()[1].data.environment).toBe('development');
      expect(mockApiClient.getCallLog()[2].data.environment).toBe('staging');
    });

    it('should handle complex app with multiple hooks and functions', async () => {
      const complexApp = {
        ...testCustomApp,
        configuration: {
          ...testCustomApp.configuration,
          endpoints: [
            { name: 'getProducts', method: 'GET', path: '/products' },
            { name: 'createOrder', method: 'POST', path: '/orders' },
            { name: 'updateInventory', method: 'PUT', path: '/inventory' }
          ]
        }
      };

      mockApiClient.mockResponse('POST', '/custom-apps', {
        success: true,
        data: complexApp
      });

      // Create multiple hooks
      mockApiClient.mockResponse('POST', '/hooks', {
        success: true,
        data: { ...testHook, name: 'Order Hook' }
      });

      mockApiClient.mockResponse('POST', '/hooks', {
        success: true,
        data: { ...testPollingHook, name: 'Inventory Hook' }
      });

      // Create multiple functions
      mockApiClient.mockResponse('POST', '/custom-functions', {
        success: true,
        data: { ...testCustomFunction, name: 'Price Calculator' }
      });

      const validatorFunction = {
        ...testCustomFunction,
        id: 2,
        name: 'Order Validator',
        type: 'validator'
      };

      mockApiClient.mockResponse('POST', '/custom-functions', {
        success: true,
        data: validatorFunction
      });

      const { addCustomAppTools } = await import('../../../src/tools/custom-apps.js');
      addCustomAppTools(mockServer, mockApiClient as any);

      const createAppTool = findTool(mockTool, 'create-custom-app');
      const createHookTool = findTool(mockTool, 'create-hook');
      const createFunctionTool = findTool(mockTool, 'create-custom-function');

      // Create the app
      await executeTool(createAppTool, {
        name: 'Complex E-commerce App',
        type: 'full_app',
        configuration: {
          endpoints: complexApp.configuration.endpoints,
          authentication: { type: 'oauth2', configuration: {} }
        }
      }, { log: mockLog, reportProgress: mockReportProgress });

      // Create webhook hook
      await executeTool(createHookTool, {
        name: 'Order Hook',
        appId: 1,
        type: 'webhook',
        configuration: {
          endpoint: 'https://api.example.com/webhook',
          authentication: { type: 'none', configuration: {} }
        },
        events: [{ name: 'order.created', schema: { type: 'object' } }]
      }, { log: mockLog, reportProgress: mockReportProgress });

      // Create polling hook
      await executeTool(createHookTool, {
        name: 'Inventory Hook',
        appId: 1,
        type: 'polling',
        configuration: {
          endpoint: 'https://api.example.com/inventory',
          authentication: { type: 'none', configuration: {} },
          polling: {
            interval: 30,
            strategy: 'incremental'
          }
        },
        events: [{ name: 'inventory.updated', schema: { type: 'object' } }]
      }, { log: mockLog, reportProgress: mockReportProgress });

      // Create calculator function
      await executeTool(createFunctionTool, {
        name: 'Price Calculator',
        appId: 1,
        type: 'calculator',
        language: 'javascript',
        code: { source: 'function calc() {}' },
        interface: { input: {}, output: {} }
      }, { log: mockLog, reportProgress: mockReportProgress });

      // Create validator function
      await executeTool(createFunctionTool, {
        name: 'Order Validator',
        appId: 1,
        type: 'validator',
        language: 'python',
        code: { source: 'def validate(): pass' },
        interface: { input: {}, output: {} }
      }, { log: mockLog, reportProgress: mockReportProgress });

      expect(mockApiClient.getCallLog()).toHaveLength(5); // 1 app + 2 hooks + 2 functions
    });
  });
});