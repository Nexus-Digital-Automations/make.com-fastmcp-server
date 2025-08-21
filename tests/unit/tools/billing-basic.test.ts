/**
 * Basic Test Suite for Billing Management Tools
 * Tests core functionality of billing and payment management tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors } from '../../fixtures/test-data.js';

describe('Billing Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Complete test billing account for testing
  const testBillingAccount = {
    id: 8001,
    organizationId: 67890,
    organizationName: 'Test Organization',
    accountStatus: 'active' as const,
    billingPlan: {
      name: 'Professional Plan',
      type: 'professional' as const,
      price: 99.00,
      currency: 'USD',
      billingCycle: 'monthly' as const,
      features: ['api_access', 'advanced_analytics', 'premium_support'],
      limits: {
        operations: 100000,
        dataTransfer: 20,
        scenarios: 50,
        users: 10,
        customApps: 5
      }
    },
    usage: {
      currentPeriod: {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        operations: {
          used: 50000,
          limit: 100000,
          percentage: 50,
        },
        dataTransfer: {
          used: 10,
          limit: 20,
          percentage: 50,
        },
        scenarios: {
          active: 25,
          limit: 50,
        },
        users: {
          active: 5,
          limit: 10,
        },
      },
      history: [
        {
          period: '2023-12',
          operations: 45000,
          dataTransfer: 8.5,
          cost: 95.50
        }
      ]
    },
    billing: {
      nextBillingDate: '2024-02-01T00:00:00Z',
      lastBillingDate: '2024-01-01T00:00:00Z',
      currentBalance: 0,
      paymentStatus: 'current' as const,
      autoRenewal: true,
    },
    paymentMethods: [
      {
        id: 'pm_123',
        type: 'credit_card' as const,
        isDefault: true,
        lastFour: '4242',
        expiryDate: '12/25',
        status: 'active' as const
      }
    ],
    contacts: {
      billing: {
        name: 'John Doe',
        email: 'billing@test.com',
        phone: '+1-555-0123'
      },
      technical: {
        name: 'Jane Smith',
        email: 'tech@test.com'
      }
    },
    taxInfo: {
      taxId: 'US123456789',
      country: 'US',
      region: 'CA',
      taxExempt: false
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T00:00:00Z',
  };

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Clear previous mock calls
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register billing tools', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      
      // Should not throw an error
      expect(() => {
        addBillingTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each billing tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected billing tools and types', async () => {
      const billingModule = await import('../../../src/tools/billing.js');
      
      // Check that expected exports exist
      expect(billingModule.addBillingTools).toBeDefined();
      expect(typeof billingModule.addBillingTools).toBe('function');
      expect(billingModule.default).toBeDefined();
      expect(typeof billingModule.default).toBe('function');
      
      // Note: TypeScript interfaces are not available at runtime, so we can't test for them
      // This is expected behavior - interfaces exist only during compilation
    });

    it('should register all core billing tools', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'get-billing-account',
        'list-invoices', 
        'get-usage-metrics',
        'add-payment-method',
        'update-billing-info',
        'set-budget',
        'create-cost-alert',
        'get-cost-projection',
        'pause-high-cost-scenarios'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for get-billing-account tool', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      
      expect(tool.name).toBe('get-billing-account');
      expect(tool.description).toContain('comprehensive billing account information');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
    });

    it('should have correct structure for advanced budgeting tools', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const setBudgetTool = findTool(mockTool, 'set-budget');
      expect(setBudgetTool.name).toBe('set-budget');
      expect(setBudgetTool.description).toContain('operational budgets');
      expect(setBudgetTool.parameters).toBeDefined();

      const costAlertTool = findTool(mockTool, 'create-cost-alert');
      expect(costAlertTool.name).toBe('create-cost-alert');
      expect(costAlertTool.description).toContain('cost alerts');
      expect(costAlertTool.parameters).toBeDefined();

      const projectionTool = findTool(mockTool, 'get-cost-projection');
      expect(projectionTool.name).toBe('get-cost-projection');
      expect(projectionTool.description).toContain('cost forecasts');
      expect(projectionTool.parameters).toBeDefined();
    });

    it('should have correct structure for payment management tools', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const paymentTool = findTool(mockTool, 'add-payment-method');
      expect(paymentTool.name).toBe('add-payment-method');
      expect(paymentTool.description).toContain('payment method');
      expect(paymentTool.parameters).toBeDefined();

      const invoiceTool = findTool(mockTool, 'list-invoices');
      expect(invoiceTool.name).toBe('list-invoices');
      expect(invoiceTool.description).toContain('invoices');
      expect(invoiceTool.parameters).toBeDefined();
    });
  });

  describe('Schema Validation', () => {
    it('should validate billing account schema with correct inputs', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      
      // Valid inputs
      const validInputs = [
        {},
        { organizationId: 12345 },
        { includeUsage: true, includeHistory: false },
        { organizationId: 67890, includeUsage: true, includeHistory: true, includePaymentMethods: false }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid billing account schema inputs', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      
      // Invalid inputs
      const invalidInputs = [
        { organizationId: 0 }, // organizationId must be >= 1
        { organizationId: -1 }, // negative organizationId
        { organizationId: 'invalid' }, // string instead of number
        { unknownField: 'value' }, // unexpected field due to strict schema
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate payment method schema with different types', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'add-payment-method');
      
      // Valid credit card input
      const validCreditCard = {
        type: 'credit_card' as const,
        details: {
          cardNumber: '4242424242424242',
          expiryMonth: 12,
          expiryYear: 2025,
          cvv: '123'
        },
        billingAddress: {
          name: 'John Doe',
          address1: '123 Main St',
          city: 'New York',
          postalCode: '10001',
          country: 'US'
        }
      };
      
      expectValidZodParse(tool.parameters, validCreditCard);

      // Valid PayPal input
      const validPayPal = {
        type: 'paypal' as const,
        details: {
          paypalEmail: 'user@paypal.com'
        },
        billingAddress: {
          name: 'Jane Smith',
          address1: '456 Oak Ave',
          city: 'Los Angeles',
          postalCode: '90210',
          country: 'US'
        }
      };
      
      expectValidZodParse(tool.parameters, validPayPal);
    });

    it('should validate budget schema with comprehensive configuration', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'set-budget');
      
      const validBudget = {
        name: 'Q1 Marketing Budget',
        description: 'Budget for marketing team Q1 activities',
        type: 'team' as const,
        scope: {
          teamIds: [12345, 67890]
        },
        budget: {
          amount: 5000,
          currency: 'USD',
          period: 'monthly' as const,
          startDate: '2024-01-01'
        },
        thresholds: [
          {
            percentage: 75,
            action: 'warn' as const,
            notificationChannels: ['email' as const, 'slack' as const]
          },
          {
            percentage: 90,
            action: 'restrict' as const,
            notificationChannels: ['email' as const]
          }
        ]
      };
      
      expectValidZodParse(tool.parameters, validBudget);
    });

    it('should validate cost alert schema with advanced conditions', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-cost-alert');
      
      const validCostAlert = {
        name: 'High Cost Scenario Alert',
        description: 'Alert when scenarios exceed cost thresholds',
        conditions: {
          costThreshold: {
            amount: 100,
            currency: 'USD',
            period: 'daily' as const
          },
          usageThreshold: {
            operations: 10000,
            dataTransfer: 50,
            percentage: 80
          },
          scenarioIds: [2001, 2002]
        },
        notifications: {
          channels: [
            {
              type: 'email' as const,
              target: 'admin@company.com'
            },
            {
              type: 'webhook' as const,
              target: 'https://company.com/webhook/alert'
            }
          ],
          frequency: 'immediate' as const,
          escalation: {
            enabled: true,
            after: 30,
            channels: [
              {
                type: 'sms' as const,
                target: '+1-555-0123'
              }
            ]
          }
        },
        actions: [
          {
            type: 'pause_scenarios' as const,
            configuration: {
              scenarioIds: [2001, 2002]
            },
            delay: 5
          }
        ]
      };
      
      expectValidZodParse(tool.parameters, validCostAlert);
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute get-billing-account successfully with mocked data', async () => {
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: testBillingAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const result = await executeTool(tool, {});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.account).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
      expect(parsedResult.summary.organizationName).toBe(testBillingAccount.organizationName);
      expect(parsedResult.summary.plan.name).toBe(testBillingAccount.billingPlan.name);
    });

    it('should execute list-invoices with pagination parameters', async () => {
      const mockInvoices = [
        {
          id: 'inv_001',
          number: 'INV-2024-001',
          organizationId: 67890,
          status: 'paid',
          amount: { subtotal: 99.00, tax: 9.90, total: 108.90, currency: 'USD' },
          period: { startDate: '2024-01-01T00:00:00Z', endDate: '2024-01-31T23:59:59Z' },
          dueDate: '2024-02-01T00:00:00Z',
          issuedDate: '2024-01-01T00:00:00Z',
          paidDate: '2024-01-15T10:30:00Z',
          lineItems: [],
          payments: []
        }
      ];

      mockApiClient.mockResponse('GET', '/billing/invoices', {
        success: true,
        data: mockInvoices,
        metadata: { total: 1, page: 1, limit: 20 }
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-invoices');
      const result = await executeTool(tool, {
        status: 'paid',
        limit: 10,
        sortBy: 'date',
        sortOrder: 'desc'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.invoices).toHaveLength(1);
      expect(parsedResult.analysis.totalInvoices).toBe(1);
      expect(parsedResult.pagination.limit).toBe(10);
    });

    it('should execute get-usage-metrics with breakdown parameters', async () => {
      const mockUsageMetrics = {
        organizationId: 67890,
        period: { startDate: '2024-01-01T00:00:00Z', endDate: '2024-01-31T23:59:59Z' },
        metrics: {
          operations: {
            total: 50000,
            byScenario: [
              { scenarioId: 1, scenarioName: 'Test Scenario', operations: 20000, cost: 40.00 }
            ],
            byApp: [
              { appName: 'email', operations: 15000, cost: 30.00 }
            ],
            byTeam: [
              { teamId: 12345, teamName: 'Test Team', operations: 50000, cost: 100.00 }
            ]
          },
          dataTransfer: {
            total: 10.5,
            byDirection: { incoming: 5.2, outgoing: 5.3 },
            byRegion: [
              { region: 'us-east-1', transfer: 8.0, cost: 2.40 }
            ]
          },
          storage: {
            dataStores: 2.1,
            logs: 0.8,
            backups: 1.2,
            total: 4.1,
            cost: 4.10
          },
          support: {
            tickets: 2,
            priority: { low: 1, medium: 1, high: 0, critical: 0 },
            responseTime: 4.5,
            cost: 0
          }
        },
        costs: {
          breakdown: {
            subscription: 99.00,
            operations: 100.00,
            dataTransfer: 2.40,
            storage: 4.10,
            support: 0,
            addons: 0
          },
          total: 205.50,
          currency: 'USD',
          projectedMonthly: 220.00
        },
        recommendations: [
          {
            type: 'cost_optimization',
            title: 'Optimize data transfer',
            description: 'Consider caching frequently accessed data',
            impact: 'medium',
            savings: 1.20
          }
        ]
      };

      mockApiClient.mockResponse('GET', '/billing/usage', {
        success: true,
        data: mockUsageMetrics
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-usage-metrics');
      const result = await executeTool(tool, {
        period: 'current',
        breakdown: ['scenario', 'app'],
        includeProjections: true,
        includeRecommendations: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.metrics.organizationId).toBe(67890);
      expect(parsedResult.summary.usage.operations).toBe(50000);
      expect(parsedResult.optimization.recommendations).toHaveLength(1);
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/billing/account', new Error('Billing service unavailable'));

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('GET', '/billing/account', testErrors.unauthorized);

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should validate required fields for payment methods', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'add-payment-method');
      
      // Credit card without required fields should fail
      await expect(executeTool(tool, {
        type: 'credit_card',
        details: { cardNumber: '4242424242424242' }, // Missing expiry and CVV
        billingAddress: {
          name: 'John Doe',
          address1: '123 Main St',
          city: 'New York',
          postalCode: '10001',
          country: 'US'
        }
      })).rejects.toThrow(UserError);
    });

    it('should validate budget configuration', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'set-budget');
      
      // Team budget without team IDs should fail
      await expect(executeTool(tool, {
        name: 'Invalid Budget',
        type: 'team',
        scope: {}, // Missing teamIds for team budget
        budget: {
          amount: 1000,
          currency: 'USD',
          period: 'monthly',
          startDate: '2024-01-01'
        },
        thresholds: [
          {
            percentage: 75,
            action: 'warn',
            notificationChannels: ['email']
          }
        ]
      })).rejects.toThrow(UserError);
    });

    it('should prevent sensitive data exposure in payment methods', async () => {
      const mockPaymentMethod = {
        id: 'pm_123',
        type: 'credit_card',
        lastFour: '4242',
        isDefault: true,
        status: 'active'
      };

      mockApiClient.mockResponse('POST', '/billing/payment-methods', {
        success: true,
        data: mockPaymentMethod
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'add-payment-method');
      const result = await executeTool(tool, {
        type: 'credit_card',
        details: {
          cardNumber: '4242424242424242',
          expiryMonth: 12,
          expiryYear: 2025,
          cvv: '123'
        },
        billingAddress: {
          name: 'John Doe',
          address1: '123 Main St',
          city: 'New York',
          postalCode: '10001',
          country: 'US'
        }
      });
      
      // Ensure sensitive data is not in the response
      expect(result).not.toContain('4242424242424242');
      expect(result).toContain('[PAYMENT_DETAILS_SECURE]');
      
      // Parse and check that the CVV is not in the structured data
      // Note: We specifically check for the CVV pattern, not the payment method ID which happens to be "pm_123"
      const parsedResult = JSON.parse(result);
      expect(parsedResult.paymentMethod.details).toBe('[PAYMENT_DETAILS_SECURE]');
      
      // Verify that sensitive data is masked in the API request
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data.details.cardNumber).toBe('[CARD_NUMBER_ENCRYPTED]');
      expect(calls[0].data.details.cvv).toBe('[CVV_ENCRYPTED]');
    });

    it('should enforce financial data validation and audit trails', async () => {
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: testBillingAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const mockLog = {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn()
      };
      
      await executeTool(tool, {}, { log: mockLog });
      
      // Verify audit logging
      expect(mockLog.info).toHaveBeenCalledWith(
        'Getting billing account information',
        expect.any(Object)
      );
      expect(mockLog.info).toHaveBeenCalledWith(
        'Successfully retrieved billing account',
        expect.any(Object)
      );
    });
  });

  describe('Enterprise Billing Features', () => {
    it('should support advanced budget management with cost controls', async () => {
      const mockBudget = {
        id: 'budget_123',
        organizationId: 67890,
        name: 'Enterprise Budget',
        type: 'organization',
        scope: { organizationId: 67890 },
        budget: {
          amount: 50000,
          currency: 'USD',
          period: 'monthly',
          startDate: '2024-01-01'
        },
        thresholds: [
          { percentage: 75, action: 'warn', notificationChannels: ['email'] },
          { percentage: 90, action: 'restrict', notificationChannels: ['email', 'webhook'] },
          { percentage: 100, action: 'pause', notificationChannels: ['email', 'sms'] }
        ],
        status: 'active',
        createdAt: '2024-01-01T00:00:00Z',
        updatedAt: '2024-01-01T00:00:00Z',
        createdBy: 'admin@company.com'
      };

      mockApiClient.mockResponse('POST', '/billing/budgets', {
        success: true,
        data: mockBudget
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'set-budget');
      const result = await executeTool(tool, {
        name: 'Enterprise Budget',
        type: 'organization',
        scope: { organizationId: 67890 },
        budget: {
          amount: 50000,
          currency: 'USD',
          period: 'monthly',
          startDate: '2024-01-01'
        },
        thresholds: [
          { percentage: 75, action: 'warn', notificationChannels: ['email'] },
          { percentage: 90, action: 'restrict', notificationChannels: ['email', 'webhook'] },
          { percentage: 100, action: 'pause', notificationChannels: ['email', 'sms'] }
        ]
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.budget.id).toBe('budget_123');
      expect(parsedResult.summary.thresholds).toContain('100% → pause');
      expect(parsedResult.warnings).toContain('Budget includes 100% threshold - may cause service interruption');
    });

    it('should support cost projection with confidence intervals', async () => {
      const mockProjection = {
        organizationId: 67890,
        projectionDate: '2024-01-20T00:00:00Z',
        period: {
          startDate: '2024-02-01',
          endDate: '2024-02-29',
          type: 'monthly'
        },
        methodology: {
          algorithm: 'seasonal',
          confidence: 95,
          basedOnDays: 90,
          factors: [
            { name: 'historical_trend', weight: 0.4, impact: 0.15 },
            { name: 'seasonal_pattern', weight: 0.3, impact: 0.08 },
            { name: 'growth_rate', weight: 0.3, impact: 0.12 }
          ]
        },
        projections: {
          conservative: {
            total: 4500,
            breakdown: { operations: 3000, dataTransfer: 500, storage: 200, support: 0, addons: 800 },
            confidence: 85
          },
          realistic: {
            total: 5200,
            breakdown: { operations: 3500, dataTransfer: 600, storage: 250, support: 50, addons: 800 },
            confidence: 95
          },
          optimistic: {
            total: 6100,
            breakdown: { operations: 4200, dataTransfer: 700, storage: 300, support: 100, addons: 800 },
            confidence: 75
          }
        },
        trends: {
          growthRate: { monthly: 15.5, quarterly: 48.2, annually: 186.4 },
          seasonality: [
            { month: 1, multiplier: 0.9 },
            { month: 2, multiplier: 1.1 }
          ],
          anomalies: []
        },
        budgetComparison: [],
        recommendations: [
          {
            type: 'budget_adjustment',
            priority: 'high',
            title: 'Increase monthly budget',
            description: 'Current budget may be insufficient for projected usage',
            impact: { cost: 1000, timeframe: '1 month' },
            actions: ['Increase budget to $6500', 'Review usage patterns']
          }
        ],
        currency: 'USD',
        generatedAt: '2024-01-20T00:00:00Z'
      };

      mockApiClient.mockResponse('POST', '/billing/projections', {
        success: true,
        data: mockProjection
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-cost-projection');
      const result = await executeTool(tool, {
        period: {
          type: 'monthly',
          count: 1
        },
        algorithm: 'seasonal',
        basedOnDays: 90,
        confidenceLevel: 95
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.projection.methodology.algorithm).toBe('seasonal');
      expect(parsedResult.projection.methodology.confidence).toBe(95);
      expect(parsedResult.analysis.projectionRange.realistic).toBe(5200);
      expect(parsedResult.recommendations.total).toBe(1);
    });

    it('should support automated high-cost scenario management', async () => {
      const mockEvaluationResult = {
        action: 'simulate',
        scenarios: [
          {
            id: 2001,
            name: 'High Volume Processing',
            currentCost: 150.00,
            projectedCost: 200.00,
            costImpact: 50.00,
            riskLevel: 'high',
            action: 'pause',
            reasoning: 'Cost exceeds threshold by 100%'
          },
          {
            id: 2002,
            name: 'Data Sync Process',
            currentCost: 75.00,
            projectedCost: 90.00,
            costImpact: 15.00,
            riskLevel: 'medium',
            action: 'restrict',
            reasoning: 'Cost trend indicates potential overrun'
          }
        ],
        summary: {
          evaluated: 50,
          identified: 2
        }
      };

      mockApiClient.mockResponse('POST', '/billing/scenarios/pause-high-cost', {
        success: true,
        data: mockEvaluationResult
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'pause-high-cost-scenarios');
      const result = await executeTool(tool, {
        criteria: {
          costThreshold: {
            amount: 100,
            currency: 'USD',
            period: 'daily'
          },
          budgetExceedance: {
            budgetIds: ['budget_123'],
            percentage: 80
          }
        },
        action: 'simulate',
        notification: {
          enabled: true,
          channels: ['email'],
          includeDetails: true
        },
        dryRun: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.summary.scenariosEvaluated).toBe(50);
      expect(parsedResult.summary.scenariosIdentified).toBe(2);
      expect(parsedResult.summary.estimatedCostSavings).toBe(65); // 50 + 15
      expect(parsedResult.evaluation.dryRun).toBe(true);
      expect(parsedResult.nextSteps).toContain('Execute with dryRun=false when ready to perform actions');
    });
  });
});