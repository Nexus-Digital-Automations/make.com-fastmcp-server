/**
 * Unit tests for billing management tools
 * Tests billing account access, invoice management, usage metrics, and payment methods
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';
import { testBillingAccount, testErrors } from '../../fixtures/test-data.js';

describe('Billing Management Tools', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;

  // Helper to parse response format consistently
  const parseToolResult = (result: any) => {
    const resultText = result.content?.[0]?.text || result;
    return typeof resultText === 'string' ? JSON.parse(resultText) : resultText;
  };

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('get-billing-account tool', () => {
    it('should register get-billing-account tool with correct configuration', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      expect(tool).toBeDefined();
      expect(tool.name).toBe('get-billing-account');
      expect(tool.description).toContain('comprehensive billing account information');
      expect(tool.parameters).toBeDefined();
    });

    it('should get billing account successfully with default options', async () => {
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: testBillingAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const mockReportProgress = jest.fn();
      
      const result = await executeTool(tool, {}, { reportProgress: mockReportProgress });
      
      // Handle the new response format
      const resultText = result.content?.[0]?.text || result;
      const parsedResult = typeof resultText === 'string' ? JSON.parse(resultText) : resultText;
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.account.organizationName).toBe(testBillingAccount.organizationName);
      expect(parsedResult.account.billingPlan.name).toBe(testBillingAccount.billingPlan.name);
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 50, total: 100 },
        { progress: 100, total: 100 }
      ]);
    });

    it('should handle organization-specific billing account', async () => {
      const orgId = 12345;
      mockApiClient.mockResponse(`GET`, `/organizations/${orgId}/billing/account`, {
        success: true,
        data: { ...testBillingAccount, organizationId: orgId }
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const result = await executeTool(tool, { organizationId: orgId });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].endpoint).toBe(`/organizations/${orgId}/billing/account`);
    });

    it('should include usage statistics when requested', async () => {
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: testBillingAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const result = await executeTool(tool, { 
        includeUsage: true,
        includeHistory: true 
      });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject({
        includeUsage: true,
        includeHistory: true
      });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.summary.usage).toBeDefined();
      expect(parsedResult.alerts).toBeDefined();
    });

    it('should mask sensitive payment information', async () => {
      const accountWithPaymentMethods = {
        ...testBillingAccount,
        paymentMethods: [{
          id: 'pm_123',
          type: 'credit_card',
          isDefault: true,
          lastFour: '4242',
          expiryDate: '12/25',
          status: 'active'
        }]
      };

      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: accountWithPaymentMethods
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const result = await executeTool(tool, { includePaymentMethods: true });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.account.paymentMethods[0]).toMatchObject({
        lastFour: '4242',
        type: 'credit_card',
        status: 'active',
        isDefault: true
      });
      // Ensure sensitive data is not exposed
      expect(parsedResult.account.paymentMethods[0]).not.toHaveProperty('cardNumber');
      expect(parsedResult.account.paymentMethods[0]).not.toHaveProperty('expiryDate');
    });

    it('should generate alerts for high usage', async () => {
      const highUsageAccount = {
        ...testBillingAccount,
        usage: {
          currentPeriod: {
            ...testBillingAccount.usage.currentPeriod,
            operations: {
              used: 85000,
              limit: 100000,
              percentage: 85
            },
            dataTransfer: {
              used: 18,
              limit: 20,
              percentage: 90
            }
          }
        }
      };

      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: highUsageAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      const result = await executeTool(tool, {});
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.alerts).toContain('Operations usage above 80%');
      expect(parsedResult.alerts).toContain('Data transfer usage above 80%');
    });
  });

  describe('list-invoices tool', () => {
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
      },
      {
        id: 'inv_002',
        number: 'INV-2024-002',
        organizationId: 67890,
        status: 'overdue',
        amount: { subtotal: 99.00, tax: 9.90, total: 108.90, currency: 'USD' },
        period: { startDate: '2024-02-01T00:00:00Z', endDate: '2024-02-29T23:59:59Z' },
        dueDate: '2024-03-01T00:00:00Z',
        issuedDate: '2024-02-01T00:00:00Z',
        lineItems: [],
        payments: []
      }
    ];

    it('should list invoices successfully', async () => {
      mockApiClient.mockResponse('GET', '/billing/invoices', {
        success: true,
        data: mockInvoices,
        metadata: { total: 2, page: 1, limit: 20 }
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-invoices');
      const result = await executeTool(tool, {});
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.invoices).toHaveLength(2);
      expect(parsedResult.analysis.totalInvoices).toBe(2);
      expect(parsedResult.analysis.financialSummary.totalAmount).toBe(217.80);
    });

    it('should filter invoices by status', async () => {
      const paidInvoices = [mockInvoices[0]];
      mockApiClient.mockResponse('GET', '/billing/invoices', {
        success: true,
        data: paidInvoices,
        metadata: { total: 1, page: 1, limit: 20 }
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-invoices');
      const result = await executeTool(tool, { status: 'paid' });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject({ status: 'paid' });
    });

    it('should filter invoices by date range', async () => {
      mockApiClient.mockResponse('GET', '/billing/invoices', {
        success: true,
        data: [mockInvoices[0]],
        metadata: { total: 1, page: 1, limit: 20 }
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-invoices');
      const result = await executeTool(tool, {
        dateRange: {
          startDate: '2024-01-01',
          endDate: '2024-01-31'
        }
      });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject({
        startDate: '2024-01-01',
        endDate: '2024-01-31'
      });
    });

    it('should provide financial analysis', async () => {
      mockApiClient.mockResponse('GET', '/billing/invoices', {
        success: true,
        data: mockInvoices,
        metadata: { total: 2, page: 1, limit: 20 }
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-invoices');
      const result = await executeTool(tool, {});
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.analysis.statusBreakdown).toEqual({
        paid: 1,
        overdue: 1
      });
      expect(parsedResult.analysis.financialSummary.paidAmount).toBe(108.90);
      expect(parsedResult.analysis.financialSummary.overdueAmount).toBe(108.90);
    });
  });

  describe('get-usage-metrics tool', () => {
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

    it('should get usage metrics successfully', async () => {
      mockApiClient.mockResponse('GET', '/billing/usage', {
        success: true,
        data: mockUsageMetrics
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-usage-metrics');
      const mockReportProgress = jest.fn();
      
      const result = await executeTool(tool, {}, { reportProgress: mockReportProgress });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.metrics.organizationId).toBe(67890);
      expect(parsedResult.summary.usage.operations).toBe(50000);
      expect(parsedResult.optimization.recommendations).toHaveLength(1);
      
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 50, total: 100 },
        { progress: 100, total: 100 }
      ]);
    });

    it('should handle custom period parameters', async () => {
      mockApiClient.mockResponse('GET', '/billing/usage', {
        success: true,
        data: mockUsageMetrics
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-usage-metrics');
      const result = await executeTool(tool, {
        period: 'custom',
        customPeriod: {
          startDate: '2024-01-01',
          endDate: '2024-01-31'
        }
      });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject({
        period: 'custom',
        startDate: '2024-01-01',
        endDate: '2024-01-31'
      });
    });

    it('should validate custom period requirement', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-usage-metrics');
      
      await expect(executeTool(tool, {
        period: 'custom'
        // Missing customPeriod
      })).rejects.toThrow(UserError);
    });

    it('should handle breakdown parameters', async () => {
      mockApiClient.mockResponse('GET', '/billing/usage', {
        success: true,
        data: mockUsageMetrics
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-usage-metrics');
      const result = await executeTool(tool, {
        breakdown: ['scenario', 'app', 'team']
      });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data.breakdown).toBe('scenario,app,team');
    });
  });

  describe('add-payment-method tool', () => {
    it('should add credit card payment method successfully', async () => {
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
      const mockReportProgress = jest.fn();
      
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
          state: 'NY',
          postalCode: '10001',
          country: 'US'
        },
        setAsDefault: true
      }, { reportProgress: mockReportProgress });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.summary.type).toBe('credit_card');
      expect(parsedResult.summary.isDefault).toBe(true);
      
      // Verify sensitive data is masked in request
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data.details.cardNumber).toBe('[CARD_NUMBER_ENCRYPTED]');
      expect(calls[0].data.details.cvv).toBe('[CVV_ENCRYPTED]');
    });

    it('should validate payment method types', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'add-payment-method');
      
      // Credit card without required fields
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
      
      // Bank account without required fields
      await expect(executeTool(tool, {
        type: 'bank_account',  
        details: { accountNumber: '12345' }, // Missing routing number
        billingAddress: {
          name: 'John Doe',
          address1: '123 Main St',
          city: 'New York',
          postalCode: '10001',
          country: 'US'
        }
      })).rejects.toThrow(UserError);
    });

    it('should handle PayPal payment method', async () => {
      const mockPaymentMethod = {
        id: 'pm_paypal_123',
        type: 'paypal',
        lastFour: 'paypal',
        isDefault: false,
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
        type: 'paypal',
        details: {
          paypalEmail: 'user@paypal.com'
        },
        billingAddress: {
          name: 'John Doe',
          address1: '123 Main St',
          city: 'New York',
          postalCode: '10001',
          country: 'US'
        }
      });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.paymentMethod.type).toBe('paypal');
    });
  });

  describe('update-billing-info tool', () => {
    it('should update billing contacts successfully', async () => {
      const updatedAccount = {
        ...testBillingAccount,
        contacts: {
          billing: {
            name: 'Jane Smith',
            email: 'billing@newcompany.com',
            phone: '+1-555-0123'
          },
          technical: {
            name: 'Bob Johnson',
            email: 'tech@newcompany.com'
          }
        }
      };

      mockApiClient.mockResponse('PUT', '/billing/account', {
        success: true,
        data: updatedAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-billing-info');
      const result = await executeTool(tool, {
        contacts: {
          billing: {
            name: 'Jane Smith',
            email: 'billing@newcompany.com',
            phone: '+1-555-0123'
          },
          technical: {
            name: 'Bob Johnson',
            email: 'tech@newcompany.com'
          }
        }
      });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.updates.contacts).toBe(true);
      expect(parsedResult.summary.billingContact).toContain('Jane Smith');
    });

    it('should update tax information', async () => {
      const updatedAccount = {
        ...testBillingAccount,
        taxInfo: {
          taxId: 'US123456789',
          vatNumber: 'VAT123456',
          country: 'US',
          region: 'CA',
          taxExempt: false
        }
      };

      mockApiClient.mockResponse('PUT', '/billing/account', {
        success: true,
        data: updatedAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-billing-info');
      const result = await executeTool(tool, {
        taxInfo: {
          taxId: 'US123456789',
          vatNumber: 'VAT123456',
          country: 'US',
          region: 'CA',
          taxExempt: false
        }
      });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.updates.taxInfo).toBe(true);
      expect(parsedResult.summary.taxExempt).toBe(false);
    });

    it('should update auto-renewal setting', async () => {
      const updatedAccount = {
        ...testBillingAccount,
        billing: {
          ...testBillingAccount.billing,
          autoRenewal: false
        }
      };

      mockApiClient.mockResponse('PUT', '/billing/account', {
        success: true,
        data: updatedAccount
      });

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-billing-info');
      const result = await executeTool(tool, {
        autoRenewal: false
      });
      
      const parsedResult = parseToolResult(result);
      expect(parsedResult.updates.autoRenewal).toBe(true);
      expect(parsedResult.summary.autoRenewal).toBe(false);
    });

    it('should require at least one update parameter', async () => {
      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-billing-info');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });
  });

  describe('Error handling and security', () => {
    it('should handle API errors gracefully', async () => {
      mockApiClient.mockFailure('GET', '/billing/account', new Error('Billing service unavailable'));

      const { addBillingTools } = await import('../../../src/tools/billing.js');
      addBillingTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-billing-account');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should never expose sensitive payment data in responses', async () => {
      const mockPaymentMethod = {
        id: 'pm_123',
        type: 'credit_card',
        cardNumber: '4242424242424242', // This should never appear in response
        cvv: '123', // This should never appear in response
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
      
      const parsedResult = parseToolResult(result);
      const resultStr = JSON.stringify(parsedResult);
      expect(resultStr).not.toContain('4242424242424242');
      expect(resultStr).not.toContain('123');
      expect(resultStr).toContain('[PAYMENT_DETAILS_SECURE]');
    });

    it('should log billing operations for audit trail', async () => {
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
      
      expectToolCall(mockLog, 'info', 'Getting billing account information');
      expectToolCall(mockLog, 'info', 'Successfully retrieved billing account');
    });
  });
});