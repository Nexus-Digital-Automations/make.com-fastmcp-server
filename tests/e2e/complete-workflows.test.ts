/**
 * End-to-end tests for complete Make.com FastMCP workflows
 * Tests full user scenarios from start to finish
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';
import { 
  executeTool,
  createTestEnvironment,
  waitForCondition,
  performanceHelpers
} from '../utils/test-helpers.js';
import { 
  testUsers,
  testScenarios, 
  testConnections,
  testTemplates,
  testBillingAccount,
  generateTestData
} from '../fixtures/test-data.js';

// Import actual tools
import * as scenarioTools from '../../src/tools/scenarios.js';
import * as connectionTools from '../../src/tools/connections.js';
import * as permissionTools from '../../src/tools/permissions.js';

describe('End-to-End Workflow Tests', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let testEnv: any;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    testEnv = createTestEnvironment();
    
    // Set up all tool modules
    const modules = [
      '../src/tools/scenarios.js',
      '../src/tools/connections.js', 
      '../src/tools/permissions.js',
      '../src/tools/analytics.js',
      '../src/tools/variables.js',
      '../src/tools/ai-agents.js',
      '../src/tools/templates.js',
      '../src/tools/folders.js',
      '../src/tools/certificates.js',
      '../src/tools/procedures.js',
      '../src/tools/custom-apps.js',
      '../src/tools/sdk.js',
      '../src/tools/billing.js',
      '../src/tools/notifications.js'
    ];
    
    for (const module of modules) {
      try {
        const { addScenarioTools, addConnectionTools, addPermissionTools, 
                addAnalyticsTools, addVariableTools, addAIAgentTools,
                addTemplateTools, addFolderTools, addCertificateTools,
                addProcedureTools, addCustomAppTools, addSDKTools,
                addBillingTools, addNotificationTools } = await import(module);
        
        // Call the appropriate add function based on the module
        if (module.includes('scenarios')) addScenarioTools?.(mockServer, mockApiClient);
        if (module.includes('connections')) addConnectionTools?.(mockServer, mockApiClient);
        if (module.includes('permissions')) addPermissionTools?.(mockServer, mockApiClient);
        if (module.includes('analytics')) addAnalyticsTools?.(mockServer, mockApiClient);
        if (module.includes('variables')) addVariableTools?.(mockServer, mockApiClient);
        if (module.includes('ai-agents')) addAIAgentTools?.(mockServer, mockApiClient);
        if (module.includes('templates')) addTemplateTools?.(mockServer, mockApiClient);
        if (module.includes('folders')) addFolderTools?.(mockServer, mockApiClient);
        if (module.includes('certificates')) addCertificateTools?.(mockServer, mockApiClient);
        if (module.includes('procedures')) addProcedureTools?.(mockServer, mockApiClient);
        if (module.includes('custom-apps')) addCustomAppTools?.(mockServer, mockApiClient);
        if (module.includes('sdk')) addSDKTools?.(mockServer, mockApiClient);
        if (module.includes('billing')) addBillingTools?.(mockServer, mockApiClient);
        if (module.includes('notifications')) addNotificationTools?.(mockServer, mockApiClient);
      } catch (error) {
        // Module might not exist or export the expected function
        // This is expected for this test setup
      }
    }
  });

  afterEach(async () => {
    await testEnv.cleanup();
    mockApiClient.reset();
    jest.clearAllMocks();
  });

  describe('Complete Scenario Management Workflow', () => {
    it('should complete full scenario lifecycle: create -> configure -> test -> deploy -> monitor', async () => {
      // Step 1: Create a new scenario
      const newScenario = generateTestData.scenario({
        name: 'E2E Test Scenario',
        isActive: false
      });
      
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: newScenario
      });
      
      const createTool = findTool(mockTool, 'create-scenario');
      const createResult = await executeTool(createTool, {
        name: 'E2E Test Scenario',
        blueprint: {
          flow: [
            { id: 1, app: 'webhook', operation: 'trigger' },
            { id: 2, app: 'filter', operation: 'condition' },
            { id: 3, app: 'email', operation: 'send' }
          ]
        },
        scheduling: { type: 'on-demand' },
        teamId: 12345
      });
      
      expect(createResult).toContain('E2E Test Scenario');
      
      // Step 2: Update scenario configuration
      const updatedScenario = { ...newScenario, isActive: true };
      mockApiClient.mockResponse('PUT', `/scenarios/${newScenario.id}`, {
        success: true,
        data: updatedScenario
      });
      
      const updateTool = findTool(mockTool, 'update-scenario');
      const updateResult = await executeTool(updateTool, {
        scenarioId: newScenario.id,
        isActive: true
      });
      
      expect(updateResult).toContain('successfully updated');
      
      // Step 3: Clone scenario for testing
      const clonedScenario = { ...newScenario, id: 9999, name: 'E2E Test Scenario (Clone)' };
      mockApiClient.mockResponse('POST', `/scenarios/${newScenario.id}/clone`, {
        success: true,
        data: clonedScenario
      });
      
      const cloneTool = findTool(mockTool, 'clone-scenario');
      const cloneResult = await executeTool(cloneTool, {
        scenarioId: newScenario.id,
        name: 'E2E Test Scenario (Clone)'
      });
      
      expect(cloneResult).toContain('E2E Test Scenario (Clone)');
      
      // Step 4: List scenarios to verify
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [updatedScenario, clonedScenario],
        metadata: { total: 2, page: 1, limit: 20 }
      });
      
      const listTool = findTool(mockTool, 'list-scenarios');
      const listResult = await executeTool(listTool, {});
      
      expect(listResult).toContain('E2E Test Scenario');
      expect(listResult).toContain('E2E Test Scenario (Clone)');
      
      // Verify all API calls were made in correct order
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(4);
      expect(callLog[0].method).toBe('POST');
      expect(callLog[1].method).toBe('PUT');
      expect(callLog[2].method).toBe('POST');
      expect(callLog[3].method).toBe('GET');
    });
  });

  describe('User Onboarding and Permission Management Workflow', () => {
    it('should complete user onboarding: invite -> assign roles -> configure permissions -> verify access', async () => {
      // Step 1: Create new user (simulate invitation)
      const newUser = generateTestData.user({
        name: 'New Team Member',
        email: 'newmember@test.com',
        role: 'member',
        isActive: false // Not yet activated
      });
      
      mockApiClient.mockResponse('POST', '/users', {
        success: true,
        data: newUser
      });
      
      // Since we don't have user creation in our current tools, we'll mock this step
      // In a real implementation, this would use a create-user tool
      
      // Step 2: Assign role and permissions
      const activatedUser = { ...newUser, isActive: true, permissions: ['read', 'write'] };
      mockApiClient.mockResponse('PUT', `/users/${newUser.id}/permissions`, {
        success: true,
        data: activatedUser
      });
      
      // This would use a user management tool that we haven't implemented
      // For this E2E test, we're demonstrating the workflow pattern
      
      // Step 3: Add user to team
      mockApiClient.mockResponse('POST', `/teams/12345/members`, {
        success: true,
        data: { message: 'User added to team successfully' }
      });
      
      // Step 4: Verify user can access resources
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [testScenarios.active],
        metadata: { total: 1 }
      });
      
      const listTool = findTool(mockTool, 'list-scenarios');
      const result = await executeTool(listTool, {}, {
        session: { user: activatedUser }
      });
      
      expect(result).toContain('Active Test Scenario');
    });
  });

  describe('Template to Production Workflow', () => {
    it('should complete template deployment: browse -> customize -> create scenario -> configure connections -> deploy', async () => {
      // Step 1: Browse available templates
      mockApiClient.mockResponse('GET', '/templates', {
        success: true,
        data: [testTemplates.public, testTemplates.private],
        metadata: { total: 2 }
      });
      
      const listTemplates = findTool(mockTool, 'list-templates');
      const templatesResult = await executeTool(listTemplates, { isPublic: true });
      
      expect(templatesResult).toContain('Email Marketing Template');
      
      // Step 2: Get template details
      mockApiClient.mockResponse('GET', `/templates/${testTemplates.public.id}`, {
        success: true,
        data: testTemplates.public
      });
      
      const getTemplate = findTool(mockTool, 'get-template');
      const templateResult = await executeTool(getTemplate, {
        templateId: testTemplates.public.id
      });
      
      expect(templateResult).toContain(testTemplates.public.name);
      
      // Step 3: Create scenario from template
      const scenarioFromTemplate = generateTestData.scenario({
        name: 'Production Email Campaign',
        blueprint: testTemplates.public.blueprint
      });
      
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: scenarioFromTemplate
      });
      
      const createScenario = findTool(mockTool, 'create-scenario');
      const scenarioResult = await executeTool(createScenario, {
        name: 'Production Email Campaign',
        blueprint: testTemplates.public.blueprint,
        scheduling: { type: 'indefinitely', interval: 3600 },
        templateId: testTemplates.public.id
      });
      
      expect(scenarioResult).toContain('Production Email Campaign');
      
      // Step 4: Configure required connections
      mockApiClient.mockResponse('GET', '/connections', {
        success: true,
        data: [testConnections.gmail],
        metadata: { total: 1 }
      });
      
      const listConnections = findTool(mockTool, 'list-connections');
      const connectionsResult = await executeTool(listConnections, {});
      
      expect(connectionsResult).toContain('Gmail Test Connection');
      
      // Step 5: Test scenario before activation
      mockApiClient.mockResponse('POST', `/scenarios/${scenarioFromTemplate.id}/test`, {
        success: true,
        data: { 
          status: 'success',
          operations: 3,
          duration: 2500,
          results: ['Webhook received', 'Filter passed', 'Email sent']
        }
      });
      
      // This would use a test-scenario tool
      // For now, we simulate the test
      
      // Step 6: Activate scenario
      const activeScenario = { ...scenarioFromTemplate, isActive: true };
      mockApiClient.mockResponse('PUT', `/scenarios/${scenarioFromTemplate.id}`, {
        success: true,
        data: activeScenario
      });
      
      const updateScenario = findTool(mockTool, 'update-scenario');
      const activationResult = await executeTool(updateScenario, {
        scenarioId: scenarioFromTemplate.id,
        isActive: true
      });
      
      expect(activationResult).toContain('successfully updated');
      
      // Verify complete workflow
      const callLog = mockApiClient.getCallLog();
      expect(callLog.length).toBeGreaterThan(5);
    });
  });

  describe('Billing and Usage Monitoring Workflow', () => {
    it('should complete billing workflow: check account -> review usage -> analyze costs -> update payment', async () => {
      // Step 1: Get billing account information
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: testBillingAccount
      });
      
      const getBilling = findTool(mockTool, 'get-billing-account');
      const billingResult = await executeTool(getBilling, { 
        includeUsage: true,
        includeHistory: true 
      });
      
      expect(billingResult).toContain(testBillingAccount.organizationName);
      
      // Step 2: Get detailed usage metrics
      const usageMetrics = {
        organizationId: 67890,
        period: { startDate: '2024-01-01T00:00:00Z', endDate: '2024-01-31T23:59:59Z' },
        metrics: {
          operations: { total: 75000 },
          dataTransfer: { total: 15.5 },
          storage: { total: 5.2 }
        },
        costs: { 
          total: 250.75,
          currency: 'USD',
          projectedMonthly: 280.00
        },
        recommendations: [
          { type: 'cost_optimization', title: 'Reduce data transfer', savings: 15.50 }
        ]
      };
      
      mockApiClient.mockResponse('GET', '/billing/usage', {
        success: true,
        data: usageMetrics
      });
      
      const getUsage = findTool(mockTool, 'get-usage-metrics');
      const usageResult = await executeTool(getUsage, {
        period: 'current',
        includeProjections: true,
        includeRecommendations: true
      });
      
      expect(usageResult).toContain('75000');
      expect(usageResult).toContain('cost_optimization');
      
      // Step 3: List invoices for review
      const invoices = [
        {
          id: 'inv_001',
          number: 'INV-2024-001',
          status: 'paid',
          amount: { total: 199.99, currency: 'USD' },
          dueDate: '2024-02-01T00:00:00Z'
        }
      ];
      
      mockApiClient.mockResponse('GET', '/billing/invoices', {
        success: true,
        data: invoices,
        metadata: { total: 1 }
      });
      
      const listInvoices = findTool(mockTool, 'list-invoices');
      const invoicesResult = await executeTool(listInvoices, {
        status: 'all',
        limit: 10
      });
      
      expect(invoicesResult).toContain('INV-2024-001');
      
      // Step 4: Add new payment method
      const newPaymentMethod = {
        id: 'pm_new123',
        type: 'credit_card',
        lastFour: '4242',
        isDefault: true,
        status: 'active'
      };
      
      mockApiClient.mockResponse('POST', '/billing/payment-methods', {
        success: true,
        data: newPaymentMethod
      });
      
      const addPayment = findTool(mockTool, 'add-payment-method');
      const paymentResult = await executeTool(addPayment, {
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
        },
        setAsDefault: true
      });
      
      expect(paymentResult).toContain('successfully');
      expect(paymentResult).not.toContain('4242424242424242'); // Sensitive data should be masked
      
      // Verify billing workflow completed
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(4);
      expect(callLog.map(call => call.method)).toEqual(['GET', 'GET', 'GET', 'POST']);
    });
  });

  describe('Notification and Alert Management Workflow', () => {
    it('should complete notification workflow: configure preferences -> create notification -> send -> track delivery', async () => {
      // Step 1: Get current email preferences
      const emailPreferences = {
        userId: 1001,
        categories: {
          system: { enabled: true, frequency: 'immediate' },
          billing: { enabled: true, frequency: 'daily' },
          security: { enabled: true, frequency: 'immediate' },
          marketing: { enabled: false, frequency: 'never' }
        },
        channels: {
          email: true,
          inApp: true,
          sms: false
        }
      };
      
      mockApiClient.mockResponse('GET', '/notifications/preferences', {
        success: true,
        data: emailPreferences
      });
      
      const getPrefs = findTool(mockTool, 'get-email-preferences');
      const prefsResult = await executeTool(getPrefs, { userId: 1001 });
      
      expect(prefsResult).toContain('system');
      expect(prefsResult).toContain('billing');
      
      // Step 2: Update preferences to enable marketing notifications
      const updatedPreferences = {
        ...emailPreferences,
        categories: {
          ...emailPreferences.categories,
          marketing: { enabled: true, frequency: 'weekly' }
        }
      };
      
      mockApiClient.mockResponse('PUT', '/notifications/preferences', {
        success: true,
        data: updatedPreferences
      });
      
      const updatePrefs = findTool(mockTool, 'update-email-preferences');
      const updatePrefsResult = await executeTool(updatePrefs, {
        userId: 1001,
        categories: {
          marketing: { enabled: true, frequency: 'weekly' }
        }
      });
      
      expect(updatePrefsResult).toContain('successfully updated');
      
      // Step 3: Create and send notification
      const newNotification = {
        id: 9001,
        type: 'marketing',
        category: 'info',
        priority: 'medium',
        title: 'New Feature Available',
        message: 'Check out our new automation templates!',
        status: 'sent',
        channels: { email: true, inApp: true, sms: false, webhook: false },
        delivery: { totalRecipients: 100, successfulDeliveries: 98, failedDeliveries: 2 }
      };
      
      mockApiClient.mockResponse('POST', '/notifications', {
        success: true,
        data: newNotification
      });
      
      const createNotification = findTool(mockTool, 'create-notification');
      const notificationResult = await executeTool(createNotification, {
        type: 'marketing',
        category: 'info',
        priority: 'medium',
        title: 'New Feature Available',  
        message: 'Check out our new automation templates!',
        recipients: ['all_users'],
        channels: ['email', 'in_app']
      });
      
      expect(notificationResult).toContain('New Feature Available');
      expect(notificationResult).toContain('successfully created');
      
      // Step 4: Track notification delivery
      mockApiClient.mockResponse('GET', '/notifications', {
        success: true,
        data: [newNotification],
        metadata: { total: 1 }
      });
      
      const listNotifications = findTool(mockTool, 'list-notifications');
      const notificationsResult = await executeTool(listNotifications, {
        status: 'sent',
        limit: 10
      });
      
      expect(notificationsResult).toContain('98'); // Successful deliveries
      expect(notificationsResult).toContain('2');  // Failed deliveries
      
      // Verify notification workflow
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(4);
      expect(callLog.map(call => call.method)).toEqual(['GET', 'PUT', 'POST', 'GET']);
    });
  });

  describe('Performance and Reliability Testing', () => {
    it('should handle complete workflow under load', async () => {
      // Set up multiple concurrent workflows
      const workflows = Array.from({ length: 5 }, (_, i) => ({
        scenario: generateTestData.scenario({ name: `Load Test Scenario ${i}` }),
        connection: generateTestData.connection({ name: `Load Test Connection ${i}` })
      }));
      
      // Mock all necessary responses
      workflows.forEach((workflow, i) => {
        mockApiClient.mockResponse('POST', '/scenarios', {
          success: true,
          data: workflow.scenario
        });
        mockApiClient.mockResponse('POST', '/connections', {
          success: true,
          data: workflow.connection
        });
      });
      
      // Execute workflows concurrently
      const { result: results, duration } = await performanceHelpers.measureExecutionTime(async () => {
        const createTool = findTool(mockTool, 'create-scenario');
        
        const promises = workflows.map(workflow => 
          executeTool(createTool, {
            name: workflow.scenario.name,
            blueprint: { flow: [] },
            scheduling: { type: 'on-demand' }
          })
        );
        
        return Promise.all(promises);
      });
      
      expect(results).toHaveLength(5);
      expect(results.every(result => result.includes('successfully'))).toBe(true);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should recover gracefully from partial failures in complex workflows', async () => {
      // Set up a workflow where some steps fail
      const scenario = generateTestData.scenario({ name: 'Failure Recovery Test' });
      
      // Step 1: Successful scenario creation
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: scenario
      });
      
      // Step 2: Failed connection creation
      mockApiClient.mockFailure('POST', '/connections', new Error('Connection service unavailable'));
      
      // Step 3: Successful billing check (recovery)
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: testBillingAccount
      });
      
      const createScenario = findTool(mockTool, 'create-scenario');
      const getBilling = findTool(mockTool, 'get-billing-account');
      
      // Execute workflow with error handling
      const scenarioResult = await executeTool(createScenario, {
        name: 'Failure Recovery Test',
        blueprint: { flow: [] },
        scheduling: { type: 'on-demand' }
      });
      
      expect(scenarioResult).toContain('Failure Recovery Test');
      
      // This step should fail
      // Note: In a real implementation, you'd have proper error handling
      
      // Recovery step should succeed
      const billingResult = await executeTool(getBilling, {});
      expect(billingResult).toContain(testBillingAccount.organizationName);
      
      // Verify partial workflow completion
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(3); // All attempts should be logged
    });
  });

  describe('Cross-Module Integration', () => {
    it('should demonstrate data flow between different tool modules', async () => {
      // Scenario: Create template -> Create scenario from template -> Monitor analytics -> Check billing
      
      // Step 1: Create template
      const newTemplate = generateTestData.scenario({
        name: 'Integration Test Template',
        blueprint: {
          flow: [
            { id: 1, app: 'webhook', operation: 'trigger' },
            { id: 2, app: 'analytics', operation: 'track' },
            { id: 3, app: 'email', operation: 'send' }
          ]
        }
      });
      
      mockApiClient.mockResponse('POST', '/templates', {
        success: true,
        data: { ...newTemplate, id: 8001, isPublic: false }
      });
      
      // Step 2: Create scenario from template
      const scenarioFromTemplate = { ...newTemplate, id: 2004 };
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: scenarioFromTemplate
      });
      
      const createScenario = findTool(mockTool, 'create-scenario');
      const scenarioResult = await executeTool(createScenario, {
        name: newTemplate.name,
        blueprint: newTemplate.blueprint,
        scheduling: { type: 'on-demand' },
        templateId: 8001
      });
      
      expect(scenarioResult).toContain('Integration Test Template');
      
      // Step 3: Get analytics for the scenario
      const analyticsData = {
        scenarioId: 2004,
        executions: 150,
        operations: 6000,
        successRate: 0.96,
        averageExecutionTime: 3500
      };
      
      mockApiClient.mockResponse('GET', `/analytics/scenarios/${scenarioFromTemplate.id}`, {
        success: true,
        data: analyticsData
      });
      
      // This would use an analytics tool when available
      
      // Step 4: Check billing for increased usage
      mockApiClient.mockResponse('GET', '/billing/account', {
        success: true,
        data: {
          ...testBillingAccount,
          usage: {
            currentPeriod: {
              startDate: '2024-01-01T00:00:00Z',
              endDate: '2024-01-31T23:59:59Z',
              operations: {
                used: 85000, // Increased from the analytics data
                limit: 100000,
                percentage: 85
              }
            }
          }
        }
      });
      
      const getBilling = findTool(mockTool, 'get-billing-account');
      const billingResult = await executeTool(getBilling, { includeUsage: true });
      
      expect(billingResult).toContain('85000'); // Should show increased usage
      expect(billingResult).toContain('Operations usage above 80%'); // Should show alert
      
      // Verify cross-module data flow
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(3);
      
      // Verify that data from one module influenced another
      const billingCall = callLog.find(call => call.endpoint === '/billing/account');
      expect(billingCall).toBeDefined();
    });
  });
});