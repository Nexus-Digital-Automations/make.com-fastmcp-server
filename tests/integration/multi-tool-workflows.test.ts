/**
 * @fileoverview Multi-tool workflow integration tests
 * 
 * Tests complex workflows that involve coordination between multiple tools,
 * data flow between different components, and end-to-end scenario execution.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import type { FastMCP } from 'fastmcp';
import type MakeApiClient from '../../src/lib/make-api-client.js';

// Import various tool modules for integration testing
import { addAIAgentTools } from '../../src/tools/ai-agents.js';
import { addScenarioTools } from '../../src/tools/scenarios.js';
import { addConnectionTools } from '../../src/tools/connections.js';
import { addAnalyticsTools } from '../../src/tools/analytics.js';
import { addNotificationTools } from '../../src/tools/notifications.js';
import { addProcedureTools } from '../../src/tools/procedures.js';
import { addBillingTools } from '../../src/tools/billing.js';
import { addAuditComplianceTools } from '../../src/tools/audit-compliance.js';

// Workflow-specific types
interface WorkflowStep {
  id: string;
  toolName: string;
  action: string;
  inputs: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  dependencies: string[];
  status: 'pending' | 'running' | 'completed' | 'failed';
  startTime?: string;
  endTime?: string;
  duration?: number;
}

interface WorkflowExecution {
  id: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: string;
  endTime?: string;
  totalDuration?: number;
  triggeredBy: string;
  context: Record<string, unknown>;
}

interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: 'automation' | 'analytics' | 'deployment' | 'monitoring' | 'security';
  stepTemplates: Omit<WorkflowStep, 'id' | 'status' | 'startTime' | 'endTime' | 'duration'>[];
  requiredPermissions: string[];
  estimatedDuration: number;
  tags: string[];
}

// Mock workflow engine
class MockWorkflowEngine {
  private executions: Map<string, WorkflowExecution> = new Map();
  private templates: Map<string, WorkflowTemplate> = new Map();
  private registeredTools: Map<string, Function> = new Map();

  async registerTool(name: string, handler: Function): Promise<void> {
    this.registeredTools.set(name, handler);
  }

  async createTemplate(template: WorkflowTemplate): Promise<WorkflowTemplate> {
    this.templates.set(template.id, { ...template });
    return template;
  }

  async getTemplate(id: string): Promise<WorkflowTemplate | null> {
    return this.templates.get(id) || null;
  }

  async listTemplates(category?: string): Promise<WorkflowTemplate[]> {
    const templates = Array.from(this.templates.values());
    return category ? templates.filter(t => t.category === category) : templates;
  }

  async executeWorkflow(templateId: string, context: Record<string, unknown>, triggeredBy: string): Promise<WorkflowExecution> {
    const template = await this.getTemplate(templateId);
    if (!template) {
      throw new Error(`Template ${templateId} not found`);
    }

    const execution: WorkflowExecution = {
      id: `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name: template.name,
      description: template.description,
      steps: template.stepTemplates.map((stepTemplate, index) => ({
        id: `step_${index + 1}`,
        ...stepTemplate,
        status: 'pending',
      })),
      status: 'pending',
      startTime: new Date().toISOString(),
      triggeredBy,
      context,
    };

    this.executions.set(execution.id, execution);
    
    // Start execution asynchronously
    this.runWorkflow(execution.id);
    
    return execution;
  }

  async getExecution(id: string): Promise<WorkflowExecution | null> {
    return this.executions.get(id) || null;
  }

  async listExecutions(status?: string): Promise<WorkflowExecution[]> {
    const executions = Array.from(this.executions.values());
    return status ? executions.filter(e => e.status === status) : executions;
  }

  async cancelExecution(id: string): Promise<boolean> {
    const execution = this.executions.get(id);
    if (!execution || execution.status === 'completed' || execution.status === 'failed') {
      return false;
    }

    execution.status = 'cancelled';
    execution.endTime = new Date().toISOString();
    if (execution.startTime) {
      execution.totalDuration = new Date(execution.endTime).getTime() - new Date(execution.startTime).getTime();
    }

    return true;
  }

  private async runWorkflow(executionId: string): Promise<void> {
    const execution = this.executions.get(executionId);
    if (!execution) return;

    execution.status = 'running';

    try {
      // Execute steps in dependency order
      const executedSteps = new Set<string>();
      
      while (executedSteps.size < execution.steps.length) {
        const readySteps = execution.steps.filter(step => 
          step.status === 'pending' && 
          step.dependencies.every(dep => executedSteps.has(dep))
        );

        if (readySteps.length === 0) {
          throw new Error('Circular dependency or missing dependencies detected');
        }

        // Execute ready steps in parallel
        await Promise.all(readySteps.map(async (step) => {
          await this.executeStep(execution, step);
          executedSteps.add(step.id);
        }));
      }

      execution.status = 'completed';
    } catch (error) {
      execution.status = 'failed';
      execution.context.error = error instanceof Error ? error.message : 'Unknown error';
    }

    execution.endTime = new Date().toISOString();
    if (execution.startTime) {
      execution.totalDuration = new Date(execution.endTime).getTime() - new Date(execution.startTime).getTime();
    }
  }

  private async executeStep(execution: WorkflowExecution, step: WorkflowStep): Promise<void> {
    step.status = 'running';
    step.startTime = new Date().toISOString();

    try {
      // Simulate tool execution
      const toolHandler = this.registeredTools.get(step.toolName);
      if (!toolHandler) {
        throw new Error(`Tool ${step.toolName} not registered`);
      }

      // Merge context with step inputs
      const inputs = { ...execution.context, ...step.inputs };
      
      // Execute tool with simulated delay
      await new Promise(resolve => setTimeout(resolve, Math.random() * 100 + 50));
      
      // Simulate tool output
      step.outputs = await this.simulateToolOutput(step.toolName, step.action, inputs);
      
      // Update execution context with step outputs
      Object.assign(execution.context, step.outputs);

      step.status = 'completed';
    } catch (error) {
      step.status = 'failed';
      step.outputs = { error: error instanceof Error ? error.message : 'Unknown error' };
      throw error;
    } finally {
      step.endTime = new Date().toISOString();
      if (step.startTime) {
        step.duration = new Date(step.endTime).getTime() - new Date(step.startTime).getTime();
      }
    }
  }

  private async simulateToolOutput(toolName: string, action: string, inputs: Record<string, unknown>): Promise<Record<string, unknown>> {
    // Simulate different tool outputs based on tool name and action
    switch (toolName) {
      case 'scenarios':
        if (action === 'create') {
          return {
            scenarioId: `scenario_${Date.now()}`,
            status: 'active',
            created: true,
          };
        }
        if (action === 'get') {
          return {
            scenario: {
              id: inputs.scenarioId,
              name: `Test Scenario`,
              status: 'active',
              modules: [],
            },
          };
        }
        break;

      case 'connections':
        if (action === 'create') {
          return {
            connectionId: `conn_${Date.now()}`,
            status: 'verified',
            created: true,
          };
        }
        if (action === 'test') {
          return {
            connectionId: inputs.connectionId,
            isValid: true,
            lastTested: new Date().toISOString(),
          };
        }
        break;

      case 'analytics':
        if (action === 'track_event') {
          return {
            eventId: `event_${Date.now()}`,
            tracked: true,
            timestamp: new Date().toISOString(),
          };
        }
        if (action === 'generate_report') {
          return {
            reportId: `report_${Date.now()}`,
            data: { metrics: { executions: 10, success_rate: 0.95 } },
            generated: true,
          };
        }
        break;

      case 'notifications':
        if (action === 'send') {
          return {
            notificationId: `notif_${Date.now()}`,
            sent: true,
            recipients: inputs.recipients || [],
          };
        }
        break;

      case 'billing':
        if (action === 'calculate_usage') {
          return {
            usage: {
              operations: 100,
              data_transfer: 1024,
              cost: 5.50,
            },
            calculated: true,
          };
        }
        break;

      case 'audit':
        if (action === 'log_activity') {
          return {
            auditId: `audit_${Date.now()}`,
            logged: true,
            timestamp: new Date().toISOString(),
          };
        }
        break;

      default:
        return {
          success: true,
          timestamp: new Date().toISOString(),
        };
    }

    return {
      success: true,
      timestamp: new Date().toISOString(),
    };
  }

  // Test utilities
  async clear(): Promise<void> {
    this.executions.clear();
    this.templates.clear();
    // Don't clear registered tools - they should persist across tests
  }

  getStats(): { executions: number; templates: number; tools: number } {
    return {
      executions: this.executions.size,
      templates: this.templates.size,
      tools: this.registeredTools.size,
    };
  }
}

describe('Multi-Tool Workflow Integration Tests', () => {
  let workflowEngine: MockWorkflowEngine;
  let mockServer: FastMCP;
  let mockApiClient: MakeApiClient;

  beforeAll(async () => {
    workflowEngine = new MockWorkflowEngine();
    
    mockServer = {
      addTool: jest.fn(),
      addResource: jest.fn(),
      addPrompt: jest.fn(),
    } as unknown as FastMCP;

    mockApiClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    } as unknown as MakeApiClient;

    // Register tool handlers
    await workflowEngine.registerTool('scenarios', jest.fn());
    await workflowEngine.registerTool('connections', jest.fn());
    await workflowEngine.registerTool('analytics', jest.fn());
    await workflowEngine.registerTool('notifications', jest.fn());
    await workflowEngine.registerTool('billing', jest.fn());
    await workflowEngine.registerTool('audit', jest.fn());
  });

  beforeEach(async () => {
    await workflowEngine.clear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Workflow Template Management', () => {
    test('should create and retrieve workflow templates', async () => {
      const template: WorkflowTemplate = {
        id: 'scenario-deployment',
        name: 'Scenario Deployment Pipeline',
        description: 'Complete pipeline for deploying and monitoring a scenario',
        category: 'deployment',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Test Scenario', blueprint: {} },
            dependencies: [],
          },
          {
            toolName: 'connections',
            action: 'test',
            inputs: {},
            dependencies: ['step_1'],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { event: 'scenario_deployed' },
            dependencies: ['step_2'],
          },
        ],
        requiredPermissions: ['write:scenarios', 'read:connections', 'write:analytics'],
        estimatedDuration: 30000,
        tags: ['deployment', 'automation'],
      };

      const created = await workflowEngine.createTemplate(template);
      expect(created).toEqual(template);

      const retrieved = await workflowEngine.getTemplate(template.id);
      expect(retrieved).toEqual(template);
    });

    test('should list templates by category', async () => {
      const templates: WorkflowTemplate[] = [
        {
          id: 'analytics-report',
          name: 'Analytics Report Generation',
          description: 'Generate comprehensive analytics reports',
          category: 'analytics',
          stepTemplates: [],
          requiredPermissions: ['read:analytics'],
          estimatedDuration: 10000,
          tags: ['reporting'],
        },
        {
          id: 'security-audit',
          name: 'Security Audit Workflow',
          description: 'Perform security audit across all components',
          category: 'security',
          stepTemplates: [],
          requiredPermissions: ['read:audit'],
          estimatedDuration: 60000,
          tags: ['security', 'compliance'],
        },
      ];

      await Promise.all(templates.map(t => workflowEngine.createTemplate(t)));

      const analyticsTemplates = await workflowEngine.listTemplates('analytics');
      expect(analyticsTemplates).toHaveLength(1);
      expect(analyticsTemplates[0].id).toBe('analytics-report');

      const allTemplates = await workflowEngine.listTemplates();
      expect(allTemplates).toHaveLength(2);
    });
  });

  describe('Simple Workflow Executions', () => {
    test('should execute a linear workflow successfully', async () => {
      const template: WorkflowTemplate = {
        id: 'linear-workflow',
        name: 'Linear Test Workflow',
        description: 'Simple linear workflow for testing',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Linear Test' },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { event: 'workflow_started' },
            dependencies: ['step_1'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { message: 'Workflow completed' },
            dependencies: ['step_2'],
          },
        ],
        requiredPermissions: ['write:scenarios'],
        estimatedDuration: 5000,
        tags: ['test'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { userId: 'test-user', teamId: 123 },
        'test-runner'
      );

      expect(execution.id).toBeTruthy();
      expect(execution.name).toBe(template.name);
      expect(execution.steps).toHaveLength(3);
      expect(['pending', 'running']).toContain(execution.status);

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');
      expect(updatedExecution!.endTime).toBeTruthy();
      expect(updatedExecution!.totalDuration).toBeGreaterThan(0);

      // Verify all steps completed
      updatedExecution!.steps.forEach(step => {
        expect(step.status).toBe('completed');
        expect(step.outputs).toBeTruthy();
        expect(step.duration).toBeGreaterThan(0);
      });
    });

    test('should execute parallel workflow steps', async () => {
      const template: WorkflowTemplate = {
        id: 'parallel-workflow',
        name: 'Parallel Test Workflow',
        description: 'Workflow with parallel execution paths',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Parallel Test' },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { event: 'branch_a' },
            dependencies: ['step_1'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { message: 'Branch B' },
            dependencies: ['step_1'],
          },
          {
            toolName: 'audit',
            action: 'log_activity',
            inputs: { activity: 'parallel_completion' },
            dependencies: ['step_2', 'step_3'],
          },
        ],
        requiredPermissions: ['write:scenarios'],
        estimatedDuration: 5000,
        tags: ['test', 'parallel'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { testMode: true },
        'parallel-test'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');

      // Verify steps 2 and 3 could run in parallel after step 1
      const step1 = updatedExecution!.steps.find(s => s.id === 'step_1')!;
      const step2 = updatedExecution!.steps.find(s => s.id === 'step_2')!;
      const step3 = updatedExecution!.steps.find(s => s.id === 'step_3')!;
      const step4 = updatedExecution!.steps.find(s => s.id === 'step_4')!;

      expect(step1.status).toBe('completed');
      expect(step2.status).toBe('completed');
      expect(step3.status).toBe('completed');
      expect(step4.status).toBe('completed');

      // Step 4 should complete after steps 2 and 3
      expect(new Date(step4.endTime!).getTime()).toBeGreaterThanOrEqual(new Date(step2.endTime!).getTime());
      expect(new Date(step4.endTime!).getTime()).toBeGreaterThanOrEqual(new Date(step3.endTime!).getTime());
    });
  });

  describe('Complex Multi-Tool Workflows', () => {
    test('should execute comprehensive scenario lifecycle workflow', async () => {
      const template: WorkflowTemplate = {
        id: 'scenario-lifecycle',
        name: 'Complete Scenario Lifecycle',
        description: 'End-to-end scenario creation, testing, and monitoring',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { 
              name: 'Production Scenario',
              blueprint: { modules: [] },
              teamId: 123,
            },
            dependencies: [],
          },
          {
            toolName: 'connections',
            action: 'create',
            inputs: { 
              name: 'API Connection',
              type: 'rest_api',
            },
            dependencies: [],
          },
          {
            toolName: 'connections',
            action: 'test',
            inputs: {},
            dependencies: ['step_2'],
          },
          {
            toolName: 'scenarios',
            action: 'get',
            inputs: {},
            dependencies: ['step_1'],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { 
              event: 'scenario_created',
              metadata: {},
            },
            dependencies: ['step_1'],
          },
          {
            toolName: 'billing',
            action: 'calculate_usage',
            inputs: { period: 'current_month' },
            dependencies: ['step_1'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { 
              message: 'Scenario deployment successful',
              recipients: ['admin@example.com'],
            },
            dependencies: ['step_3', 'step_4', 'step_5'],
          },
          {
            toolName: 'audit',
            action: 'log_activity',
            inputs: { 
              activity: 'scenario_lifecycle_completed',
              resourceType: 'scenario',
            },
            dependencies: ['step_7'],
          },
        ],
        requiredPermissions: [
          'write:scenarios',
          'write:connections',
          'read:analytics',
          'read:billing',
          'write:notifications',
          'write:audit',
        ],
        estimatedDuration: 60000,
        tags: ['production', 'lifecycle', 'comprehensive'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { 
          userId: 'admin-user',
          teamId: 123,
          environment: 'production',
        },
        'lifecycle-automation'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 1000));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');
      expect(updatedExecution!.steps).toHaveLength(8);

      // Verify key outputs are present in context
      expect(updatedExecution!.context.scenarioId).toBeTruthy();
      expect(updatedExecution!.context.connectionId).toBeTruthy();
      expect(updatedExecution!.context.usage).toBeTruthy();

      // Verify proper step execution order
      const completedSteps = updatedExecution!.steps.filter(s => s.status === 'completed');
      expect(completedSteps).toHaveLength(8);

      // Check that notification step ran after its dependencies
      const notificationStep = updatedExecution!.steps.find(s => s.toolName === 'notifications')!;
      expect(notificationStep.outputs!.sent).toBe(true);
    });

    test('should execute analytics and reporting workflow', async () => {
      const template: WorkflowTemplate = {
        id: 'analytics-reporting',
        name: 'Analytics and Reporting Pipeline',
        description: 'Comprehensive analytics data collection and reporting',
        category: 'analytics',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'get',
            inputs: { scenarioId: 'test-scenario' },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { event: 'report_generation_started' },
            dependencies: [],
          },
          {
            toolName: 'billing',
            action: 'calculate_usage',
            inputs: { period: 'last_week' },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'generate_report',
            inputs: { 
              type: 'performance',
              period: 'last_week',
            },
            dependencies: ['step_1', 'step_3'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { 
              message: 'Weekly report generated',
              channel: 'email',
            },
            dependencies: ['step_4'],
          },
          {
            toolName: 'audit',
            action: 'log_activity',
            inputs: { 
              activity: 'report_generated',
              resourceType: 'report',
            },
            dependencies: ['step_4'],
          },
        ],
        requiredPermissions: ['read:scenarios', 'write:analytics', 'read:billing'],
        estimatedDuration: 30000,
        tags: ['analytics', 'reporting', 'automation'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { reportType: 'weekly', requestedBy: 'analytics-team' },
        'automated-reporting'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 800));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');

      // Verify analytics outputs
      expect(updatedExecution!.context.reportId).toBeTruthy();
      expect(updatedExecution!.context.usage).toBeTruthy();
      expect(updatedExecution!.context.tracked).toBe(true);

      // Verify reporting chain
      const reportStep = updatedExecution!.steps.find(s => s.action === 'generate_report')!;
      expect(reportStep.outputs!.generated).toBe(true);
      expect(reportStep.outputs!.data).toBeTruthy();
    });

    test('should execute security audit and compliance workflow', async () => {
      const template: WorkflowTemplate = {
        id: 'security-audit',
        name: 'Security Audit and Compliance Check',
        description: 'Comprehensive security audit with compliance reporting',
        category: 'security',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'get',
            inputs: { includeSecurityData: true },
            dependencies: [],
          },
          {
            toolName: 'connections',
            action: 'test',
            inputs: { securityCheck: true },
            dependencies: [],
          },
          {
            toolName: 'audit',
            action: 'log_activity',
            inputs: { 
              activity: 'security_audit_started',
              severity: 'info',
            },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'generate_report',
            inputs: { 
              type: 'security',
              includeVulnerabilities: true,
            },
            dependencies: ['step_1', 'step_2'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { 
              message: 'Security audit completed',
              priority: 'high',
              recipients: ['security@example.com'],
            },
            dependencies: ['step_4'],
          },
          {
            toolName: 'audit',
            action: 'log_activity',
            inputs: { 
              activity: 'security_audit_completed',
              severity: 'info',
            },
            dependencies: ['step_5'],
          },
        ],
        requiredPermissions: ['read:scenarios', 'read:connections', 'write:audit', 'write:analytics'],
        estimatedDuration: 120000,
        tags: ['security', 'audit', 'compliance'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { auditType: 'comprehensive', compliance: 'SOC2' },
        'security-automation'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 800));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');

      // Verify security audit outputs
      expect(updatedExecution!.context.reportId).toBeTruthy();
      expect(updatedExecution!.context.auditId).toBeTruthy();

      // Verify proper audit trail
      const auditSteps = updatedExecution!.steps.filter(s => s.toolName === 'audit');
      expect(auditSteps).toHaveLength(2);
      auditSteps.forEach(step => {
        expect(step.status).toBe('completed');
        expect(step.outputs!.logged).toBe(true);
      });
    });
  });

  describe('Workflow Error Handling and Recovery', () => {
    test('should handle workflow execution failures gracefully', async () => {
      const template: WorkflowTemplate = {
        id: 'failure-test',
        name: 'Failure Test Workflow',
        description: 'Workflow designed to test failure handling',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Test' },
            dependencies: [],
          },
          {
            toolName: 'nonexistent-tool',
            action: 'invalid_action',
            inputs: {},
            dependencies: ['step_1'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { message: 'This should not execute' },
            dependencies: ['step_2'],
          },
        ],
        requiredPermissions: ['write:scenarios'],
        estimatedDuration: 5000,
        tags: ['test', 'failure'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { testFailure: true },
        'failure-test'
      );

      // Wait for execution to fail
      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('failed');
      expect(updatedExecution!.context.error).toBeTruthy();

      // First step should complete, second should fail, third should not execute
      const step1 = updatedExecution!.steps.find(s => s.id === 'step_1')!;
      const step2 = updatedExecution!.steps.find(s => s.id === 'step_2')!;
      const step3 = updatedExecution!.steps.find(s => s.id === 'step_3')!;

      expect(step1.status).toBe('completed');
      expect(step2.status).toBe('failed');
      expect(step3.status).toBe('pending'); // Never started due to dependency failure
    });

    test('should support workflow cancellation', async () => {
      const template: WorkflowTemplate = {
        id: 'long-running',
        name: 'Long Running Workflow',
        description: 'Workflow for testing cancellation',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Long Test' },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'generate_report',
            inputs: { type: 'comprehensive' },
            dependencies: ['step_1'],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { message: 'Long process complete' },
            dependencies: ['step_2'],
          },
        ],
        requiredPermissions: ['write:scenarios'],
        estimatedDuration: 30000,
        tags: ['test', 'long-running'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { timeout: 30000 },
        'cancellation-test'
      );

      // Cancel workflow quickly
      const cancelled = await workflowEngine.cancelExecution(execution.id);
      expect(cancelled).toBe(true);

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('cancelled');
      expect(updatedExecution!.endTime).toBeTruthy();
    });

    test('should handle circular dependency detection', async () => {
      const template: WorkflowTemplate = {
        id: 'circular-deps',
        name: 'Circular Dependencies Test',
        description: 'Workflow with circular dependencies',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: {},
            dependencies: ['step_2'], // Circular: step_1 depends on step_2
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: {},
            dependencies: ['step_1'], // Circular: step_2 depends on step_1
          },
        ],
        requiredPermissions: ['write:scenarios'],
        estimatedDuration: 5000,
        tags: ['test', 'circular'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        {},
        'circular-test'
      );

      // Wait for execution to fail due to circular dependency
      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('failed');
      expect(updatedExecution!.context.error).toContain('Circular dependency');

      // All steps should remain pending
      updatedExecution!.steps.forEach(step => {
        expect(step.status).toBe('pending');
      });
    });
  });

  describe('Workflow Context and Data Flow', () => {
    test('should pass data between workflow steps correctly', async () => {
      const template: WorkflowTemplate = {
        id: 'data-flow',
        name: 'Data Flow Test',
        description: 'Test data passing between steps',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Data Flow Test' },
            dependencies: [],
          },
          {
            toolName: 'connections',
            action: 'create',
            inputs: { 
              name: 'Test Connection',
              scenarioId: '${scenarioId}', // Should be replaced from step 1 output
            },
            dependencies: ['step_1'],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { 
              event: 'connection_created',
              scenarioId: '${scenarioId}',
              connectionId: '${connectionId}',
            },
            dependencies: ['step_2'],
          },
        ],
        requiredPermissions: ['write:scenarios', 'write:connections'],
        estimatedDuration: 10000,
        tags: ['test', 'data-flow'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { userId: 'test-user' },
        'data-flow-test'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');

      // Verify data flow through context
      expect(updatedExecution!.context.scenarioId).toBeTruthy();
      expect(updatedExecution!.context.connectionId).toBeTruthy();
      expect(updatedExecution!.context.eventId).toBeTruthy();

      // Verify step outputs contain expected data
      const step1 = updatedExecution!.steps.find(s => s.id === 'step_1')!;
      const step2 = updatedExecution!.steps.find(s => s.id === 'step_2')!;
      const step3 = updatedExecution!.steps.find(s => s.id === 'step_3')!;

      expect(step1.outputs!.scenarioId).toBeTruthy();
      expect(step2.outputs!.connectionId).toBeTruthy();
      expect(step3.outputs!.eventId).toBeTruthy();
    });

    test('should merge workflow context with step inputs', async () => {
      const template: WorkflowTemplate = {
        id: 'context-merge',
        name: 'Context Merge Test',
        description: 'Test context merging with step inputs',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { 
              event: 'workflow_started',
              customData: 'step_input',
            },
            dependencies: [],
          },
          {
            toolName: 'notifications',
            action: 'send',
            inputs: { 
              message: 'Context test notification',
            },
            dependencies: ['step_1'],
          },
        ],
        requiredPermissions: ['write:analytics'],
        estimatedDuration: 5000,
        tags: ['test', 'context'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { 
          globalData: 'from_context',
          userId: 'context-test-user',
          environment: 'test',
        },
        'context-merge-test'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');

      // Verify context is preserved and merged
      expect(updatedExecution!.context.globalData).toBe('from_context');
      expect(updatedExecution!.context.userId).toBe('context-test-user');
      expect(updatedExecution!.context.environment).toBe('test');

      // Verify step outputs are added to context
      expect(updatedExecution!.context.eventId).toBeTruthy();
      expect(updatedExecution!.context.notificationId).toBeTruthy();
    });
  });

  describe('Performance and Scalability', () => {
    test('should handle concurrent workflow executions', async () => {
      const template: WorkflowTemplate = {
        id: 'concurrent-test',
        name: 'Concurrent Execution Test',
        description: 'Test concurrent workflow execution',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { name: 'Concurrent Test' },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { event: 'concurrent_execution' },
            dependencies: ['step_1'],
          },
        ],
        requiredPermissions: ['write:scenarios'],
        estimatedDuration: 5000,
        tags: ['test', 'concurrent'],
      };

      await workflowEngine.createTemplate(template);

      // Start multiple executions concurrently
      const executions = await Promise.all([
        workflowEngine.executeWorkflow(template.id, { executionId: 1 }, 'concurrent-1'),
        workflowEngine.executeWorkflow(template.id, { executionId: 2 }, 'concurrent-2'),
        workflowEngine.executeWorkflow(template.id, { executionId: 3 }, 'concurrent-3'),
        workflowEngine.executeWorkflow(template.id, { executionId: 4 }, 'concurrent-4'),
        workflowEngine.executeWorkflow(template.id, { executionId: 5 }, 'concurrent-5'),
      ]);

      expect(executions).toHaveLength(5);
      executions.forEach(execution => {
        expect(['pending', 'running']).toContain(execution.status);
        expect(execution.id).toBeTruthy();
      });

      // Wait for all executions to complete
      await new Promise(resolve => setTimeout(resolve, 800));

      // Verify all executions completed successfully
      const completedExecutions = await Promise.all(
        executions.map(e => workflowEngine.getExecution(e.id))
      );

      completedExecutions.forEach(execution => {
        expect(execution!.status).toBe('completed');
        expect(execution!.totalDuration).toBeGreaterThan(0);
      });

      // Verify each execution has unique context
      const executionIds = completedExecutions.map(e => e!.context.executionId);
      const uniqueIds = new Set(executionIds);
      expect(uniqueIds.size).toBe(5);
    });

    test('should handle large workflow with many steps', async () => {
      // Create a workflow with many steps
      const stepCount = 20;
      const stepTemplates: Omit<WorkflowStep, 'id' | 'status' | 'startTime' | 'endTime' | 'duration'>[] = [];

      for (let i = 0; i < stepCount; i++) {
        stepTemplates.push({
          toolName: i % 2 === 0 ? 'analytics' : 'scenarios',
          action: i % 2 === 0 ? 'track_event' : 'get',
          inputs: { stepNumber: i + 1 },
          dependencies: i > 0 ? [`step_${i}`] : [],
        });
      }

      const template: WorkflowTemplate = {
        id: 'large-workflow',
        name: 'Large Workflow Test',
        description: `Workflow with ${stepCount} steps`,
        category: 'automation',
        stepTemplates,
        requiredPermissions: ['write:analytics', 'read:scenarios'],
        estimatedDuration: stepCount * 1000,
        tags: ['test', 'large', 'performance'],
      };

      await workflowEngine.createTemplate(template);

      const startTime = Date.now();
      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { largeWorkflow: true, stepCount },
        'large-workflow-test'
      );

      // Wait for execution to complete (20 steps with dependencies need more time)
      await new Promise(resolve => setTimeout(resolve, 5000));

      const endTime = Date.now();
      const executionTime = endTime - startTime;

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');
      expect(updatedExecution!.steps).toHaveLength(stepCount);

      // Verify all steps completed
      updatedExecution!.steps.forEach((step, index) => {
        expect(step.status).toBe('completed');
        expect(step.outputs).toBeTruthy();
        expect(step.outputs!.stepNumber).toBe(index + 1);
      });

      // Performance check - should complete in reasonable time
      expect(executionTime).toBeLessThan(10000); // Less than 10 seconds
      expect(updatedExecution!.totalDuration).toBeLessThan(5000); // Less than 5 seconds execution time
    });
  });

  describe('Tool Integration Verification', () => {
    test('should verify all tools are properly integrated', async () => {
      // Register actual tools with mock server
      addAIAgentTools(mockServer, mockApiClient);
      addScenarioTools(mockServer, mockApiClient);
      addConnectionTools(mockServer, mockApiClient);
      addAnalyticsTools(mockServer, mockApiClient);
      addNotificationTools(mockServer, mockApiClient);
      addProcedureTools(mockServer, mockApiClient);
      addBillingTools(mockServer, mockApiClient);
      addAuditComplianceTools(mockServer, mockApiClient);

      // Verify tools were registered
      expect(mockServer.addTool).toHaveBeenCalled();

      const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
      const registeredToolNames = toolCalls.map(call => call[0].name);

      // Verify key tools are registered
      expect(registeredToolNames).toContain('create_scenario');
      expect(registeredToolNames).toContain('test_connection');
      expect(registeredToolNames).toContain('track_analytics_event');
      expect(registeredToolNames).toContain('send_notification');

      // Tools should have proper schemas
      toolCalls.forEach(([tool]) => {
        expect(tool.name).toBeTruthy();
        expect(tool.description).toBeTruthy();
        expect(tool.inputSchema).toBeTruthy();
        expect(tool.inputSchema.type).toBe('object');
      });
    });

    test('should execute workflow using registered tools', async () => {
      const template: WorkflowTemplate = {
        id: 'tool-integration',
        name: 'Tool Integration Verification',
        description: 'Verify tools work together in workflow',
        category: 'automation',
        stepTemplates: [
          {
            toolName: 'scenarios',
            action: 'create',
            inputs: { 
              name: 'Integration Test Scenario',
              blueprint: { modules: [] },
            },
            dependencies: [],
          },
          {
            toolName: 'analytics',
            action: 'track_event',
            inputs: { 
              event: 'integration_test',
              metadata: { source: 'workflow' },
            },
            dependencies: ['step_1'],
          },
          {
            toolName: 'billing',
            action: 'calculate_usage',
            inputs: { resourceType: 'scenario' },
            dependencies: ['step_1'],
          },
          {
            toolName: 'audit',
            action: 'log_activity',
            inputs: { 
              activity: 'tool_integration_test',
              resourceType: 'workflow',
            },
            dependencies: ['step_2', 'step_3'],
          },
        ],
        requiredPermissions: ['write:scenarios', 'write:analytics', 'read:billing', 'write:audit'],
        estimatedDuration: 15000,
        tags: ['integration', 'tools', 'verification'],
      };

      await workflowEngine.createTemplate(template);

      const execution = await workflowEngine.executeWorkflow(
        template.id,
        { 
          integrationTest: true,
          toolCount: 4,
        },
        'tool-integration-test'
      );

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 600));

      const updatedExecution = await workflowEngine.getExecution(execution.id);
      expect(updatedExecution!.status).toBe('completed');

      // Verify each tool step completed successfully
      updatedExecution!.steps.forEach(step => {
        expect(step.status).toBe('completed');
        expect(step.outputs).toBeTruthy();
        expect(step.duration).toBeGreaterThan(0);
      });

      // Verify cross-tool data flow
      expect(updatedExecution!.context.scenarioId).toBeTruthy();
      expect(updatedExecution!.context.eventId).toBeTruthy();
      expect(updatedExecution!.context.usage).toBeTruthy();
      expect(updatedExecution!.context.auditId).toBeTruthy();
    });
  });
});