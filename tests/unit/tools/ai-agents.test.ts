/**
 * Unit tests for AI agent management tools
 * Tests AI agent CRUD operations, LLM provider management, testing functionality, and external service integrations
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';

// Test data fixtures
const testAIAgent = {
  id: 1,
  name: 'Test AI Agent',
  description: 'Test AI agent for automation',
  type: 'chat',
  status: 'active',
  configuration: {
    model: 'gpt-4',
    provider: 'openai',
    parameters: {
      maxTokens: 4000,
      temperature: 0.7,
    },
    systemPrompt: 'You are a helpful assistant.',
    temperature: 0.7,
    maxTokens: 4000,
    topP: 0.9,
    frequencyPenalty: 0,
    presencePenalty: 0,
  },
  context: {
    maxHistoryLength: 10,
    memoryType: 'conversation',
    memorySize: 1024,
    instructions: 'Be helpful and concise.',
  },
  capabilities: ['text_generation', 'conversation'],
  organizationId: 123,
  teamId: 456,
  scenarioId: 789,
  isPublic: false,
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  lastUsed: '2024-01-01T00:00:00Z',
  usage: {
    totalCalls: 100,
    totalTokens: 50000,
    avgResponseTime: 1500,
    errorRate: 0.02,
  },
};

const testLLMProvider = {
  id: 1,
  name: 'OpenAI',
  type: 'openai',
  status: 'active',
  configuration: {
    apiKey: 'sk-test-key',
    baseUrl: 'https://api.openai.com/v1',
    organization: 'org-123',
  },
  models: [
    {
      id: 'gpt-4',
      name: 'GPT-4',
      type: 'chat',
      maxTokens: 8192,
      supportsStreaming: true,
      costPer1kTokens: 0.03,
    },
    {
      id: 'gpt-3.5-turbo',
      name: 'GPT-3.5 Turbo',
      type: 'chat',
      maxTokens: 4096,
      supportsStreaming: true,
      costPer1kTokens: 0.002,
    },
  ],
  rateLimit: {
    requestsPerMinute: 60,
    tokensPerMinute: 90000,
  },
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
};

const testErrors = {
  invalidProvider: { message: 'LLM provider "invalid" not found or not accessible', code: 'PROVIDER_NOT_FOUND' },
  invalidModel: { message: 'Model "invalid-model" not supported by provider "openai"', code: 'MODEL_NOT_SUPPORTED' },
  agentNotFound: { message: 'AI agent with ID 999 not found', code: 'AGENT_NOT_FOUND' },
  agentInUse: { message: 'AI agent is currently in use (3 active connections)', code: 'AGENT_IN_USE' },
  networkError: { message: 'Network timeout', code: 'NETWORK_TIMEOUT' },
  authError: { message: 'Unauthorized access', code: 'UNAUTHORIZED' },
};

describe('AI Agent Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;

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
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all AI agent management tools with correct configuration', async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-ai-agent',
        'list-ai-agents', 
        'get-ai-agent',
        'update-ai-agent',
        'delete-ai-agent',
        'test-ai-agent',
        'create-llm-provider',
        'list-llm-providers'
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(typeof tool.execute).toBe('function');
        expect(tool.parameters).toBeInstanceOf(Object);
      });
    });
  });

  describe('AI Agent Management', () => {
    beforeEach(async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
    });

    describe('create-ai-agent tool', () => {
      it('should create AI agent successfully with minimal configuration', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });
        mockApiClient.mockResponse('POST', '/ai-agents', {
          success: true,
          data: testAIAgent
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Test Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'openai',
            parameters: {},
          }
        };

        const result = await executeTool(tool, agentConfig);
        
        expect(result).toContain('Test Agent');
        expect(result).toContain('created successfully');
        expect(mockApiClient.getCallLog()).toHaveLength(2);
        expect(JSON.parse(result).agent.configuration.apiKey).toBeUndefined();
      });

      it('should create organization-scoped AI agent', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });
        mockApiClient.mockResponse('POST', '/organizations/123/ai-agents', {
          success: true,
          data: { ...testAIAgent, organizationId: 123 }
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Org Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'openai',
            parameters: {},
          },
          organizationId: 123
        };

        const result = await executeTool(tool, agentConfig);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].endpoint).toBe('/organizations/123/ai-agents');
        expect(result).toContain('created successfully');
      });

      it('should create team-scoped AI agent', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });
        mockApiClient.mockResponse('POST', '/teams/456/ai-agents', {
          success: true,
          data: { ...testAIAgent, teamId: 456 }
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Team Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'openai',
            parameters: {},
          },
          teamId: 456
        };

        const result = await executeTool(tool, agentConfig);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].endpoint).toBe('/teams/456/ai-agents');
        expect(result).toContain('created successfully');
      });

      it('should create scenario-scoped AI agent', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });
        mockApiClient.mockResponse('POST', '/scenarios/789/ai-agents', {
          success: true,
          data: { ...testAIAgent, scenarioId: 789 }
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Scenario Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'openai',
            parameters: {},
          },
          scenarioId: 789
        };

        const result = await executeTool(tool, agentConfig);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].endpoint).toBe('/scenarios/789/ai-agents');
        expect(result).toContain('created successfully');
      });

      it('should validate provider exists before creating agent', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/invalid', {
          success: false,
          error: testErrors.invalidProvider
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Test Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'invalid',
            parameters: {},
          }
        };

        await expect(executeTool(tool, agentConfig))
          .rejects.toThrow('LLM provider "invalid" not found or not accessible');
      });

      it('should validate model is supported by provider', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Test Agent',
          type: 'chat',
          configuration: {
            model: 'invalid-model',
            provider: 'openai',
            parameters: {},
          }
        };

        await expect(executeTool(tool, agentConfig))
          .rejects.toThrow('Model "invalid-model" not supported by provider "openai"');
      });

      it('should apply model-specific defaults and validation', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });
        mockApiClient.mockResponse('POST', '/ai-agents', {
          success: true,
          data: testAIAgent
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Test Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'openai',
            parameters: {},
            maxTokens: 10000, // Exceeds model max
          }
        };

        const result = await executeTool(tool, agentConfig);
        
        const calls = mockApiClient.getCallLog();
        const createCall = calls[1];
        expect(createCall.data.configuration.maxTokens).toBeLessThanOrEqual(8192); // Model limit
      });

      it('should mask sensitive API keys in response', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/openai', {
          success: true,
          data: testLLMProvider
        });
        mockApiClient.mockResponse('POST', '/ai-agents', {
          success: true,
          data: {
            ...testAIAgent,
            configuration: {
              ...testAIAgent.configuration,
              parameters: { apiKey: 'sk-secret-key' }
            }
          }
        });

        const tool = findTool(mockTool, 'create-ai-agent');
        const agentConfig = {
          name: 'Test Agent',
          type: 'chat',
          configuration: {
            model: 'gpt-4',
            provider: 'openai',
            parameters: { apiKey: 'sk-secret-key' },
          }
        };

        const result = await executeTool(tool, agentConfig);
        
        expect(result).not.toContain('sk-secret-key');
        expect(result).toContain('[MASKED]');
      });
    });

    describe('list-ai-agents tool', () => {
      it('should list AI agents with default filters and analytics', async () => {
        const agents = [testAIAgent, { ...testAIAgent, id: 2, name: 'Agent 2', type: 'completion' }];
        mockApiClient.mockResponse('GET', '/ai-agents', {
          success: true,
          data: agents,
          metadata: { total: 2 }
        });

        const tool = findTool(mockTool, 'list-ai-agents');
        const result = await executeTool(tool, {});
        
        const parsed = JSON.parse(result);
        expect(parsed.agents).toHaveLength(2);
        expect(parsed.summary.totalAgents).toBe(2);
        expect(parsed.summary.typeBreakdown.chat).toBe(1);
        expect(parsed.summary.typeBreakdown.completion).toBe(1);
        expect(parsed.summary.statusBreakdown.active).toBe(2);
      });

      it('should filter agents by type, status, and provider', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents', {
          success: true,
          data: [testAIAgent],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'list-ai-agents');
        const result = await executeTool(tool, {
          type: 'chat',
          status: 'active',
          provider: 'openai',
          includeUsage: true
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.type).toBe('chat');
        expect(calls[0].params.status).toBe('active');
        expect(calls[0].params.provider).toBe('openai');
        expect(calls[0].params.includeUsage).toBe(true);
      });

      it('should filter agents by organization, team, and scenario', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents', {
          success: true,
          data: [testAIAgent],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'list-ai-agents');
        await executeTool(tool, {
          organizationId: 123,
          teamId: 456,
          scenarioId: 789,
          isPublic: false
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.organizationId).toBe(123);
        expect(calls[0].params.teamId).toBe(456);
        expect(calls[0].params.scenarioId).toBe(789);
        expect(calls[0].params.isPublic).toBe(false);
      });

      it('should provide comprehensive usage analytics when requested', async () => {
        const agents = [
          testAIAgent,
          { ...testAIAgent, id: 2, usage: { totalCalls: 200, totalTokens: 100000, avgResponseTime: 2000, errorRate: 0.01 } }
        ];
        mockApiClient.mockResponse('GET', '/ai-agents', {
          success: true,
          data: agents,
          metadata: { total: 2 }
        });

        const tool = findTool(mockTool, 'list-ai-agents');
        const result = await executeTool(tool, { includeUsage: true });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.totalUsage).toBeDefined();
        expect(parsed.summary.totalUsage.totalCalls).toBe(300);
        expect(parsed.summary.totalUsage.totalTokens).toBe(150000);
        expect(parsed.summary.totalUsage.avgResponseTime).toBe(1750);
      });

      it('should handle pagination correctly', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents', {
          success: true,
          data: [testAIAgent],
          metadata: { total: 10 }
        });

        const tool = findTool(mockTool, 'list-ai-agents');
        const result = await executeTool(tool, {
          limit: 5,
          offset: 5,
          sortBy: 'name',
          sortOrder: 'desc'
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.pagination.total).toBe(10);
        expect(parsed.pagination.limit).toBe(5);
        expect(parsed.pagination.offset).toBe(5);
        expect(parsed.pagination.hasMore).toBe(true);
      });

      it('should mask sensitive configuration data in agent list', async () => {
        const agentWithSecrets = {
          ...testAIAgent,
          configuration: {
            ...testAIAgent.configuration,
            parameters: { apiKey: 'sk-secret-key', secretToken: 'secret-token' }
          }
        };
        mockApiClient.mockResponse('GET', '/ai-agents', {
          success: true,
          data: [agentWithSecrets],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'list-ai-agents');
        const result = await executeTool(tool, {});
        
        expect(result).not.toContain('sk-secret-key');
        expect(result).not.toContain('secret-token');
        expect(result).toContain('[MASKED]');
      });
    });

    describe('get-ai-agent tool', () => {
      it('should get AI agent details with usage and history', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents/1', {
          success: true,
          data: testAIAgent
        });
        mockApiClient.mockResponse('GET', '/ai-agents/1/usage', {
          success: true,
          data: { 
            detailedUsage: true,
            lastHealthCheck: '2024-01-01T00:00:00Z',
            estimatedCost: 15.50
          }
        });
        mockApiClient.mockResponse('GET', '/ai-agents/1/history', {
          success: true,
          data: [
            { id: 1, timestamp: '2024-01-01T00:00:00Z', message: 'Hello', response: 'Hi there!' },
            { id: 2, timestamp: '2024-01-01T01:00:00Z', message: 'How are you?', response: 'I am doing well!' }
          ]
        });

        const tool = findTool(mockTool, 'get-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          includeUsage: true,
          includeHistory: true
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.agent.id).toBe(1);
        expect(parsed.usage.detailedUsage).toBe(true);
        expect(parsed.history).toHaveLength(2);
        expect(parsed.metadata.canEdit).toBe(true);
        expect(parsed.metadata.canTest).toBe(true);
      });

      it('should handle agent not found error', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents/999', {
          success: false,
          error: testErrors.agentNotFound
        });

        const tool = findTool(mockTool, 'get-ai-agent');
        await expect(executeTool(tool, { agentId: 999 }))
          .rejects.toThrow('AI agent with ID 999 not found');
      });

      it('should gracefully handle missing usage or history data', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents/1', {
          success: true,
          data: testAIAgent
        });
        mockApiClient.mockResponse('GET', '/ai-agents/1/usage', {
          success: false,
          error: { message: 'Usage data not available' }
        });
        mockApiClient.mockResponse('GET', '/ai-agents/1/history', {
          success: false,
          error: { message: 'History not available' }
        });

        const tool = findTool(mockTool, 'get-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          includeUsage: true,
          includeHistory: true
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.agent.id).toBe(1);
        expect(parsed.usage).toBeNull();
        expect(parsed.history).toBeNull();
        expectToolCall(mockLog, 'warn', 'Failed to retrieve agent usage statistics');
        expectToolCall(mockLog, 'warn', 'Failed to retrieve agent conversation history');
      });

      it('should mask sensitive configuration in agent details', async () => {
        const agentWithSecrets = {
          ...testAIAgent,
          configuration: {
            ...testAIAgent.configuration,
            parameters: { apiKey: 'sk-secret-key' }
          }
        };
        mockApiClient.mockResponse('GET', '/ai-agents/1', {
          success: true,
          data: agentWithSecrets
        });

        const tool = findTool(mockTool, 'get-ai-agent');
        const result = await executeTool(tool, { agentId: 1 });
        
        expect(result).not.toContain('sk-secret-key');
        expect(result).toContain('[MASKED]');
      });
    });

    describe('update-ai-agent tool', () => {
      it('should update AI agent configuration successfully', async () => {
        const updatedAgent = {
          ...testAIAgent,
          name: 'Updated Agent',
          configuration: {
            ...testAIAgent.configuration,
            temperature: 0.8,
          }
        };
        mockApiClient.mockResponse('PUT', '/ai-agents/1', {
          success: true,
          data: updatedAgent
        });

        const tool = findTool(mockTool, 'update-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          name: 'Updated Agent',
          configuration: { temperature: 0.8 }
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.agent.name).toBe('Updated Agent');
        expect(parsed.agent.configuration.temperature).toBe(0.8);
        expect(parsed.changes).toContain('name');
        expect(parsed.changes).toContain('configuration');
      });

      it('should validate model compatibility when updating provider/model', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/anthropic', {
          success: true,
          data: {
            ...testLLMProvider,
            type: 'anthropic',
            models: [
              { id: 'claude-3', name: 'Claude 3', type: 'chat', maxTokens: 100000, supportsStreaming: true, costPer1kTokens: 0.015 }
            ]
          }
        });
        mockApiClient.mockResponse('PUT', '/ai-agents/1', {
          success: true,
          data: { ...testAIAgent, configuration: { ...testAIAgent.configuration, provider: 'anthropic', model: 'claude-3' } }
        });

        const tool = findTool(mockTool, 'update-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          configuration: {
            provider: 'anthropic',
            model: 'claude-3'
          }
        }, { log: mockLog });
        
        expect(result).toContain('updated successfully');
      });

      it('should reject invalid provider/model combinations', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers/invalid', {
          success: false,
          error: testErrors.invalidProvider
        });

        const tool = findTool(mockTool, 'update-ai-agent');
        await expect(executeTool(tool, {
          agentId: 1,
          configuration: {
            provider: 'invalid',
            model: 'some-model'
          }
        }, { log: mockLog }))
          .rejects.toThrow('LLM provider "invalid" not found');
      });

      it('should require at least one update parameter', async () => {
        const tool = findTool(mockTool, 'update-ai-agent');
        await expect(executeTool(tool, { agentId: 1 }))
          .rejects.toThrow('No update data provided');
      });

      it('should update context and capabilities', async () => {
        mockApiClient.mockResponse('PUT', '/ai-agents/1', {
          success: true,
          data: {
            ...testAIAgent,
            context: { ...testAIAgent.context, maxHistoryLength: 20 },
            capabilities: ['text_generation', 'conversation', 'function_calling']
          }
        });

        const tool = findTool(mockTool, 'update-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          context: { maxHistoryLength: 20 },
          capabilities: ['text_generation', 'conversation', 'function_calling'],
          isPublic: true
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.agent.context.maxHistoryLength).toBe(20);
        expect(parsed.agent.capabilities).toContain('function_calling');
        expect(parsed.changes).toHaveLength(3);
      });
    });

    describe('delete-ai-agent tool', () => {
      it('should delete AI agent successfully when not in use', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents/1/usage', {
          success: true,
          data: { activeConnections: 0 }
        });
        mockApiClient.mockResponse('DELETE', '/ai-agents/1', {
          success: true,
          data: { deleted: true }
        });

        const tool = findTool(mockTool, 'delete-ai-agent');
        const result = await executeTool(tool, { agentId: 1 });
        
        const parsed = JSON.parse(result);
        expect(parsed.message).toContain('deleted successfully');
        expect(parsed.agentId).toBe(1);
        expect(parsed.forced).toBe(false);
      });

      it('should prevent deletion when agent is in use without force', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents/1/usage', {
          success: true,
          data: { activeConnections: 3 }
        });

        const tool = findTool(mockTool, 'delete-ai-agent');
        await expect(executeTool(tool, { agentId: 1 }))
          .rejects.toThrow('AI agent is currently in use (3 active connections)');
      });

      it('should allow force deletion when agent is in use', async () => {
        mockApiClient.mockResponse('DELETE', '/ai-agents/1', {
          success: true,
          data: { deleted: true }
        });

        const tool = findTool(mockTool, 'delete-ai-agent');
        const result = await executeTool(tool, { agentId: 1, force: true });
        
        const parsed = JSON.parse(result);
        expect(parsed.forced).toBe(true);
        expect(parsed.message).toContain('deleted successfully');
      });

      it('should handle deletion failures', async () => {
        mockApiClient.mockResponse('GET', '/ai-agents/1/usage', {
          success: true,
          data: { activeConnections: 0 }
        });
        mockApiClient.mockResponse('DELETE', '/ai-agents/1', {
          success: false,
          error: { message: 'Deletion failed', code: 'DELETE_ERROR' }
        });

        const tool = findTool(mockTool, 'delete-ai-agent');
        await expect(executeTool(tool, { agentId: 1 }))
          .rejects.toThrow('Failed to delete AI agent: Deletion failed');
      });
    });

    describe('test-ai-agent tool', () => {
      it('should test AI agent with simple test successfully', async () => {
        const testResult = {
          success: true,
          message: 'Test completed successfully',
          response: 'Hello! How can I help you today?',
          metrics: {
            responseTime: 1200,
            tokens: { input: 10, output: 15, total: 25 },
            cost: 0.0008
          },
          validation: {
            format: 'valid',
            quality: 'good',
            errors: []
          }
        };
        mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
          success: true,
          data: testResult
        });

        const tool = findTool(mockTool, 'test-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          testType: 'simple',
          testInput: 'Hello, how are you?',
          options: { includeMetrics: true, timeout: 30000 }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.testResult.success).toBe(true);
        expect(parsed.performance.agentResponseTime).toBe(1200);
        expect(parsed.performance.tokenUsage.total).toBe(25);
        expect(parsed.validation.responseFormat).toBe('valid');
        expect(parsed.summary.success).toBe(true);
        
      });

      it('should test AI agent with conversation test', async () => {
        const conversationTestResult = {
          success: true,
          message: 'Conversation test completed',
          conversation: [
            { role: 'user', content: 'Hello' },
            { role: 'assistant', content: 'Hi there!' },
            { role: 'user', content: 'How are you?' },
            { role: 'assistant', content: 'I am doing well, thank you!' }
          ],
          metrics: {
            responseTime: 2500,
            tokens: { input: 25, output: 40, total: 65 },
            cost: 0.0020
          },
          validation: {
            format: 'valid',
            quality: 'excellent',
            errors: [],
            contextMaintained: true
          }
        };
        mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
          success: true,
          data: conversationTestResult
        });

        const tool = findTool(mockTool, 'test-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          testType: 'conversation',
          testInput: [
            { role: 'user', content: 'Hello' },
            { role: 'user', content: 'How are you?' }
          ]
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.testResult.conversation).toHaveLength(4);
        expect(parsed.validation.contentQuality).toBe('excellent');
      });

      it('should test AI agent with function calling test', async () => {
        const functionTestResult = {
          success: true,
          message: 'Function calling test completed',
          functionCalls: [
            { name: 'get_weather', parameters: { location: 'New York' }, result: 'Sunny, 75°F' }
          ],
          metrics: {
            responseTime: 3000,
            tokens: { input: 50, output: 30, total: 80 },
            cost: 0.0024
          },
          validation: {
            format: 'valid',
            quality: 'good',
            errors: [],
            functionsExecuted: true
          }
        };
        mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
          success: true,
          data: functionTestResult
        });

        const tool = findTool(mockTool, 'test-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          testType: 'function_calling',
          testInput: { query: 'What\'s the weather in New York?', functions: ['get_weather'] }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.testResult.functionCalls).toHaveLength(1);
        expect(parsed.testResult.functionCalls[0].name).toBe('get_weather');
      });

      it('should test AI agent performance characteristics', async () => {
        const performanceTestResult = {
          success: true,
          message: 'Performance test completed',
          performance: {
            averageResponseTime: 1800,
            p95ResponseTime: 2500,
            p99ResponseTime: 3200,
            throughput: 15.5,
            errorRate: 0.02,
            memoryUsage: 45.2
          },
          metrics: {
            responseTime: 1800,
            tokens: { input: 100, output: 80, total: 180 },
            cost: 0.0054
          },
          validation: {
            format: 'valid',
            quality: 'good',
            errors: []
          }
        };
        mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
          success: true,
          data: performanceTestResult
        });

        const tool = findTool(mockTool, 'test-ai-agent');
        const result = await executeTool(tool, {
          agentId: 1,
          testType: 'performance',
          testInput: { 
            iterations: 100,
            concurrency: 5,
            timeout: 5000
          },
          options: { includeMetrics: true, timeout: 60000 }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.testResult.performance.throughput).toBe(15.5);
        expect(parsed.testResult.performance.errorRate).toBe(0.02);
      });

      it('should handle test failures and errors', async () => {
        mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
          success: false,
          error: { message: 'Agent test failed', code: 'TEST_FAILED' }
        });

        const tool = findTool(mockTool, 'test-ai-agent');
        await expect(executeTool(tool, {
          agentId: 1,
          testType: 'simple',
          testInput: 'Test input'
        }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('Failed to test AI agent: Agent test failed');
      });

      it('should validate test input parameters', async () => {
        const tool = findTool(mockTool, 'test-ai-agent');
        
        // Test invalid agent ID
        await expect(executeTool(tool, {
          agentId: 0,
          testType: 'simple',
          testInput: 'Test'
        }, { log: mockLog }))
          .rejects.toThrow();

        // Test invalid test type
        await expect(executeTool(tool, {
          agentId: 1,
          testType: 'invalid' as any,
          testInput: 'Test'
        }, { log: mockLog }))
          .rejects.toThrow();
      });
    });
  });

  describe('LLM Provider Management', () => {
    beforeEach(async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
    });

    describe('create-llm-provider tool', () => {
      it('should create LLM provider successfully', async () => {
        mockApiClient.mockResponse('POST', '/llm-providers', {
          success: true,
          data: testLLMProvider
        });

        const tool = findTool(mockTool, 'create-llm-provider');
        const providerConfig = {
          name: 'OpenAI Provider',
          type: 'openai',
          configuration: {
            apiKey: 'sk-test-key',
            organization: 'org-123'
          },
          models: [
            {
              id: 'gpt-4',
              name: 'GPT-4',
              type: 'chat',
              maxTokens: 8192,
              supportsStreaming: true,
              costPer1kTokens: 0.03
            }
          ],
          rateLimit: {
            requestsPerMinute: 60,
            tokensPerMinute: 90000
          }
        };

        const result = await executeTool(tool, providerConfig);
        
        const parsed = JSON.parse(result);
        expect(parsed.provider.name).toBe('OpenAI Provider');
        expect(parsed.provider.type).toBe('openai');
        expect(parsed.provider.configuration.apiKey).toBe('[MASKED]');
        expect(parsed.message).toContain('created successfully');
        expect(parsed.testUrl).toBe('/llm-providers/1/test');
      });

      it('should create custom LLM provider with custom configuration', async () => {
        const customProvider = {
          ...testLLMProvider,
          type: 'custom',
          configuration: {
            apiKey: 'custom-key',
            baseUrl: 'https://api.custom.com/v1',
            customHeaders: {
              'X-Custom-Header': 'value'
            }
          }
        };
        mockApiClient.mockResponse('POST', '/llm-providers', {
          success: true,
          data: customProvider
        });

        const tool = findTool(mockTool, 'create-llm-provider');
        const providerConfig = {
          name: 'Custom Provider',
          type: 'custom',
          configuration: {
            apiKey: 'custom-key',
            baseUrl: 'https://api.custom.com/v1',
            customHeaders: {
              'X-Custom-Header': 'value'
            }
          },
          models: [
            {
              id: 'custom-model',
              name: 'Custom Model',
              type: 'chat',
              maxTokens: 4096,
              supportsStreaming: false,
              costPer1kTokens: 0.01
            }
          ]
        };

        const result = await executeTool(tool, providerConfig);
        
        const parsed = JSON.parse(result);
        expect(parsed.provider.type).toBe('custom');
        expect(parsed.provider.configuration.baseUrl).toBe('https://api.custom.com/v1');
        expect(parsed.provider.configuration.apiKey).toBe('[MASKED]');
      });

      it('should apply default rate limits when not specified', async () => {
        mockApiClient.mockResponse('POST', '/llm-providers', {
          success: true,
          data: testLLMProvider
        });

        const tool = findTool(mockTool, 'create-llm-provider');
        const providerConfig = {
          name: 'Test Provider',
          type: 'openai',
          configuration: { apiKey: 'sk-test' },
          models: [
            {
              id: 'gpt-3.5-turbo',
              name: 'GPT-3.5 Turbo',
              type: 'chat',
              maxTokens: 4096,
              supportsStreaming: true,
              costPer1kTokens: 0.002
            }
          ]
        };

        const result = await executeTool(tool, providerConfig);
        
        const calls = mockApiClient.getCallLog();
        const createCall = calls[0];
        expect(createCall.data.rateLimit.requestsPerMinute).toBe(60);
        expect(createCall.data.rateLimit.tokensPerMinute).toBe(60000);
      });

      it('should validate required model information', async () => {
        const tool = findTool(mockTool, 'create-llm-provider');
        
        // Test missing models
        await expect(executeTool(tool, {
          name: 'Test Provider',
          type: 'openai',
          configuration: { apiKey: 'sk-test' },
          models: []
        }, { log: mockLog }))
          .rejects.toThrow();

        // Test invalid model type
        await expect(executeTool(tool, {
          name: 'Test Provider',
          type: 'openai',
          configuration: { apiKey: 'sk-test' },
          models: [
            {
              id: 'gpt-4',
              name: 'GPT-4',
              type: 'invalid' as any,
              maxTokens: 8192,
              supportsStreaming: true,
              costPer1kTokens: 0.03
            }
          ]
        }, { log: mockLog }))
          .rejects.toThrow();
      });
    });

    describe('list-llm-providers tool', () => {
      it('should list all LLM providers with models', async () => {
        const providers = [
          testLLMProvider,
          {
            ...testLLMProvider,
            id: 2,
            name: 'Anthropic',
            type: 'anthropic',
            models: [
              {
                id: 'claude-3',
                name: 'Claude 3',
                type: 'chat',
                maxTokens: 100000,
                supportsStreaming: true,
                costPer1kTokens: 0.015
              }
            ]
          }
        ];
        mockApiClient.mockResponse('GET', '/llm-providers', {
          success: true,
          data: providers
        });

        const tool = findTool(mockTool, 'list-llm-providers');
        const result = await executeTool(tool, {});
        
        const parsed = JSON.parse(result);
        expect(parsed.providers).toHaveLength(2);
        expect(parsed.summary.totalProviders).toBe(2);
        expect(parsed.summary.typeBreakdown.openai).toBe(1);
        expect(parsed.summary.typeBreakdown.anthropic).toBe(1);
        expect(parsed.summary.totalModels).toBe(3);
        expect(parsed.summary.modelTypes).toContain('chat');
      });

      it('should filter providers by type and status', async () => {
        mockApiClient.mockResponse('GET', '/llm-providers', {
          success: true,
          data: [testLLMProvider]
        });

        const tool = findTool(mockTool, 'list-llm-providers');
        await executeTool(tool, {
          type: 'openai',
          status: 'active',
          includeModels: true
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.type).toBe('openai');
        expect(calls[0].params.status).toBe('active');
        expect(calls[0].params.includeModels).toBe(true);
      });

      it('should optionally exclude model information', async () => {
        const providersWithoutModels = [
          { ...testLLMProvider, models: undefined }
        ];
        mockApiClient.mockResponse('GET', '/llm-providers', {
          success: true,
          data: providersWithoutModels
        });

        const tool = findTool(mockTool, 'list-llm-providers');
        await executeTool(tool, { includeModels: false });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.includeModels).toBe(false);
      });

      it('should mask sensitive configuration data', async () => {
        const providersWithSecrets = [
          {
            ...testLLMProvider,
            configuration: {
              ...testLLMProvider.configuration,
              apiKey: 'sk-secret-key',
              secretToken: 'secret-token'
            }
          }
        ];
        mockApiClient.mockResponse('GET', '/llm-providers', {
          success: true,
          data: providersWithSecrets
        });

        const tool = findTool(mockTool, 'list-llm-providers');
        const result = await executeTool(tool, {});
        
        expect(result).not.toContain('sk-secret-key');
        expect(result).not.toContain('secret-token');
        expect(result).toContain('[MASKED]');
      });

      it('should provide comprehensive provider statistics', async () => {
        const mixedProviders = [
          { ...testLLMProvider, status: 'active', type: 'openai' },
          { ...testLLMProvider, id: 2, status: 'inactive', type: 'anthropic', models: [
            { id: 'claude-3', name: 'Claude 3', type: 'embedding', maxTokens: 100000, supportsStreaming: false, costPer1kTokens: 0.015 }
          ] },
          { ...testLLMProvider, id: 3, status: 'error', type: 'google', models: [] }
        ];
        mockApiClient.mockResponse('GET', '/llm-providers', {
          success: true,
          data: mixedProviders
        });

        const tool = findTool(mockTool, 'list-llm-providers');
        const result = await executeTool(tool, {});
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.statusBreakdown.active).toBe(1);
        expect(parsed.summary.statusBreakdown.inactive).toBe(1);
        expect(parsed.summary.statusBreakdown.error).toBe(1);
        expect(parsed.summary.modelTypes).toContain('chat');
        expect(parsed.summary.modelTypes).toContain('embedding');
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
    });

    it('should handle API errors gracefully across all tools', async () => {
      const tools = ['list-ai-agents', 'get-ai-agent', 'create-llm-provider', 'list-llm-providers'];
      
      for (const toolName of tools) {
        mockApiClient.mockResponse('GET', '/*', {
          success: false,
          error: testErrors.networkError
        });
        mockApiClient.mockResponse('POST', '/*', {
          success: false,
          error: testErrors.networkError
        });

        const tool = findTool(mockTool, toolName);
        const defaultInput = toolName === 'get-ai-agent' ? { agentId: 1 } :
                           toolName === 'create-llm-provider' ? {
                             name: 'Test', type: 'openai', configuration: {}, models: [
                               { id: 'test', name: 'Test', type: 'chat', maxTokens: 1000, supportsStreaming: false, costPer1kTokens: 0.01 }
                             ]
                           } : {};

        await expect(executeTool(tool, defaultInput))
          .rejects.toThrow(UserError);
      }
    });

    it('should handle network errors and timeouts', async () => {
      mockApiClient.mockNetworkError('POST', '/ai-agents', new Error('Network timeout'));

      const tool = findTool(mockTool, 'create-ai-agent');
      await expect(executeTool(tool, {
        name: 'Test Agent',
        type: 'chat',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog }))
        .rejects.toThrow('Failed to create AI agent');
    });

    it('should handle authentication errors', async () => {
      mockApiClient.mockResponse('GET', '/ai-agents', {
        success: false,
        error: testErrors.authError
      });

      const tool = findTool(mockTool, 'list-ai-agents');
      await expect(executeTool(tool, {}))
        .rejects.toThrow('Failed to list AI agents: Unauthorized access');
    });

    it('should log operations correctly', async () => {
      mockApiClient.mockResponse('GET', '/llm-providers/openai', {
        success: true,
        data: testLLMProvider
      });
      mockApiClient.mockResponse('POST', '/ai-agents', {
        success: true,
        data: testAIAgent
      });

      const tool = findTool(mockTool, 'create-ai-agent');
      await executeTool(tool, {
        name: 'Test Agent',
        type: 'chat',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog });

      expectToolCall(mockLog, 'info', 'Creating AI agent');
      expectToolCall(mockLog, 'info', 'Successfully created AI agent');
    });

    it('should handle malformed API responses', async () => {
      mockApiClient.mockResponse('GET', '/ai-agents', {
        success: true,
        data: null // Malformed response
      });

      const tool = findTool(mockTool, 'list-ai-agents');
      const result = await executeTool(tool, {});
      
      const parsed = JSON.parse(result);
      expect(parsed.agents).toEqual([]);
      expect(parsed.summary.totalAgents).toBe(0);
    });

    it('should validate input parameters with Zod schema', async () => {
      const tool = findTool(mockTool, 'create-ai-agent');
      
      // Test invalid agent type
      await expect(executeTool(tool, {
        name: 'Test Agent',
        type: 'invalid-type',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog }))
        .rejects.toThrow();

      // Test missing required fields
      await expect(executeTool(tool, {
        name: '',
        type: 'chat',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog }))
        .rejects.toThrow();

      // Test invalid temperature range
      await expect(executeTool(tool, {
        name: 'Test Agent',
        type: 'chat',
        configuration: { 
          model: 'gpt-4', 
          provider: 'openai', 
          parameters: {},
          temperature: 3.0 // Out of range
        }
      }, { log: mockLog }))
        .rejects.toThrow();
    });
  });

  describe('Security and Data Protection', () => {
    beforeEach(async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
    });

    it('should never expose API keys or sensitive data in responses', async () => {
      const sensitiveAgent = {
        ...testAIAgent,
        configuration: {
          ...testAIAgent.configuration,
          parameters: {
            apiKey: 'sk-very-secret-key',
            secretToken: 'super-secret-token',
            password: 'secret-password'
          }
        }
      };

      mockApiClient.mockResponse('GET', '/ai-agents', {
        success: true,
        data: [sensitiveAgent]
      });

      const tool = findTool(mockTool, 'list-ai-agents');
      const result = await executeTool(tool, {});
      
      expect(result).not.toContain('sk-very-secret-key');
      expect(result).not.toContain('super-secret-token');
      expect(result).not.toContain('secret-password');
      expect(result).toContain('[MASKED]');
    });

    it('should mask provider credentials in all responses', async () => {
      const sensitiveProvider = {
        ...testLLMProvider,
        configuration: {
          ...testLLMProvider.configuration,
          apiKey: 'sk-provider-secret',
          secretKey: 'provider-secret-key'
        }
      };

      mockApiClient.mockResponse('GET', '/llm-providers', {
        success: true,
        data: [sensitiveProvider]
      });

      const tool = findTool(mockTool, 'list-llm-providers');
      const result = await executeTool(tool, {});
      
      expect(result).not.toContain('sk-provider-secret');
      expect(result).not.toContain('provider-secret-key');
      expect(result).toContain('[MASKED]');
    });

    it('should log security operations for audit trail', async () => {
      mockApiClient.mockResponse('GET', '/ai-agents/1/usage', {
        success: true,
        data: { activeConnections: 0 }
      });
      mockApiClient.mockResponse('DELETE', '/ai-agents/1', {
        success: true,
        data: { deleted: true }
      });

      const tool = findTool(mockTool, 'delete-ai-agent');
      await executeTool(tool, { agentId: 1, force: true });

      expectToolCall(mockLog, 'info', 'Deleting AI agent');
      expectToolCall(mockLog, 'info', 'Successfully deleted AI agent');
    });

    it('should validate and sanitize all input data', async () => {
      const tool = findTool(mockTool, 'create-ai-agent');
      
      // Test XSS prevention in name field
      await expect(executeTool(tool, {
        name: '<script>alert("xss")</script>',
        type: 'chat',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog }))
        .rejects.toThrow(); // Should be caught by Zod validation

      // Test SQL injection prevention in description
      await expect(executeTool(tool, {
        name: 'Test Agent',
        description: "'; DROP TABLE agents; --",
        type: 'chat',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog }))
        .rejects.toThrow(); // Should be caught by validation if malicious
    });
  });

  describe('External Service Integration Testing', () => {
    beforeEach(async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
    });

    it('should handle external LLM service failures gracefully', async () => {
      // Simulate external service failure
      mockApiClient.mockResponse('GET', '/llm-providers/openai', {
        success: true,
        data: testLLMProvider
      });
      mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
        success: false,
        error: { message: 'External LLM service unavailable', code: 'EXTERNAL_SERVICE_ERROR' }
      });

      const tool = findTool(mockTool, 'test-ai-agent');
      await expect(executeTool(tool, {
        agentId: 1,
        testType: 'simple',
        testInput: 'Test message'
      }, { log: mockLog, reportProgress: mockReportProgress }))
        .rejects.toThrow('Failed to test AI agent: External LLM service unavailable');
    });

    it('should handle rate limiting from external services', async () => {
      mockApiClient.mockResponse('POST', '/ai-agents/1/test', {
        success: false,
        error: { message: 'Rate limit exceeded', code: 'RATE_LIMIT_EXCEEDED' }
      });

      const tool = findTool(mockTool, 'test-ai-agent');
      await expect(executeTool(tool, {
        agentId: 1,
        testType: 'simple',
        testInput: 'Test message'
      }, { log: mockLog, reportProgress: mockReportProgress }))
        .rejects.toThrow('Rate limit exceeded');
    });

    it('should handle provider authentication failures', async () => {
      mockApiClient.mockResponse('GET', '/llm-providers/openai', {
        success: false,
        error: { message: 'Provider authentication failed', code: 'AUTH_FAILED' }
      });

      const tool = findTool(mockTool, 'create-ai-agent');
      await expect(executeTool(tool, {
        name: 'Test Agent',
        type: 'chat',
        configuration: { model: 'gpt-4', provider: 'openai', parameters: {} }
      }, { log: mockLog }))
        .rejects.toThrow('Provider authentication failed');
    });

    it('should handle model deprecation and migration', async () => {
      const deprecatedModelProvider = {
        ...testLLMProvider,
        models: [
          {
            id: 'gpt-3-deprecated',
            name: 'GPT-3 (Deprecated)',
            type: 'chat',
            maxTokens: 2048,
            supportsStreaming: false,
            costPer1kTokens: 0.02,
            deprecated: true
          }
        ]
      };

      mockApiClient.mockResponse('GET', '/llm-providers/openai', {
        success: true,
        data: deprecatedModelProvider
      });

      const tool = findTool(mockTool, 'create-ai-agent');
      const result = await executeTool(tool, {
        name: 'Test Agent',
        type: 'chat',
        configuration: { model: 'gpt-3-deprecated', provider: 'openai', parameters: {} }
      }, { log: mockLog });

      // Should still work but might include warnings
      expect(result).toContain('created successfully');
    });
  });

  describe('Performance and Load Testing', () => {
    beforeEach(async () => {
      const { addAIAgentTools } = await import('../../../src/tools/ai-agents.js');
      addAIAgentTools(mockServer, mockApiClient as any);
    });

    it('should handle concurrent agent operations', async () => {
      mockApiClient.mockResponse('GET', '/ai-agents', {
        success: true,
        data: Array.from({ length: 100 }, (_, i) => ({ ...testAIAgent, id: i + 1 })),
        metadata: { total: 100 }
      });

      const tool = findTool(mockTool, 'list-ai-agents');
      
      // Simulate concurrent requests
      const promises = Array.from({ length: 10 }, () => 
        executeTool(tool, { limit: 10 })
      );

      const results = await Promise.all(promises);
      results.forEach(result => {
        expect(result).toContain('totalAgents');
      });
    });

    it('should handle large agent lists efficiently', async () => {
      const largeAgentList = Array.from({ length: 1000 }, (_, i) => ({
        ...testAIAgent,
        id: i + 1,
        name: `Agent ${i + 1}`
      }));

      mockApiClient.mockResponse('GET', '/ai-agents', {
        success: true,
        data: largeAgentList.slice(0, 100),
        metadata: { total: 1000 }
      });

      const tool = findTool(mockTool, 'list-ai-agents');
      const startTime = Date.now();
      
      const result = await executeTool(tool, { limit: 100 });
      
      const endTime = Date.now();
      const executionTime = endTime - startTime;
      
      expect(executionTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(result).toContain('totalAgents');
      
      const parsed = JSON.parse(result);
      expect(parsed.pagination.total).toBe(1000);
      expect(parsed.agents).toHaveLength(100);
    });
  });
});