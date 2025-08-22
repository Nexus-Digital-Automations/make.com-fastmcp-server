/**
 * AI Agent Configuration and Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing AI agents, LLM providers, and agent configurations
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// AI Agent types for comprehensive management
export interface MakeAIAgent {
  id: number;
  name: string;
  description?: string;
  type: 'chat' | 'completion' | 'embedding' | 'image' | 'function_calling';
  status: 'active' | 'inactive' | 'training' | 'error';
  configuration: {
    model: string;
    provider: string;
    parameters: Record<string, unknown>;
    systemPrompt?: string;
    temperature?: number;
    maxTokens?: number;
    topP?: number;
    frequencyPenalty?: number;
    presencePenalty?: number;
  };
  context: {
    maxHistoryLength: number;
    memoryType: 'none' | 'conversation' | 'semantic' | 'hybrid';
    memorySize?: number;
    instructions?: string;
  };
  capabilities: string[];
  organizationId?: number;
  teamId?: number;
  scenarioId?: number;
  isPublic: boolean;
  createdAt: string;
  updatedAt: string;
  lastUsed?: string;
  usage: {
    totalCalls: number;
    totalTokens: number;
    avgResponseTime: number;
    errorRate: number;
  };
}

export interface MakeLLMProvider {
  id: number;
  name: string;
  type: 'openai' | 'anthropic' | 'google' | 'azure' | 'custom';
  status: 'active' | 'inactive' | 'error';
  configuration: {
    apiKey?: string;
    baseUrl?: string;
    apiVersion?: string;
    organization?: string;
    customHeaders?: Record<string, string>;
  };
  models: Array<{
    id: string;
    name: string;
    type: 'chat' | 'completion' | 'embedding' | 'image';
    maxTokens: number;
    supportsStreaming: boolean;
    costPer1kTokens: number;
  }>;
  rateLimit: {
    requestsPerMinute: number;
    tokensPerMinute: number;
  };
  createdAt: string;
  updatedAt: string;
}

// Input validation schemas
const AIAgentCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('AI agent name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Agent description (max 500 characters)'),
  type: z.enum(['chat', 'completion', 'embedding', 'image', 'function_calling']).describe('Agent type'),
  configuration: z.object({
    model: z.string().min(1).describe('Model identifier (e.g., gpt-4, claude-3)'),
    provider: z.string().min(1).describe('LLM provider name'),
    parameters: z.record(z.string(), z.any()).default(() => ({})).describe('Model-specific parameters'),
    systemPrompt: z.string().optional().describe('System prompt for the agent'),
    temperature: z.number().min(0).max(2).optional().describe('Sampling temperature (0-2)'),
    maxTokens: z.number().min(1).max(200000).optional().describe('Maximum tokens in response'),
    topP: z.number().min(0).max(1).optional().describe('Nucleus sampling parameter'),
    frequencyPenalty: z.number().min(-2).max(2).optional().describe('Frequency penalty (-2 to 2)'),
    presencePenalty: z.number().min(-2).max(2).optional().describe('Presence penalty (-2 to 2)'),
  }).describe('Agent configuration'),
  context: z.object({
    maxHistoryLength: z.number().min(0).max(1000).default(10).describe('Maximum conversation history length'),
    memoryType: z.enum(['none', 'conversation', 'semantic', 'hybrid']).default('conversation').describe('Memory management type'),
    memorySize: z.number().min(0).optional().describe('Memory size limit (MB)'),
    instructions: z.string().optional().describe('Additional context instructions'),
  }).default(() => ({ maxHistoryLength: 10, memoryType: 'conversation' as const })).describe('Context and memory configuration'),
  capabilities: z.array(z.string()).default([]).describe('Agent capabilities (function names, tools)'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization-scoped agents)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team-scoped agents)'),
  scenarioId: z.number().min(1).optional().describe('Scenario ID (for scenario-scoped agents)'),
  isPublic: z.boolean().default(false).describe('Whether agent is publicly accessible'),
}).strict();

const AIAgentUpdateSchema = z.object({
  agentId: z.number().min(1).describe('AI agent ID to update'),
  name: z.string().min(1).max(100).optional().describe('New agent name'),
  description: z.string().max(500).optional().describe('New agent description'),
  configuration: z.object({
    model: z.string().min(1).optional(),
    provider: z.string().min(1).optional(),
    parameters: z.record(z.string(), z.any()).optional(),
    systemPrompt: z.string().optional(),
    temperature: z.number().min(0).max(2).optional(),
    maxTokens: z.number().min(1).max(200000).optional(),
    topP: z.number().min(0).max(1).optional(),
    frequencyPenalty: z.number().min(-2).max(2).optional(),
    presencePenalty: z.number().min(-2).max(2).optional(),
  }).optional().describe('Configuration updates'),
  context: z.object({
    maxHistoryLength: z.number().min(0).max(1000).optional(),
    memoryType: z.enum(['none', 'conversation', 'semantic', 'hybrid']).optional(),
    memorySize: z.number().min(0).optional(),
    instructions: z.string().optional(),
  }).optional().describe('Context updates'),
  capabilities: z.array(z.string()).optional().describe('Updated capabilities'),
  isPublic: z.boolean().optional().describe('Update public accessibility'),
}).strict();

const AIAgentListSchema = z.object({
  type: z.enum(['chat', 'completion', 'embedding', 'image', 'function_calling', 'all']).default('all').describe('Filter by agent type'),
  status: z.enum(['active', 'inactive', 'training', 'error', 'all']).default('all').describe('Filter by agent status'),
  provider: z.string().optional().describe('Filter by LLM provider'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
  isPublic: z.boolean().optional().describe('Filter by public accessibility'),
  includeUsage: z.boolean().default(false).describe('Include usage statistics'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of agents to return'),
  offset: z.number().min(0).default(0).describe('Number of agents to skip for pagination'),
  sortBy: z.enum(['name', 'createdAt', 'lastUsed', 'totalCalls']).default('name').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
}).strict();

const LLMProviderCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Provider name'),
  type: z.enum(['openai', 'anthropic', 'google', 'azure', 'custom']).describe('Provider type'),
  configuration: z.object({
    apiKey: z.string().optional().describe('API key (will be encrypted)'),
    baseUrl: z.string().url().optional().describe('Custom API base URL'),
    apiVersion: z.string().optional().describe('API version (for Azure/custom)'),
    organization: z.string().optional().describe('Organization ID (for OpenAI)'),
    customHeaders: z.record(z.string(), z.string()).optional().describe('Custom HTTP headers'),
  }).describe('Provider configuration'),
  models: z.array(z.object({
    id: z.string().min(1).describe('Model ID'),
    name: z.string().min(1).describe('Model display name'),
    type: z.enum(['chat', 'completion', 'embedding', 'image']).describe('Model type'),
    maxTokens: z.number().min(1).describe('Maximum context tokens'),
    supportsStreaming: z.boolean().default(false).describe('Supports streaming responses'),
    costPer1kTokens: z.number().min(0).describe('Cost per 1000 tokens (USD)'),
  })).min(1).describe('Available models'),
  rateLimit: z.object({
    requestsPerMinute: z.number().min(1).default(60).describe('Requests per minute limit'),
    tokensPerMinute: z.number().min(1).default(60000).describe('Tokens per minute limit'),
  }).default(() => ({ requestsPerMinute: 60, tokensPerMinute: 60000 })).describe('Rate limiting configuration'),
}).strict();

const AgentTestSchema = z.object({
  agentId: z.number().min(1).describe('AI agent ID to test'),
  testType: z.enum(['simple', 'conversation', 'function_calling', 'performance']).default('simple').describe('Type of test to perform'),
  testInput: z.any().describe('Test input (string for simple test, array for conversation)'),
  options: z.object({
    includeMetrics: z.boolean().default(true).describe('Include performance metrics'),
    timeout: z.number().min(1000).max(60000).default(30000).describe('Test timeout in milliseconds'),
    validateResponse: z.boolean().default(true).describe('Validate response format'),
  }).default(() => ({ includeMetrics: true, timeout: 30000, validateResponse: true })).describe('Test options'),
}).strict();

/**
 * Add create AI agent tool
 */
function addCreateAIAgentTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-ai-agent',
    description: 'Create a new AI agent with LLM configuration and context management',
    parameters: AIAgentCreateSchema,
    annotations: {
      title: 'Create AI Agent',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { name, description, type, configuration, context, capabilities, organizationId, teamId, scenarioId, isPublic } = input;

      log.info('Creating AI agent', {
        name,
        type,
        provider: configuration.provider,
        model: configuration.model,
      });

      try {
        // Validate provider exists
        const providerResponse = await apiClient.get(`/llm-providers/${configuration.provider}`);
        if (!providerResponse.success) {
          throw new UserError(`LLM provider "${configuration.provider}" not found or not accessible`);
        }

        const provider = providerResponse.data as MakeLLMProvider;
        const supportedModel = provider.models.find(m => m.id === configuration.model);
        if (!supportedModel) {
          throw new UserError(`Model "${configuration.model}" not supported by provider "${configuration.provider}"`);
        }

        const agentData = {
          name,
          description,
          type,
          configuration: {
            ...configuration,
            parameters: {
              ...configuration.parameters,
              // Set defaults based on model capabilities
              maxTokens: configuration.maxTokens || Math.min(supportedModel.maxTokens, 4000),
              temperature: configuration.temperature ?? 0.7,
            },
          },
          context: {
            ...context,
            maxHistoryLength: context?.maxHistoryLength ?? 10,
            memoryType: context?.memoryType ?? 'conversation',
          },
          capabilities,
          organizationId,
          teamId,
          scenarioId,
          isPublic,
          status: 'active',
        };

        let endpoint = '/ai-agents';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/ai-agents`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/ai-agents`;
        } else if (scenarioId) {
          endpoint = `/scenarios/${scenarioId}/ai-agents`;
        }

        const response = await apiClient.post(endpoint, agentData);

        if (!response.success) {
          throw new UserError(`Failed to create AI agent: ${response.error?.message || 'Unknown error'}`);
        }

        const agent = response.data as MakeAIAgent;
        if (!agent) {
          throw new UserError('AI agent creation failed - no data returned');
        }

        log.info('Successfully created AI agent', {
          agentId: agent.id,
          name: agent.name,
          type: agent.type,
          model: agent.configuration.model,
        });

        return formatSuccessResponse({
          agent: {
            ...agent,
            configuration: {
              ...agent.configuration,
              // Mask sensitive information
              apiKey: agent.configuration.parameters?.apiKey ? '[MASKED]' : undefined,
            },
          },
          message: `AI agent "${name}" created successfully`,
          testUrl: `/ai-agents/${agent.id}/test`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating AI agent', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create AI agent: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list AI agents tool
 */
function addListAIAgentsTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'list-ai-agents',
    description: 'List and filter AI agents with comprehensive search capabilities',
    parameters: AIAgentListSchema,
    annotations: {
      title: 'List AI Agents',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { type, status, provider, organizationId, teamId, scenarioId, isPublic, includeUsage, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing AI agents', {
        type,
        status,
        provider,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeUsage,
        };

        if (type !== 'all') {params.type = type;}
        if (status !== 'all') {params.status = status;}
        if (provider) {params.provider = provider;}
        if (organizationId) {params.organizationId = organizationId;}
        if (teamId) {params.teamId = teamId;}
        if (scenarioId) {params.scenarioId = scenarioId;}
        if (isPublic !== undefined) {params.isPublic = isPublic;}

        const response = await apiClient.get('/ai-agents', { params });

        if (!response.success) {
          throw new UserError(`Failed to list AI agents: ${response.error?.message || 'Unknown error'}`);
        }

        const agents = response.data as MakeAIAgent[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved AI agents', {
          count: agents.length,
          total: metadata?.total,
        });

        // Create summary statistics
        const summary = {
          totalAgents: metadata?.total || agents.length,
          typeBreakdown: {
            chat: agents.filter(a => a.type === 'chat').length,
            completion: agents.filter(a => a.type === 'completion').length,
            embedding: agents.filter(a => a.type === 'embedding').length,
            image: agents.filter(a => a.type === 'image').length,
            function_calling: agents.filter(a => a.type === 'function_calling').length,
          },
          statusBreakdown: {
            active: agents.filter(a => a.status === 'active').length,
            inactive: agents.filter(a => a.status === 'inactive').length,
            training: agents.filter(a => a.status === 'training').length,
            error: agents.filter(a => a.status === 'error').length,
          },
          providerBreakdown: agents.reduce((acc: Record<string, number>, agent) => {
            const provider = agent.configuration.provider;
            acc[provider] = (acc[provider] || 0) + 1;
            return acc;
          }, {}),
          publicAgents: agents.filter(a => a.isPublic).length,
          totalUsage: includeUsage ? {
            totalCalls: agents.reduce((sum, a) => sum + a.usage.totalCalls, 0),
            totalTokens: agents.reduce((sum, a) => sum + a.usage.totalTokens, 0),
            avgResponseTime: agents.length > 0 ? 
              agents.reduce((sum, a) => sum + a.usage.avgResponseTime, 0) / agents.length : 0,
          } : undefined,
        };

        return formatSuccessResponse({
          agents: agents.map(agent => ({
            ...agent,
            configuration: {
              ...agent.configuration,
              // Mask sensitive data
              parameters: {
                ...agent.configuration.parameters,
                apiKey: agent.configuration.parameters?.apiKey ? '[MASKED]' : undefined,
              },
            },
          })),
          summary,
          pagination: {
            total: metadata?.total || agents.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + agents.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing AI agents', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list AI agents: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add get AI agent tool
 */
function addGetAIAgentTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'get-ai-agent',
    description: 'Get detailed information about a specific AI agent',
    parameters: z.object({
      agentId: z.number().min(1).describe('AI agent ID to retrieve'),
      includeUsage: z.boolean().default(true).describe('Include detailed usage statistics'),
      includeHistory: z.boolean().default(false).describe('Include recent conversation history'),
    }),
    annotations: {
      title: 'Get AI Agent Details',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { agentId, includeUsage, includeHistory } = input;

      log.info('Getting AI agent details', { agentId });

      try {
        const response = await apiClient.get(`/ai-agents/${agentId}`);

        if (!response.success) {
          throw new UserError(`Failed to get AI agent: ${response.error?.message || 'Unknown error'}`);
        }

        const agent = response.data as MakeAIAgent;
        if (!agent) {
          throw new UserError(`AI agent with ID ${agentId} not found`);
        }

        let usage: unknown = null;
        let history: unknown = null;

        if (includeUsage) {
          try {
            const usageResponse = await apiClient.get(`/ai-agents/${agentId}/usage`);
            if (usageResponse.success) {
              usage = usageResponse.data;
            }
          } catch {
            log.warn('Failed to retrieve agent usage statistics', { agentId });
          }
        }

        if (includeHistory) {
          try {
            const historyResponse = await apiClient.get(`/ai-agents/${agentId}/history`, {
              params: { limit: 10 }
            });
            if (historyResponse.success) {
              history = historyResponse.data;
            }
          } catch {
            log.warn('Failed to retrieve agent conversation history', { agentId });
          }
        }

        log.info('Successfully retrieved AI agent', {
          agentId,
          name: agent.name,
          type: agent.type,
          status: agent.status,
        });

        return formatSuccessResponse({
          agent: {
            ...agent,
            configuration: {
              ...agent.configuration,
              parameters: {
                ...agent.configuration.parameters,
                apiKey: agent.configuration.parameters?.apiKey ? '[MASKED]' : undefined,
              },
            },
          },
          usage,
          history,
          metadata: {
            canEdit: true, // This would be determined by user permissions
            canDelete: agent.status !== 'training',
            canTest: agent.status === 'active',
            lastHealthCheck: (usage as Record<string, unknown>)?.lastHealthCheck,
            costEstimate: (usage as Record<string, unknown>)?.estimatedCost,
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting AI agent', { agentId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get AI agent details: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add update AI agent tool
 */
function addUpdateAIAgentTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'update-ai-agent',
    description: 'Update an existing AI agent configuration',
    parameters: AIAgentUpdateSchema,
    annotations: {
      title: 'Update AI Agent',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { agentId, name, description, configuration, context, capabilities, isPublic } = input;

      log.info('Updating AI agent', { agentId, name });

      try {
        const updateData: Record<string, unknown> = {};

        if (name !== undefined) {updateData.name = name;}
        if (description !== undefined) {updateData.description = description;}
        if (configuration !== undefined) {updateData.configuration = configuration;}
        if (context !== undefined) {updateData.context = context;}
        if (capabilities !== undefined) {updateData.capabilities = capabilities;}
        if (isPublic !== undefined) {updateData.isPublic = isPublic;}

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        // If updating configuration, validate model compatibility
        if (configuration?.model && configuration?.provider) {
          const providerResponse = await apiClient.get(`/llm-providers/${configuration.provider}`);
          if (!providerResponse.success) {
            throw new UserError(`LLM provider "${configuration.provider}" not found`);
          }
          
          const provider = providerResponse.data as MakeLLMProvider;
          const supportedModel = provider.models.find(m => m.id === configuration.model);
          if (!supportedModel) {
            throw new UserError(`Model "${configuration.model}" not supported by provider "${configuration.provider}"`);
          }
        }

        const response = await apiClient.put(`/ai-agents/${agentId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update AI agent: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedAgent = response.data as MakeAIAgent;

        log.info('Successfully updated AI agent', {
          agentId,
          name: updatedAgent.name,
          changes: Object.keys(updateData),
        });

        return formatSuccessResponse({
          agent: {
            ...updatedAgent,
            configuration: {
              ...updatedAgent.configuration,
              parameters: {
                ...updatedAgent.configuration.parameters,
                apiKey: updatedAgent.configuration.parameters?.apiKey ? '[MASKED]' : undefined,
              },
            },
          },
          message: `AI agent "${updatedAgent.name}" updated successfully`,
          changes: Object.keys(updateData),
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating AI agent', { agentId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update AI agent: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add delete AI agent tool
 */
function addDeleteAIAgentTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'delete-ai-agent',
    description: 'Delete an AI agent',
    parameters: z.object({
      agentId: z.number().min(1).describe('AI agent ID to delete'),
      force: z.boolean().default(false).describe('Force delete even if agent is in use'),
    }),
    annotations: {
      title: 'Delete AI Agent',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { agentId, force } = input;

      log.info('Deleting AI agent', { agentId, force });

      try {
        // Check if agent is in use (unless force delete)
        if (!force) {
          const usageResponse = await apiClient.get(`/ai-agents/${agentId}/usage`);
          if (usageResponse.success && (usageResponse.data as Record<string, unknown>)?.activeConnections as number > 0) {
            throw new UserError(`AI agent is currently in use (${(usageResponse.data as Record<string, unknown>).activeConnections as number} active connections). Use force=true to delete anyway.`);
          }
        }

        const response = await apiClient.delete(`/ai-agents/${agentId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete AI agent: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted AI agent', { agentId });

        return formatSuccessResponse({
          message: `AI agent ${agentId} deleted successfully`,
          agentId,
          forced: force,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting AI agent', { agentId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete AI agent: ${errorMessage}`);
      }
    },
  });
}

// Helper function to safely extract metrics from test result
function extractPerformanceMetrics(testResult: Record<string, unknown>, totalTime: number): Record<string, unknown> {
  const metrics = testResult.metrics as Record<string, unknown> | undefined;
  return {
    totalTime: `${totalTime}ms`,
    agentResponseTime: metrics?.responseTime,
    tokenUsage: metrics?.tokens,
    cost: metrics?.cost,
  };
}

// Helper function to safely extract validation info from test result
function extractValidationInfo(testResult: Record<string, unknown>): Record<string, unknown> {
  const validation = testResult.validation as Record<string, unknown> | undefined;
  const errors = validation?.errors as unknown[] | undefined;
  
  return {
    responseFormat: validation?.format || 'valid',
    contentQuality: validation?.quality || 'good',
    errorCount: errors?.length || 0,
  };
}

// Helper function to create test summary
function createTestSummary(testType: string, testResult: Record<string, unknown>): Record<string, unknown> {
  return {
    testType,
    success: testResult?.success || false,
    message: testResult?.message || 'Test completed',
    timestamp: new Date().toISOString(),
  };
}

/**
 * Add test AI agent tool
 */
function addTestAIAgentTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'test-ai-agent',
    description: 'Test an AI agent with various test scenarios and performance metrics',
    parameters: AgentTestSchema,
    annotations: {
      title: 'Test AI Agent',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { agentId, testType, testInput, options } = input;

      log.info('Testing AI agent', { agentId, testType });

      try {
        reportProgress({ progress: 0, total: 100 });

        const testData = {
          testType,
          testInput,
          options,
        };

        const startTime = Date.now();
        const response = await apiClient.post(`/ai-agents/${agentId}/test`, testData);

        if (!response.success) {
          throw new UserError(`Failed to test AI agent: ${response.error?.message || 'Unknown error'}`);
        }

        const testResult = response.data as Record<string, unknown>;
        const endTime = Date.now();
        const totalTime = endTime - startTime;

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully tested AI agent', {
          agentId,
          testType,
          success: testResult?.success as boolean,
          responseTime: totalTime,
        });

        return formatSuccessResponse({
          testResult,
          performance: extractPerformanceMetrics(testResult, totalTime),
          validation: extractValidationInfo(testResult),
          summary: createTestSummary(testType, testResult),
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error testing AI agent', { agentId, testType, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to test AI agent: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add create LLM provider tool
 */
function addCreateLLMProviderTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-llm-provider',
    description: 'Create a new LLM provider configuration',
    parameters: LLMProviderCreateSchema,
    annotations: {
      title: 'Create LLM Provider',
      readOnlyHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { name, type, configuration, models, rateLimit } = input;

      log.info('Creating LLM provider', { name, type, modelCount: models.length });

      try {
        const providerData = {
          name,
          type,
          configuration,
          models,
          rateLimit: {
            ...rateLimit,
            requestsPerMinute: rateLimit?.requestsPerMinute ?? 60,
            tokensPerMinute: rateLimit?.tokensPerMinute ?? 60000,
          },
          status: 'active',
        };

        const response = await apiClient.post('/llm-providers', providerData);

        if (!response.success) {
          throw new UserError(`Failed to create LLM provider: ${response.error?.message || 'Unknown error'}`);
        }

        const provider = response.data as MakeLLMProvider;

        log.info('Successfully created LLM provider', {
          providerId: provider.id,
          name: provider.name,
          type: provider.type,
        });

        return formatSuccessResponse({
          provider: {
            ...provider,
            configuration: {
              ...provider.configuration,
              apiKey: provider.configuration.apiKey ? '[MASKED]' : undefined,
            },
          },
          message: `LLM provider "${name}" created successfully`,
          testUrl: `/llm-providers/${provider.id}/test`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating LLM provider', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create LLM provider: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list LLM providers tool
 */
function addListLLMProvidersTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'list-llm-providers',
    description: 'List available LLM providers and their models',
    parameters: z.object({
      type: z.enum(['openai', 'anthropic', 'google', 'azure', 'custom', 'all']).default('all').describe('Filter by provider type'),
      status: z.enum(['active', 'inactive', 'error', 'all']).default('all').describe('Filter by provider status'),
      includeModels: z.boolean().default(true).describe('Include model information'),
    }),
    annotations: {
      title: 'List LLM Providers',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { type, status, includeModels } = input;

      log.info('Listing LLM providers', { type, status });

      try {
        const params: Record<string, unknown> = {
          includeModels,
        };

        if (type !== 'all') {params.type = type;}
        if (status !== 'all') {params.status = status;}

        const response = await apiClient.get('/llm-providers', { params });

        if (!response.success) {
          throw new UserError(`Failed to list LLM providers: ${response.error?.message || 'Unknown error'}`);
        }

        const providers = response.data as MakeLLMProvider[] || [];

        log.info('Successfully retrieved LLM providers', { count: providers.length });

        const summary = {
          totalProviders: providers.length,
          typeBreakdown: providers.reduce((acc: Record<string, number>, provider) => {
            acc[provider.type] = (acc[provider.type] || 0) + 1;
            return acc;
          }, {}),
          statusBreakdown: providers.reduce((acc: Record<string, number>, provider) => {
            acc[provider.status] = (acc[provider.status] || 0) + 1;
            return acc;
          }, {}),
          totalModels: providers.reduce((sum, p) => sum + p.models.length, 0),
          modelTypes: [...new Set(providers.flatMap(p => p.models.map(m => m.type)))],
        };

        return formatSuccessResponse({
          providers: providers.map(provider => ({
            ...provider,
            configuration: {
              ...provider.configuration,
              apiKey: provider.configuration.apiKey ? '[MASKED]' : undefined,
            },
          })),
          summary,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing LLM providers', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list LLM providers: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add AI agent management tools to FastMCP server
 */
export function addAIAgentTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'AIAgentTools' });
  
  componentLogger.info('Adding AI agent management tools');

  // Add all AI agent tools
  addCreateAIAgentTool(server, apiClient);
  addListAIAgentsTool(server, apiClient);
  addGetAIAgentTool(server, apiClient);
  addUpdateAIAgentTool(server, apiClient);
  addDeleteAIAgentTool(server, apiClient);
  addTestAIAgentTool(server, apiClient);
  addCreateLLMProviderTool(server, apiClient);
  addListLLMProvidersTool(server, apiClient);

  componentLogger.info('AI agent management tools added successfully');
}

export default addAIAgentTools;