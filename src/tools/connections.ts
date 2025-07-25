/**
 * @fileoverview Make.com Connection and Webhook Management Tools
 * 
 * Provides comprehensive CRUD operations for Make.com app connections and webhooks including:
 * - Creating, updating, and deleting connections with secure credential handling
 * - Connection validation and testing with service-specific protocols
 * - Webhook management with endpoint configuration and monitoring
 * - Service discovery and integration status monitoring
 * - Advanced filtering and search capabilities
 * - Security-conscious credential storage and access control
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api/connections} Make.com Connections API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { safeGetRecord, safeGetArray } from '../utils/validation.js';

// Input validation schemas
const ConnectionFiltersSchema = z.object({
  service: z.string().optional().describe('Filter by service name (e.g., "slack", "gmail")'),
  status: z.enum(['valid', 'invalid', 'all']).default('all').describe('Filter by connection status'),
  search: z.string().optional().describe('Search connections by name or account'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of connections to return'),
  offset: z.number().min(0).default(0).describe('Number of connections to skip for pagination'),
}).strict();

const CreateConnectionSchema = z.object({
  name: z.string().min(1).max(100).describe('Connection name'),
  service: z.string().min(1).describe('Service identifier (e.g., "slack", "gmail")'),
  accountName: z.string().min(1).max(100).describe('Account name or identifier'),
  credentials: z.record(z.any()).describe('Service-specific credentials'),
  metadata: z.record(z.any()).optional().describe('Additional connection metadata'),
}).strict();

const UpdateConnectionSchema = z.object({
  connectionId: z.number().min(1).describe('Connection ID to update'),
  name: z.string().min(1).max(100).optional().describe('New connection name'),
  accountName: z.string().min(1).max(100).optional().describe('New account name'),
  credentials: z.record(z.any()).optional().describe('Updated credentials'),
  metadata: z.record(z.any()).optional().describe('Updated metadata'),
}).strict();

const WebhookFiltersSchema = z.object({
  connectionId: z.number().min(1).optional().describe('Filter by connection ID'),
  scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
  status: z.enum(['active', 'inactive', 'all']).default('all').describe('Filter by webhook status'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of webhooks to return'),
  offset: z.number().min(0).default(0).describe('Number of webhooks to skip for pagination'),
}).strict();

const CreateWebhookSchema = z.object({
  name: z.string().min(1).max(100).describe('Webhook name'),
  url: z.string().url().describe('Webhook endpoint URL'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('POST').describe('HTTP method'),
  headers: z.record(z.string()).optional().describe('HTTP headers to include'),
  connectionId: z.number().min(1).optional().describe('Associated connection ID'),
  scenarioId: z.number().min(1).optional().describe('Associated scenario ID'),
  isActive: z.boolean().default(true).describe('Whether webhook is active'),
}).strict();

const UpdateWebhookSchema = z.object({
  webhookId: z.number().min(1).describe('Webhook ID to update'),
  name: z.string().min(1).max(100).optional().describe('New webhook name'),
  url: z.string().url().optional().describe('New webhook URL'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).optional().describe('New HTTP method'),
  headers: z.record(z.string()).optional().describe('Updated headers'),
  isActive: z.boolean().optional().describe('Update webhook status'),
}).strict();

/**
 * Adds comprehensive connection and webhook management tools to the FastMCP server
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting and error handling
 * @returns {void}
 * 
 * @example
 * ```typescript
 * import { addConnectionTools } from './tools/connections.js';
 * 
 * const server = new FastMCP();
 * const apiClient = new MakeApiClient(config);
 * addConnectionTools(server, apiClient);
 * ```
 */
export function addConnectionTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'ConnectionTools' });
  
  componentLogger.info('Adding connection management tools');

  /**
   * List and filter app connections in Make.com with advanced search capabilities
   * 
   * Provides comprehensive connection listing with support for service filtering,
   * status validation, text search, and pagination for managing integrations.
   * 
   * @tool list-connections
   * @category Connection Management
   * @permission connection:read
   * 
   * @param {Object} args - Connection filtering parameters
   * @param {string} [args.service] - Filter by service name (e.g., "slack", "gmail")
   * @param {('valid'|'invalid'|'all')} [args.status='all'] - Filter by connection status
   * @param {string} [args.search] - Search connections by name or account
   * @param {number} [args.limit=20] - Maximum number of connections to return (1-100)
   * @param {number} [args.offset=0] - Number of connections to skip for pagination
   * 
   * @returns {Promise<string>} JSON response containing:
   * - connections: Array of connection objects with service details
   * - pagination: Pagination metadata (total, limit, offset, hasMore)
   * - filters: Applied filter parameters for reference
   * - timestamp: ISO timestamp of the response
   * 
   * @throws {UserError} When API request fails or parameters are invalid
   * 
   * @example
   * ```bash
   * # List all connections
   * mcp-client list-connections
   * 
   * # Filter by service and status
   * mcp-client list-connections --service "slack" --status "valid"
   * 
   * # Search connections with pagination
   * mcp-client list-connections --search "production" --limit 50 --offset 20
   * ```
   * 
   * @see {@link https://docs.make.com/api/connections#list} Make.com List Connections API
   */
  server.addTool({
    name: 'list-connections',
    description: 'List and filter app connections in Make.com',
    parameters: ConnectionFiltersSchema,
    execute: async (input, { log }) => {
      const { service, status, search, limit, offset } = input;

      log.info('Listing connections', {
        service,
        status,
        search,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (service) params.service = service;
        if (search) params.search = search;
        if (status !== 'all') params.valid = status === 'valid';

        const response = await apiClient.get('/connections', { params });

        if (!response.success) {
          throw new UserError(`Failed to list connections: ${response.error?.message || 'Unknown error'}`);
        }

        const connections = safeGetArray(response.data);
        const metadata = response.metadata;

        log.info('Successfully retrieved connections', {
          count: connections.length,
          total: metadata?.total,
        });

        return JSON.stringify({
          connections,
          pagination: {
            total: metadata?.total || connections.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + connections.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing connections', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list connections: ${errorMessage}`);
      }
    },
  });

  /**
   * Get detailed information about a specific Make.com connection
   * 
   * Retrieves comprehensive details for a specific connection including
   * service configuration, authentication status, and usage metadata.
   * 
   * @tool get-connection
   * @category Connection Management
   * @permission connection:read
   * 
   * @param {Object} args - Connection retrieval parameters
   * @param {number} args.connectionId - Connection ID to retrieve (required)
   * 
   * @returns {Promise<string>} JSON response containing:
   * - connection: Complete connection object with service details and status
   * 
   * @throws {UserError} When connection not found, access denied, or API request fails
   * 
   * @example
   * ```bash
   * # Get connection details
   * mcp-client get-connection --connectionId 12345
   * ```
   * 
   * @see {@link https://docs.make.com/api/connections#get} Make.com Get Connection API
   */
  server.addTool({
    name: 'get-connection',
    description: 'Get detailed information about a specific connection',
    parameters: z.object({
      connectionId: z.number().min(1).describe('Connection ID to retrieve'),
    }),
    execute: async (input, { log }) => {
      const { connectionId } = input;

      log.info('Getting connection details', { connectionId });

      try {
        const response = await apiClient.get(`/connections/${connectionId}`);

        if (!response.success) {
          throw new UserError(`Failed to get connection: ${response.error?.message || 'Unknown error'}`);
        }

        const connection = safeGetRecord(response.data);
        
        if (!connection || Object.keys(connection).length === 0) {
          throw new UserError(`Connection with ID ${connectionId} not found`);
        }

        log.info('Successfully retrieved connection', {
          connectionId,
          name: connection.name as string,
          service: connection.service as string,
        });

        return JSON.stringify({ connection }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting connection', { connectionId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get connection details: ${errorMessage}`);
      }
    },
  });

  /**
   * Create a new app connection in Make.com with secure credential handling
   * 
   * Creates a new connection to external services with proper credential
   * storage, validation, and security measures for integration management.
   * 
   * @tool create-connection
   * @category Connection Management
   * @permission connection:create
   * 
   * @param {Object} args - Connection creation parameters
   * @param {string} args.name - Connection name (required, 1-100 chars)
   * @param {string} args.service - Service identifier (e.g., "slack", "gmail") (required)
   * @param {string} args.accountName - Account name or identifier (required, 1-100 chars)
   * @param {Object} args.credentials - Service-specific credentials (required)
   * @param {Object} [args.metadata] - Additional connection metadata
   * 
   * @returns {Promise<string>} JSON response containing:
   * - connection: Complete created connection object
   * - message: Success confirmation message
   * 
   * @throws {UserError} When creation fails, credentials are invalid, or service is not supported
   * 
   * @example
   * ```bash
   * # Create Slack connection
   * mcp-client create-connection \
   *   --name "Team Slack" \
   *   --service "slack" \
   *   --accountName "team-workspace" \
   *   --credentials '{"token": "xoxb-...", "workspace": "team"}'
   * 
   * # Create Gmail connection with metadata
   * mcp-client create-connection \
   *   --name "Support Gmail" \
   *   --service "gmail" \
   *   --accountName "support@company.com" \
   *   --credentials '{"refresh_token": "...", "client_id": "..."}' \
   *   --metadata '{"department": "support", "primary": true}'
   * ```
   * 
   * @see {@link https://docs.make.com/api/connections#create} Make.com Create Connection API
   */
  server.addTool({
    name: 'create-connection',
    description: 'Create a new app connection in Make.com',
    parameters: CreateConnectionSchema,
    execute: async (input, { log }) => {
      const { name, service, accountName, credentials, metadata } = input;

      log.info('Creating new connection', {
        name,
        service,
        accountName,
      });

      try {
        const connectionData = {
          name,
          service,
          accountName,
          credentials,
          metadata: metadata || {},
        };

        const response = await apiClient.post('/connections', connectionData);

        if (!response.success) {
          throw new UserError(`Failed to create connection: ${response.error?.message || 'Unknown error'}`);
        }

        const connection = safeGetRecord(response.data);
        
        if (!connection || Object.keys(connection).length === 0) {
          throw new UserError('Connection creation failed - no data returned');
        }

        log.info('Successfully created connection', {
          connectionId: connection.id as number,
          name: connection.name as string,
          service: connection.service as string,
        });

        return JSON.stringify({
          connection,
          message: `Connection "${name}" created successfully`,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating connection', { name, service, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create connection: ${errorMessage}`);
      }
    },
  });

  /**
   * Update an existing app connection with secure credential management
   * 
   * Modifies connection properties including name, account details, credentials,
   * and metadata with validation and security measures for safe updates.
   * 
   * @tool update-connection
   * @category Connection Management
   * @permission connection:write
   * 
   * @param {Object} args - Connection update parameters
   * @param {number} args.connectionId - Connection ID to update (required)
   * @param {string} [args.name] - New connection name (1-100 chars)
   * @param {string} [args.accountName] - New account name (1-100 chars)
   * @param {Object} [args.credentials] - Updated credentials
   * @param {Object} [args.metadata] - Updated metadata
   * 
   * @returns {Promise<string>} JSON response containing:
   * - connection: Updated connection object
   * - message: Success confirmation message
   * - updatedFields: List of fields that were modified
   * 
   * @throws {UserError} When connection not found, update fails, or no data provided
   * 
   * @example
   * ```bash
   * # Update connection name
   * mcp-client update-connection --connectionId 12345 --name "Updated Slack Connection"
   * 
   * # Update credentials and metadata
   * mcp-client update-connection \
   *   --connectionId 12345 \
   *   --credentials '{"token": "new-token-123"}' \
   *   --metadata '{"updated": true, "version": "2.0"}'
   * 
   * # Update account name
   * mcp-client update-connection \
   *   --connectionId 12345 \
   *   --accountName "new-account@company.com"
   * ```
   * 
   * @see {@link https://docs.make.com/api/connections#update} Make.com Update Connection API
   */
  server.addTool({
    name: 'update-connection',
    description: 'Update an existing app connection',
    parameters: UpdateConnectionSchema,
    execute: async (input, { log }) => {
      const { connectionId, name, accountName, credentials, metadata } = input;

      log.info('Updating connection', { connectionId });

      try {
        const updateData: Record<string, unknown> = {};
        if (name !== undefined) updateData.name = name;
        if (accountName !== undefined) updateData.accountName = accountName;
        if (credentials !== undefined) updateData.credentials = credentials;
        if (metadata !== undefined) updateData.metadata = metadata;

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        const response = await apiClient.patch(`/connections/${connectionId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update connection: ${response.error?.message || 'Unknown error'}`);
        }

        const connection = safeGetRecord(response.data);
        if (!connection || Object.keys(connection).length === 0) {
          throw new UserError('Connection update failed - no data returned');
        }

        log.info('Successfully updated connection', {
          connectionId,
          name: connection.name as string,
          updatedFields: Object.keys(updateData),
        });

        return JSON.stringify({
          connection,
          message: 'Connection updated successfully',
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating connection', { connectionId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update connection: ${errorMessage}`);
      }
    },
  });

  // Delete connection tool
  server.addTool({
    name: 'delete-connection',
    description: 'Delete an app connection from Make.com',
    parameters: z.object({
      connectionId: z.number().min(1).describe('Connection ID to delete'),
    }),
    execute: async (input, { log }) => {
      const { connectionId } = input;

      log.info('Deleting connection', { connectionId });

      try {
        const response = await apiClient.delete(`/connections/${connectionId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete connection: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted connection', { connectionId });

        return JSON.stringify({
          message: `Connection ${connectionId} deleted successfully`,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting connection', { connectionId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete connection: ${errorMessage}`);
      }
    },
  });

  // Test connection tool
  server.addTool({
    name: 'test-connection',
    description: 'Test an app connection to verify it\'s working correctly',
    parameters: z.object({
      connectionId: z.number().min(1).describe('Connection ID to test'),
      testEndpoint: z.string().optional().describe('Specific endpoint to test (optional)'),
    }),
    execute: async (input, { log }) => {
      const { connectionId, testEndpoint } = input;

      log.info('Testing connection', { connectionId, testEndpoint });

      try {
        const testData: Record<string, unknown> = {};
        if (testEndpoint) testData.endpoint = testEndpoint;

        const response = await apiClient.post(`/connections/${connectionId}/test`, testData);

        if (!response.success) {
          throw new UserError(`Failed to test connection: ${response.error?.message || 'Unknown error'}`);
        }

        const testResult = safeGetRecord(response.data);
        if (!testResult || Object.keys(testResult).length === 0) {
          throw new UserError('Connection test failed - no result returned');
        }

        const isValid = testResult.valid as boolean;
        const message = (testResult.message as string) || (isValid ? 'Connection test successful' : 'Connection test failed');

        log.info('Connection test completed', {
          connectionId,
          isValid,
          message,
        });

        return JSON.stringify({
          connectionId,
          isValid,
          message,
          details: testResult.details,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error testing connection', { connectionId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to test connection: ${errorMessage}`);
      }
    },
  });

  // List webhooks tool
  server.addTool({
    name: 'list-webhooks',  
    description: 'List and filter webhooks in Make.com',
    parameters: WebhookFiltersSchema,
    execute: async (input, { log }) => {
      const { connectionId, scenarioId, status, limit, offset } = input;

      log.info('Listing webhooks', {
        connectionId,
        scenarioId,
        status,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (connectionId) params.connectionId = connectionId;
        if (scenarioId) params.scenarioId = scenarioId;
        if (status !== 'all') params.active = status === 'active';

        const response = await apiClient.get('/webhooks', { params });

        if (!response.success) {
          throw new UserError(`Failed to list webhooks: ${response.error?.message || 'Unknown error'}`);
        }

        const webhooks = safeGetArray(response.data);
        const metadata = response.metadata;

        log.info('Successfully retrieved webhooks', {
          count: webhooks.length,
          total: metadata?.total,
        });

        return JSON.stringify({
          webhooks,
          pagination: {
            total: metadata?.total || webhooks.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + webhooks.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing webhooks', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list webhooks: ${errorMessage}`);
      }
    },
  });

  // Create webhook tool
  server.addTool({
    name: 'create-webhook',
    description: 'Create a new webhook in Make.com',
    parameters: CreateWebhookSchema,
    execute: async (input, { log }) => {
      const { name, url, method, headers, connectionId, scenarioId, isActive } = input;

      log.info('Creating new webhook', {
        name,
        url,
        method,
        connectionId,
        scenarioId,
      });

      try {
        const webhookData = {
          name,
          url,
          method,
          headers: headers || {},
          connectionId,
          scenarioId,
          isActive,
        };

        const response = await apiClient.post('/webhooks', webhookData);

        if (!response.success) {
          throw new UserError(`Failed to create webhook: ${response.error?.message || 'Unknown error'}`);
        }

        const webhook = safeGetRecord(response.data);
        if (!webhook || Object.keys(webhook).length === 0) {
          throw new UserError('Webhook creation failed - no data returned');
        }

        log.info('Successfully created webhook', {
          webhookId: webhook.id as number,
          name: webhook.name as string,
          url: webhook.url as string,
        });

        return JSON.stringify({
          webhook,
          message: `Webhook "${name}" created successfully`,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating webhook', { name, url, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create webhook: ${errorMessage}`);
      }
    },
  });

  // Update webhook tool
  server.addTool({
    name: 'update-webhook',
    description: 'Update an existing webhook',
    parameters: UpdateWebhookSchema,
    execute: async (input, { log }) => {
      const { webhookId, name, url, method, headers, isActive } = input;

      log.info('Updating webhook', { webhookId });

      try {
        const updateData: Record<string, unknown> = {};
        if (name !== undefined) updateData.name = name;
        if (url !== undefined) updateData.url = url;
        if (method !== undefined) updateData.method = method;
        if (headers !== undefined) updateData.headers = headers;
        if (isActive !== undefined) updateData.isActive = isActive;

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        const response = await apiClient.patch(`/webhooks/${webhookId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update webhook: ${response.error?.message || 'Unknown error'}`);
        }

        const webhook = safeGetRecord(response.data);
        if (!webhook || Object.keys(webhook).length === 0) {
          throw new UserError('Webhook update failed - no data returned');
        }

        log.info('Successfully updated webhook', {
          webhookId,
          name: webhook.name as string,
          updatedFields: Object.keys(updateData),
        });

        return JSON.stringify({
          webhook,
          message: 'Webhook updated successfully',
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating webhook', { webhookId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update webhook: ${errorMessage}`);
      }
    },
  });

  // Delete webhook tool
  server.addTool({
    name: 'delete-webhook',
    description: 'Delete a webhook from Make.com',
    parameters: z.object({
      webhookId: z.number().min(1).describe('Webhook ID to delete'),
    }),
    execute: async (input, { log }) => {
      const { webhookId } = input;

      log.info('Deleting webhook', { webhookId });

      try {
        const response = await apiClient.delete(`/webhooks/${webhookId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete webhook: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted webhook', { webhookId });

        return JSON.stringify({
          message: `Webhook ${webhookId} deleted successfully`,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting webhook', { webhookId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete webhook: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Connection management tools added successfully');
}

export default addConnectionTools;