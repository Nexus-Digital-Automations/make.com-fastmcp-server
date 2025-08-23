/**
 * @fileoverview Make.com Webhook Management Tools
 * 
 * Provides comprehensive webhook management operations including:
 * - Listing and filtering webhooks with advanced search capabilities
 * - Creating new webhooks with endpoint configuration and monitoring
 * - Updating existing webhook configurations and status
 * - Deleting webhooks with proper cleanup and validation
 * - Webhook status monitoring and validation
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api/webhooks} Make.com Webhooks API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { safeGetRecord, safeGetArray } from '../../utils/validation.js';
import { formatSuccessResponse } from '../../utils/response-formatter.js';

// Input validation schemas for webhooks

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
  headers: z.record(z.string(), z.string()).optional().describe('HTTP headers to include'),
  connectionId: z.number().min(1).optional().describe('Associated connection ID'),
  scenarioId: z.number().min(1).optional().describe('Associated scenario ID'),
  isActive: z.boolean().default(true).describe('Whether webhook is active'),
}).strict();

const UpdateWebhookSchema = z.object({
  webhookId: z.number().min(1).describe('Webhook ID to update'),
  name: z.string().min(1).max(100).optional().describe('New webhook name'),
  url: z.string().url().optional().describe('New webhook URL'),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).optional().describe('New HTTP method'),
  headers: z.record(z.string(), z.string()).optional().describe('Updated headers'),
  isActive: z.boolean().optional().describe('Update webhook status'),
}).strict();

/**
 * Adds webhook management tools to the FastMCP server
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting and error handling
 * @returns {void}
 * 
 * @example
 * ```typescript
 * import { addWebhookTools } from './tools/connections/webhook-manager.js';
 * 
 * const server = new FastMCP();
 * const apiClient = new MakeApiClient(config);
 * addWebhookTools(server, apiClient);
 * ```
 */
export function addWebhookTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = () => {
    try {
      return logger.child({ component: 'WebhookTools' });
    } catch (error) {
      // Fallback for test environments
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding webhook management tools');

  // List webhooks tool
  server.addTool({
    name: 'list-webhooks',  
    description: 'List and filter webhooks in Make.com',
    parameters: WebhookFiltersSchema,
    annotations: {
      title: 'List Webhooks',
      readOnlyHint: true,
      openWorldHint: true,
    },
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

        if (connectionId) {params.connectionId = connectionId;}
        if (scenarioId) {params.scenarioId = scenarioId;}
        if (status !== 'all') {params.active = status === 'active';}

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

        return formatSuccessResponse({
          webhooks,
          pagination: {
            total: metadata?.total || webhooks.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + webhooks.length),
          },
        }, "Webhooks retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing webhooks', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list webhooks: ${errorMessage}`);
      }
    },
  });

  // Create webhook tool
  server.addTool({
    name: 'create-webhook',
    description: 'Create a new webhook in Make.com',
    parameters: CreateWebhookSchema,
    annotations: {
      title: 'Create Webhook',
      idempotentHint: true,
      openWorldHint: true,
    },
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

        return formatSuccessResponse({
          webhook,
        }, `Webhook "${name}" created successfully`).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating webhook', { name, url, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create webhook: ${errorMessage}`);
      }
    },
  });

  // Update webhook tool
  server.addTool({
    name: 'update-webhook',
    description: 'Update an existing webhook',
    parameters: UpdateWebhookSchema,
    annotations: {
      title: 'Update Webhook',
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { webhookId, name, url, method, headers, isActive } = input;

      log.info('Updating webhook', { webhookId });

      try {
        const updateData: Record<string, unknown> = {};
        if (name !== undefined) {updateData.name = name;}
        if (url !== undefined) {updateData.url = url;}
        if (method !== undefined) {updateData.method = method;}
        if (headers !== undefined) {updateData.headers = headers;}
        if (isActive !== undefined) {updateData.isActive = isActive;}

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

        return formatSuccessResponse({
          webhook,
        }, "Webhook updated successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating webhook', { webhookId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
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
    annotations: {
      title: 'Delete Webhook',
      destructiveHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { webhookId } = input;

      log.info('Deleting webhook', { webhookId });

      try {
        const response = await apiClient.delete(`/webhooks/${webhookId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete webhook: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted webhook', { webhookId });

        return formatSuccessResponse(
          {},
          `Webhook ${webhookId} deleted successfully`
        ).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting webhook', { webhookId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete webhook: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Webhook management tools added successfully');
}

export default addWebhookTools;