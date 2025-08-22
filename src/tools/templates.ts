/**
 * Template Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing Make.com templates, sharing, and template operations
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { MakeTemplate } from '../types/index.js';
import logger from '../lib/logger.js';

// Extended template types for comprehensive management
export interface MakeExtendedTemplate extends MakeTemplate {
  organizationId?: number;
  teamId?: number;
  creatorId: number;
  creatorName: string;
  version: number;
  versionHistory?: Array<{
    version: number;
    createdAt: string;
    changes: string;
    createdBy: number;
  }>;
  usage: {
    totalUses: number;
    lastUsed?: string;
    activeScenarios: number;
  };
  sharing: {
    isPublic: boolean;
    organizationVisible: boolean;
    teamVisible: boolean;
    sharedWith: Array<{
      type: 'user' | 'team' | 'organization';
      id: number;
      name: string;
      permissions: string[];
    }>;
  };
  metadata: {
    complexity: 'simple' | 'moderate' | 'complex';
    estimatedSetupTime: number; // minutes
    requiredConnections: string[];
    supportedRegions?: string[];
  };
}

export interface MakeFolder {
  id: number;
  name: string;
  description?: string;
  parentId?: number;
  path: string;
  organizationId?: number;
  teamId?: number; 
  type: 'template' | 'scenario' | 'connection' | 'mixed';
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  itemCount: {
    templates: number;
    scenarios: number;
    connections: number;
    subfolders: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Input validation schemas
const TemplateCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Template name (1-100 characters)'),
  description: z.string().max(1000).optional().describe('Template description (max 1000 characters)'),
  category: z.string().max(50).optional().describe('Template category'),
  blueprint: z.any().describe('Template blueprint (scenario configuration)'),
  tags: z.array(z.string().max(30)).max(20).default([]).describe('Template tags (max 20 tags, 30 chars each)'),
  folderId: z.number().min(1).optional().describe('Folder ID to place template in'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization templates)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team templates)'),
  isPublic: z.boolean().default(false).describe('Whether template is publicly visible'),
  sharing: z.object({
    organizationVisible: z.boolean().default(true).describe('Visible to organization members'),
    teamVisible: z.boolean().default(true).describe('Visible to team members'),
    specificShares: z.array(z.object({
      type: z.enum(['user', 'team', 'organization']),
      id: z.number().min(1),
      permissions: z.array(z.enum(['view', 'use', 'edit', 'admin'])).default(['view', 'use']),
    })).default([]).describe('Specific sharing permissions'),
  }).default({}).describe('Sharing configuration'),
  metadata: z.object({
    estimatedSetupTime: z.number().min(0).optional().describe('Estimated setup time in minutes'),
    requiredConnections: z.array(z.string()).default([]).describe('Required connection types'),
    supportedRegions: z.array(z.string()).optional().describe('Supported regions'),
    complexity: z.enum(['simple', 'moderate', 'complex']).optional().describe('Template complexity level'),
  }).default({}).describe('Template metadata'),
}).strict();

const TemplateUpdateSchema = z.object({
  templateId: z.number().min(1).describe('Template ID to update'),
  name: z.string().min(1).max(100).optional().describe('New template name'),
  description: z.string().max(1000).optional().describe('New template description'),
  category: z.string().max(50).optional().describe('New template category'),
  blueprint: z.any().optional().describe('Updated blueprint'),
  tags: z.array(z.string().max(30)).max(20).optional().describe('Updated tags'),
  folderId: z.number().min(1).optional().describe('New folder ID'),
  isPublic: z.boolean().optional().describe('Update public visibility'),
  sharing: z.object({
    organizationVisible: z.boolean().optional(),
    teamVisible: z.boolean().optional(),
    specificShares: z.array(z.object({
      type: z.enum(['user', 'team', 'organization']),
      id: z.number().min(1),
      permissions: z.array(z.enum(['view', 'use', 'edit', 'admin'])),
    })).optional(),
  }).optional().describe('Updated sharing configuration'),
  metadata: z.object({
    estimatedSetupTime: z.number().min(0).optional(),
    requiredConnections: z.array(z.string()).optional(),
    supportedRegions: z.array(z.string()).optional(),
    complexity: z.enum(['simple', 'moderate', 'complex']).optional(),
  }).optional().describe('Updated metadata'),
}).strict();

const TemplateListSchema = z.object({
  category: z.string().optional().describe('Filter by category'),
  tags: z.array(z.string()).optional().describe('Filter by tags (OR operation)'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  folderId: z.number().min(1).optional().describe('Filter by folder ID'),
  creatorId: z.number().min(1).optional().describe('Filter by creator ID'),
  isPublic: z.boolean().optional().describe('Filter by public visibility'),
  complexity: z.enum(['simple', 'moderate', 'complex']).optional().describe('Filter by complexity'),
  hasConnections: z.array(z.string()).optional().describe('Filter by required connections'),
  searchQuery: z.string().max(100).optional().describe('Search in name and description'),
  minUsage: z.number().min(0).optional().describe('Minimum usage count'),
  includeUsage: z.boolean().default(false).describe('Include usage statistics'),
  includeVersions: z.boolean().default(false).describe('Include version history'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of templates to return'),
  offset: z.number().min(0).default(0).describe('Number of templates to skip for pagination'),
  sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'usage', 'complexity']).default('name').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
}).strict();

const TemplateUseSchema = z.object({
  templateId: z.number().min(1).describe('Template ID to use'),
  scenarioName: z.string().min(1).max(100).describe('Name for the new scenario'),
  folderId: z.number().min(1).optional().describe('Folder to place the new scenario'),
  customizations: z.record(z.any()).default({}).describe('Customizations to apply to the template'),
  connectionMappings: z.record(z.number().min(1)).default({}).describe('Map template connections to existing connections'),
  variableOverrides: z.record(z.any()).default({}).describe('Override template variables'),
  schedulingOverride: z.object({
    type: z.enum(['immediate', 'indefinitely', 'on-demand']).optional(),
    interval: z.number().min(60).optional(),
  }).optional().describe('Override template scheduling'),
}).strict();


/**
 * Add template management tools to FastMCP server
 */
export function addTemplateTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'TemplateTools' });
  
  componentLogger.info('Adding template management tools');

  // Create template
  server.addTool({
    name: 'create-template',
    description: 'Create a new Make.com template from a scenario or blueprint',
    parameters: TemplateCreateSchema,
    annotations: {
      title: 'Create Template',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { name, description, category, blueprint, tags, folderId, organizationId, teamId, isPublic, sharing, metadata } = input;

      log.info('Creating template', {
        name,
        category,
        isPublic,
        tagsCount: tags.length,
      });

      try {
        // Validate blueprint structure
        if (!blueprint || typeof blueprint !== 'object') {
          throw new UserError('Blueprint must be a valid scenario configuration object');
        }

        // Analyze blueprint complexity with safe property access
        const complexity = metadata?.complexity || (blueprint ? analyzeTemplateComplexity(blueprint) : 'simple');
        const estimatedSetupTime = metadata?.estimatedSetupTime || (blueprint ? estimateSetupTime(blueprint) : 5);
        const requiredConnections = (metadata?.requiredConnections && metadata.requiredConnections.length > 0) 
          ? metadata.requiredConnections 
          : (blueprint ? extractRequiredConnections(blueprint) : []);

        const templateData = {
          name,
          description,
          category,
          blueprint,
          tags,
          folderId,
          organizationId,
          teamId,
          isPublic,
          sharing: {
            ...sharing,
            organizationVisible: sharing?.organizationVisible ?? true,
            teamVisible: sharing?.teamVisible ?? true,
          },
          metadata: {
            complexity,
            estimatedSetupTime,
            requiredConnections,
            supportedRegions: metadata?.supportedRegions,
          },
          version: 1,
        };

        let endpoint = '/templates';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/templates`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/templates`;
        }

        const response = await apiClient.post(endpoint, templateData);

        if (!response.success) {
          throw new UserError(`Failed to create template: ${response.error?.message || 'Unknown error'}`);
        }

        const template = response.data as MakeExtendedTemplate;
        if (!template) {
          throw new UserError('Template creation failed - no data returned');
        }

        log.info('Successfully created template', {
          templateId: template.id,
          name: template.name,
          category: template.category,
          complexity: template.metadata?.complexity || 'simple',
        });

        return JSON.stringify({
          template,
          message: `Template "${name}" created successfully`,
          analysis: {
            complexity: template.metadata?.complexity || 'simple',
            estimatedSetupTime: `${template.metadata?.estimatedSetupTime || 5} minutes`,
            requiredConnections: template.metadata?.requiredConnections || [],
            tags: template.tags,
          },
          sharing: {
            isPublic: template.sharing?.isPublic || false,
            organizationVisible: template.sharing?.organizationVisible || false,
            teamVisible: template.sharing?.teamVisible || false,
            specificShares: template.sharing?.sharedWith?.length || 0,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating template', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create template: ${errorMessage}`);
      }
    },
  });

  // List templates
  server.addTool({
    name: 'list-templates',
    description: 'List and filter Make.com templates with comprehensive search capabilities',
    parameters: TemplateListSchema,
    annotations: {
      title: 'List Templates',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { category, tags, organizationId, teamId, folderId, creatorId, isPublic, complexity, hasConnections, searchQuery, minUsage, includeUsage, includeVersions, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing templates', {
        category,
        tagsCount: tags?.length || 0,
        searchQuery,
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
          includeVersions,
        };

        if (category) params.category = category;
        if (tags && tags.length > 0) params.tags = tags.join(',');
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (folderId) params.folderId = folderId;
        if (creatorId) params.creatorId = creatorId;
        if (isPublic !== undefined) params.isPublic = isPublic;
        if (complexity) params.complexity = complexity;
        if (hasConnections && hasConnections.length > 0) params.hasConnections = hasConnections.join(',');
        if (searchQuery) params.search = searchQuery;
        if (minUsage !== undefined) params.minUsage = minUsage;

        const response = await apiClient.get('/templates', { params });

        if (!response.success) {
          throw new UserError(`Failed to list templates: ${response.error?.message || 'Unknown error'}`);
        }

        const templates = response.data as MakeExtendedTemplate[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved templates', {
          count: templates.length,
          total: metadata?.total,
        });

        // Create summary statistics
        const summary = {
          totalTemplates: metadata?.total || templates.length,
          categoryBreakdown: templates.reduce((acc: Record<string, number>, template) => {
            const cat = template.category || 'uncategorized';
            acc[cat] = (acc[cat] || 0) + 1;
            return acc;
          }, {}),
          complexityBreakdown: {
            simple: templates.filter(t => t.metadata?.complexity === 'simple').length,
            moderate: templates.filter(t => t.metadata?.complexity === 'moderate').length,
            complex: templates.filter(t => t.metadata?.complexity === 'complex').length,
          },
          visibilityBreakdown: {
            public: templates.filter(t => t.sharing?.isPublic).length,
            organization: templates.filter(t => t.sharing?.organizationVisible && !t.sharing?.isPublic).length,
            team: templates.filter(t => t.sharing?.teamVisible && !t.sharing?.organizationVisible && !t.sharing?.isPublic).length,
            private: templates.filter(t => !t.sharing?.isPublic && !t.sharing?.organizationVisible && !t.sharing?.teamVisible).length,
          },
          mostUsedTemplates: includeUsage ? templates
            .sort((a, b) => (b.usage?.totalUses || 0) - (a.usage?.totalUses || 0))
            .slice(0, 5)
            .map(t => ({ id: t.id, name: t.name, uses: t.usage?.totalUses || 0 })) : undefined,
          popularTags: [...new Set(templates.flatMap(t => t.tags))]
            .map(tag => ({
              tag,
              count: templates.filter(t => t.tags.includes(tag)).length,
            }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10),
        };

        return JSON.stringify({
          templates,
          summary,
          pagination: {
            total: metadata?.total || templates.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + templates.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing templates', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list templates: ${errorMessage}`);
      }
    },
  });

  // Get template details
  server.addTool({
    name: 'get-template',
    description: 'Get detailed information about a specific template',
    annotations: {
      title: 'Get Template Details',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      templateId: z.number().min(1).describe('Template ID to retrieve'),
      includeBlueprint: z.boolean().default(false).describe('Include full blueprint in response'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      includeVersions: z.boolean().default(false).describe('Include version history'),
      includeSharing: z.boolean().default(true).describe('Include sharing information'),
    }),
    execute: async (input, { log }) => {
      const { templateId, includeBlueprint, includeUsage, includeVersions, includeSharing } = input;

      log.info('Getting template details', { templateId });

      try {
        const params: Record<string, unknown> = {
          includeBlueprint,
          includeUsage,
          includeVersions,
          includeSharing,
        };

        const response = await apiClient.get(`/templates/${templateId}`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get template: ${response.error?.message || 'Unknown error'}`);
        }

        const template = response.data as MakeExtendedTemplate;
        if (!template) {
          throw new UserError(`Template with ID ${templateId} not found`);
        }

        log.info('Successfully retrieved template', {
          templateId,
          name: template.name,
          category: template.category,
          version: template.version,
        });

        // Prepare response data
        const responseData: Record<string, unknown> = {
          template: {
            ...template,
            blueprint: includeBlueprint ? template.blueprint : '[Blueprint excluded - use includeBlueprint=true to view]',
          },
        };

        if (includeUsage) {
          responseData.usage = template.usage;
        }

        if (includeVersions) {
          responseData.versions = template.versionHistory;
        }

        if (includeSharing) {
          responseData.sharing = template.sharing;
        }

        responseData.metadata = {
          canEdit: true, // This would be determined by user permissions
          canDelete: template.usage?.activeScenarios === 0,
          canUse: true,
          canShare: true,
          lastModified: template.updatedAt,
          complexity: template.metadata?.complexity || 'simple',
          estimatedSetupTime: template.metadata?.estimatedSetupTime || 5,
          requiredConnections: template.metadata?.requiredConnections || [],
        };

        return JSON.stringify(responseData, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting template', { templateId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get template details: ${errorMessage}`);
      }
    },
  });

  // Update template
  server.addTool({
    name: 'update-template',
    description: 'Update an existing template',
    parameters: TemplateUpdateSchema,
    annotations: {
      title: 'Update Template',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { templateId, name, description, category, blueprint, tags, folderId, isPublic, sharing, metadata } = input;

      log.info('Updating template', { templateId, name });

      try {
        const updateData: Record<string, unknown> = {};

        if (name !== undefined) updateData.name = name;
        if (description !== undefined) updateData.description = description;
        if (category !== undefined) updateData.category = category;
        if (blueprint !== undefined) {
          updateData.blueprint = blueprint;
          // Recalculate metadata if blueprint is updated
          updateData.metadata = {
            ...metadata,
            complexity: metadata?.complexity || analyzeTemplateComplexity(blueprint),
            estimatedSetupTime: metadata?.estimatedSetupTime || estimateSetupTime(blueprint),
            requiredConnections: metadata?.requiredConnections || extractRequiredConnections(blueprint),
          };
        }
        if (tags !== undefined) updateData.tags = tags;
        if (folderId !== undefined) updateData.folderId = folderId;
        if (isPublic !== undefined) updateData.isPublic = isPublic;
        if (sharing !== undefined) updateData.sharing = sharing;
        if (metadata !== undefined && !blueprint) updateData.metadata = metadata;

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        const response = await apiClient.put(`/templates/${templateId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update template: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedTemplate = response.data as MakeExtendedTemplate;

        log.info('Successfully updated template', {
          templateId,
          name: updatedTemplate.name,
          changes: Object.keys(updateData),
          newVersion: updatedTemplate.version,
        });

        return JSON.stringify({
          template: updatedTemplate,
          message: `Template "${updatedTemplate.name}" updated successfully`,
          changes: Object.keys(updateData),
          version: {
            previous: updatedTemplate.version - 1,
            current: updatedTemplate.version,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating template', { templateId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update template: ${errorMessage}`);
      }
    },
  });

  // Use template to create scenario
  server.addTool({
    name: 'use-template',
    description: 'Create a new scenario from a template with customizations',
    parameters: TemplateUseSchema,
    annotations: {
      title: 'Use Template',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { templateId, scenarioName, folderId, customizations, connectionMappings, variableOverrides, schedulingOverride } = input;

      log.info('Using template to create scenario', {
        templateId,
        scenarioName,
        customizationsCount: Object.keys(customizations).length,
      });

      try {
        const useData = {
          scenarioName,
          folderId,
          customizations,
          connectionMappings,
          variableOverrides,
          schedulingOverride,
        };

        const response = await apiClient.post(`/templates/${templateId}/use`, useData);

        if (!response.success) {
          throw new UserError(`Failed to use template: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data as Record<string, unknown>;

        log.info('Successfully created scenario from template', {
          templateId,
          scenarioId: result?.scenarioId as number,
          scenarioName,
        });

        return JSON.stringify({
          result,
          message: `Scenario "${scenarioName}" created successfully from template`,
          scenario: {
            id: result?.scenarioId,
            name: scenarioName,
            templateId,
            templateName: result?.templateName,
          },
          customizations: {
            applied: Object.keys(customizations).length,
            connectionsMapped: Object.keys(connectionMappings).length,
            variablesOverridden: Object.keys(variableOverrides).length,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error using template', { templateId, scenarioName, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to use template: ${errorMessage}`);
      }
    },
  });

  // Delete template
  server.addTool({
    name: 'delete-template',
    description: 'Delete a template',
    annotations: {
      title: 'Delete Template',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      templateId: z.number().min(1).describe('Template ID to delete'),
      force: z.boolean().default(false).describe('Force delete even if template is in use'),
    }),
    execute: async (input, { log }) => {
      const { templateId, force } = input;

      log.info('Deleting template', { templateId, force });

      try {
        // Check if template is in use (unless force delete)
        if (!force) {
          const usageResponse = await apiClient.get(`/templates/${templateId}/usage`);
          if (usageResponse.success && Number((usageResponse.data as Record<string, unknown>)?.activeScenarios) > 0) {
            throw new UserError(`Template is currently in use (${(usageResponse.data as Record<string, unknown>).activeScenarios} active scenarios). Use force=true to delete anyway.`);
          }
        }

        const response = await apiClient.delete(`/templates/${templateId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete template: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted template', { templateId });

        return JSON.stringify({
          message: `Template ${templateId} deleted successfully`,
          templateId,
          forced: force,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting template', { templateId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete template: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Template management tools added successfully');
}

// Helper functions
function analyzeTemplateComplexity(blueprint: Record<string, unknown>): 'simple' | 'moderate' | 'complex' {
  const modules = Array.isArray(blueprint?.modules) ? blueprint.modules : [];
  const moduleCount = modules.length;
  const connectionCount = new Set(modules.map((m: Record<string, unknown>) => m.app).filter(Boolean)).size;
  const routes = Array.isArray(blueprint?.routes) ? blueprint.routes : [];
  const routeCount = routes.length;

  if (moduleCount <= 5 && connectionCount <= 2 && routeCount <= 5) {
    return 'simple';
  } else if (moduleCount <= 15 && connectionCount <= 5 && routeCount <= 15) {
    return 'moderate';
  } else {
    return 'complex';
  }
}

function estimateSetupTime(blueprint: Record<string, unknown>): number {
  const modules = Array.isArray(blueprint?.modules) ? blueprint.modules : [];
  const moduleCount = modules.length;
  const connectionCount = new Set(modules.map((m: Record<string, unknown>) => m.app).filter(Boolean)).size;
  
  // Base time + time per module + time per connection
  return Math.max(5, 10 + (moduleCount * 2) + (connectionCount * 5));
}

function extractRequiredConnections(blueprint: Record<string, unknown>): string[] {
  const modules = Array.isArray(blueprint?.modules) ? blueprint.modules : [];
  return [...new Set(modules.map((m: Record<string, unknown>) => m.app).filter(Boolean))] as string[];
}

export default addTemplateTools;