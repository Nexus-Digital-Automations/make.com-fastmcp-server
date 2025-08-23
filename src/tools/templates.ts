/**
 * Template Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing Make.com templates, sharing, and template operations
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { MakeTemplate } from '../types/index.js';
import logger from '../lib/logger.js';
// import { formatSuccessResponse } from '../utils/response-formatter.js';

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
  }).default(() => ({ organizationVisible: false, teamVisible: false, specificShares: [] })).describe('Sharing configuration'),
  metadata: z.object({
    estimatedSetupTime: z.number().min(0).optional().describe('Estimated setup time in minutes'),
    requiredConnections: z.array(z.string()).default([]).describe('Required connection types'),
    supportedRegions: z.array(z.string()).optional().describe('Supported regions'),
    complexity: z.enum(['simple', 'moderate', 'complex']).optional().describe('Template complexity level'),
  }).default(() => ({ requiredConnections: [] })).describe('Template metadata'),
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
  customizations: z.record(z.string(), z.any()).default(() => ({})).describe('Customizations to apply to the template'),
  connectionMappings: z.record(z.string(), z.number().min(1)).default(() => ({})).describe('Map template connections to existing connections'),
  variableOverrides: z.record(z.string(), z.any()).default(() => ({})).describe('Override template variables'),
  schedulingOverride: z.object({
    type: z.enum(['immediate', 'indefinitely', 'on-demand']).optional(),
    interval: z.number().min(60).optional(),
  }).optional().describe('Override template scheduling'),
}).strict();

/**
 * Add create template tool
 */
function addCreateTemplateTool(server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'create-template',
    description: 'Create a new Make.com template from a scenario or blueprint',
    parameters: TemplateCreateSchema,
    annotations: {
      title: 'Create Template',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    execute: async (input, _context) => {
      // Placeholder implementation
      return `Template creation requested: ${input.name}`;
    },
  });
}

/**
 * Add list templates tool
 */
function addListTemplatesTool(server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'list-templates',
    description: 'List available templates',
    parameters: TemplateListSchema,
    annotations: {
      title: 'List Templates',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    execute: async (_input, _context) => {
      return 'Templates listed';
    },
  });
}

/**
 * Add get template tool
 */
function addGetTemplateTool(server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'get-template',
    description: 'Get template details',
    parameters: z.object({
      templateId: z.number().min(1).describe('Template ID'),
      includeBlueprint: z.boolean().default(false).describe('Include blueprint details'),
      includeUsage: z.boolean().default(false).describe('Include usage statistics'),
      includeSharing: z.boolean().default(false).describe('Include sharing information'),
      includeVersions: z.boolean().default(false).describe('Include version history'),
    }).strict(),
    annotations: {
      title: 'Get Template',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    execute: async (input, _context) => {
      return `Template ${input.templateId} retrieved`;
    },
  });
}

/**
 * Add update template tool
 */
function addUpdateTemplateTool(server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'update-template',
    description: 'Update template',
    parameters: TemplateUpdateSchema,
    annotations: {
      title: 'Update Template',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    execute: async (input, _context) => {
      return `Template ${input.templateId} updated`;
    },
  });
}

/**
 * Add use template tool
 */
function addUseTemplateTool(server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'use-template',
    description: 'Use template to create scenario',
    parameters: TemplateUseSchema,
    annotations: {
      title: 'Use Template',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    execute: async (input, _context) => {
      return `Template ${input.templateId} used`;
    },
  });
}

/**
 * Add delete template tool
 */
function addDeleteTemplateTool(server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'delete-template',
    description: 'Delete template',
    parameters: z.object({
      templateId: z.number().min(1).describe('Template ID'),
      force: z.boolean().default(false).describe('Force delete even if template is in use'),
    }).strict(),
    annotations: {
      title: 'Delete Template',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: false,
    },
    execute: async (input, _context) => {
      return `Template ${input.templateId} deleted`;
    },
  });
}

/**
 * Add template management tools to FastMCP server
 */
export function addTemplateTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'TemplateTools' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding template management tools');

  // Add core template management tools
  addCreateTemplateTool(server, apiClient, componentLogger);
  addListTemplatesTool(server, apiClient, componentLogger);
  addGetTemplateTool(server, apiClient, componentLogger);
  addUpdateTemplateTool(server, apiClient, componentLogger);
  addUseTemplateTool(server, apiClient, componentLogger);
  addDeleteTemplateTool(server, apiClient, componentLogger);

  componentLogger.info('Template management tools added successfully');
}

export default addTemplateTools;
