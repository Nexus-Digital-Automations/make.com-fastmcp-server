/**
 * SDK App Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing Make.com SDK apps, installation, configuration, and integration
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// SDK app management types
export interface MakeSDKApp {
  id: number;
  name: string;
  description?: string;
  version: string;
  publisher: string;
  category: 'productivity' | 'integration' | 'automation' | 'analytics' | 'communication' | 'utility' | 'custom';
  status: 'available' | 'installed' | 'updating' | 'deprecated' | 'suspended';
  organizationId?: number;
  teamId?: number;
  installation: {
    installedAt?: string;
    installedBy?: number;
    installedByName?: string;
    version: string;
    autoUpdate: boolean;
    configuration: Record<string, unknown>;
    permissions: {
      granted: string[];
      requested: string[];
      denied: string[];
    };
  };
  metadata: {
    homepage?: string;
    documentation?: string;
    support?: string;
    repository?: string;
    license: string;
    tags: string[];
    screenshots: string[];
    icon?: string;
  };
  requirements: {
    makeVersion: string;
    dependencies: Record<string, string>;
    features: string[];
    permissions: string[];
  };
  usage: {
    installations: number;
    rating: number;
    reviews: number;
    activeUsers: number;
    executions: number;
    lastUsed?: string;
  };
  integration: {
    endpoints: Array<{
      name: string;
      method: string;
      path: string;
      description?: string;
    }>;
    webhooks: Array<{
      name: string;
      events: string[];
      endpoint: string;
    }>;
    triggers: Array<{
      name: string;
      description?: string;
      type: 'webhook' | 'polling' | 'instant';
    }>;
    actions: Array<{
      name: string;
      description?: string;
      category: string;
    }>;
  };
  compatibility: {
    platforms: string[];
    regions: string[];
    languages: string[];
  };
  security: {
    verified: boolean;
    sandboxed: boolean;
    permissions: string[];
    dataAccess: 'none' | 'read' | 'write' | 'full';
    networkAccess: boolean;
  };
  createdAt: string;
  updatedAt: string;
  publishedAt: string;
}

export interface SDKAppVersion {
  version: string;
  releaseDate: string;
  releaseNotes: string;
  breaking: boolean;
  security: boolean;
  features: string[];
  bugfixes: string[];
  deprecated: string[];
  downloadUrl?: string;
  checksums: {
    md5: string;
    sha256: string;
  };
}

export interface SDKAppWorkflow {
  id: number;
  name: string;
  description?: string;
  appId: number;
  appName: string;
  version: string;
  template: Record<string, unknown>; // Workflow template JSON
  category: 'starter' | 'advanced' | 'integration' | 'example';
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert';
  tags: string[];
  usage: {
    installs: number;
    rating: number;
    reviews: number;
  };
  requirements: {
    apps: Array<{
      name: string;
      version?: string;
      required: boolean;
    }>;
    features: string[];
    permissions: string[];
  };
  documentation: {
    setup: string;
    usage: string;
    troubleshooting?: string;
    examples?: string;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Input validation schemas
const SDKAppInstallSchema = z.object({
  appId: z.number().min(1).describe('SDK app ID to install'),
  version: z.string().optional().describe('Specific version to install (defaults to latest)'),
  organizationId: z.number().min(1).optional().describe('Organization ID to install for'),
  teamId: z.number().min(1).optional().describe('Team ID to install for'),
  configuration: z.record(z.string(), z.any()).default({}).describe('App configuration settings'),
  permissions: z.object({
    autoGrant: z.boolean().default(false).describe('Automatically grant requested permissions'),
    restrictions: z.record(z.string(), z.any()).default({}).describe('Permission restrictions'),
  }).default(() => ({
    autoGrant: false,
    restrictions: {},
  })).describe('Permission settings'),
  autoUpdate: z.boolean().default(true).describe('Enable automatic updates'),
  skipValidation: z.boolean().default(false).describe('Skip compatibility validation'),
}).strict();

const SDKAppUpdateSchema = z.object({
  appId: z.number().min(1).describe('SDK app ID to update'),
  version: z.string().optional().describe('Target version (defaults to latest)'),
  force: z.boolean().default(false).describe('Force update even if breaking changes'),
  backup: z.boolean().default(true).describe('Create backup before update'),
  rollbackOnFailure: z.boolean().default(true).describe('Rollback on update failure'),
}).strict();

const SDKAppConfigureSchema = z.object({
  appId: z.number().min(1).describe('SDK app ID to configure'),
  configuration: z.record(z.string(), z.any()).describe('New configuration settings'),
  permissions: z.object({
    grant: z.array(z.string()).default([]).describe('Permissions to grant'),
    revoke: z.array(z.string()).default([]).describe('Permissions to revoke'),
  }).optional().describe('Permission changes'),
  integrations: z.object({
    enable: z.array(z.string()).default([]).describe('Integrations to enable'),
    disable: z.array(z.string()).default([]).describe('Integrations to disable'),
    configure: z.record(z.string(), z.any()).default({}).describe('Integration configurations'),
  }).optional().describe('Integration settings'),
}).strict();

const WorkflowInstallSchema = z.object({
  workflowId: z.number().min(1).describe('Workflow ID to install'),
  name: z.string().min(1).max(100).describe('Name for the installed workflow'),
  teamId: z.number().min(1).optional().describe('Team ID to install workflow in'),
  folderId: z.number().min(1).optional().describe('Folder ID to organize workflow'),
  configuration: z.record(z.string(), z.any()).default({}).describe('Workflow configuration overrides'),
  autoStart: z.boolean().default(false).describe('Automatically start workflow after installation'),
  installDependencies: z.boolean().default(true).describe('Install required app dependencies'),
}).strict();

/**
 * Build search parameters for SDK apps marketplace
 */
function buildSdkAppSearchParams(input: any): Record<string, unknown> {
  const { query, category, publisher, verified, rating, features, compatibility, sortBy, sortOrder, limit, offset } = input;
  
  const params: Record<string, unknown> = {
    limit,
    offset,
    sortBy,
    sortOrder,
  };

  if (query) {params.q = query;}
  if (category !== 'all') {params.category = category;}
  if (publisher) {params.publisher = publisher;}
  if (verified !== undefined) {params.verified = verified;}
  if (rating) {params.minRating = rating;}
  if (features.length > 0) {params.features = features.join(',');}
  if (compatibility?.platform) {params.platform = compatibility.platform;}
  if (compatibility?.region) {params.region = compatibility.region;}
  if (compatibility?.language) {params.language = compatibility.language;}

  return params;
}

/**
 * Generate marketplace analysis from apps
 */
function generateMarketplaceAnalysis(apps: any[], metadata: any): any {
  return {
    totalApps: metadata?.total || apps.length,
    categoryBreakdown: apps.reduce((acc: Record<string, number>, app) => {
      acc[app.category] = (acc[app.category] || 0) + 1;
      return acc;
    }, {}),
    publisherBreakdown: apps.reduce((acc: Record<string, number>, app) => {
      acc[app.publisher] = (acc[app.publisher] || 0) + 1;
      return acc;
    }, {}),
    verificationStatus: {
      verified: apps.filter(a => a.security.verified).length,
      unverified: apps.filter(a => !a.security.verified).length,
    },
    ratingDistribution: {
      excellent: apps.filter(a => a.usage.rating >= 4.5).length,
      good: apps.filter(a => a.usage.rating >= 3.5 && a.usage.rating < 4.5).length,
      average: apps.filter(a => a.usage.rating >= 2.5 && a.usage.rating < 3.5).length,
      poor: apps.filter(a => a.usage.rating < 2.5).length,
    },
    popularApps: apps
      .sort((a, b) => b.usage.installations - a.usage.installations)
      .slice(0, 5)
      .map(a => ({
        id: a.id,
        name: a.name,
        publisher: a.publisher,
        installations: a.usage.installations,
        rating: a.usage.rating,
        category: a.category,
      })),
  };
}

/**
 * Transform app data for response
 */
function transformAppForResponse(app: any): any {
  return {
    id: app.id,
    name: app.name,
    description: app.description,
    version: app.version,
    publisher: app.publisher,
    category: app.category,
    status: app.status,
    usage: app.usage,
    metadata: {
      ...app.metadata,
      screenshots: app.metadata.screenshots.slice(0, 3), // Limited screenshots
    },
    security: app.security,
    compatibility: app.compatibility,
    integration: {
      ...app.integration,
      endpoints: app.integration.endpoints.length,
      webhooks: app.integration.webhooks.length,
      triggers: app.integration.triggers.length,
      actions: app.integration.actions.length,
    },
  };
}

/**
 * Helper function to add search SDK apps tool
 */
function addSearchSdkAppsTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'search-sdk-apps',
    description: 'Search and browse available SDK apps in the Make.com marketplace',
    parameters: z.object({
      query: z.string().optional().describe('Search query for app name, description, or tags'),
      category: z.enum(['productivity', 'integration', 'automation', 'analytics', 'communication', 'utility', 'custom', 'all']).default('all').describe('Filter by app category'),
      publisher: z.string().optional().describe('Filter by publisher name'),
      verified: z.boolean().optional().describe('Filter by verified apps only'),
      rating: z.number().min(1).max(5).optional().describe('Minimum rating filter'),
      features: z.array(z.string()).default([]).describe('Required features'),
      compatibility: z.object({
        platform: z.string().optional().describe('Platform compatibility'),
        region: z.string().optional().describe('Region availability'),
        language: z.string().optional().describe('Language support'),
      }).optional().describe('Compatibility requirements'),
      sortBy: z.enum(['name', 'rating', 'installs', 'updated', 'created']).default('rating').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
      limit: z.number().min(1).max(100).default(20).describe('Maximum results to return'),
      offset: z.number().min(0).default(0).describe('Results offset for pagination'),
    }),
    annotations: {
      title: 'Search SDK Apps in Marketplace',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { query, category, publisher, verified, rating, features, compatibility, sortBy, sortOrder, limit, offset } = input;

      log.info('Searching SDK apps', {
        query,
        category,
        publisher,
        verified,
        limit,
        offset,
      });

      try {
        const params = buildSdkAppSearchParams(input);

        const response = await apiClient.get('/sdk-apps/marketplace', { params });

        if (!response.success) {
          throw new UserError(`Failed to search SDK apps: ${response.error?.message || 'Unknown error'}`);
        }

        const apps = response.data as MakeSDKApp[] || [];
        const metadata = response.metadata;

        log.info('Successfully searched SDK apps', {
          query,
          count: apps.length,
          total: metadata?.total,
        });

        // Create marketplace analysis
        const analysis = generateMarketplaceAnalysis(apps, metadata);

        return formatSuccessResponse({
          apps: apps.map(transformAppForResponse),
          analysis,
          pagination: {
            total: metadata?.total || apps.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + apps.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error searching SDK apps', { query, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to search SDK apps: ${errorMessage}`);
      }
    },
  });
}

/**
 * Validate SDK app compatibility
 */
async function validateSdkAppCompatibility(apiClient: MakeApiClient, appId: string, log: any): Promise<void> {
  log.info('Validating app compatibility');
  const compatResponse = await apiClient.get(`/sdk-apps/${appId}/compatibility`);
  
  if (!compatResponse.success) {
    throw new UserError(`Compatibility check failed: ${compatResponse.error?.message}`);
  }

  const compatibility = compatResponse.data as Record<string, unknown>;
  if (!compatibility.compatible) {
    throw new UserError(`App is not compatible: ${(compatibility.reasons as string[]).join(', ')}`);
  }
}

/**
 * Build SDK app install data payload
 */
function buildSdkAppInstallData(input: any): any {
  const { appId, version, organizationId, teamId, configuration, permissions, autoUpdate, skipValidation } = input;
  
  return {
    appId,
    version: version || 'latest',
    organizationId,
    teamId,
    configuration,
    permissions: {
      ...permissions,
      autoGrant: permissions?.autoGrant ?? false,
      restrictions: permissions?.restrictions ?? {},
    },
    autoUpdate,
    installOptions: {
      skipValidation,
      createBackup: true,
      notifyUsers: true,
    },
  };
}

/**
 * Determine SDK app install endpoint
 */
function determineSdkAppEndpoint(organizationId?: string, teamId?: string): string {
  if (organizationId) {
    return `/organizations/${organizationId}/sdk-apps/install`;
  } else if (teamId) {
    return `/teams/${teamId}/sdk-apps/install`;
  }
  return '/sdk-apps/install';
}

/**
 * Format SDK app install response
 */
function formatSdkAppInstallResponse(installation: any, input: any): any {
  const { appId, autoUpdate, configuration } = input;
  
  // Type guards for installation data
  const installationId = typeof installation.id === 'string' || typeof installation.id === 'number' ? installation.id : 'unknown';
  const appName = typeof installation.appName === 'string' ? installation.appName : 'unknown';
  const installedAt = typeof installation.installedAt === 'string' ? installation.installedAt : new Date().toISOString();
  const installedVersion = typeof installation.version === 'string' ? installation.version : 'unknown';
  const installationPermissions = installation.permissions && typeof installation.permissions === 'object' ? installation.permissions as Record<string, unknown> : {};
  const granted = Array.isArray(installationPermissions.granted) ? installationPermissions.granted : [];

  return formatSuccessResponse({
    installation,
    message: `SDK app ${appId} installed successfully`,
    summary: {
      appId,
      appName: appName,
      version: installedVersion,
      installedAt: installedAt,
      autoUpdate,
      permissionsGranted: granted.length,
      configurationApplied: Object.keys(configuration).length > 0,
    },
    postInstall: {
      configurationUrl: `/sdk-apps/${appId}/configure`,
      documentationUrl: ((installation?.app as Record<string, unknown>)?.metadata as Record<string, unknown>)?.documentation,
      supportUrl: ((installation?.app as Record<string, unknown>)?.metadata as Record<string, unknown>)?.support,
    },
    nextSteps: [
      'Review and configure app settings',
      'Test app functionality',
      'Set up integrations if needed',
      'Train team members on app usage',
    ],
  });
}

/**
 * Helper function to add install SDK app tool
 */
function addInstallSdkAppTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'install-sdk-app',
    description: 'Install an SDK app with configuration and permission management',
    parameters: SDKAppInstallSchema,
    annotations: {
      title: 'Install SDK Application',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { appId, version, organizationId, teamId, configuration, permissions, autoUpdate, skipValidation } = input;

      log.info('Installing SDK app', {
        appId,
        version,
        organizationId,
        teamId,
        autoUpdate,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate compatibility unless skipped
        if (!skipValidation) {
          await validateSdkAppCompatibility(apiClient, appId, log);
        }

        reportProgress({ progress: 25, total: 100 });

        const installData = buildSdkAppInstallData(input);

        reportProgress({ progress: 50, total: 100 });

        const endpoint = determineSdkAppEndpoint(organizationId, teamId);

        const response = await apiClient.post(endpoint, installData);

        if (!response.success) {
          throw new UserError(`Failed to install SDK app: ${response.error?.message || 'Unknown error'}`);
        }

        const installation = response.data as Record<string, unknown>;
        
        reportProgress({ progress: 100, total: 100 });

        // Log successful installation
        const installationId = typeof installation.id === 'string' || typeof installation.id === 'number' ? installation.id : 'unknown';
        log.info('Successfully installed SDK app', {
          appId,
          installationId: installationId,
          version: typeof installation.version === 'string' ? installation.version : 'unknown',
        });

        return formatSdkAppInstallResponse(installation, input);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error installing SDK app', { appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to install SDK app: ${errorMessage}`);
      }
    },
  });
}

/**
 * Helper function to add list installed apps tool
 */
function addListInstalledAppsTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'list-installed-apps',
    description: 'List installed SDK apps with status, usage, and configuration details',
    parameters: z.object({
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      status: z.enum(['installed', 'updating', 'error', 'disabled', 'all']).default('all').describe('Filter by installation status'),
      category: z.enum(['productivity', 'integration', 'automation', 'analytics', 'communication', 'utility', 'custom', 'all']).default('all').describe('Filter by app category'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      includeConfiguration: z.boolean().default(false).describe('Include configuration details'),
      sortBy: z.enum(['name', 'installedAt', 'lastUsed', 'usage']).default('name').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum apps to return'),
      offset: z.number().min(0).default(0).describe('Apps to skip for pagination'),
    }),
    annotations: {
      title: 'List Installed SDK Apps',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { organizationId, teamId, status, category, includeUsage, includeConfiguration, sortBy, sortOrder, limit, offset } = input;

      log.info('Listing installed SDK apps', {
        organizationId,
        teamId,
        status,
        category,
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
          includeConfiguration,
        };

        if (organizationId) {params.organizationId = organizationId;}
        if (teamId) {params.teamId = teamId;}
        if (status !== 'all') {params.status = status;}
        if (category !== 'all') {params.category = category;}

        const response = await apiClient.get('/sdk-apps/installed', { params });

        if (!response.success) {
          throw new UserError(`Failed to list installed apps: ${response.error?.message || 'Unknown error'}`);
        }

        const apps = response.data as MakeSDKApp[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved installed apps', {
          count: apps.length,
          total: metadata?.total,
        });

        // Create installation analysis
        const analysis = {
          totalInstalled: metadata?.total || apps.length,
          statusBreakdown: apps.reduce((acc: Record<string, number>, app) => {
            acc[app.status] = (acc[app.status] || 0) + 1;
            return acc;
          }, {}),
          categoryBreakdown: apps.reduce((acc: Record<string, number>, app) => {
            acc[app.category] = (acc[app.category] || 0) + 1;
            return acc;
          }, {}),
          updateStatus: {
            autoUpdateEnabled: apps.filter(a => a.installation.autoUpdate).length,
            updatesAvailable: apps.filter(a => a.status === 'updating').length,
            outdatedApps: apps.filter(a => a.installation.version !== a.version).length,
          },
          usageSummary: includeUsage ? {
            totalExecutions: apps.reduce((sum, a) => sum + (a.usage.executions || 0), 0),
            activeApps: apps.filter(a => a.usage.lastUsed && 
              new Date(a.usage.lastUsed) > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)).length,
            mostUsedApps: apps
              .sort((a, b) => (b.usage.executions || 0) - (a.usage.executions || 0))
              .slice(0, 5)
              .map(a => ({
                id: a.id,
                name: a.name,
                executions: a.usage.executions,
                lastUsed: a.usage.lastUsed,
              })),
          } : undefined,
        };

        return formatSuccessResponse({
          apps: apps.map(app => ({
            ...app,
            installation: {
              ...app.installation,
              configuration: includeConfiguration ? app.installation.configuration : '[CONFIG_HIDDEN]',
            },
          })),
          analysis,
          pagination: {
            total: metadata?.total || apps.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + apps.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing installed apps', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list installed apps: ${errorMessage}`);
      }
    },
  });
}

/**
 * Extract current installation version with type safety
 */
function extractCurrentVersion(currentInstallation: unknown): string {
  const installationData = currentInstallation && typeof currentInstallation === 'object' ? currentInstallation as Record<string, unknown> : {};
  return typeof installationData.version === 'string' ? installationData.version : 'unknown';
}

/**
 * Build SDK app update data payload
 */
function buildSdkAppUpdateData(input: any, currentVersion: string): any {
  const { appId, version, force, backup, rollbackOnFailure } = input;
  
  return {
    appId,
    targetVersion: version || 'latest',
    options: {
      force,
      backup,
      rollbackOnFailure,
      preserveConfiguration: true,
      notifyUsers: true,
    },
    currentVersion: currentVersion,
  };
}

/**
 * Extract update result data with type safety
 */
function extractUpdateResultData(updateResult: unknown): {
  toVersion: string;
  success: boolean;
  appName: string;
  updatedAt: string;
  breaking: boolean;
  backupId: string | undefined;
} {
  const updateResultData = updateResult && typeof updateResult === 'object' ? updateResult as Record<string, unknown> : {};
  
  return {
    toVersion: typeof updateResultData.version === 'string' ? updateResultData.version : 'unknown',
    success: typeof updateResultData.success === 'boolean' ? updateResultData.success : true,
    appName: typeof updateResultData.appName === 'string' ? updateResultData.appName : 'unknown',
    updatedAt: typeof updateResultData.updatedAt === 'string' ? updateResultData.updatedAt : new Date().toISOString(),
    breaking: typeof updateResultData.breaking === 'boolean' ? updateResultData.breaking : false,
    backupId: typeof updateResultData.backupId === 'string' ? updateResultData.backupId : undefined,
  };
}

/**
 * Extract changelog data with type safety
 */
function extractChangelogData(updateResultData: Record<string, unknown>): {
  features: unknown[];
  bugfixes: unknown[];
  breaking: unknown[];
  deprecated: unknown[];
} {
  const changelog = updateResultData.changelog && typeof updateResultData.changelog === 'object' ? updateResultData.changelog as Record<string, unknown> : {};
  
  return {
    features: Array.isArray(changelog.features) ? changelog.features : [],
    bugfixes: Array.isArray(changelog.bugfixes) ? changelog.bugfixes : [],
    breaking: Array.isArray(changelog.breaking) ? changelog.breaking : [],
    deprecated: Array.isArray(changelog.deprecated) ? changelog.deprecated : [],
  };
}

/**
 * Format SDK app update response
 */
function formatSdkAppUpdateResponse(updateResult: unknown, input: any, currentVersion: string): any {
  const { appId, backup } = input;
  const { toVersion, success, appName, updatedAt, breaking, backupId } = extractUpdateResultData(updateResult);
  const updateResultData = updateResult && typeof updateResult === 'object' ? updateResult as Record<string, unknown> : {};
  const changelog = extractChangelogData(updateResultData);

  return formatSuccessResponse({
    update: updateResult,
    message: `SDK app ${appId} updated successfully`,
    summary: {
      appId,
      appName: appName,
      fromVersion: currentVersion,
      toVersion: toVersion,
      updatedAt: updatedAt,
      breaking: breaking,
      backupCreated: backup && backupId,
    },
    changes: changelog,
    postUpdate: {
      configurationMigrated: typeof updateResultData.configurationMigrated === 'boolean' ? updateResultData.configurationMigrated : false,
      permissionsChanged: typeof updateResultData.permissionsChanged === 'boolean' ? updateResultData.permissionsChanged : false,
      testingRequired: typeof updateResultData.requiresTesting === 'boolean' ? updateResultData.requiresTesting : false,
      rollbackAvailable: typeof updateResultData.rollbackAvailable === 'boolean' ? updateResultData.rollbackAvailable : false,
    },
  });
}

/**
 * Helper function to add update SDK app tool
 */
function addUpdateSdkAppTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'update-sdk-app',
    description: 'Update an installed SDK app to a newer version with rollback support',
    parameters: SDKAppUpdateSchema,
    annotations: {
      title: 'Update SDK Application',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { appId, version, force, backup, rollbackOnFailure } = input;

      log.info('Updating SDK app', {
        appId,
        version,
        force,
        backup,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Get current installation details
        const currentResponse = await apiClient.get(`/sdk-apps/${appId}/installation`);
        if (!currentResponse.success) {
          throw new UserError(`Failed to get current installation: ${currentResponse.error?.message}`);
        }

        const currentInstallation = currentResponse.data;
        
        // Extract current version with type safety
        const currentVersion = extractCurrentVersion(currentInstallation);
        
        reportProgress({ progress: 20, total: 100 });

        const updateData = buildSdkAppUpdateData(input, currentVersion);

        reportProgress({ progress: 40, total: 100 });

        const response = await apiClient.post(`/sdk-apps/${appId}/update`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update SDK app: ${response.error?.message || 'Unknown error'}`);
        }

        const updateResult = response.data;
        
        reportProgress({ progress: 100, total: 100 });

        // Log successful update
        const { toVersion, success } = extractUpdateResultData(updateResult);
        log.info('Successfully updated SDK app', {
          appId,
          fromVersion: currentVersion,
          toVersion: toVersion,
          success: success,
        });

        return formatSdkAppUpdateResponse(updateResult, input, currentVersion);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating SDK app', { appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update SDK app: ${errorMessage}`);
      }
    },
  });
}

/**
 * Build SDK app configuration data payload
 */
function buildSdkAppConfigData(input: any): any {
  const { appId, configuration, permissions, integrations } = input;
  
  return {
    appId,
    configuration,
    permissions,
    integrations,
    validateConfiguration: true,
    applyImmediately: true,
  };
}

/**
 * Extract configuration result data with type safety
 */
function extractConfigResultData(configResult: unknown): {
  configurationApplied: boolean;
  permissionsChanged: boolean;
  integrationsUpdated: boolean;
  appName: string;
  validationErrors: unknown[];
  validationWarnings: unknown[];
  validationValid: boolean;
} {
  const configResultData = configResult && typeof configResult === 'object' ? configResult as Record<string, unknown> : {};
  const validation = configResultData.validation && typeof configResultData.validation === 'object' ? configResultData.validation as Record<string, unknown> : {};
  
  return {
    configurationApplied: typeof configResultData.configurationApplied === 'boolean' ? configResultData.configurationApplied : false,
    permissionsChanged: typeof configResultData.permissionsChanged === 'boolean' ? configResultData.permissionsChanged : false,
    integrationsUpdated: typeof configResultData.integrationsUpdated === 'boolean' ? configResultData.integrationsUpdated : false,
    appName: typeof configResultData.appName === 'string' ? configResultData.appName : 'unknown',
    validationErrors: Array.isArray(validation.errors) ? validation.errors : [],
    validationWarnings: Array.isArray(validation.warnings) ? validation.warnings : [],
    validationValid: typeof validation.valid === 'boolean' ? validation.valid : false,
  };
}

/**
 * Format SDK app configuration response
 */
function formatSdkAppConfigResponse(configResult: unknown, input: any): any {
  const { appId, configuration, permissions, integrations } = input;
  const {
    configurationApplied,
    permissionsChanged,
    integrationsUpdated,
    appName,
    validationErrors,
    validationWarnings,
    validationValid,
  } = extractConfigResultData(configResult);

  return formatSuccessResponse({
    configuration: configResult,
    message: `SDK app ${appId} configured successfully`,
    summary: {
      appId,
      appName: appName,
      configurationKeys: Object.keys(configuration).length,
      permissionsGranted: Array.isArray(permissions?.grant) ? permissions.grant.length : 0,
      permissionsRevoked: Array.isArray(permissions?.revoke) ? permissions.revoke.length : 0,
      integrationsEnabled: Array.isArray(integrations?.enable) ? integrations.enable.length : 0,
      integrationsDisabled: Array.isArray(integrations?.disable) ? integrations.disable.length : 0,
    },
    applied: {
      configuration: configurationApplied,
      permissions: permissionsChanged,
      integrations: integrationsUpdated,
    },
    validation: {
      errors: validationErrors,
      warnings: validationWarnings,
      valid: validationValid,
    },
  });
}

/**
 * Helper function to add configure SDK app tool
 */
function addConfigureSdkAppTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'configure-sdk-app',
    description: 'Configure an installed SDK app settings, permissions, and integrations',
    parameters: SDKAppConfigureSchema,
    annotations: {
      title: 'Configure SDK Application',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { appId, configuration, permissions, integrations } = input;

      log.info('Configuring SDK app', {
        appId,
        configKeys: Object.keys(configuration).length,
        hasPermissions: !!permissions,
        hasIntegrations: !!integrations,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const configData = buildSdkAppConfigData(input);

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.put(`/sdk-apps/${appId}/configure`, configData);

        if (!response.success) {
          throw new UserError(`Failed to configure SDK app: ${response.error?.message || 'Unknown error'}`);
        }

        const configResult = response.data;
        
        reportProgress({ progress: 100, total: 100 });

        // Log successful configuration
        const { configurationApplied, permissionsChanged, integrationsUpdated } = extractConfigResultData(configResult);
        log.info('Successfully configured SDK app', {
          appId,
          configurationApplied: configurationApplied,
          permissionsChanged: permissionsChanged,
          integrationsUpdated: integrationsUpdated,
        });

        return formatSdkAppConfigResponse(configResult, input);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error configuring SDK app', { appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to configure SDK app: ${errorMessage}`);
      }
    },
  });
}

/**
 * Validate and prepare workflow template data
 */
function prepareWorkflowTemplate(workflowTemplate: unknown): {
  defaultConfiguration: Record<string, unknown>;
  requirements: unknown[];
} {
  const templateObj = workflowTemplate as {
    defaultConfiguration?: unknown;
    requirements?: { apps?: unknown[] };
  } | null | undefined;

  return {
    defaultConfiguration: templateObj?.defaultConfiguration && typeof templateObj.defaultConfiguration === 'object' 
      ? templateObj.defaultConfiguration as Record<string, unknown> 
      : {},
    requirements: Array.isArray(templateObj?.requirements?.apps) ? templateObj.requirements.apps : [],
  };
}

/**
 * Build install workflow data payload
 */
function buildInstallWorkflowData(input: any, workflowTemplate: unknown): any {
  const { workflowId, name, teamId, folderId, configuration, autoStart, installDependencies } = input;
  const { defaultConfiguration, requirements } = prepareWorkflowTemplate(workflowTemplate);

  return {
    workflowId,
    name,
    teamId,
    folderId,
    configuration: {
      ...defaultConfiguration,
      ...configuration,
    },
    options: {
      autoStart,
      installDependencies,
      validateTemplate: true,
      createBackup: true,
    },
    dependencies: requirements,
  };
}

/**
 * Format install workflow response
 */
function formatInstallWorkflowResponse(installation: unknown, workflowTemplate: unknown, input: any): any {
  const { workflowId, name, autoStart } = input;
  
  // Type guard for installation object
  const installationObj = installation as {
    scenarioId?: unknown;
    dependenciesInstalled?: unknown;
    started?: unknown;
    installedDependencies?: unknown[];
    missingDependencies?: unknown[];
  } | null | undefined;

  // Type guard for template object with additional fields
  const templateObjFull = workflowTemplate as {
    name?: unknown;
    category?: unknown;
    difficulty?: unknown;
    requirements?: { apps?: unknown[] };
  } | null | undefined;

  return formatSuccessResponse({
    workflow: installation,
    message: `Workflow "${name}" installed successfully`,
    summary: {
      workflowId,
      scenarioId: installationObj?.scenarioId,
      name,
      templateName: templateObjFull?.name,
      category: templateObjFull?.category,
      difficulty: templateObjFull?.difficulty,
      dependenciesInstalled: installationObj?.dependenciesInstalled || 0,
      autoStarted: autoStart && installationObj?.started,
    },
    dependencies: {
      required: Array.isArray(templateObjFull?.requirements?.apps) ? templateObjFull.requirements.apps : [],
      installed: Array.isArray(installationObj?.installedDependencies) ? installationObj.installedDependencies : [],
      missing: Array.isArray(installationObj?.missingDependencies) ? installationObj.missingDependencies : [],
    },
    access: {
      scenarioUrl: `/scenarios/${installationObj?.scenarioId}`,
      editUrl: `/scenarios/${installationObj?.scenarioId}/edit`,
      runUrl: `/scenarios/${installationObj?.scenarioId}/run`,
    },
    nextSteps: [
      'Review workflow configuration',
      'Test workflow execution',
      'Customize workflow if needed',
      autoStart ? 'Monitor workflow execution' : 'Activate workflow when ready',
    ],
  });
}

/**
 * Helper function to add install workflow tool
 */
function addInstallWorkflowTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'install-workflow',
    description: 'Install a pre-built workflow template from an SDK app',
    parameters: WorkflowInstallSchema,
    annotations: {
      title: 'Install Workflow Template',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { workflowId, name, teamId, folderId, configuration, autoStart, installDependencies } = input;

      log.info('Installing workflow template', {
        workflowId,
        name,
        teamId,
        folderId,
        autoStart,
        installDependencies,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Check workflow template details
        const workflowResponse = await apiClient.get(`/workflows/templates/${workflowId}`);
        if (!workflowResponse.success) {
          throw new UserError(`Failed to get workflow template: ${workflowResponse.error?.message}`);
        }

        const workflowTemplate = workflowResponse.data;
        reportProgress({ progress: 25, total: 100 });

        const installData = buildInstallWorkflowData(input, workflowTemplate);

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post('/workflows/install', installData);

        if (!response.success) {
          throw new UserError(`Failed to install workflow: ${response.error?.message || 'Unknown error'}`);
        }

        const installation = response.data;
        reportProgress({ progress: 100, total: 100 });

        // Log success for the installation
        const installationObj = installation as { scenarioId?: unknown } | null | undefined;
        log.info('Successfully installed workflow', {
          workflowId,
          scenarioId: String(installationObj?.scenarioId ?? 'unknown'),
          name,
          autoStart,
        });

        return formatInstallWorkflowResponse(installation, workflowTemplate, input);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error installing workflow', { workflowId, name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to install workflow: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add SDK app management tools to FastMCP server
 */
export function addSDKTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'SDKTools' });
  
  componentLogger.info('Adding SDK app management tools');

  // Add all SDK tool functions
  addSearchSdkAppsTool(server, apiClient);
  addInstallSdkAppTool(server, apiClient);
  addListInstalledAppsTool(server, apiClient);
  addUpdateSdkAppTool(server, apiClient);
  addConfigureSdkAppTool(server, apiClient);
  addInstallWorkflowTool(server, apiClient);

  componentLogger.info('SDK app management tools added successfully');
}

export default addSDKTools;