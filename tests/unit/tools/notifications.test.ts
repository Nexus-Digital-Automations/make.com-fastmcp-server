/**
 * Unit tests for notification management tools
 * Tests notification creation, email preferences, template management, data structures, and multi-channel delivery
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
import type { 
  MakeNotification, 
  MakeEmailPreferences, 
  MakeNotificationTemplate, 
  MakeCustomDataStructure 
} from '../../../src/tools/notifications.js';

describe('Notification Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: jest.MockedFunction<any>;
  let mockReportProgress: jest.MockedFunction<any>;

  const testNotification: MakeNotification = {
    id: 1,
    type: 'system',
    category: 'info',
    priority: 'medium',
    title: 'Test Notification',
    message: 'This is a test notification message',
    data: { source: 'test' },
    recipients: {
      users: [1, 2, 3],
      teams: [1],
      organizations: [1],
      emails: ['test@example.com']
    },
    channels: {
      email: true,
      inApp: true,
      sms: false,
      webhook: false,
      slack: false,
      teams: false
    },
    status: 'sent',
    delivery: {
      sentAt: '2024-01-01T12:00:00Z',
      deliveredAt: '2024-01-01T12:01:00Z',
      totalRecipients: 5,
      successfulDeliveries: 4,
      failedDeliveries: 1,
      errors: [{
        recipient: 'test2@example.com',
        channel: 'email',
        error: 'Mailbox full',
        timestamp: '2024-01-01T12:00:30Z'
      }]
    },
    schedule: {
      sendAt: '2024-01-01T12:00:00Z',
      timezone: 'UTC'
    },
    template: {
      id: 1,
      name: 'System Alert Template',
      variables: { severity: 'low' }
    },
    tracking: {
      opens: 3,
      clicks: 1,
      unsubscribes: 0,
      complaints: 0
    },
    createdAt: '2024-01-01T11:00:00Z',
    updatedAt: '2024-01-01T12:00:00Z',
    createdBy: 1,
    createdByName: 'Test User'
  };

  const testEmailPreferences: MakeEmailPreferences = {
    userId: 1,
    organizationId: 123,
    preferences: {
      system: {
        enabled: true,
        frequency: 'daily',
        categories: {
          updates: true,
          maintenance: true,
          security: true,
          announcements: false
        }
      },
      billing: {
        enabled: true,
        categories: {
          invoices: true,
          paymentReminders: true,
          usageAlerts: true,
          planChanges: true
        }
      },
      scenarios: {
        enabled: true,
        frequency: 'immediate',
        categories: {
          failures: true,
          completions: false,
          warnings: true,
          scheduleChanges: false
        },
        filters: {
          onlyMyScenarios: true,
          onlyImportantScenarios: false,
          scenarioIds: [1, 2, 3],
          teamIds: [1]
        }
      },
      team: {
        enabled: true,
        categories: {
          invitations: true,
          roleChanges: true,
          memberChanges: false,
          teamUpdates: true
        }
      },
      marketing: {
        enabled: false,
        categories: {
          productUpdates: false,
          newsletters: false,
          webinars: false,
          surveys: false
        }
      },
      customChannels: [{
        name: 'Slack Alerts',
        type: 'slack',
        enabled: true,
        configuration: { webhook: 'https://hooks.slack.com/test' },
        filters: { priority: 'high' }
      }]
    },
    timezone: 'America/New_York',
    language: 'en',
    unsubscribeAll: false,
    lastUpdated: '2024-01-01T10:00:00Z'
  };

  const testNotificationTemplate: MakeNotificationTemplate = {
    id: 1,
    name: 'System Alert Template',
    description: 'Template for system notifications',
    type: 'email',
    category: 'system',
    organizationId: 123,
    isGlobal: false,
    template: {
      subject: 'System Alert: {{title}}',
      body: '<h1>{{title}}</h1><p>{{message}}</p>',
      format: 'html',
      variables: [
        {
          name: 'title',
          type: 'string',
          required: true,
          description: 'Alert title'
        },
        {
          name: 'message',
          type: 'string',
          required: true,
          description: 'Alert message'
        },
        {
          name: 'severity',
          type: 'string',
          required: false,
          defaultValue: 'medium',
          description: 'Alert severity level'
        }
      ]
    },
    design: {
      theme: 'default',
      colors: { primary: '#007bff', secondary: '#6c757d' },
      fonts: { body: 'Arial, sans-serif' },
      layout: 'standard'
    },
    testing: {
      lastTested: '2024-01-01T09:00:00Z',
      testResults: {
        renderingTime: 150,
        size: 2048,
        errors: [],
        warnings: ['Consider adding alt text to images']
      }
    },
    usage: {
      totalSent: 50,
      lastUsed: '2024-01-01T11:30:00Z',
      averageDeliveryTime: 2.5,
      deliveryRate: 98.5
    },
    createdAt: '2023-12-01T10:00:00Z',
    updatedAt: '2024-01-01T09:00:00Z',
    createdBy: 1
  };

  const testDataStructure: MakeCustomDataStructure = {
    id: 1,
    name: 'User Profile Schema',
    description: 'Schema for user profile validation',
    type: 'schema',
    organizationId: 123,
    teamId: 1,
    scope: 'team',
    structure: {
      schema: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1 },
          email: { type: 'string', format: 'email' },
          age: { type: 'number', minimum: 0 }
        },
        required: ['name', 'email']
      },
      version: '1.0.0',
      format: 'json'
    },
    validation: {
      enabled: true,
      strict: false,
      rules: [
        {
          field: 'email',
          type: 'format',
          parameters: { format: 'email' },
          message: 'Invalid email format'
        }
      ]
    },
    transformation: {
      enabled: true,
      mappings: [
        {
          source: 'full_name',
          target: 'name',
          function: 'trim'
        }
      ],
      filters: [
        {
          field: 'age',
          operator: 'gte',
          value: 0
        }
      ]
    },
    usage: {
      scenariosUsing: 5,
      lastUsed: '2024-01-01T11:00:00Z',
      validationCount: 1250,
      errorRate: 2.3
    },
    versions: [
      {
        version: '1.0.0',
        changes: 'Initial version',
        createdAt: '2023-12-01T10:00:00Z',
        createdBy: 1
      }
    ],
    createdAt: '2023-12-01T10:00:00Z',
    updatedAt: '2024-01-01T09:00:00Z',
    createdBy: 1
  };

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = jest.fn();
    mockReportProgress = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all notification management tools with correct configuration', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-notification',
        'get-email-preferences',
        'update-email-preferences',
        'create-notification-template',
        'create-data-structure',
        'list-notifications'
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });
    });
  });

  describe('Notification Creation and Management', () => {
    describe('create-notification tool', () => {
      it('should create notification successfully with all channels', async () => {
        mockApiClient.mockResponse('POST', '/notifications', {
          success: true,
          data: testNotification
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        const result = await executeTool(tool, {
          type: 'system',
          category: 'info',
          priority: 'medium',
          title: 'Test Notification',
          message: 'This is a test notification message',
          recipients: {
            users: [1, 2, 3],
            teams: [1],
            organizations: [1],
            emails: ['test@example.com']
          },
          channels: {
            email: true,
            inApp: true,
            sms: false,
            webhook: false,
            slack: false,
            teams: false
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Test Notification');
        expect(result).toContain('created successfully');
        expect(result).toContain('"type": "system"');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.type).toBe('system');
        expect(calls[0].data.title).toBe('Test Notification');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create scheduled notification with recurring pattern', async () => {
        const scheduledNotification = {
          ...testNotification,
          status: 'scheduled',
          schedule: {
            sendAt: '2024-02-01T12:00:00Z',
            timezone: 'America/New_York',
            recurring: {
              frequency: 'weekly',
              interval: 1,
              daysOfWeek: [1, 3, 5],
              endDate: '2024-12-31T23:59:59Z'
            }
          }
        };

        mockApiClient.mockResponse('POST', '/notifications', {
          success: true,
          data: scheduledNotification
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        const result = await executeTool(tool, {
          type: 'marketing',
          category: 'reminder',
          title: 'Weekly Newsletter',
          message: 'Your weekly update is here!',
          recipients: { emails: ['subscriber@example.com'] },
          channels: { email: true },
          schedule: {
            sendAt: '2024-02-01T12:00:00Z',
            timezone: 'America/New_York',
            recurring: {
              frequency: 'weekly',
              interval: 1,
              daysOfWeek: [1, 3, 5],
              endDate: '2024-12-31T23:59:59Z'
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('scheduled');
        expect(result).toContain('2024-02-01T12:00:00Z');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.schedule.recurring.frequency).toBe('weekly');
        expect(calls[0].data.schedule.recurring.daysOfWeek).toEqual([1, 3, 5]);
      });

      it('should create notification with template variables', async () => {
        mockApiClient.mockResponse('POST', '/notifications', {
          success: true,
          data: {
            ...testNotification,
            template: {
              id: 5,
              variables: { userName: 'John Doe', action: 'login' }
            }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        await executeTool(tool, {
          type: 'security',
          category: 'alert',
          title: 'Security Alert',
          message: 'Unusual login activity detected',
          recipients: { users: [1] },
          channels: { email: true, inApp: true },
          templateId: 5,
          templateVariables: {
            userName: 'John Doe',
            action: 'login',
            location: 'New York, NY'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.template.id).toBe(5);
        expect(calls[0].data.template.variables.userName).toBe('John Doe');
        expect(calls[0].data.template.variables.action).toBe('login');
      });

      it('should validate recipient requirements', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        await expect(executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test',
          message: 'Test message',
          recipients: {
            users: [],
            teams: [],
            organizations: [],
            emails: []
          },
          channels: { email: true }
        }, { log: mockLog })).rejects.toThrow('At least one recipient must be specified');
      });

      it('should validate channel requirements', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        await expect(executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test',
          message: 'Test message',
          recipients: { users: [1] },
          channels: {
            email: false,
            inApp: false,
            sms: false,
            webhook: false,
            slack: false,
            teams: false
          }
        }, { log: mockLog })).rejects.toThrow('At least one delivery channel must be enabled');
      });

      it('should handle API errors gracefully', async () => {
        mockApiClient.mockResponse('POST', '/notifications', {
          success: false,
          error: { message: 'Rate limit exceeded' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        await expect(executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test',
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true }
        }, { log: mockLog })).rejects.toThrow('Failed to create notification: Rate limit exceeded');
      });

      it('should validate input parameters with Zod schema', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        // Test invalid type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            type: 'invalid-type',
            category: 'info',
            title: 'Test',
            message: 'Test message',
            recipients: { users: [1] },
            channels: { email: true }
          }, { log: mockLog })
        );
        
        // Test invalid priority
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            type: 'system',
            category: 'info',
            priority: 'invalid-priority',
            title: 'Test',
            message: 'Test message',
            recipients: { users: [1] },
            channels: { email: true }
          }, { log: mockLog })
        );
        
        // Test empty title
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            type: 'system',
            category: 'info',
            title: '',
            message: 'Test message',
            recipients: { users: [1] },
            channels: { email: true }
          }, { log: mockLog })
        );
        
        // Test invalid email in recipients
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            type: 'system',
            category: 'info',
            title: 'Test',
            message: 'Test message',
            recipients: { emails: ['invalid-email'] },
            channels: { email: true }
          }, { log: mockLog })
        );
      });
    });
  });

  describe('Email Preferences Management', () => {
    describe('get-email-preferences tool', () => {
      it('should get email preferences for current user', async () => {
        mockApiClient.mockResponse('GET', '/notifications/email-preferences', {
          success: true,
          data: testEmailPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('"userId": 1');
        expect(result).toContain('America/New_York');
        expect(result).toContain('Slack Alerts');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications/email-preferences');
        expect(calls[0].method).toBe('GET');
      });

      it('should get email preferences for specific user', async () => {
        const userId = 456;
        mockApiClient.mockResponse('GET', `/users/${userId}/email-preferences`, {
          success: true,
          data: { ...testEmailPreferences, userId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        await executeTool(tool, { userId }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/users/${userId}/email-preferences`);
      });

      it('should include statistics when requested', async () => {
        mockApiClient.mockResponse('GET', '/notifications/email-preferences', {
          success: true,
          data: {
            ...testEmailPreferences,
            stats: {
              emailsSent: 50,
              emailsOpened: 35,
              emailsClicked: 8,
              unsubscribeRate: 2.1
            }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        await executeTool(tool, { includeStats: true }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.includeStats).toBe(true);
      });

      it('should handle user not found', async () => {
        mockApiClient.mockResponse('GET', '/notifications/email-preferences', {
          success: true,
          data: null
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('Email preferences not found');
      });
    });

    describe('update-email-preferences tool', () => {
      it('should update email preferences successfully', async () => {
        const updatedPreferences = {
          ...testEmailPreferences,
          preferences: {
            ...testEmailPreferences.preferences,
            marketing: {
              enabled: true,
              categories: {
                productUpdates: true,
                newsletters: true,
                webinars: false,
                surveys: false
              }
            }
          },
          lastUpdated: '2024-01-02T10:00:00Z'
        };

        mockApiClient.mockResponse('PUT', '/notifications/email-preferences', {
          success: true,
          data: updatedPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        const result = await executeTool(tool, {
          preferences: {
            marketing: {
              enabled: true,
              categories: {
                productUpdates: true,
                newsletters: true,
                webinars: false,
                surveys: false
              }
            }
          },
          timezone: 'Europe/London'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('updated successfully');
        expect(result).toContain('marketing');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.preferences.marketing.enabled).toBe(true);
        expect(calls[0].data.timezone).toBe('Europe/London');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should update preferences for specific user', async () => {
        const userId = 789;
        mockApiClient.mockResponse('PUT', `/users/${userId}/email-preferences`, {
          success: true,
          data: { ...testEmailPreferences, userId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        await executeTool(tool, {
          userId,
          unsubscribeAll: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/users/${userId}/email-preferences`);
        expect(calls[0].data.unsubscribeAll).toBe(true);
      });

      it('should update scenario-specific preferences', async () => {
        mockApiClient.mockResponse('PUT', '/notifications/email-preferences', {
          success: true,
          data: testEmailPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        await executeTool(tool, {
          preferences: {
            scenarios: {
              enabled: true,
              frequency: 'hourly',
              categories: {
                failures: true,
                completions: true,
                warnings: false,
                scheduleChanges: true
              },
              filters: {
                onlyMyScenarios: false,
                onlyImportantScenarios: true,
                scenarioIds: [4, 5, 6],
                teamIds: [2, 3]
              }
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.preferences.scenarios.frequency).toBe('hourly');
        expect(calls[0].data.preferences.scenarios.filters.scenarioIds).toEqual([4, 5, 6]);
      });

      it('should require at least one update parameter', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('No preference updates provided');
      });
    });
  });

  describe('Notification Template Management', () => {
    describe('create-notification-template tool', () => {
      it('should create notification template successfully', async () => {
        mockApiClient.mockResponse('POST', '/notifications/templates', {
          success: true,
          data: testNotificationTemplate
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        const result = await executeTool(tool, {
          name: 'System Alert Template',
          description: 'Template for system notifications',
          type: 'email',
          category: 'system',
          template: {
            subject: 'System Alert: {{title}}',
            body: '<h1>{{title}}</h1><p>{{message}}</p>',
            format: 'html',
            variables: [
              {
                name: 'title',
                type: 'string',
                required: true,
                description: 'Alert title'
              },
              {
                name: 'message',
                type: 'string',
                required: true,
                description: 'Alert message'
              }
            ]
          },
          design: {
            theme: 'default',
            colors: { primary: '#007bff' }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('System Alert Template');
        expect(result).toContain('created successfully');
        expect(result).toContain('testUrl');
        expect(result).toContain('previewUrl');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications/templates');
        expect(calls[0].data.name).toBe('System Alert Template');
        expect(calls[0].data.template.variables).toHaveLength(2);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create organization-specific template', async () => {
        const orgId = 456;
        mockApiClient.mockResponse('POST', `/organizations/${orgId}/notifications/templates`, {
          success: true,
          data: { ...testNotificationTemplate, organizationId: orgId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        await executeTool(tool, {
          name: 'Org Template',
          type: 'slack',
          category: 'team',
          organizationId: orgId,
          template: {
            body: 'Team update: {{message}}',
            format: 'text',
            variables: []
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/notifications/templates`);
        expect(calls[0].data.organizationId).toBe(orgId);
        expect(calls[0].data.isGlobal).toBe(false);
      });

      it('should create different template types', async () => {
        const templates = [
          { type: 'sms', format: 'text', body: 'SMS: {{message}}' },
          { type: 'webhook', format: 'json', body: '{"text": "{{message}}"}' },
          { type: 'teams', format: 'markdown', body: '## {{title}}\n\n{{message}}' }
        ];

        for (const templateData of templates) {
          mockApiClient.mockResponse('POST', '/notifications/templates', {
            success: true,
            data: { ...testNotificationTemplate, type: templateData.type }
          });

          const { addNotificationTools } = await import('../../../src/tools/notifications.js');
          addNotificationTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'create-notification-template');
          await executeTool(tool, {
            name: `${templateData.type} Template`,
            type: templateData.type as any,
            category: 'custom',
            template: {
              body: templateData.body,
              format: templateData.format as any,
              variables: []
            }
          }, { log: mockLog, reportProgress: mockReportProgress });
          
          mockApiClient.reset();
        }
      });

      it('should validate template parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        
        // Test invalid template type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Template',
            type: 'invalid-type',
            category: 'system',
            template: { body: 'Test body', format: 'text' }
          }, { log: mockLog })
        );
        
        // Test missing template body
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Template',
            type: 'email',
            category: 'system',
            template: { format: 'html' }
          }, { log: mockLog })
        );
        
        // Test invalid variable type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Template',
            type: 'email',
            category: 'system',
            template: {
              body: 'Test {{var}}',
              format: 'html',
              variables: [{
                name: 'var',
                type: 'invalid-type',
                required: false
              }]
            }
          }, { log: mockLog })
        );
      });
    });
  });

  describe('Data Structure Management', () => {
    describe('create-data-structure tool', () => {
      it('should create data structure successfully', async () => {
        mockApiClient.mockResponse('POST', '/data-structures', {
          success: true,
          data: testDataStructure
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-data-structure');
        const result = await executeTool(tool, {
          name: 'User Profile Schema',
          description: 'Schema for user profile validation',
          type: 'schema',
          scope: 'team',
          structure: {
            schema: {
              type: 'object',
              properties: {
                name: { type: 'string', minLength: 1 },
                email: { type: 'string', format: 'email' },
                age: { type: 'number', minimum: 0 }
              },
              required: ['name', 'email']
            },
            version: '1.0.0',
            format: 'json'
          },
          validation: {
            enabled: true,
            strict: false,
            rules: [{
              field: 'email',
              type: 'format',
              parameters: { format: 'email' },
              message: 'Invalid email format'
            }]
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('User Profile Schema');
        expect(result).toContain('created successfully');
        expect(result).toContain('validateUrl');
        expect(result).toContain('transformUrl');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/data-structures');
        expect(calls[0].data.name).toBe('User Profile Schema');
        expect(calls[0].data.structure.schema.properties.email.format).toBe('email');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create organization-scoped data structure', async () => {
        const orgId = 789;
        mockApiClient.mockResponse('POST', `/organizations/${orgId}/data-structures`, {
          success: true,
          data: { ...testDataStructure, organizationId: orgId, scope: 'organization' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-data-structure');
        await executeTool(tool, {
          name: 'Org Schema',
          type: 'validation',
          organizationId: orgId,
          scope: 'organization',
          structure: {
            schema: { type: 'object' },
            format: 'json'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/data-structures`);
        expect(calls[0].data.organizationId).toBe(orgId);
      });

      it('should create team-scoped data structure', async () => {
        const teamId = 321;
        mockApiClient.mockResponse('POST', `/teams/${teamId}/data-structures`, {
          success: true,
          data: { ...testDataStructure, teamId, scope: 'team' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-data-structure');
        await executeTool(tool, {
          name: 'Team Schema',
          type: 'transformation',
          teamId,
          scope: 'team',
          structure: {
            schema: { type: 'object' },
            format: 'json'
          },
          transformation: {
            enabled: true,
            mappings: [{
              source: 'old_field',
              target: 'new_field',
              function: 'upperCase'
            }],
            filters: [{
              field: 'status',
              operator: 'eq',
              value: 'active'
            }]
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/teams/${teamId}/data-structures`);
        expect(calls[0].data.teamId).toBe(teamId);
        expect(calls[0].data.transformation.enabled).toBe(true);
      });

      it('should validate JSON schema', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-data-structure');
        
        // This should work with valid JSON schema
        mockApiClient.mockResponse('POST', '/data-structures', {
          success: true,
          data: testDataStructure
        });
        
        await executeTool(tool, {
          name: 'Valid Schema',
          type: 'schema',
          structure: {
            schema: { type: 'object', properties: { name: { type: 'string' } } },
            format: 'json'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(mockApiClient.getCallLog()).toHaveLength(1);
      });

      it('should validate input parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-data-structure');
        
        // Test invalid data structure type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Schema',
            type: 'invalid-type',
            structure: { schema: {}, format: 'json' }
          }, { log: mockLog })
        );
        
        // Test invalid scope
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Schema',
            type: 'schema',
            scope: 'invalid-scope',
            structure: { schema: {}, format: 'json' }
          }, { log: mockLog })
        );
        
        // Test invalid format
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Schema',
            type: 'schema',
            structure: { schema: {}, format: 'invalid-format' }
          }, { log: mockLog })
        );
      });
    });
  });

  describe('Notification Listing and Analytics', () => {
    describe('list-notifications tool', () => {
      it('should list notifications with default filters', async () => {
        const notificationsList = [
          testNotification,
          { ...testNotification, id: 2, type: 'billing', priority: 'high' },
          { ...testNotification, id: 3, type: 'scenario', status: 'failed' }
        ];

        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: notificationsList,
          metadata: { total: 3 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('"totalNotifications": 3');
        expect(result).toContain('typeBreakdown');
        expect(result).toContain('statusBreakdown');
        expect(result).toContain('deliveryAnalytics');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.type).toBeUndefined(); // 'all' should not be sent
        expect(calls[0].params.status).toBeUndefined(); // 'all' should not be sent
        expect(calls[0].params.limit).toBe(20);
        expect(calls[0].params.offset).toBe(0);
      });

      it('should filter notifications by type and status', async () => {
        const filteredNotifications = [
          { ...testNotification, type: 'billing', status: 'sent' }
        ];

        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: filteredNotifications,
          metadata: { total: 1 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        await executeTool(tool, {
          type: 'billing',
          status: 'sent',
          priority: 'high',
          limit: 10
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.type).toBe('billing');
        expect(calls[0].params.status).toBe('sent');
        expect(calls[0].params.priority).toBe('high');
        expect(calls[0].params.limit).toBe(10);
      });

      it('should filter notifications by date range', async () => {
        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: [testNotification],
          metadata: { total: 1 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        await executeTool(tool, {
          dateRange: {
            startDate: '2024-01-01',
            endDate: '2024-01-31'
          },
          sortBy: 'sentAt',
          sortOrder: 'asc'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.startDate).toBe('2024-01-01');
        expect(calls[0].params.endDate).toBe('2024-01-31');
        expect(calls[0].params.sortBy).toBe('sentAt');
        expect(calls[0].params.sortOrder).toBe('asc');
      });

      it('should include tracking data when requested', async () => {
        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: [testNotification],
          metadata: { total: 1 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        await executeTool(tool, {
          includeTracking: true,
          includeDelivery: false
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.includeTracking).toBe(true);
        expect(calls[0].params.includeDelivery).toBe(false);
      });

      it('should generate comprehensive analytics', async () => {
        const mixedNotifications = [
          { ...testNotification, type: 'system', status: 'sent', priority: 'low', channels: { email: true, sms: false } },
          { ...testNotification, id: 2, type: 'billing', status: 'delivered', priority: 'high', channels: { email: true, slack: true } },
          { ...testNotification, id: 3, type: 'system', status: 'failed', priority: 'critical', channels: { email: false, webhook: true } }
        ];

        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: mixedNotifications,
          metadata: { total: 3 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = JSON.parse(result);
        
        expect(parsed.analytics.typeBreakdown.system).toBe(2);
        expect(parsed.analytics.typeBreakdown.billing).toBe(1);
        expect(parsed.analytics.statusBreakdown.sent).toBe(1);
        expect(parsed.analytics.statusBreakdown.delivered).toBe(1);
        expect(parsed.analytics.statusBreakdown.failed).toBe(1);
        expect(parsed.analytics.priorityBreakdown.low).toBe(1);
        expect(parsed.analytics.priorityBreakdown.high).toBe(1);
        expect(parsed.analytics.priorityBreakdown.critical).toBe(1);
        expect(parsed.analytics.channelUsage.email).toBe(2);
        expect(parsed.analytics.channelUsage.slack).toBe(1);
        expect(parsed.analytics.channelUsage.webhook).toBe(1);
      });

      it('should mask recipient details for privacy', async () => {
        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: [testNotification],
          metadata: { total: 1 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = JSON.parse(result);
        const notification = parsed.notifications[0];
        
        expect(notification.recipients.total).toBe(5);
        expect(notification.recipients.users).toBeUndefined();
        expect(notification.recipients.emails).toBeUndefined();
        expect(notification.recipients.teams).toBeUndefined();
        expect(notification.recipients.organizations).toBeUndefined();
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully across all tools', async () => {
      const tools = [
        'create-notification',
        'get-email-preferences',
        'update-email-preferences',
        'create-notification-template',
        'create-data-structure',
        'list-notifications'
      ];

      for (const toolName of tools) {
        mockApiClient.mockResponse('*', '*', {
          success: false,
          error: { message: 'Service temporarily unavailable' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, toolName);
        
        let testInput: any = {};
        if (toolName === 'create-notification') {
          testInput = {
            type: 'system',
            category: 'info',
            title: 'Test',
            message: 'Test message',
            recipients: { users: [1] },
            channels: { email: true }
          };
        } else if (toolName === 'update-email-preferences') {
          testInput = { unsubscribeAll: true };
        } else if (toolName === 'create-notification-template') {
          testInput = {
            name: 'Test Template',
            type: 'email',
            category: 'system',
            template: { body: 'Test', format: 'text' }
          };
        } else if (toolName === 'create-data-structure') {
          testInput = {
            name: 'Test Schema',
            type: 'schema',
            structure: { schema: {}, format: 'json' }
          };
        }
        
        await expect(executeTool(tool, testInput, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow(UserError);
        
        mockApiClient.reset();
      }
    });

    it('should handle network errors', async () => {
      mockApiClient.mockError('POST', '/notifications', new Error('Network timeout'));

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-notification');
      
      await expect(executeTool(tool, {
        type: 'system',
        category: 'info',
        title: 'Test',
        message: 'Test message',
        recipients: { users: [1] },
        channels: { email: true }
      }, { log: mockLog })).rejects.toThrow('Failed to create notification: Network timeout');
    });

    it('should log operations correctly', async () => {
      mockApiClient.mockResponse('POST', '/notifications', {
        success: true,
        data: testNotification
      });

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-notification');
      await executeTool(tool, {
        type: 'system',
        category: 'info',
        title: 'Test Notification',
        message: 'Test message',
        recipients: { users: [1] },
        channels: { email: true }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Creating notification',
        expect.objectContaining({
          type: 'system',
          category: 'info',
          title: 'Test Notification'
        })
      );
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Successfully created notification',
        expect.objectContaining({
          notificationId: 1,
          type: 'system'
        })
      );
    });
  });

  describe('Input Validation', () => {
    it('should validate notification creation parameters', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-notification');
      
      // Test title length limits
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'x'.repeat(201), // Too long
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true }
        }, { log: mockLog })
      );
      
      // Test message length limits
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test',
          message: 'x'.repeat(2001), // Too long
          recipients: { users: [1] },
          channels: { email: true }
        }, { log: mockLog })
      );
      
      // Test invalid recurring frequency
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test',
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true },
          schedule: {
            recurring: {
              frequency: 'invalid-frequency',
              interval: 1
            }
          }
        }, { log: mockLog })
      );
    });

    it('should validate email preference parameters', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-email-preferences');
      
      // Test invalid frequency values
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          preferences: {
            system: {
              frequency: 'invalid-frequency'
            }
          }
        }, { log: mockLog })
      );
      
      // Test invalid user ID
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          userId: 0, // Invalid
          unsubscribeAll: true
        }, { log: mockLog })
      );
    });

    it('should validate template creation parameters', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-notification-template');
      
      // Test name length limits
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          name: 'x'.repeat(101), // Too long
          type: 'email',
          category: 'system',
          template: { body: 'Test', format: 'html' }
        }, { log: mockLog })
      );
      
      // Test description length limits
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          name: 'Test Template',
          description: 'x'.repeat(501), // Too long
          type: 'email',
          category: 'system',
          template: { body: 'Test', format: 'html' }
        }, { log: mockLog })
      );
      
      // Test subject length limits for email templates
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          name: 'Test Template',
          type: 'email',
          category: 'system',
          template: {
            subject: 'x'.repeat(201), // Too long
            body: 'Test',
            format: 'html'
          }
        }, { log: mockLog })
      );
    });

    it('should validate data structure parameters', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-structure');
      
      // Test name length limits
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          name: 'x'.repeat(101), // Too long
          type: 'schema',
          structure: { schema: {}, format: 'json' }
        }, { log: mockLog })
      );
      
      // Test invalid validation rule type
      await expectInvalidZodParse(() => 
        executeTool(tool, {
          name: 'Test Schema',
          type: 'schema',
          structure: { schema: {}, format: 'json' },
          validation: {
            rules: [{
              field: 'test',
              type: 'invalid-type',
              message: 'Error'
            }]
          }
        }, { log: mockLog })
      );
    });

    it('should validate list notifications parameters', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-notifications');
      
      // Test invalid limit
      await expectInvalidZodParse(() => 
        executeTool(tool, { limit: 0 }, { log: mockLog })
      );
      
      await expectInvalidZodParse(() => 
        executeTool(tool, { limit: 101 }, { log: mockLog })
      );
      
      // Test invalid offset
      await expectInvalidZodParse(() => 
        executeTool(tool, { offset: -1 }, { log: mockLog })
      );
    });
  });
});