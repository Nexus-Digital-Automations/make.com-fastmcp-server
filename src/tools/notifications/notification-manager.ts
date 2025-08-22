/**
 * Notification Management Tools for Make.com FastMCP Server
 * 
 * This module contains notification-specific tools extracted from the main notifications.ts file
 * for better maintainability and separation of concerns.
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { formatSuccessResponse } from '../../utils/response-formatter.js';

// ==================== HELPER FUNCTIONS ====================

// Re-export notification types for external usage
export interface MakeNotification {
  id: number;
  type: 'system' | 'billing' | 'security' | 'scenario' | 'team' | 'marketing' | 'custom';
  category: 'info' | 'warning' | 'error' | 'success' | 'reminder' | 'alert';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  message: string;
  data?: Record<string, unknown>;
  recipients: {
    users: number[];
    teams: number[];
    organizations: number[];
    emails: string[];
  };
  channels: {
    email: boolean;
    inApp: boolean;
    sms: boolean;
    webhook: boolean;
    slack: boolean;
    teams: boolean;
  };
  status: 'draft' | 'scheduled' | 'sent' | 'delivered' | 'failed' | 'cancelled';
  delivery: {
    sentAt?: string;
    deliveredAt?: string;
    failedAt?: string;
    totalRecipients: number;
    successfulDeliveries: number;
    failedDeliveries: number;
    errors: Array<{
      recipient: string;
      channel: string;
      error: string;
      timestamp: string;
    }>;
  };
  schedule: {
    sendAt?: string;
    timezone?: string;
    recurring?: {
      enabled: boolean;
      frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';
      interval: number;
      daysOfWeek?: number[];
      dayOfMonth?: number;
      endDate?: string;
    };
  };
  template: {
    id?: number;
    name?: string;
    variables: Record<string, unknown>;
  };
  tracking: {
    opens: number;
    clicks: number;
    unsubscribes: number;
    complaints: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeEmailPreferences {
  userId: number;
  organizationId: number;
  preferences: {
    system: {
      enabled: boolean;
      frequency: 'immediate' | 'hourly' | 'daily' | 'weekly' | 'never';
      categories: {
        updates: boolean;
        maintenance: boolean;
        security: boolean;
        announcements: boolean;
      };
    };
    billing: {
      enabled: boolean;
      categories: {
        invoices: boolean;
        paymentReminders: boolean;
        usageAlerts: boolean;
        planChanges: boolean;
      };
    };
    scenarios: {
      enabled: boolean;
      frequency: 'immediate' | 'hourly' | 'daily' | 'never';
      categories: {
        failures: boolean;
        completions: boolean;
        warnings: boolean;
        scheduleChanges: boolean;
      };
      filters: {
        onlyMyScenarios: boolean;
        onlyImportantScenarios: boolean;
        scenarioIds: number[];
        teamIds: number[];
      };
    };
    team: {
      enabled: boolean;
      categories: {
        invitations: boolean;
        roleChanges: boolean;
        memberChanges: boolean;
        teamUpdates: boolean;
      };
    };
    marketing: {
      enabled: boolean;
      categories: {
        productUpdates: boolean;
        newsletters: boolean;
        webinars: boolean;
        surveys: boolean;
      };
    };
    customChannels: Array<{
      name: string;
      type: 'webhook' | 'slack' | 'teams' | 'discord';
      enabled: boolean;
      configuration: Record<string, unknown>;
      filters: Record<string, unknown>;
    }>;
  };
  timezone: string;
  language: string;
  unsubscribeAll: boolean;
  lastUpdated: string;
}

export interface MakeNotificationTemplate {
  id: number;
  name: string;
  description?: string;
  type: 'email' | 'sms' | 'push' | 'webhook' | 'slack' | 'teams';
  category: 'system' | 'billing' | 'scenario' | 'team' | 'marketing' | 'custom';
  organizationId?: number;
  isGlobal: boolean;
  template: {
    subject?: string;
    body: string;
    format: 'text' | 'html' | 'markdown' | 'json';
    variables: Array<{
      name: string;
      type: 'string' | 'number' | 'boolean' | 'date' | 'object';
      required: boolean;
      defaultValue?: unknown;
      description?: string;
    }>;
  };
  design: {
    theme?: string;
    colors?: Record<string, string>;
    fonts?: Record<string, string>;
    layout?: string;
    customCss?: string;
  };
  testing: {
    lastTested?: string;
    testResults?: {
      renderingTime: number;
      size: number;
      errors: string[];
      warnings: string[];
    };
  };
  usage: {
    totalSent: number;
    lastUsed?: string;
    averageDeliveryTime: number;
    deliveryRate: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Validation schemas
const NotificationCreateSchema = z.object({
  type: z.enum(['system', 'billing', 'security', 'scenario', 'team', 'marketing', 'custom']).describe('Notification type'),
  category: z.enum(['info', 'warning', 'error', 'success', 'reminder', 'alert']).describe('Notification category'),
  priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium').describe('Notification priority'),
  title: z.string().min(1).max(200).describe('Notification title'),
  message: z.string().min(1).max(2000).describe('Notification message content'),
  data: z.record(z.string(), z.any()).optional().describe('Additional structured data'),
  recipients: z.object({
    users: z.array(z.number()).default([]).describe('User IDs to notify'),
    teams: z.array(z.number()).default([]).describe('Team IDs to notify'),
    organizations: z.array(z.number()).default([]).describe('Organization IDs to notify'),
    emails: z.array(z.string().email()).default([]).describe('Direct email addresses'),
  }).describe('Notification recipients'),
  channels: z.object({
    email: z.boolean().default(true).describe('Send via email'),
    inApp: z.boolean().default(true).describe('Show in-app notification'),
    sms: z.boolean().default(false).describe('Send via SMS'),
    webhook: z.boolean().default(false).describe('Send to webhook'),
    slack: z.boolean().default(false).describe('Send to Slack'),
    teams: z.boolean().default(false).describe('Send to Microsoft Teams'),
  }).describe('Delivery channels'),
  schedule: z.object({
    sendAt: z.string().optional().describe('Schedule send time (ISO 8601)'),
    timezone: z.string().default('UTC').describe('Timezone for scheduling'),
    recurring: z.object({
      frequency: z.enum(['daily', 'weekly', 'monthly', 'quarterly', 'yearly']).describe('Recurrence frequency'),
      interval: z.number().min(1).default(1).describe('Interval between recurrences'),
      daysOfWeek: z.array(z.number().min(0).max(6)).optional().describe('Days of week (0=Sunday)'),
      dayOfMonth: z.number().min(1).max(31).optional().describe('Day of month'),
      endDate: z.string().optional().describe('End date for recurrence'),
    }).optional().describe('Recurring schedule configuration'),
  }).optional().describe('Scheduling options'),
  templateId: z.number().optional().describe('Template ID to use'),
  templateVariables: z.record(z.string(), z.any()).default({}).describe('Template variable values'),
}).strict();

const EmailPreferencesSchema = z.object({
  userId: z.number().min(1).optional().describe('User ID (defaults to current user)'),
  preferences: z.object({
    system: z.object({
      enabled: z.boolean().describe('Enable system notifications'),
      frequency: z.enum(['immediate', 'hourly', 'daily', 'weekly', 'never']).describe('System notification frequency'),
      categories: z.object({
        updates: z.boolean().describe('Product updates'),
        maintenance: z.boolean().describe('Maintenance notifications'),
        security: z.boolean().describe('Security alerts'),
        announcements: z.boolean().describe('Company announcements'),
      }).partial(),
    }).partial().optional(),
    billing: z.object({
      enabled: z.boolean().describe('Enable billing notifications'),
      categories: z.object({
        invoices: z.boolean().describe('Invoice notifications'),
        paymentReminders: z.boolean().describe('Payment reminders'),
        usageAlerts: z.boolean().describe('Usage limit alerts'),
        planChanges: z.boolean().describe('Plan change notifications'),
      }).partial(),
    }).partial().optional(),
    scenarios: z.object({
      enabled: z.boolean().describe('Enable scenario notifications'),
      frequency: z.enum(['immediate', 'hourly', 'daily', 'never']).describe('Scenario notification frequency'),
      categories: z.object({
        failures: z.boolean().describe('Scenario failure notifications'),
        completions: z.boolean().describe('Scenario completion notifications'),
        warnings: z.boolean().describe('Scenario warning notifications'),
        scheduleChanges: z.boolean().describe('Schedule change notifications'),
      }).partial(),
      filters: z.object({
        onlyMyScenarios: z.boolean().describe('Only notify for my scenarios'),
        onlyImportantScenarios: z.boolean().describe('Only notify for important scenarios'),
        scenarioIds: z.array(z.number()).describe('Specific scenario IDs to monitor'),
        teamIds: z.array(z.number()).describe('Team IDs to monitor'),
      }).partial(),
    }).partial().optional(),
    team: z.object({
      enabled: z.boolean().describe('Enable team notifications'),
      categories: z.object({
        invitations: z.boolean().describe('Team invitation notifications'),
        roleChanges: z.boolean().describe('Role change notifications'),
        memberChanges: z.boolean().describe('Member change notifications'),
        teamUpdates: z.boolean().describe('Team update notifications'),
      }).partial(),
    }).partial().optional(),
    marketing: z.object({
      enabled: z.boolean().describe('Enable marketing notifications'),
      categories: z.object({
        productUpdates: z.boolean().describe('Product update emails'),
        newsletters: z.boolean().describe('Newsletter subscriptions'),
        webinars: z.boolean().describe('Webinar invitations'),
        surveys: z.boolean().describe('Survey invitations'),
      }).partial(),
    }).partial().optional(),
  }).optional().describe('Email preference settings'),
  timezone: z.string().optional().describe('User timezone'),
  language: z.string().optional().describe('Preferred language'),
  unsubscribeAll: z.boolean().optional().describe('Unsubscribe from all emails'),
}).strict().refine(
  (data) => {
    // At least one field must be provided for updates
    return !!(data.preferences || data.timezone || data.language || data.unsubscribeAll !== undefined);
  },
  {
    message: "At least one field must be provided for update (preferences, timezone, language, or unsubscribeAll)",
  }
);

const NotificationTemplateSchema = z.object({
  name: z.string().min(1).max(100).describe('Template name'),
  description: z.string().max(500).optional().describe('Template description'),
  type: z.enum(['email', 'sms', 'push', 'webhook', 'slack', 'teams']).describe('Template type'),
  category: z.enum(['system', 'billing', 'scenario', 'team', 'marketing', 'custom']).describe('Template category'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for org templates)'),
  template: z.object({
    subject: z.string().max(200).optional().describe('Email subject template'),
    body: z.string().min(1).describe('Template body content'),
    format: z.enum(['text', 'html', 'markdown', 'json']).default('html').describe('Template format'),
    variables: z.array(z.object({
      name: z.string().min(1).describe('Variable name'),
      type: z.enum(['string', 'number', 'boolean', 'date', 'object']).describe('Variable type'),
      required: z.boolean().default(false).describe('Is variable required'),
      defaultValue: z.any().optional().describe('Default value'),
      description: z.string().optional().describe('Variable description'),
    })).default([]).describe('Template variables'),
  }).describe('Template configuration'),
  design: z.object({
    theme: z.string().optional().describe('Design theme'),
    colors: z.record(z.string(), z.string()).optional().describe('Color scheme'),
    fonts: z.record(z.string(), z.string()).optional().describe('Font configuration'),
    layout: z.string().optional().describe('Layout template'),
    customCss: z.string().optional().describe('Custom CSS'),
  }).optional().describe('Design configuration'),
}).strict();

/**
 * Add create notification tool
 */
function addCreateNotificationTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'create-notification',
    description: 'Create and send a notification through multiple channels with scheduling support',
    parameters: NotificationCreateSchema,
    annotations: {
      title: 'Create Multi-Channel Notification',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false, // Each notification is unique with timestamp
      openWorldHint: true, // External messaging services (email, SMS, Slack, etc.)
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { type, category, priority, title, message, data, recipients, channels, schedule, templateId, templateVariables } = input;

      if (log?.info) {
        log.info('Creating notification', {
          type,
          category,
          priority,
          title: title.substring(0, 50),
          recipientCount: recipients.users.length + recipients.teams.length + recipients.organizations.length + recipients.emails.length,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        // Validate recipients
        const totalRecipients = recipients.users.length + recipients.teams.length + recipients.organizations.length + recipients.emails.length;
        if (totalRecipients === 0) {
          throw new UserError('At least one recipient must be specified');
        }

        // Validate channels
        const enabledChannels = Object.values(channels).filter(Boolean);
        if (enabledChannels.length === 0) {
          throw new UserError('At least one delivery channel must be enabled');
        }

        const notificationData = {
          type,
          category,
          priority,
          title,
          message,
          data,
          recipients,
          channels,
          schedule: schedule || {},
          template: templateId ? {
            id: templateId,
            variables: templateVariables,
          } : undefined,
          status: schedule?.sendAt ? 'scheduled' : 'draft',
        };

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        const response = await apiClient.post('/notifications', notificationData);

        if (!response.success) {
          throw new UserError(`Failed to create notification: ${response.error?.message || 'Unknown error'}`);
        }

        const notification = response.data as MakeNotification;
        if (!notification) {
          throw new UserError('Notification creation failed - no data returned');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully created notification', {
            notificationId: notification.id,
            type: notification.type,
            status: notification.status,
            recipientCount: notification.delivery.totalRecipients,
          });
        }

        return formatSuccessResponse({
          notification: {
            ...notification,
            // Mask sensitive recipient data
            recipients: {
              userCount: notification.recipients.users.length,
              teamCount: notification.recipients.teams.length,
              organizationCount: notification.recipients.organizations.length,
              emailCount: notification.recipients.emails.length,
            },
          },
          message: `Notification "${title}" created successfully`,
          summary: {
            id: notification.id,
            type: notification.type,
            category: notification.category,
            priority: notification.priority,
            status: notification.status,
            channels: Object.entries(notification.channels)
              .filter(([, enabled]) => enabled)
              .map(([channel]) => channel),
            totalRecipients: notification.delivery.totalRecipients,
            scheduled: !!schedule?.sendAt,
            scheduledFor: schedule?.sendAt,
          },
          delivery: {
            status: notification.status,
            sentAt: notification.delivery.sentAt,
            successfulDeliveries: notification.delivery.successfulDeliveries,
            failedDeliveries: notification.delivery.failedDeliveries,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error creating notification', { title, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create notification: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add get email preferences tool
 */
function addGetEmailPreferencesTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'get-email-preferences',
    description: 'Get user email notification preferences and subscription settings',
    parameters: z.object({
      userId: z.number().min(1).optional().describe('User ID (defaults to current user)'),
      includeStats: z.boolean().default(false).describe('Include email statistics'),
    }),
    annotations: {
      title: 'Get Email Notification Preferences',
      readOnlyHint: true,
      openWorldHint: true, // May access external preference systems
    },
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} } } = context || {};
      const { userId, includeStats } = input;

      if (log?.info) {
        log.info('Getting email preferences', { userId, includeStats });
      }

      try {
        const params: Record<string, unknown> = {
          includeStats,
        };

        let endpoint = '/notifications/email-preferences';
        if (userId) {
          endpoint = `/users/${userId}/email-preferences`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get email preferences: ${response.error?.message || 'Unknown error'}`);
        }

        const preferences = response.data as MakeEmailPreferences;
        if (!preferences) {
          throw new UserError('Email preferences not found');
        }

        if (log?.info) {
          log.info('Successfully retrieved email preferences', {
            userId: preferences.userId,
            systemEnabled: preferences.preferences.system.enabled,
            unsubscribeAll: preferences.unsubscribeAll,
          });
        }

        return formatSuccessResponse({
          preferences,
          summary: {
            userId: preferences.userId,
            organizationId: preferences.organizationId,
            unsubscribeAll: preferences.unsubscribeAll,
            timezone: preferences.timezone,
            language: preferences.language,
            categories: {
              system: preferences.preferences.system.enabled,
              billing: preferences.preferences.billing.enabled,
              scenarios: preferences.preferences.scenarios.enabled,
              team: preferences.preferences.team.enabled,
              marketing: preferences.preferences.marketing.enabled,
            },
            customChannels: preferences.preferences.customChannels.length,
          },
          settings: {
            systemFrequency: preferences.preferences.system.frequency,
            scenarioFrequency: preferences.preferences.scenarios.frequency,
            scenarioFilters: preferences.preferences.scenarios.filters,
            lastUpdated: preferences.lastUpdated,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error getting email preferences', { userId, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get email preferences: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add update email preferences tool
 */
function addUpdateEmailPreferencesTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'update-email-preferences',
    description: 'Update user email notification preferences and subscription settings',
    parameters: EmailPreferencesSchema,
    annotations: {
      title: 'Update Email Notification Preferences',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true, // Same preferences produce same result
      openWorldHint: true, // May update external preference systems
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { userId, preferences, timezone, language, unsubscribeAll } = input;

      if (log?.info) {
        log.info('Updating email preferences', {
          userId,
          hasPreferences: !!preferences,
          timezone,
          language,
          unsubscribeAll,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        const updateData: Record<string, unknown> = {};

        if (preferences) {
          updateData.preferences = preferences;
        }

        if (timezone) {
          updateData.timezone = timezone;
        }

        if (language) {
          updateData.language = language;
        }

        if (unsubscribeAll !== undefined) {
          updateData.unsubscribeAll = unsubscribeAll;
        }

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No preference updates provided');
        }

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        let endpoint = '/notifications/email-preferences';
        if (userId) {
          endpoint = `/users/${userId}/email-preferences`;
        }

        const response = await apiClient.put(endpoint, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update email preferences: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedPreferences = response.data as MakeEmailPreferences;
        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully updated email preferences', {
            userId: updatedPreferences.userId,
            unsubscribeAll: updatedPreferences.unsubscribeAll,
            categoriesUpdated: !!preferences,
          });
        }

        return formatSuccessResponse({
          preferences: updatedPreferences,
          message: 'Email preferences updated successfully',
          changes: {
            preferences: !!preferences,
            timezone: !!timezone,
            language: !!language,
            unsubscribeAll: unsubscribeAll !== undefined,
          },
          summary: {
            userId: updatedPreferences.userId,
            unsubscribeAll: updatedPreferences.unsubscribeAll,
            enabledCategories: Object.entries({
              system: updatedPreferences.preferences.system.enabled,
              billing: updatedPreferences.preferences.billing.enabled,
              scenarios: updatedPreferences.preferences.scenarios.enabled,
              team: updatedPreferences.preferences.team.enabled,
              marketing: updatedPreferences.preferences.marketing.enabled,
            }).filter(([, enabled]) => enabled).map(([category]) => category),
            lastUpdated: updatedPreferences.lastUpdated,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error updating email preferences', { userId, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update email preferences: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add create notification template tool
 */
function addCreateNotificationTemplateTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'create-notification-template',
    description: 'Create a reusable notification template with variables and design',
    parameters: NotificationTemplateSchema,
    annotations: {
      title: 'Create Notification Template',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false, // Each template creation is unique
      openWorldHint: false, // Internal template management
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { name, description, type, category, organizationId, template, design } = input;

      if (log?.info) {
        log.info('Creating notification template', {
          name,
          type,
          category,
          organizationId,
          variableCount: template.variables.length,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        const templateData = {
          name,
          description,
          type,
          category,
          organizationId,
          isGlobal: !organizationId,
          template: {
            subject: template.subject,
            body: template.body,
            format: template.format || 'html',
            variables: template.variables || [],
          },
          design: design || {},
        };

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        let endpoint = '/notifications/templates';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/notifications/templates`;
        }

        const response = await apiClient.post(endpoint, templateData);

        if (!response.success) {
          throw new UserError(`Failed to create notification template: ${response.error?.message || 'Unknown error'}`);
        }

        const notificationTemplate = response.data as MakeNotificationTemplate;
        if (!notificationTemplate) {
          throw new UserError('Notification template creation failed - no data returned');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully created notification template', {
            templateId: notificationTemplate.id,
            name: notificationTemplate.name,
            type: notificationTemplate.type,
            category: notificationTemplate.category,
          });
        }

        return formatSuccessResponse({
          template: notificationTemplate,
          message: `Notification template "${name}" created successfully`,
          summary: {
            id: notificationTemplate.id,
            name: notificationTemplate.name,
            type: notificationTemplate.type,
            category: notificationTemplate.category,
            isGlobal: notificationTemplate.isGlobal,
            variables: notificationTemplate.template.variables.length,
            format: notificationTemplate.template.format,
          },
          usage: {
            testUrl: `/notifications/templates/${notificationTemplate.id}/test`,
            previewUrl: `/notifications/templates/${notificationTemplate.id}/preview`,
          },
          nextSteps: [
            'Test template with sample data',
            'Configure design settings if needed',
            'Use template in notifications',
            'Share with team members',
          ],
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error creating notification template', { name, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create notification template: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list notifications tool
 */
function addListNotificationsTool(server: FastMCP, apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'list-notifications',
    description: 'List and filter notifications with delivery status and analytics',
    parameters: z.object({
      type: z.enum(['system', 'billing', 'security', 'scenario', 'team', 'marketing', 'custom', 'all']).default('all').describe('Filter by notification type'),
      status: z.enum(['draft', 'scheduled', 'sent', 'delivered', 'failed', 'cancelled', 'all']).default('all').describe('Filter by notification status'),
      priority: z.enum(['low', 'medium', 'high', 'critical', 'all']).default('all').describe('Filter by priority'),
      dateRange: z.object({
        startDate: z.string().optional().describe('Start date (YYYY-MM-DD)'),
        endDate: z.string().optional().describe('End date (YYYY-MM-DD)'),
      }).optional().describe('Date range filter'),
      includeDelivery: z.boolean().default(true).describe('Include delivery statistics'),
      includeTracking: z.boolean().default(false).describe('Include tracking data'),
      limit: z.number().min(1).max(100).default(20).describe('Maximum notifications to return'),
      offset: z.number().min(0).default(0).describe('Notifications to skip for pagination'),
      sortBy: z.enum(['createdAt', 'sentAt', 'priority', 'title']).default('createdAt').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
    }),
    annotations: {
      title: 'List Notifications with Analytics',
      readOnlyHint: true,
      openWorldHint: true, // May query delivery status from external systems
    },
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} } } = context || {};
      const { type, status, priority, dateRange, includeDelivery, includeTracking, limit, offset, sortBy, sortOrder } = input;

      if (log?.info) {
        log.info('Listing notifications', {
          type,
          status,
          priority,
          dateRange,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeDelivery,
          includeTracking,
        };

        if (type !== 'all') {params.type = type;}
        if (status !== 'all') {params.status = status;}
        if (priority !== 'all') {params.priority = priority;}
        if (dateRange?.startDate) {params.startDate = dateRange.startDate;}
        if (dateRange?.endDate) {params.endDate = dateRange.endDate;}

        const response = await apiClient.get('/notifications', { params });

        if (!response.success) {
          throw new UserError(`Failed to list notifications: ${response.error?.message || 'Unknown error'}`);
        }

        const notifications = response.data as MakeNotification[] || [];
        const metadata = response.metadata;

        if (log?.info) {
          log.info('Successfully retrieved notifications', {
            count: notifications.length,
            total: metadata?.total,
          });
        }

        // Create notification analytics
        const analytics = {
          totalNotifications: metadata?.total || notifications.length,
          typeBreakdown: notifications.reduce((acc: Record<string, number>, notif) => {
            acc[notif.type] = (acc[notif.type] || 0) + 1;
            return acc;
          }, {}),
          statusBreakdown: notifications.reduce((acc: Record<string, number>, notif) => {
            acc[notif.status] = (acc[notif.status] || 0) + 1;
            return acc;
          }, {}),
          priorityBreakdown: notifications.reduce((acc: Record<string, number>, notif) => {
            acc[notif.priority] = (acc[notif.priority] || 0) + 1;
            return acc;
          }, {}),
          deliveryAnalytics: includeDelivery ? {
            totalRecipients: notifications.reduce((sum, n) => sum + n.delivery.totalRecipients, 0),
            successfulDeliveries: notifications.reduce((sum, n) => sum + n.delivery.successfulDeliveries, 0),
            failedDeliveries: notifications.reduce((sum, n) => sum + n.delivery.failedDeliveries, 0),
            averageDeliveryRate: notifications.length > 0 ? 
              notifications.reduce((sum, n) => sum + (n.delivery.successfulDeliveries / Math.max(n.delivery.totalRecipients, 1)), 0) / notifications.length * 100 : 0,
          } : undefined,
          channelUsage: notifications.reduce((acc: Record<string, number>, notif) => {
            Object.entries(notif.channels).forEach(([channel, enabled]) => {
              if (enabled) {
                acc[channel] = (acc[channel] || 0) + 1;
              }
            });
            return acc;
          }, {}),
        };

        return formatSuccessResponse({
          notifications: notifications.map(notif => ({
            ...notif,
            recipients: {
              total: notif.delivery.totalRecipients,
              // Hide specific recipient details for privacy
            },
          })),
          analytics,
          pagination: {
            total: metadata?.total || notifications.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + notifications.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error listing notifications', { error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list notifications: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add notification management tools to FastMCP server
 * 
 * This function adds the core notification tools:
 * - create-notification
 * - get-email-preferences
 * - update-email-preferences
 * - create-notification-template
 * - list-notifications
 */
export function addNotificationTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'NotificationManager' });
  
  componentLogger.info('Adding notification management tools');

  // Add core notification tools
  addCreateNotificationTool(server, apiClient, componentLogger);
  addGetEmailPreferencesTool(server, apiClient, componentLogger);
  addUpdateEmailPreferencesTool(server, apiClient, componentLogger);
  addCreateNotificationTemplateTool(server, apiClient, componentLogger);
  addListNotificationsTool(server, apiClient, componentLogger);

  componentLogger.info('Notification management tools added successfully');
}

export default addNotificationTools;