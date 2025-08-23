/**
 * Notification and Email Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing notifications, email preferences, and custom data structures
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { addNotificationTools as addNotificationManagementTools } from './notifications/notification-manager.js';
import { addDataStructureTools } from './notifications/datastructure-manager.js';

// Notification management types
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

export interface MakeCustomDataStructure {
  id: number;
  name: string;
  description?: string;
  type: 'schema' | 'template' | 'validation' | 'transformation';
  organizationId?: number;
  teamId?: number;
  scope: 'global' | 'organization' | 'team' | 'personal';
  structure: {
    schema: Record<string, unknown>; // JSON Schema
    version: string;
    format: 'json' | 'xml' | 'yaml' | 'csv' | 'custom';
  };
  validation: {
    enabled: boolean;
    strict: boolean;
    rules: Array<{
      field: string;
      type: 'required' | 'format' | 'range' | 'custom';
      parameters: unknown;
      message: string;
    }>;
  };
  transformation: {
    enabled: boolean;
    mappings: Array<{
      source: string;
      target: string;
      function?: string;
      parameters?: unknown;
    }>;
    filters: Array<{
      field: string;
      operator: string;
      value: unknown;
    }>;
  };
  usage: {
    scenariosUsing: number;
    lastUsed?: string;
    validationCount: number;
    errorRate: number;
  };
  versions: Array<{
    version: string;
    changes: string;
    createdAt: string;
    createdBy: number;
  }>;
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Data structure management interfaces for type safety
export interface DataStructureUpdateData {
  name?: string;
  description?: string | null;
  structure?: {
    schema?: Record<string, unknown>;
    version?: string;
    format?: 'json' | 'xml' | 'yaml' | 'csv' | 'custom';
  };
  validation?: {
    enabled?: boolean;
    strict?: boolean;
    rules?: Array<{
      field: string;
      type: 'required' | 'format' | 'range' | 'custom';
      parameters?: unknown;
      message: string;
    }>;
  };
  transformation?: {
    enabled?: boolean;
    mappings?: Array<{
      source: string;
      target: string;
      type: 'direct' | 'computed' | 'lookup' | 'constant';
      parameters?: unknown;
    }>;
    filters?: Array<{
      field: string;
      operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'gt' | 'lt' | 'gte' | 'lte' | 'in' | 'notIn';
      value: unknown;
      caseSensitive?: boolean;
    }>;
  };
}

export interface DataStructureListResponse {
  dataStructures: MakeCustomDataStructure[];
  pagination: {
    total: number;
    offset: number;
    limit: number;
    hasMore: boolean;
  };
  filters: {
    type: string;
    scope: string;
    format: string;
    search?: string;
  };
}

export interface DataStructureDependency {
  type: string;
  id: string;
  name: string;
  usage: string;
}

export interface DataStructureDependencyResponse {
  dependencies: DataStructureDependency[];
}

export interface DataStructureArchiveInfo {
  archiveId: string;
  archiveUrl: string;
}

export interface DataStructureArchiveResponse {
  archiveId: string;
  downloadUrl: string;
}

export interface DataStructureUsageStats {
  scenariosUsing: number;
  lastUsed?: string;
  validationCount: number;
  errorRate: number;
  transformationCount: number;
  averageValidationTime: number;
  successRate: number;
}

export interface DataStructureValidationHistoryItem {
  timestamp: string;
  result: 'success' | 'failure';
  errors: string[];
  processingTime: number;
}

export interface DataStructureTransformationHistoryItem {
  timestamp: string;
  result: 'success' | 'failure';
  inputRecords: number;
  outputRecords: number;
  processingTime: number;
}

export interface DataStructureWithStats extends MakeCustomDataStructure {
  usage: DataStructureUsageStats;
  validationHistory?: DataStructureValidationHistoryItem[];
  transformationHistory?: DataStructureTransformationHistoryItem[];
}


/**
 * Add notification and email management tools to FastMCP server
 */
export function addNotificationTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'NotificationTools' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding notification and email management tools');

  // Add notification management tools (extracted to separate module)
  addNotificationManagementTools(server, apiClient);

  // Add data structure management tools (extracted to separate module)
  addDataStructureTools(server, apiClient);

  componentLogger.info('Notification and email management tools added successfully');
}

export default addNotificationTools;