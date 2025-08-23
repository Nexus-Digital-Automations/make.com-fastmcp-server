/**
 * Billing and Payment Management Tools for Make.com FastMCP Server
 * Comprehensive tools for accessing billing information, payment methods, and financial data
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Billing management types
export interface MakeBillingAccount {
  id: number;
  organizationId: number;
  organizationName: string;
  accountStatus: 'active' | 'suspended' | 'cancelled' | 'pending';
  billingPlan: {
    name: string;
    type: 'free' | 'starter' | 'professional' | 'team' | 'enterprise';
    price: number;
    currency: string;
    billingCycle: 'monthly' | 'annual';
    features: string[];
    limits: {
      operations: number;
      dataTransfer: number; // GB
      scenarios: number;
      users: number;
      customApps: number;
    };
  };
  usage: {
    currentPeriod: {
      startDate: string;
      endDate: string;
      operations: {
        used: number;
        limit: number;
        percentage: number;
      };
      dataTransfer: {
        used: number; // GB
        limit: number; // GB
        percentage: number;
      };
      scenarios: {
        active: number;
        limit: number;
      };
      users: {
        active: number;
        limit: number;
      };
    };
    history: Array<{
      period: string;
      operations: number;
      dataTransfer: number;
      cost: number;
    }>;
  };
  billing: {
    nextBillingDate: string;
    lastBillingDate: string;
    currentBalance: number;
    paymentStatus: 'current' | 'overdue' | 'failed' | 'processing';
    autoRenewal: boolean;
  };
  paymentMethods: Array<{
    id: string;
    type: 'credit_card' | 'bank_account' | 'paypal' | 'wire_transfer';
    isDefault: boolean;
    lastFour: string;
    expiryDate?: string;
    status: 'active' | 'expired' | 'failed';
  }>;
  contacts: {
    billing: {
      name: string;
      email: string;
      phone?: string;
    };
    technical: {
      name: string;
      email: string;
      phone?: string;
    };
  };
  taxInfo: {
    taxId?: string;
    vatNumber?: string;
    country: string;
    region?: string;
    taxExempt: boolean;
  };
  createdAt: string;
  updatedAt: string;
}

export interface MakeInvoice {
  id: string;
  number: string;
  organizationId: number;
  status: 'draft' | 'sent' | 'paid' | 'overdue' | 'cancelled';
  amount: {
    subtotal: number;
    tax: number;
    total: number;
    currency: string;
  };
  period: {
    startDate: string;
    endDate: string;
  };
  lineItems: Array<{
    description: string;
    quantity: number;
    unitPrice: number;
    total: number;
    type: 'subscription' | 'usage' | 'addon' | 'support';
  }>;
  payments: Array<{
    id: string;
    amount: number;
    method: string;
    status: 'pending' | 'completed' | 'failed';
    processedAt?: string;
  }>;
  dueDate: string;
  issuedDate: string;
  paidDate?: string;
  downloadUrl?: string;
}

export interface MakeUsageMetrics {
  organizationId: number;
  period: {
    startDate: string;
    endDate: string;
  };
  metrics: {
    operations: {
      total: number;
      byScenario: Array<{
        scenarioId: number;
        scenarioName: string;
        operations: number;
        cost: number;
      }>;
      byApp: Array<{
        appName: string;
        operations: number;
        cost: number;
      }>;
      byTeam: Array<{
        teamId: number;
        teamName: string;
        operations: number;
        cost: number;
      }>;
    };
    dataTransfer: {
      total: number; // GB
      byDirection: {
        incoming: number;
        outgoing: number;
      };
      byRegion: Array<{
        region: string;
        transfer: number;
        cost: number;
      }>;
    };
    storage: {
      dataStores: number; // GB
      logs: number; // GB
      backups: number; // GB
      total: number; // GB
      cost: number;
    };
    support: {
      tickets: number;
      priority: {
        low: number;
        medium: number;
        high: number;
        critical: number;
      };
      responseTime: number; // hours
      cost: number;
    };
  };
  costs: {
    breakdown: {
      subscription: number;
      operations: number;
      dataTransfer: number;
      storage: number;
      support: number;
      addons: number;
    };
    total: number;
    currency: string;
    projectedMonthly: number;
  };
  recommendations: Array<{
    type: 'cost_optimization' | 'plan_upgrade' | 'usage_alert' | 'efficiency';
    title: string;
    description: string;
    impact: 'low' | 'medium' | 'high';
    savings?: number;
  }>;
}

// Advanced budgeting and cost control types
export interface MakeBudget {
  id: string;
  organizationId: number;
  name: string;
  description: string;
  type: 'organization' | 'team' | 'project' | 'scenario';
  scope: {
    organizationId?: number;
    teamIds?: number[];
    projectIds?: string[];
    scenarioIds?: number[];
  };
  budget: {
    amount: number;
    currency: string;
    period: 'monthly' | 'quarterly' | 'annually';
    startDate: string;
    endDate?: string;
  };
  categories: {
    operations?: {
      limit: number;
      cost: number;
    };
    dataTransfer?: {
      limit: number; // GB
      cost: number;
    };
    storage?: {
      limit: number; // GB
      cost: number;
    };
    addons?: {
      limit: number;
      cost: number;
    };
  };
  thresholds: Array<{
    percentage: number; // 25, 50, 75, 90, 100
    action: 'notify' | 'warn' | 'restrict' | 'pause';
    notificationChannels: Array<'email' | 'webhook' | 'sms' | 'slack'>;
  }>;
  currentSpend: {
    amount: number;
    percentage: number;
    breakdown: {
      operations: number;
      dataTransfer: number;
      storage: number;
      addons: number;
    };
    lastUpdated: string;
  };
  alerts: Array<{
    id: string;
    level: 'info' | 'warning' | 'critical';
    threshold: number;
    triggeredAt: string;
    resolved: boolean;
    message: string;
  }>;
  status: 'active' | 'exceeded' | 'paused' | 'expired';
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface MakeCostAlert {
  id: string;
  organizationId: number;
  name: string;
  description: string;
  conditions: {
    budgetIds?: string[];
    costThreshold?: {
      amount: number;
      currency: string;
      period: 'daily' | 'weekly' | 'monthly';
    };
    usageThreshold?: {
      operations?: number;
      dataTransfer?: number; // GB
      percentage?: number; // of plan limit
    };
    scenarioIds?: number[];
    teamIds?: number[];
  };
  notifications: {
    channels: Array<{
      type: 'email' | 'webhook' | 'sms' | 'slack';
      target: string; // email address, webhook URL, phone, slack channel
      template?: string;
    }>;
    frequency: 'immediate' | 'hourly' | 'daily' | 'weekly';
    escalation: {
      enabled: boolean;
      after: number; // minutes
      channels: Array<{
        type: 'email' | 'webhook' | 'sms' | 'slack';
        target: string;
      }>;
    };
  };
  actions: Array<{
    type: 'pause_scenarios' | 'restrict_operations' | 'notify_only' | 'webhook';
    configuration: Record<string, unknown>;
    delay: number; // minutes
  }>;
  status: 'active' | 'triggered' | 'paused' | 'resolved';
  lastTriggered?: string;
  triggerCount: number;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface MakeCostProjection {
  organizationId: number;
  projectionDate: string;
  period: {
    startDate: string;
    endDate: string;
    type: 'monthly' | 'quarterly' | 'annually';
  };
  methodology: {
    algorithm: 'linear' | 'exponential' | 'seasonal' | 'ml_based';
    confidence: number; // 0-100
    basedOnDays: number;
    factors: Array<{
      name: string;
      weight: number;
      impact: number;
    }>;
  };
  projections: {
    conservative: {
      total: number;
      breakdown: {
        operations: number;
        dataTransfer: number;
        storage: number;
        support: number;
        addons: number;
      };
      confidence: number;
    };
    realistic: {
      total: number;
      breakdown: {
        operations: number;
        dataTransfer: number;
        storage: number;
        support: number;
        addons: number;
      };
      confidence: number;
    };
    optimistic: {
      total: number;
      breakdown: {
        operations: number;
        dataTransfer: number;
        storage: number;
        support: number;
        addons: number;
      };
      confidence: number;
    };
  };
  trends: {
    growthRate: {
      monthly: number; // percentage
      quarterly: number;
      annually: number;
    };
    seasonality: Array<{
      month: number;
      multiplier: number;
    }>;
    anomalies: Array<{
      date: string;
      deviation: number;
      cause?: string;
    }>;
  };
  budgetComparison: Array<{
    budgetId: string;
    budgetName: string;
    budgetAmount: number;
    projectedSpend: number;
    variance: number;
    risk: 'low' | 'medium' | 'high';
  }>;
  recommendations: Array<{
    type: 'budget_adjustment' | 'cost_optimization' | 'plan_change' | 'usage_control';
    priority: 'low' | 'medium' | 'high' | 'critical';
    title: string;
    description: string;
    impact: {
      cost: number;
      timeframe: string;
    };
    actions: string[];
  }>;
  currency: string;
  generatedAt: string;
}

// Input validation schemas
const BillingAccountSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  includeUsage: z.boolean().default(true).describe('Include current usage statistics'),
  includeHistory: z.boolean().default(false).describe('Include historical usage data'),
  includePaymentMethods: z.boolean().default(true).describe('Include payment method information'),
}).strict();

const _InvoiceListSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  status: z.enum(['draft', 'sent', 'paid', 'overdue', 'cancelled', 'all']).default('all').describe('Filter by invoice status'),
  dateRange: z.object({
    startDate: z.string().optional().describe('Start date (YYYY-MM-DD)'),
    endDate: z.string().optional().describe('End date (YYYY-MM-DD)'),
  }).optional().describe('Date range filter'),
  includeLineItems: z.boolean().default(false).describe('Include detailed line items'),
  includePayments: z.boolean().default(false).describe('Include payment information'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum invoices to return'),
  offset: z.number().min(0).default(0).describe('Invoices to skip for pagination'),
  sortBy: z.enum(['date', 'amount', 'status', 'number']).default('date').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
}).strict();

const _UsageMetricsSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  period: z.enum(['current', 'last_month', 'last_3_months', 'last_6_months', 'last_year', 'custom']).default('current').describe('Usage period'),
  customPeriod: z.object({
    startDate: z.string().describe('Start date (YYYY-MM-DD)'),
    endDate: z.string().describe('End date (YYYY-MM-DD)'),
  }).optional().describe('Custom date range (required if period=custom)'),
  breakdown: z.array(z.enum(['scenario', 'app', 'team', 'region', 'time'])).default(['scenario']).describe('Usage breakdown dimensions'),
  includeProjections: z.boolean().default(true).describe('Include cost projections'),
  includeRecommendations: z.boolean().default(true).describe('Include optimization recommendations'),
}).strict();

const _PaymentMethodSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  type: z.enum(['credit_card', 'bank_account', 'paypal', 'wire_transfer']).describe('Payment method type'),
  details: z.object({
    cardNumber: z.string().optional().describe('Credit card number (for credit_card)'),
    expiryMonth: z.number().min(1).max(12).optional().describe('Expiry month (for credit_card)'),
    expiryYear: z.number().min(2024).optional().describe('Expiry year (for credit_card)'),
    cvv: z.string().optional().describe('CVV code (for credit_card)'),
    accountNumber: z.string().optional().describe('Bank account number (for bank_account)'),
    routingNumber: z.string().optional().describe('Routing number (for bank_account)'),
    paypalEmail: z.string().email().optional().describe('PayPal email (for paypal)'),
    wireDetails: z.object({
      bankName: z.string(),
      accountName: z.string(),
      accountNumber: z.string(),
      swiftCode: z.string(),
    }).optional().describe('Wire transfer details (for wire_transfer)'),
  }).describe('Payment method details'),
  billingAddress: z.object({
    name: z.string().min(1).describe('Billing name'),
    address1: z.string().min(1).describe('Address line 1'),
    address2: z.string().optional().describe('Address line 2'),
    city: z.string().min(1).describe('City'),
    state: z.string().optional().describe('State/Province'),
    postalCode: z.string().min(1).describe('Postal code'),
    country: z.string().min(2).max(2).describe('Country code (ISO 2-letter)'),
  }).describe('Billing address'),
  setAsDefault: z.boolean().default(false).describe('Set as default payment method'),
}).strict();

const _BillingUpdateSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  contacts: z.object({
    billing: z.object({
      name: z.string().min(1).describe('Billing contact name'),
      email: z.string().email().describe('Billing contact email'),
      phone: z.string().optional().describe('Billing contact phone'),
    }).optional(),
    technical: z.object({
      name: z.string().min(1).describe('Technical contact name'),
      email: z.string().email().describe('Technical contact email'),
      phone: z.string().optional().describe('Technical contact phone'),
    }).optional(),
  }).optional().describe('Contact information updates'),
  taxInfo: z.object({
    taxId: z.string().optional().describe('Tax ID number'),
    vatNumber: z.string().optional().describe('VAT number'),
    country: z.string().min(2).max(2).describe('Country code (ISO 2-letter)'),
    region: z.string().optional().describe('State/Province'),
    taxExempt: z.boolean().optional().describe('Tax exemption status'),
  }).optional().describe('Tax information updates'),
  autoRenewal: z.boolean().optional().describe('Auto-renewal setting'),
}).strict();

// Advanced budgeting and cost control schemas
const _SetBudgetSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  name: z.string().min(1).max(100).describe('Budget name'),
  description: z.string().max(500).optional().describe('Budget description'),
  type: z.enum(['organization', 'team', 'project', 'scenario']).describe('Budget scope type'),
  scope: z.object({
    organizationId: z.number().min(1).optional().describe('Organization ID (for organization budgets)'),
    teamIds: z.array(z.number().min(1)).optional().describe('Team IDs (for team budgets)'),
    projectIds: z.array(z.string().min(1)).optional().describe('Project IDs (for project budgets)'),
    scenarioIds: z.array(z.number().min(1)).optional().describe('Scenario IDs (for scenario budgets)'),
  }).describe('Budget scope definition'),
  budget: z.object({
    amount: z.number().min(0).describe('Budget amount'),
    currency: z.string().min(3).max(3).default('USD').describe('Currency code (ISO 3-letter)'),
    period: z.enum(['monthly', 'quarterly', 'annually']).describe('Budget period'),
    startDate: z.string().describe('Start date (YYYY-MM-DD)'),
    endDate: z.string().optional().describe('End date (YYYY-MM-DD)'),
  }).describe('Budget configuration'),
  categories: z.object({
    operations: z.object({
      limit: z.number().min(0).describe('Operations limit'),
      cost: z.number().min(0).describe('Operations cost allocation'),
    }).optional(),
    dataTransfer: z.object({
      limit: z.number().min(0).describe('Data transfer limit (GB)'),
      cost: z.number().min(0).describe('Data transfer cost allocation'),
    }).optional(),
    storage: z.object({
      limit: z.number().min(0).describe('Storage limit (GB)'),
      cost: z.number().min(0).describe('Storage cost allocation'),
    }).optional(),
    addons: z.object({
      limit: z.number().min(0).describe('Addons cost limit'),
      cost: z.number().min(0).describe('Addons cost allocation'),
    }).optional(),
  }).optional().describe('Budget category limits'),
  thresholds: z.array(z.object({
    percentage: z.number().min(1).max(100).describe('Threshold percentage'),
    action: z.enum(['notify', 'warn', 'restrict', 'pause']).describe('Action to take'),
    notificationChannels: z.array(z.enum(['email', 'webhook', 'sms', 'slack'])).describe('Notification channels'),
  })).min(1).describe('Budget thresholds and actions'),
}).strict();

const _CreateCostAlertSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  name: z.string().min(1).max(100).describe('Alert name'),
  description: z.string().max(500).optional().describe('Alert description'),
  conditions: z.object({
    budgetIds: z.array(z.string().min(1)).optional().describe('Budget IDs to monitor'),
    costThreshold: z.object({
      amount: z.number().min(0).describe('Cost threshold amount'),
      currency: z.string().min(3).max(3).default('USD').describe('Currency code'),
      period: z.enum(['daily', 'weekly', 'monthly']).describe('Threshold period'),
    }).optional(),
    usageThreshold: z.object({
      operations: z.number().min(0).optional().describe('Operations threshold'),
      dataTransfer: z.number().min(0).optional().describe('Data transfer threshold (GB)'),
      percentage: z.number().min(1).max(100).optional().describe('Percentage of plan limit'),
    }).optional(),
    scenarioIds: z.array(z.number().min(1)).optional().describe('Scenario IDs to monitor'),
    teamIds: z.array(z.number().min(1)).optional().describe('Team IDs to monitor'),
  }).describe('Alert trigger conditions'),
  notifications: z.object({
    channels: z.array(z.object({
      type: z.enum(['email', 'webhook', 'sms', 'slack']).describe('Notification type'),
      target: z.string().min(1).describe('Notification target (email, URL, phone, channel)'),
      template: z.string().optional().describe('Notification template'),
    })).min(1).describe('Notification channels'),
    frequency: z.enum(['immediate', 'hourly', 'daily', 'weekly']).describe('Notification frequency'),
    escalation: z.object({
      enabled: z.boolean().describe('Enable escalation'),
      after: z.number().min(1).describe('Escalation delay (minutes)'),
      channels: z.array(z.object({
        type: z.enum(['email', 'webhook', 'sms', 'slack']).describe('Escalation notification type'),
        target: z.string().min(1).describe('Escalation target'),
      })).describe('Escalation channels'),
    }).describe('Escalation configuration'),
  }).describe('Notification configuration'),
  actions: z.array(z.object({
    type: z.enum(['pause_scenarios', 'restrict_operations', 'notify_only', 'webhook']).describe('Action type'),
    configuration: z.record(z.string(), z.unknown()).describe('Action configuration'),
    delay: z.number().min(0).describe('Action delay (minutes)'),
  })).describe('Alert actions'),
}).strict();

const _GetCostProjectionSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  period: z.object({
    type: z.enum(['monthly', 'quarterly', 'annually']).describe('Projection period type'),
    count: z.number().min(1).max(12).default(1).describe('Number of periods to project'),
    startDate: z.string().optional().describe('Projection start date (YYYY-MM-DD)'),
  }).describe('Projection period configuration'),
  algorithm: z.enum(['linear', 'exponential', 'seasonal', 'ml_based']).default('seasonal').describe('Projection algorithm'),
  basedOnDays: z.number().min(7).max(365).default(90).describe('Historical days to base projection on'),
  includeSeasonality: z.boolean().default(true).describe('Include seasonal adjustments'),
  includeBudgetComparison: z.boolean().default(true).describe('Compare against budgets'),
  includeRecommendations: z.boolean().default(true).describe('Include optimization recommendations'),
  confidenceLevel: z.number().min(50).max(99).default(95).describe('Confidence level percentage'),
}).strict();

const _PauseHighCostScenariosSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Organization ID (defaults to current user org)'),
  criteria: z.object({
    costThreshold: z.object({
      amount: z.number().min(0).describe('Cost threshold amount'),
      currency: z.string().min(3).max(3).default('USD').describe('Currency code'),
      period: z.enum(['hourly', 'daily', 'weekly', 'monthly']).describe('Threshold period'),
    }).optional(),
    budgetExceedance: z.object({
      budgetIds: z.array(z.string().min(1)).describe('Budget IDs to check'),
      percentage: z.number().min(50).max(100).describe('Budget exceedance percentage'),
    }).optional(),
    operationsThreshold: z.object({
      operations: z.number().min(1).describe('Operations threshold'),
      period: z.enum(['hourly', 'daily']).describe('Operations period'),
    }).optional(),
    scenarioIds: z.array(z.number().min(1)).optional().describe('Specific scenarios to evaluate (optional)'),
  }).describe('Pause criteria'),
  action: z.enum(['pause', 'restrict', 'simulate']).default('simulate').describe('Action to take'),
  notification: z.object({
    enabled: z.boolean().default(true).describe('Send notifications'),
    channels: z.array(z.enum(['email', 'webhook', 'slack'])).default(['email']).describe('Notification channels'),
    includeDetails: z.boolean().default(true).describe('Include scenario details'),
  }).describe('Notification configuration'),
  dryRun: z.boolean().default(true).describe('Simulate action without executing'),
}).strict();

// ==================== BILLING HELPER FUNCTIONS ====================

/**
 * Build endpoint URL based on organization ID
 */
function buildBillingEndpoint(organizationId?: number): string {
  return organizationId 
    ? `/organizations/${organizationId}/billing/account`
    : '/billing/account';
}

/**
 * Generate billing account summary data
 */
function generateAccountSummary(account: MakeBillingAccount): Record<string, unknown> {
  return {
    accountId: account.id,
    organizationId: account.organizationId,
    currentPlan: account.billingPlan.name,
    billingCycle: account.billingPlan.billingCycle,
    status: account.accountStatus,
    nextBillingDate: account.billing.nextBillingDate,
    currency: account.billingPlan.currency,
    autoRenewal: account.billing.autoRenewal,
  };
}

/**
 * Generate plan details data
 */
function generatePlanDetails(account: MakeBillingAccount): Record<string, unknown> {
  return {
    name: account.billingPlan.name,
    tier: account.billingPlan.type,
    price: account.billingPlan.price,
    currency: account.billingPlan.currency,
    includedOperations: account.billingPlan.limits.operations,
    includedDataTransfer: account.billingPlan.limits.dataTransfer,
    includedScenarios: account.billingPlan.limits.scenarios,
  };
}

/**
 * Generate current usage data if requested
 */
function generateCurrentUsage(account: MakeBillingAccount, includeUsage: boolean): Record<string, unknown> | undefined {
  if (!includeUsage) {
    return undefined;
  }
  return {
    operations: account.usage?.currentPeriod.operations,
    dataTransfer: account.usage?.currentPeriod.dataTransfer,
    scenarios: account.usage?.currentPeriod.scenarios,
    billingPeriodStart: account.usage?.currentPeriod.startDate,
    billingPeriodEnd: account.usage?.currentPeriod.endDate,
  };
}

/**
 * Generate payment information if requested
 */
function generatePaymentInfo(account: MakeBillingAccount, includePaymentMethods: boolean): Record<string, unknown> | undefined {
  if (!includePaymentMethods) {
    return undefined;
  }
  return {
    primaryMethod: account.paymentMethods?.find(pm => pm.isDefault),
    methodCount: account.paymentMethods?.length || 0,
    lastChargeDate: account.billing.lastBillingDate,
    nextChargeAmount: account.billing.currentBalance,
  };
}

/**
 * Log billing account retrieval information
 */
function logBillingAccountInfo(
  log: { info?: (message: string, meta?: unknown) => void },
  account: MakeBillingAccount
): void {
  if (log?.info) {
    log.info('Successfully retrieved billing account', {
      accountId: account.id,
      currentPlan: account.billingPlan.name,
      billingCycle: account.billingPlan.billingCycle,
      status: account.accountStatus,
    });
  }
}

/**
 * Handle billing account errors with proper logging
 */
function handleBillingError(
  error: unknown,
  organizationId: number | undefined,
  log: { error?: (message: string, meta?: unknown) => void }
): never {
  const errorMessage = error instanceof Error ? error.message : String(error);
  if (log?.error) {
    log.error('Error getting billing account', { organizationId, error: errorMessage });
  }
  if (error instanceof UserError) {
    throw error;
  }
  throw new UserError(`Failed to get billing account: ${errorMessage}`);
}

/**
 * Add get billing account tool
 */
function addGetBillingAccountTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'get-billing-account',
    description: 'Get comprehensive billing account information including plan, usage, and payment details',
    parameters: BillingAccountSchema,
    annotations: {
      title: 'Get Billing Account Information',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { organizationId, includeUsage, includeHistory, includePaymentMethods } = input;

      if (log?.info) {
        log.info('Getting billing account information', {
          organizationId,
          includeUsage,
          includeHistory,
          includePaymentMethods,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        const params: Record<string, unknown> = {
          includeUsage,
          includeHistory,
          includePaymentMethods,
        };

        const endpoint = buildBillingEndpoint(organizationId);

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get billing account: ${response.error?.message || 'Unknown error'}`);
        }

        const account = response.data as MakeBillingAccount;
        if (!account) {
          throw new UserError('Billing account not found');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        logBillingAccountInfo(log, account);

        return formatSuccessResponse({
          account,
          summary: generateAccountSummary(account),
          planDetails: generatePlanDetails(account),
          currentUsage: generateCurrentUsage(account, includeUsage),
          paymentInfo: generatePaymentInfo(account, includePaymentMethods),
        }).content[0].text;
      } catch (error: unknown) {
        handleBillingError(error, organizationId, log);
      }
    },
  });
}

/**
 * Add billing and payment management tools to FastMCP server
 */
export function addBillingTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'BillingTools' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding billing and payment management tools');
  
  // Add core billing tools
  addGetBillingAccountTool(server, apiClient);
  addInvoiceTools(server, apiClient);
  addUsageMetricsTools(server, apiClient);
  addPaymentTools(server, apiClient);
  addBudgetTools(server, apiClient);
  addCostManagementTools(server, apiClient);
  
  componentLogger.info('Billing and payment management tools added successfully');
}

/**
 * Add invoice-related tools
 */
function addInvoiceTools(_server: FastMCP, _apiClient: MakeApiClient): void {
  // This will contain list-invoices tool
}

/**
 * Add usage metrics tools
 */
function addUsageMetricsTools(_server: FastMCP, _apiClient: MakeApiClient): void {
  // This will contain get-usage-metrics tool
}

/**
 * Add payment-related tools
 */
function addPaymentTools(_server: FastMCP, _apiClient: MakeApiClient): void {
  // This will contain add-payment-method, update-billing-info tools
}

/**
 * Add budget management tools
 */
function addBudgetTools(_server: FastMCP, _apiClient: MakeApiClient): void {
  // This will contain set-budget tool
}

/**
 * Add cost management and alerting tools
 */
function addCostManagementTools(_server: FastMCP, _apiClient: MakeApiClient): void {
  // This will contain create-cost-alert, get-cost-projection, pause-high-cost-scenarios tools
}

export default addBillingTools;
