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

const InvoiceListSchema = z.object({
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

const UsageMetricsSchema = z.object({
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

const PaymentMethodSchema = z.object({
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

const BillingUpdateSchema = z.object({
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
const SetBudgetSchema = z.object({
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

const CreateCostAlertSchema = z.object({
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

const GetCostProjectionSchema = z.object({
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

const PauseHighCostScenariosSchema = z.object({
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

/**
 * Add billing and payment management tools to FastMCP server
 */
export function addBillingTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'BillingTools' });
  
  componentLogger.info('Adding billing and payment management tools');

  // Get billing account information
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

      if (log && log.info) {
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

        let endpoint = '/billing/account';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/account`;
        }

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get billing account: ${response.error?.message || 'Unknown error'}`);
        }

        const account = response.data as MakeBillingAccount;
        if (!account) {
          throw new UserError('Billing account information not found');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log && log.info) {
          log.info('Successfully retrieved billing account', {
            organizationId: account.organizationId,
            plan: account.billingPlan.name,
            status: account.accountStatus,
            nextBilling: account.billing.nextBillingDate,
          });
        }

        return formatSuccessResponse({
          account: {
            ...account,
            paymentMethods: includePaymentMethods && account.paymentMethods ? account.paymentMethods.map(pm => ({
              ...pm,
              // Mask sensitive payment information
              lastFour: pm.lastFour,
              type: pm.type,
              status: pm.status,
              isDefault: pm.isDefault,
            })) : undefined,
          },
          summary: {
            organizationName: account.organizationName,
            plan: {
              name: account.billingPlan.name,
              type: account.billingPlan.type,
              price: account.billingPlan.price,
              currency: account.billingPlan.currency,
              cycle: account.billingPlan.billingCycle,
            },
            usage: includeUsage && account.usage && account.usage.currentPeriod ? {
              operations: {
                used: account.usage.currentPeriod.operations?.used || 0,
                limit: account.usage.currentPeriod.operations?.limit || 0,
                percentage: account.usage.currentPeriod.operations?.percentage || 0,
              },
              dataTransfer: {
                used: account.usage.currentPeriod.dataTransfer?.used || 0,
                limit: account.usage.currentPeriod.dataTransfer?.limit || 0,
                percentage: account.usage.currentPeriod.dataTransfer?.percentage || 0,
              },
            } : undefined,
            billing: {
              status: account.billing?.paymentStatus || 'unknown',
              nextBillingDate: account.billing?.nextBillingDate || 'unknown',
              balance: account.billing?.currentBalance || 0,
              autoRenewal: account.billing?.autoRenewal || false,
            },
          },
          alerts: [
            (account.usage?.currentPeriod?.operations?.percentage || 0) > 80 ? 'Operations usage above 80%' : null,
            (account.usage?.currentPeriod?.dataTransfer?.percentage || 0) > 80 ? 'Data transfer usage above 80%' : null,
            account.billing?.paymentStatus === 'overdue' ? 'Payment overdue' : null,
            account.billing?.paymentStatus === 'failed' ? 'Payment failed' : null,
          ].filter(Boolean),
        }, "Billing account information retrieved successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting billing account', { organizationId, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get billing account: ${errorMessage}`);
      }
    },
  });

  // List invoices
  server.addTool({
    name: 'list-invoices',
    description: 'List and filter invoices with payment status and detailed breakdown',
    parameters: InvoiceListSchema,
    annotations: {
      title: 'List Invoices and Payment History',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }): Promise<string> => {
      const { organizationId, status, dateRange, includeLineItems, includePayments, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing invoices', {
        organizationId,
        status,
        dateRange,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeLineItems,
          includePayments,
        };

        if (status !== 'all') {params.status = status;}
        if (dateRange?.startDate) {params.startDate = dateRange.startDate;}
        if (dateRange?.endDate) {params.endDate = dateRange.endDate;}

        let endpoint = '/billing/invoices';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/invoices`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to list invoices: ${response.error?.message || 'Unknown error'}`);
        }

        const invoices = response.data as MakeInvoice[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved invoices', {
          count: invoices.length,
          total: metadata?.total,
        });

        // Create financial analysis
        const analysis = {
          totalInvoices: metadata?.total || invoices.length,
          statusBreakdown: invoices.reduce((acc: Record<string, number>, invoice) => {
            acc[invoice.status] = (acc[invoice.status] || 0) + 1;
            return acc;
          }, {}),
          financialSummary: {
            totalAmount: invoices.reduce((sum, inv) => sum + inv.amount.total, 0),
            paidAmount: invoices.filter(inv => inv.status === 'paid').reduce((sum, inv) => sum + inv.amount.total, 0),
            outstandingAmount: invoices.filter(inv => ['sent', 'overdue'].includes(inv.status)).reduce((sum, inv) => sum + inv.amount.total, 0),
            overdueAmount: invoices.filter(inv => inv.status === 'overdue').reduce((sum, inv) => sum + inv.amount.total, 0),
            currency: invoices[0]?.amount.currency || 'USD',
          },
          paymentAnalysis: {
            averagePaymentTime: 0, // Would be calculated from payment data
            onTimePayments: invoices.filter(inv => inv.status === 'paid' && inv.paidDate && inv.paidDate <= inv.dueDate).length,
            latePayments: invoices.filter(inv => inv.status === 'paid' && inv.paidDate && inv.paidDate > inv.dueDate).length,
            pendingPayments: invoices.filter(inv => ['sent', 'overdue'].includes(inv.status)).length,
          },
          recentInvoices: invoices
            .sort((a, b) => new Date(b.issuedDate).getTime() - new Date(a.issuedDate).getTime())
            .slice(0, 5)
            .map(inv => ({
              number: inv.number,
              amount: inv.amount.total,
              status: inv.status,
              issuedDate: inv.issuedDate,
              dueDate: inv.dueDate,
            })),
        };

        return formatSuccessResponse({
          invoices,
          analysis,
          pagination: {
            total: metadata?.total || invoices.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + invoices.length),
          },
        }, "Invoices retrieved successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing invoices', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list invoices: ${errorMessage}`);
      }
    },
  });

  // Get usage metrics
  server.addTool({
    name: 'get-usage-metrics',
    description: 'Get detailed usage metrics and cost breakdown with optimization recommendations',
    parameters: UsageMetricsSchema,
    annotations: {
      title: 'Get Usage Metrics and Cost Analysis',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { organizationId, period, customPeriod, breakdown, includeProjections, includeRecommendations } = input;

      log.info('Getting usage metrics', {
        organizationId,
        period,
        breakdown,
        includeProjections,
        includeRecommendations,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        if (period === 'custom' && !customPeriod) {
          throw new UserError('Custom period dates are required when period is set to custom');
        }

        const params: Record<string, unknown> = {
          period,
          breakdown: breakdown.join(','),
          includeProjections,
          includeRecommendations,
        };

        if (customPeriod) {
          params.startDate = customPeriod.startDate;
          params.endDate = customPeriod.endDate;
        }

        let endpoint = '/billing/usage';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/usage`;
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get usage metrics: ${response.error?.message || 'Unknown error'}`);
        }

        const metrics = response.data as MakeUsageMetrics;
        if (!metrics) {
          throw new UserError('Usage metrics not found');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully retrieved usage metrics', {
          organizationId: metrics.organizationId,
          period: metrics.period,
          totalOperations: metrics.metrics.operations.total,
          totalCost: metrics.costs.total,
        });

        return formatSuccessResponse({
          metrics,
          summary: {
            organizationId: metrics.organizationId,
            period: metrics.period,
            usage: {
              operations: metrics.metrics.operations.total,
              dataTransfer: metrics.metrics.dataTransfer.total,
              storage: metrics.metrics.storage.total,
            },
            costs: {
              total: metrics.costs.total,
              currency: metrics.costs.currency,
              breakdown: metrics.costs.breakdown,
              projectedMonthly: includeProjections ? metrics.costs.projectedMonthly : undefined,
            },
            topConsumers: {
              scenarios: metrics.metrics.operations.byScenario.slice(0, 5),
              apps: metrics.metrics.operations.byApp.slice(0, 5),
              teams: metrics.metrics.operations.byTeam.slice(0, 5),
            },
          },
          optimization: includeRecommendations ? {
            recommendations: metrics.recommendations,
            potentialSavings: metrics.recommendations.reduce((sum, rec) => sum + (rec.savings || 0), 0),
            highImpactRecommendations: metrics.recommendations.filter(rec => rec.impact === 'high'),
          } : undefined,
        }, "Usage metrics retrieved successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting usage metrics', { organizationId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get usage metrics: ${errorMessage}`);
      }
    },
  });

  // Add payment method
  server.addTool({
    name: 'add-payment-method',
    description: 'Add a new payment method for billing with secure processing',
    parameters: PaymentMethodSchema,
    annotations: {
      title: 'Add Payment Method',
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { organizationId, type, details, billingAddress, setAsDefault } = input;

      log.info('Adding payment method', {
        organizationId,
        type,
        setAsDefault,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate required fields based on payment type
        if (type === 'credit_card') {
          if (!details.cardNumber || !details.expiryMonth || !details.expiryYear || !details.cvv) {
            throw new UserError('Credit card details are incomplete');
          }
        } else if (type === 'bank_account') {
          if (!details.accountNumber || !details.routingNumber) {
            throw new UserError('Bank account details are incomplete');
          }
        } else if (type === 'paypal') {
          if (!details.paypalEmail) {
            throw new UserError('PayPal email is required');
          }
        } else if (type === 'wire_transfer') {
          if (!details.wireDetails) {
            throw new UserError('Wire transfer details are required');
          }
        }

        const paymentData = {
          type,
          details: {
            ...details,
            // Sensitive data should be handled securely in production
            cardNumber: details.cardNumber ? '[CARD_NUMBER_ENCRYPTED]' : undefined,
            cvv: details.cvv ? '[CVV_ENCRYPTED]' : undefined,
            accountNumber: details.accountNumber ? '[ACCOUNT_NUMBER_ENCRYPTED]' : undefined,
          },
          billingAddress,
          setAsDefault,
        };

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/billing/payment-methods';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/payment-methods`;
        }

        const response = await apiClient.post(endpoint, paymentData);

        if (!response.success) {
          throw new UserError(`Failed to add payment method: ${response.error?.message || 'Unknown error'}`);
        }

        const paymentMethod = response.data || {};
        reportProgress({ progress: 100, total: 100 });

        // Type guard for payment method data
        const isValidPaymentMethod = (data: unknown): data is Record<string, unknown> => {
          return typeof data === 'object' && data !== null;
        };

        const validPaymentMethod = isValidPaymentMethod(paymentMethod) ? paymentMethod : {};

        log.info('Successfully added payment method', {
          paymentMethodId: String(validPaymentMethod.id || ''),
          type,
          isDefault: Boolean(setAsDefault || validPaymentMethod.isDefault),
        });

        return formatSuccessResponse({
          paymentMethod: {
            ...validPaymentMethod,
            // Never expose sensitive payment details
            details: '[PAYMENT_DETAILS_SECURE]',
          },
          summary: {
            id: validPaymentMethod.id,
            type,
            lastFour: validPaymentMethod.lastFour,
            isDefault: setAsDefault || validPaymentMethod.isDefault,
            status: (validPaymentMethod.status as string) || 'active',
          },
          nextSteps: [
            'Verify payment method if required',
            setAsDefault ? 'Payment method set as default' : 'Set as default if needed',
            'Update billing preferences if necessary',
          ],
        }, "Payment method added successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error adding payment method', { type, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to add payment method: ${errorMessage}`);
      }
    },
  });

  // Update billing information
  server.addTool({
    name: 'update-billing-info',
    description: 'Update billing contact information, tax details, and account settings',
    parameters: BillingUpdateSchema,
    annotations: {
      title: 'Update Billing Information',
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { organizationId, contacts, taxInfo, autoRenewal } = input;

      log.info('Updating billing information', {
        organizationId,
        hasContacts: !!contacts,
        hasTaxInfo: !!taxInfo,
        autoRenewal,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const updateData: Record<string, unknown> = {};

        if (contacts) {
          updateData.contacts = contacts;
        }

        if (taxInfo) {
          updateData.taxInfo = taxInfo;
        }

        if (autoRenewal !== undefined) {
          updateData.autoRenewal = autoRenewal;
        }

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/billing/account';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/account`;
        }

        const response = await apiClient.put(endpoint, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update billing information: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedAccount = response.data || {};
        reportProgress({ progress: 100, total: 100 });

        // Type guard for updated account data
        const isValidAccount = (data: unknown): data is Record<string, unknown> => {
          return typeof data === 'object' && data !== null;
        };

        const validAccount = isValidAccount(updatedAccount) ? updatedAccount : {};
        const accountBilling = isValidAccount(validAccount.billing) ? validAccount.billing : {};

        log.info('Successfully updated billing information', {
          organizationId: String(validAccount.organizationId || ''),
          contactsUpdated: !!contacts,
          taxInfoUpdated: !!taxInfo,
          autoRenewalUpdated: autoRenewal !== undefined,
        });

        return formatSuccessResponse({
          account: validAccount,
          updates: {
            contacts: !!contacts,
            taxInfo: !!taxInfo,
            autoRenewal: autoRenewal !== undefined,
          },
          summary: {
            organizationId: validAccount.organizationId || organizationId,
            billingContact: contacts?.billing ? `${contacts.billing.name} <${contacts.billing.email}>` : undefined,
            technicalContact: contacts?.technical ? `${contacts.technical.name} <${contacts.technical.email}>` : undefined,
            taxExempt: taxInfo?.taxExempt,
            autoRenewal: autoRenewal !== undefined ? autoRenewal : accountBilling.autoRenewal,
          },
        }, "Billing information updated successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating billing information', { organizationId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update billing information: ${errorMessage}`);
      }
    },
  });

  // Set budget
  server.addTool({
    name: 'set-budget',
    description: 'Establish operational budgets for teams/organizations with advanced cost control and alerting',
    parameters: SetBudgetSchema,
    annotations: {
      title: 'Set Budget with Cost Controls',
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { organizationId, name, description, type, scope, budget, categories, thresholds } = input;

      log.info('Setting budget', {
        organizationId,
        name,
        type,
        amount: budget.amount,
        currency: budget.currency,
        period: budget.period,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate scope based on type
        if (type === 'organization' && !scope.organizationId && !organizationId) {
          throw new UserError('Organization ID is required for organization budgets');
        }
        if (type === 'team' && (!scope.teamIds || scope.teamIds.length === 0)) {
          throw new UserError('Team IDs are required for team budgets');
        }
        if (type === 'scenario' && (!scope.scenarioIds || scope.scenarioIds.length === 0)) {
          throw new UserError('Scenario IDs are required for scenario budgets');
        }

        // Validate budget dates
        const startDate = new Date(budget.startDate);
        const endDate = budget.endDate ? new Date(budget.endDate) : null;
        
        if (startDate > new Date()) {
          log.info('Budget start date is in the future', { startDate: budget.startDate });
        }
        
        if (endDate && endDate <= startDate) {
          throw new UserError('Budget end date must be after start date');
        }

        reportProgress({ progress: 25, total: 100 });

        const budgetData: Record<string, unknown> = {
          name,
          description,
          type,
          scope,
          budget,
          categories,
          thresholds,
        };

        let endpoint = '/billing/budgets';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/budgets`;
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post(endpoint, budgetData);

        if (!response.success) {
          throw new UserError(`Failed to set budget: ${response.error?.message || 'Unknown error'}`);
        }

        const createdBudget = response.data as MakeBudget;
        if (!createdBudget) {
          throw new UserError('Budget creation response is invalid');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created budget', {
          budgetId: createdBudget.id,
          name: createdBudget.name,
          amount: createdBudget.budget.amount,
          currency: createdBudget.budget.currency,
          type: createdBudget.type,
        });

        return formatSuccessResponse({
          budget: createdBudget,
          summary: {
            id: createdBudget.id,
            name: createdBudget.name,
            type: createdBudget.type,
            amount: createdBudget.budget.amount,
            currency: createdBudget.budget.currency,
            period: createdBudget.budget.period,
            thresholds: createdBudget.thresholds.map(t => `${t.percentage}% → ${t.action}`),
            status: createdBudget.status,
          },
          nextSteps: [
            'Monitor budget usage through get-usage-metrics',
            'Review cost projections with get-cost-projection',
            'Set up cost alerts with create-cost-alert',
            'Configure notification channels for threshold alerts',
          ],
          warnings: [
            budget.endDate ? null : 'No end date set - budget will continue indefinitely',
            thresholds.some(t => t.percentage >= 100) ? 'Budget includes 100% threshold - may cause service interruption' : null,
          ].filter(Boolean),
        }, `Budget "${name}" created successfully`).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error setting budget', { name, type, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to set budget: ${errorMessage}`);
      }
    },
  });

  // Create cost alert
  server.addTool({
    name: 'create-cost-alert',
    description: 'Create advanced cost alerts with notifications when costs exceed thresholds',
    parameters: CreateCostAlertSchema,
    annotations: {
      title: 'Create Cost Alert',
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { organizationId, name, description, conditions, notifications, actions } = input;

      log.info('Creating cost alert', {
        organizationId,
        name,
        conditions,
        notificationChannels: notifications.channels.map(c => c.type),
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate that at least one condition is provided
        const hasConditions = conditions.budgetIds?.length || 
                             conditions.costThreshold || 
                             conditions.usageThreshold || 
                             conditions.scenarioIds?.length ||
                             conditions.teamIds?.length;

        if (!hasConditions) {
          throw new UserError('At least one alert condition must be specified');
        }

        // Validate notification channels
        for (const channel of notifications.channels) {
          if (channel.type === 'email' && !channel.target.includes('@')) {
            throw new UserError(`Invalid email address: ${channel.target}`);
          }
          if (channel.type === 'webhook' && !channel.target.startsWith('http')) {
            throw new UserError(`Invalid webhook URL: ${channel.target}`);
          }
        }

        reportProgress({ progress: 25, total: 100 });

        const alertData: Record<string, unknown> = {
          name,
          description,
          conditions,
          notifications,
          actions,
        };

        let endpoint = '/billing/alerts';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/alerts`;
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post(endpoint, alertData);

        if (!response.success) {
          throw new UserError(`Failed to create cost alert: ${response.error?.message || 'Unknown error'}`);
        }

        const createdAlert = response.data as MakeCostAlert;
        if (!createdAlert) {
          throw new UserError('Cost alert creation response is invalid');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created cost alert', {
          alertId: createdAlert.id,
          name: createdAlert.name,
          status: createdAlert.status,
        });

        return formatSuccessResponse({
          alert: createdAlert,
          summary: {
            id: createdAlert.id,
            name: createdAlert.name,
            status: createdAlert.status,
            conditions: {
              budgetIds: conditions.budgetIds?.length || 0,
              costThreshold: !!conditions.costThreshold,
              usageThreshold: !!conditions.usageThreshold,
              scenarioIds: conditions.scenarioIds?.length || 0,
              teamIds: conditions.teamIds?.length || 0,
            },
            notifications: {
              channels: notifications.channels.length,
              frequency: notifications.frequency,
              escalation: notifications.escalation.enabled,
            },
            actions: actions.length,
          },
          monitoring: {
            budgets: conditions.budgetIds || [],
            scenarios: conditions.scenarioIds || [],
            teams: conditions.teamIds || [],
            thresholds: {
              cost: conditions.costThreshold ? 
                `${conditions.costThreshold.amount} ${conditions.costThreshold.currency} per ${conditions.costThreshold.period}` : 
                'None',
              usage: conditions.usageThreshold ? 
                `${conditions.usageThreshold.operations || 'N/A'} ops, ${conditions.usageThreshold.dataTransfer || 'N/A'} GB` : 
                'None',
            },
          },
          nextSteps: [
            'Alert is now active and monitoring specified conditions',
            'Test notification channels if needed',
            'Monitor alert trigger history',
            'Adjust thresholds based on actual usage patterns',
          ],
        }, `Cost alert "${name}" created successfully`).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating cost alert', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create cost alert: ${errorMessage}`);
      }
    },
  });

  // Get cost projection
  server.addTool({
    name: 'get-cost-projection',
    description: 'Generate detailed cost forecasts based on usage patterns with confidence intervals',
    parameters: GetCostProjectionSchema,
    annotations: {
      title: 'Generate Cost Projections',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { 
        organizationId, 
        period, 
        algorithm, 
        basedOnDays, 
        includeSeasonality, 
        includeBudgetComparison, 
        includeRecommendations,
        confidenceLevel 
      } = input;

      log.info('Generating cost projection', {
        organizationId,
        period,
        algorithm,
        basedOnDays,
        confidenceLevel,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Calculate projection parameters
        const projectionStartDate = period.startDate || new Date().toISOString().split('T')[0];
        const startDate = new Date(projectionStartDate);
        
        let endDate: Date;
        switch (period.type) {
          case 'monthly':
            endDate = new Date(startDate);
            endDate.setMonth(startDate.getMonth() + period.count);
            break;
          case 'quarterly':
            endDate = new Date(startDate);
            endDate.setMonth(startDate.getMonth() + (period.count * 3));
            break;
          case 'annually':
            endDate = new Date(startDate);
            endDate.setFullYear(startDate.getFullYear() + period.count);
            break;
        }

        const params: Record<string, unknown> = {
          period: {
            type: period.type,
            count: period.count,
            startDate: projectionStartDate,
            endDate: endDate.toISOString().split('T')[0],
          },
          algorithm,
          basedOnDays,
          includeSeasonality,
          includeBudgetComparison,
          includeRecommendations,
          confidenceLevel,
        };

        reportProgress({ progress: 25, total: 100 });

        let endpoint = '/billing/projections';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/projections`;
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post(endpoint, params);

        if (!response.success) {
          throw new UserError(`Failed to generate cost projection: ${response.error?.message || 'Unknown error'}`);
        }

        const projection = response.data as MakeCostProjection;
        if (!projection) {
          throw new UserError('Cost projection response is invalid');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully generated cost projection', {
          organizationId: projection.organizationId,
          period: projection.period,
          algorithm: projection.methodology.algorithm,
          confidence: projection.methodology.confidence,
        });

        // Calculate variance analysis
        const conservativeTotal = projection.projections.conservative.total;
        const realisticTotal = projection.projections.realistic.total;
        const optimisticTotal = projection.projections.optimistic.total;
        const range = optimisticTotal - conservativeTotal;
        const variancePercentage = realisticTotal > 0 ? (range / realisticTotal) * 100 : 0;

        return formatSuccessResponse({
          projection,
          analysis: {
            period: `${period.count} ${period.type.replace('ly', '')}(s)`,
            algorithm: algorithm,
            confidence: `${projection.methodology.confidence}%`,
            basedOnDays,
            projectionRange: {
              conservative: conservativeTotal,
              realistic: realisticTotal,
              optimistic: optimisticTotal,
              variance: variancePercentage.toFixed(1) + '%',
            },
            monthlyAverage: {
              conservative: (conservativeTotal / period.count).toFixed(2),
              realistic: (realisticTotal / period.count).toFixed(2),
              optimistic: (optimisticTotal / period.count).toFixed(2),
            },
            trends: {
              monthlyGrowth: projection.trends.growthRate.monthly.toFixed(2) + '%',
              quarterlyGrowth: projection.trends.growthRate.quarterly.toFixed(2) + '%',
              annualGrowth: projection.trends.growthRate.annually.toFixed(2) + '%',
              seasonalFactors: projection.trends.seasonality.length > 0,
              anomaliesDetected: projection.trends.anomalies.length,
            },
          },
          budgetAnalysis: includeBudgetComparison ? {
            budgetsEvaluated: projection.budgetComparison.length,
            budgetsAtRisk: projection.budgetComparison.filter(b => b.risk === 'high').length,
            totalBudgetVariance: projection.budgetComparison.reduce((sum, b) => sum + b.variance, 0),
            riskSummary: {
              low: projection.budgetComparison.filter(b => b.risk === 'low').length,
              medium: projection.budgetComparison.filter(b => b.risk === 'medium').length,
              high: projection.budgetComparison.filter(b => b.risk === 'high').length,
            },
          } : undefined,
          recommendations: includeRecommendations ? {
            total: projection.recommendations.length,
            critical: projection.recommendations.filter(r => r.priority === 'critical').length,
            highPriority: projection.recommendations.filter(r => r.priority === 'high').length,
            potentialSavings: projection.recommendations.reduce((sum, r) => sum + (r.impact.cost || 0), 0),
            topRecommendations: projection.recommendations
              .filter(r => r.priority === 'critical' || r.priority === 'high')
              .slice(0, 3)
              .map(r => ({
                type: r.type,
                title: r.title,
                priority: r.priority,
                impact: r.impact.cost,
              })),
          } : undefined,
          nextSteps: [
            'Review budget comparisons and adjust budgets if needed',
            'Implement high-priority cost optimization recommendations',
            'Set up cost alerts based on projection thresholds',
            'Monitor actual vs projected costs',
            includeSeasonality ? 'Plan for seasonal cost variations' : null,
          ].filter(Boolean),
        }, "Cost projection generated successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error generating cost projection', { period, algorithm, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to generate cost projection: ${errorMessage}`);
      }
    },
  });

  // Pause high cost scenarios
  server.addTool({
    name: 'pause-high-cost-scenarios',
    description: 'Automatically identify and pause scenarios that exceed cost thresholds for cost protection',
    parameters: PauseHighCostScenariosSchema,
    annotations: {
      title: 'Pause High Cost Scenarios',
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }): Promise<string> => {
      const { organizationId, criteria, action, notification, dryRun } = input;

      log.info('Evaluating high cost scenarios for pausing', {
        organizationId,
        action,
        dryRun,
        criteria,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate that at least one criteria is provided
        const hasCriteria = criteria.costThreshold || 
                           criteria.budgetExceedance || 
                           criteria.operationsThreshold ||
                           criteria.scenarioIds?.length;

        if (!hasCriteria) {
          throw new UserError('At least one pause criteria must be specified');
        }

        reportProgress({ progress: 20, total: 100 });

        const pauseData: Record<string, unknown> = {
          criteria,
          action,
          notification,
          dryRun,
        };

        let endpoint = '/billing/scenarios/pause-high-cost';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/scenarios/pause-high-cost`;
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post(endpoint, pauseData);

        if (!response.success) {
          throw new UserError(`Failed to evaluate high cost scenarios: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data || {};
        
        // Type guard for result data
        const isValidResult = (data: unknown): data is Record<string, unknown> => {
          return typeof data === 'object' && data !== null;
        };

        const validResult = isValidResult(result) ? result : {};
        const scenarios = Array.isArray(validResult.scenarios) ? validResult.scenarios : [];
        const summary = isValidResult(validResult.summary) ? validResult.summary : {};

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully evaluated high cost scenarios', {
          scenariosEvaluated: Number(summary.evaluated) || 0,
          scenariosIdentified: Number(summary.identified) || 0,
          action: String(validResult.action || action),
          dryRun: Boolean(dryRun),
        });

        // Type definitions for scenario data
        interface ScenarioData {
          id: number;
          name: string;
          currentCost: number;
          projectedCost: number;
          costImpact: number;
          riskLevel: string;
          action: string;
          reasoning: string;
          actionTimestamp?: string;
        }

        // Type guard for scenario data
        const isValidScenario = (data: unknown): data is ScenarioData => {
          return typeof data === 'object' && data !== null &&
                 typeof (data as Record<string, unknown>).id === 'number' &&
                 typeof (data as Record<string, unknown>).costImpact === 'number';
        };

        const typedScenarios = scenarios.filter(isValidScenario);

        // Calculate cost impact
        const totalCostSavings = typedScenarios.reduce((sum: number, scenario: ScenarioData) => {
          return sum + (Number(scenario.costImpact) || 0);
        }, 0);

        const riskLevels = typedScenarios.reduce((acc: Record<string, number>, scenario: ScenarioData) => {
          const risk = String(scenario.riskLevel || 'unknown');
          acc[risk] = (acc[risk] || 0) + 1;
          return acc;
        }, {});

        return formatSuccessResponse({
          evaluation: {
            action: validResult.action || action,
            dryRun: Boolean(dryRun),
            executed: !dryRun && action !== 'simulate',
            timestamp: new Date().toISOString(),
          },
          criteria: {
            costThreshold: criteria.costThreshold ? 
              `${criteria.costThreshold.amount} ${criteria.costThreshold.currency} per ${criteria.costThreshold.period}` : 
              null,
            budgetExceedance: criteria.budgetExceedance ? 
              `${criteria.budgetExceedance.percentage}% of budgets: ${criteria.budgetExceedance.budgetIds.join(', ')}` : 
              null,
            operationsThreshold: criteria.operationsThreshold ? 
              `${criteria.operationsThreshold.operations} operations per ${criteria.operationsThreshold.period}` : 
              null,
            specificScenarios: criteria.scenarioIds?.length || 0,
          },
          summary: {
            scenariosEvaluated: Number(summary.evaluated) || 0,
            scenariosIdentified: Number(summary.identified) || 0,
            scenariosAffected: typedScenarios.length,
            estimatedCostSavings: totalCostSavings,
            riskDistribution: riskLevels,
          },
          scenarios: typedScenarios.map((scenario: ScenarioData) => ({
            id: scenario.id,
            name: scenario.name,
            currentCost: scenario.currentCost,
            projectedCost: scenario.projectedCost,
            costImpact: scenario.costImpact,
            riskLevel: scenario.riskLevel,
            action: scenario.action,
            reasoning: scenario.reasoning,
          })),
          actions: {
            performed: dryRun ? [] : typedScenarios.filter((s: ScenarioData) => s.action !== 'none').map((s: ScenarioData) => ({
              scenarioId: s.id,
              action: s.action,
              timestamp: s.actionTimestamp,
            })),
            notifications: notification.enabled ? {
              channels: notification.channels,
              sent: !dryRun,
              recipients: validResult.notificationsSent || 0,
            } : null,
          },
          recommendations: [
            typedScenarios.length > 0 ? `Review ${typedScenarios.length} high-cost scenarios identified` : 'No high-cost scenarios found',
            dryRun ? 'Execute with dryRun=false to perform actual pause actions' : 'Actions have been executed',
            totalCostSavings > 0 ? `Potential cost savings: ${totalCostSavings.toFixed(2)} ${criteria.costThreshold?.currency || 'USD'}` : null,
            'Set up proactive cost alerts to prevent future cost spikes',
            'Review and adjust budgets based on identified scenarios',
          ].filter(Boolean),
          warnings: [
            !dryRun && action === 'pause' ? 'Scenarios have been paused - business operations may be affected' : null,
            typedScenarios.filter((s: ScenarioData) => s.riskLevel === 'high').length > 0 ? 'High-risk scenarios identified - immediate attention required' : null,
          ].filter(Boolean),
          nextSteps: dryRun ? [
            'Review identified scenarios and their cost impact',
            'Execute with dryRun=false when ready to perform actions',
            'Set up automated cost alerts for ongoing protection',
          ] : [
            'Monitor paused scenarios for business impact',
            'Investigate root causes of high costs',
            'Update budgets and thresholds as needed',
          ],
        }, `High cost scenarios evaluation completed - ${dryRun ? 'simulation mode' : 'actions executed'}`).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error evaluating high cost scenarios', { action, dryRun, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to evaluate high cost scenarios: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Advanced budgeting and cost control tools added successfully');
  componentLogger.info('Billing and payment management tools added successfully');
}

export default addBillingTools;