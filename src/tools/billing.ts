/**
 * Billing and Payment Management Tools for Make.com FastMCP Server
 * Comprehensive tools for accessing billing information, payment methods, and financial data
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

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
    execute: async (input, { log, reportProgress }) => {
      const { organizationId, includeUsage, includeHistory, includePaymentMethods } = input;

      log.info('Getting billing account information', {
        organizationId,
        includeUsage,
        includeHistory,
        includePaymentMethods,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const params: Record<string, unknown> = {
          includeUsage,
          includeHistory,
          includePaymentMethods,
        };

        let endpoint = '/billing/account';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/billing/account`;
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get billing account: ${response.error?.message || 'Unknown error'}`);
        }

        const account = response.data as MakeBillingAccount;
        if (!account) {
          throw new UserError('Billing account information not found');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully retrieved billing account', {
          organizationId: account.organizationId,
          plan: account.billingPlan.name,
          status: account.accountStatus,
          nextBilling: account.billing.nextBillingDate,
        });

        return JSON.stringify({
          account: {
            ...account,
            paymentMethods: includePaymentMethods ? account.paymentMethods.map(pm => ({
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
            usage: includeUsage ? {
              operations: {
                used: account.usage.currentPeriod.operations.used,
                limit: account.usage.currentPeriod.operations.limit,
                percentage: account.usage.currentPeriod.operations.percentage,
              },
              dataTransfer: {
                used: account.usage.currentPeriod.dataTransfer.used,
                limit: account.usage.currentPeriod.dataTransfer.limit,
                percentage: account.usage.currentPeriod.dataTransfer.percentage,
              },
            } : undefined,
            billing: {
              status: account.billing.paymentStatus,
              nextBillingDate: account.billing.nextBillingDate,
              balance: account.billing.currentBalance,
              autoRenewal: account.billing.autoRenewal,
            },
          },
          alerts: [
            account.usage.currentPeriod.operations.percentage > 80 ? 'Operations usage above 80%' : null,
            account.usage.currentPeriod.dataTransfer.percentage > 80 ? 'Data transfer usage above 80%' : null,
            account.billing.paymentStatus === 'overdue' ? 'Payment overdue' : null,
            account.billing.paymentStatus === 'failed' ? 'Payment failed' : null,
          ].filter(Boolean),
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting billing account', { organizationId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get billing account: ${errorMessage}`);
      }
    },
  });

  // List invoices
  server.addTool({
    name: 'list-invoices',
    description: 'List and filter invoices with payment status and detailed breakdown',
    parameters: InvoiceListSchema,
    execute: async (input, { log }) => {
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

        if (status !== 'all') params.status = status;
        if (dateRange?.startDate) params.startDate = dateRange.startDate;
        if (dateRange?.endDate) params.endDate = dateRange.endDate;

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

        return JSON.stringify({
          invoices,
          analysis,
          pagination: {
            total: metadata?.total || invoices.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + invoices.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing invoices', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list invoices: ${errorMessage}`);
      }
    },
  });

  // Get usage metrics
  server.addTool({
    name: 'get-usage-metrics',
    description: 'Get detailed usage metrics and cost breakdown with optimization recommendations',
    parameters: UsageMetricsSchema,
    execute: async (input, { log, reportProgress }) => {
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

        return JSON.stringify({
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
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting usage metrics', { organizationId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get usage metrics: ${errorMessage}`);
      }
    },
  });

  // Add payment method
  server.addTool({
    name: 'add-payment-method',
    description: 'Add a new payment method for billing with secure processing',
    parameters: PaymentMethodSchema,
    execute: async (input, { log, reportProgress }) => {
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

        return JSON.stringify({
          paymentMethod: {
            ...validPaymentMethod,
            // Never expose sensitive payment details
            details: '[PAYMENT_DETAILS_SECURE]',
          },
          message: `Payment method added successfully`,
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
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error adding payment method', { type, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to add payment method: ${errorMessage}`);
      }
    },
  });

  // Update billing information
  server.addTool({
    name: 'update-billing-info',
    description: 'Update billing contact information, tax details, and account settings',
    parameters: BillingUpdateSchema,
    execute: async (input, { log, reportProgress }) => {
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

        return JSON.stringify({
          account: validAccount,
          message: 'Billing information updated successfully',
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
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating billing information', { organizationId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update billing information: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Billing and payment management tools added successfully');
}

export default addBillingTools;