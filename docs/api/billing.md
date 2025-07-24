# Billing & Payment Management Tools

Comprehensive tools for accessing billing information, managing payment methods, and analyzing usage metrics with security features and financial analytics.

## Tools Overview

| Tool | Description | Type |
|------|-------------|------|
| `get-billing-account` | Get comprehensive billing account info | Read |
| `list-invoices` | List and filter invoices | Read |
| `get-usage-metrics` | Get detailed usage and cost breakdown | Read |
| `add-payment-method` | Add new payment method securely | Write |
| `update-billing-info` | Update billing contacts and settings | Write |

## Account Management

### `get-billing-account`

Get comprehensive billing account information including plan details, usage statistics, and payment information with security-conscious data handling.

**Parameters:**
```typescript
{
  organizationId?: number;    // Organization ID (defaults to current user org)
  includeUsage?: boolean;     // Include usage statistics (default: true)
  includeHistory?: boolean;   // Include historical usage (default: false)
  includePaymentMethods?: boolean; // Include payment methods (default: true)
}
```

**Returns:**
```typescript
{
  account: {
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
        dataTransfer: number;
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
          used: number;
          limit: number;
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
      history?: Array<{
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
    paymentMethods?: Array<{
      id: string;
      type: 'credit_card' | 'bank_account' | 'paypal' | 'wire_transfer';
      isDefault: boolean;
      lastFour: string;
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
  };
  summary: {
    organizationName: string;
    plan: {
      name: string;
      type: string;
      price: number;
      currency: string;
      cycle: string;
    };
    usage?: {
      operations: {
        used: number;
        limit: number;
        percentage: number;
      };
      dataTransfer: {
        used: number;
        limit: number;
        percentage: number;
      };
    };
    billing: {
      status: string;
      nextBillingDate: string;
      balance: number;
      autoRenewal: boolean;
    };
  };
  alerts: string[];            // Usage and payment alerts
}
```

**Example:**
```bash
# Get complete billing account info
mcp-client get-billing-account

# Get account info for specific organization
mcp-client get-billing-account --organizationId 123

# Get account with usage history
mcp-client get-billing-account \
  --includeUsage true \
  --includeHistory true
```

**Security Features:**
- Payment method details are masked (only last 4 digits shown)
- Sensitive financial data is encrypted
- Access logging for audit compliance
- Role-based access control

**Use Cases:**
- Account dashboard display
- Usage monitoring and alerts
- Billing status verification
- Plan comparison analysis
- Financial planning

---

### `list-invoices`

List and filter invoices with payment status and detailed financial breakdown.

**Parameters:**
```typescript
{
  organizationId?: number;    // Organization ID (defaults to current)
  status?: 'draft' | 'sent' | 'paid' | 'overdue' | 'cancelled' | 'all';  // Invoice status filter
  dateRange?: {
    startDate?: string;       // Start date (YYYY-MM-DD)
    endDate?: string;         // End date (YYYY-MM-DD)
  };
  includeLineItems?: boolean; // Include detailed line items (default: false)
  includePayments?: boolean;  // Include payment information (default: false)
  limit?: number;             // Max invoices (1-100, default: 20)
  offset?: number;            // Invoices to skip (default: 0)
  sortBy?: 'date' | 'amount' | 'status' | 'number';  // Sort field (default: date)
  sortOrder?: 'asc' | 'desc'; // Sort order (default: desc)
}
```

**Returns:**
```typescript
{
  invoices: Array<{
    id: string;
    number: string;
    organizationId: number;
    status: string;
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
    lineItems?: Array<{
      description: string;
      quantity: number;
      unitPrice: number;
      total: number;
      type: 'subscription' | 'usage' | 'addon' | 'support';
    }>;
    payments?: Array<{
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
  }>;
  analysis: {
    totalInvoices: number;
    statusBreakdown: object;
    financialSummary: {
      totalAmount: number;
      paidAmount: number;
      outstandingAmount: number;
      overdueAmount: number;
      currency: string;
    };
    paymentAnalysis: {
      averagePaymentTime: number;
      onTimePayments: number;
      latePayments: number;
      pendingPayments: number;
    };
    recentInvoices: Array<{
      number: string;
      amount: number;
      status: string;
      issuedDate: string;
      dueDate: string;
    }>;
  };
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}
```

**Example:**
```bash
# List recent invoices
mcp-client list-invoices --limit 10

# Find overdue invoices
mcp-client list-invoices --status "overdue"

# Get invoices for date range with details
mcp-client list-invoices \
  --dateRange.startDate "2024-01-01" \
  --dateRange.endDate "2024-01-31" \
  --includeLineItems true \
  --includePayments true

# Sort by amount (highest first)
mcp-client list-invoices \
  --sortBy "amount" \
  --sortOrder "desc"
```

**Invoice Statuses:**
- **draft**: Invoice created but not sent
- **sent**: Invoice sent to customer
- **paid**: Invoice fully paid
- **overdue**: Invoice past due date
- **cancelled**: Invoice cancelled

**Use Cases:**
- Financial reporting
- Accounts receivable management
- Payment tracking
- Cash flow analysis
- Customer billing support

---

### `get-usage-metrics`

Get detailed usage metrics and cost breakdown with optimization recommendations.

**Parameters:**
```typescript
{
  organizationId?: number;    // Organization ID (defaults to current)
  period?: 'current' | 'last_month' | 'last_3_months' | 'last_6_months' | 'last_year' | 'custom';  // Usage period
  customPeriod?: {
    startDate: string;        // Start date (YYYY-MM-DD, required if period=custom)
    endDate: string;          // End date (YYYY-MM-DD, required if period=custom)
  };
  breakdown?: Array<'scenario' | 'app' | 'team' | 'region' | 'time'>;  // Usage breakdown dimensions
  includeProjections?: boolean; // Include cost projections (default: true)
  includeRecommendations?: boolean; // Include optimization recommendations (default: true)
}
```

**Returns:**
```typescript
{
  metrics: {
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
        total: number;
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
        dataStores: number;
        logs: number;
        backups: number;
        total: number;
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
        responseTime: number;
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
  };
  summary: {
    organizationId: number;
    period: object;
    usage: {
      operations: number;
      dataTransfer: number;
      storage: number;
    };
    costs: {
      total: number;
      currency: string;
      breakdown: object;
      projectedMonthly?: number;
    };
    topConsumers: {
      scenarios: Array<object>;
      apps: Array<object>;
      teams: Array<object>;
    };
  };
  optimization?: {
    recommendations: Array<object>;
    potentialSavings: number;
    highImpactRecommendations: Array<object>;
  };
}
```

**Example:**
```bash
# Get current period usage
mcp-client get-usage-metrics

# Get detailed breakdown for last 3 months
mcp-client get-usage-metrics \
  --period "last_3_months" \
  --breakdown "scenario,app,team"

# Get custom period with projections
mcp-client get-usage-metrics \
  --period "custom" \
  --customPeriod.startDate "2024-01-01" \
  --customPeriod.endDate "2024-01-31" \
  --includeProjections true \
  --includeRecommendations true
```

**Breakdown Dimensions:**
- **scenario**: Usage by individual scenarios
- **app**: Usage by connected applications
- **team**: Usage by team/department
- **region**: Usage by geographic region
- **time**: Usage over time periods

**Use Cases:**
- Cost analysis and optimization
- Budget planning and forecasting
- Department chargeback
- Usage pattern analysis
- Performance optimization

## Payment Management

### `add-payment-method`

Add a new payment method for billing with secure processing and validation.

**Parameters:**
```typescript
{
  organizationId?: number;    // Organization ID (defaults to current)
  type: 'credit_card' | 'bank_account' | 'paypal' | 'wire_transfer';  // Payment method type
  details: {
    // Credit Card
    cardNumber?: string;      // Credit card number
    expiryMonth?: number;     // Expiry month (1-12)
    expiryYear?: number;      // Expiry year (≥2024)
    cvv?: string;            // CVV code
    
    // Bank Account
    accountNumber?: string;   // Bank account number
    routingNumber?: string;   // Routing number
    
    // PayPal
    paypalEmail?: string;     // PayPal email address
    
    // Wire Transfer
    wireDetails?: {
      bankName: string;
      accountName: string;
      accountNumber: string;
      swiftCode: string;
    };
  };
  billingAddress: {
    name: string;             // Billing name (required)
    address1: string;         // Address line 1 (required)
    address2?: string;        // Address line 2
    city: string;             // City (required)
    state?: string;           // State/Province
    postalCode: string;       // Postal code (required)
    country: string;          // Country code (ISO 2-letter, required)
  };
  setAsDefault?: boolean;     // Set as default payment method (default: false)
}
```

**Returns:**
```typescript
{
  paymentMethod: {
    id: string;
    type: string;
    lastFour: string;
    isDefault: boolean;
    status: 'active' | 'expired' | 'failed';
    // Sensitive details are never returned
  };
  message: string;
  summary: {
    id: string;
    type: string;
    lastFour: string;
    isDefault: boolean;
    status: string;
  };
  nextSteps: string[];
}
```

**Example:**
```bash
# Add credit card
mcp-client add-payment-method \
  --type "credit_card" \
  --details.cardNumber "4111111111111111" \
  --details.expiryMonth 12 \
  --details.expiryYear 2025 \
  --details.cvv "123" \
  --billingAddress.name "John Doe" \
  --billingAddress.address1 "123 Main St" \
  --billingAddress.city "New York" \
  --billingAddress.postalCode "10001" \
  --billingAddress.country "US" \
  --setAsDefault true

# Add PayPal payment method
mcp-client add-payment-method \
  --type "paypal" \
  --details.paypalEmail "billing@company.com" \
  --billingAddress.name "Company Inc" \
  --billingAddress.address1 "456 Business Ave" \
  --billingAddress.city "San Francisco" \
  --billingAddress.postalCode "94105" \
  --billingAddress.country "US"
```

**Security Features:**
- PCI DSS compliant payment processing
- Encryption of sensitive payment data
- Tokenization of payment methods
- Secure transmission protocols
- Access logging and audit trails

**Validation:**
- Credit card number format and checksum validation
- Expiry date validation (future dates only)
- CVV format validation
- Bank routing number validation
- Address format validation

**Use Cases:**
- Payment method setup
- Backup payment methods
- Payment method rotation
- Multiple payment sources
- Automated billing setup

---

### `update-billing-info`

Update billing contact information, tax details, and account settings.

**Parameters:**
```typescript
{
  organizationId?: number;    // Organization ID (defaults to current)
  contacts?: {
    billing?: {
      name: string;           // Billing contact name
      email: string;          // Billing contact email
      phone?: string;         // Billing contact phone
    };
    technical?: {
      name: string;           // Technical contact name
      email: string;          // Technical contact email
      phone?: string;         // Technical contact phone
    };
  };
  taxInfo?: {
    taxId?: string;           // Tax ID number
    vatNumber?: string;       // VAT number
    country: string;          // Country code (ISO 2-letter)
    region?: string;          // State/Province
    taxExempt?: boolean;      // Tax exemption status
  };
  autoRenewal?: boolean;      // Auto-renewal setting
}
```

**Returns:**
```typescript
{
  account: object;            // Updated account information
  message: string;
  updates: {
    contacts: boolean;
    taxInfo: boolean;
    autoRenewal: boolean;
  };
  summary: {
    organizationId: number;
    billingContact?: string;
    technicalContact?: string;
    taxExempt?: boolean;
    autoRenewal?: boolean;
  };
}
```

**Example:**
```bash
# Update billing contact
mcp-client update-billing-info \
  --contacts.billing.name "Jane Smith" \
  --contacts.billing.email "billing@company.com" \
  --contacts.billing.phone "+1-555-0123"

# Update tax information
mcp-client update-billing-info \
  --taxInfo.taxId "12-3456789" \
  --taxInfo.country "US" \
  --taxInfo.region "CA" \
  --taxInfo.taxExempt false

# Enable auto-renewal
mcp-client update-billing-info --autoRenewal true
```

**Use Cases:**
- Contact information maintenance
- Tax compliance updates
- Billing preference changes
- Corporate structure changes
- Compliance requirements

## Error Handling

### Common Billing Errors

**Insufficient Permissions**
```json
{
  "error": {
    "code": "BILLING_ACCESS_DENIED",
    "message": "You don't have permission to access billing information for this organization",
    "organizationId": 123,
    "requiredRole": "billing_admin"
  }
}
```

**Payment Method Errors**
```json
{
  "error": {
    "code": "INVALID_PAYMENT_METHOD",
    "message": "Credit card number is invalid",
    "field": "cardNumber",
    "validation": "Invalid checksum"
  }
}
```

**Billing Account Not Found**
```json
{
  "error": {
    "code": "BILLING_ACCOUNT_NOT_FOUND",
    "message": "No billing account found for organization 123",
    "organizationId": 123
  }
}
```

### Usage Metrics Errors

**Invalid Date Range**
```json
{
  "error": {
    "code": "INVALID_DATE_RANGE",
    "message": "Custom period requires both startDate and endDate",
    "period": "custom",
    "provided": {"startDate": "2024-01-01"}
  }
}
```

**Data Not Available**
```json
{
  "error": {
    "code": "USAGE_DATA_NOT_AVAILABLE",
    "message": "Usage data not available for the requested period",
    "period": "2023-01-01 to 2023-01-31",
    "reason": "Data retention period exceeded"
  }
}
```

## Security & Compliance

### Data Security
- **Encryption**: All financial data encrypted at rest and in transit
- **PCI Compliance**: Payment processing follows PCI DSS standards
- **Access Control**: Role-based access to billing information
- **Audit Logging**: All billing operations logged for compliance

### Privacy Protection
- **Data Masking**: Sensitive payment details masked in responses
- **Minimal Exposure**: Only necessary data returned in API responses
- **Secure Storage**: Payment methods tokenized and securely stored
- **Data Retention**: Configurable retention policies for financial data

### Compliance Features
- **SOX Compliance**: Financial data handling for public companies
- **GDPR Compliance**: EU data protection requirements
- **Regional Tax**: Automatic tax calculation by region
- **Audit Trail**: Complete audit trail for all billing operations

## Best Practices

### Cost Optimization
```bash
# Regular usage monitoring
mcp-client get-usage-metrics --includeRecommendations true

# Analyze top consumers
mcp-client get-usage-metrics --breakdown "scenario,team"

# Track cost trends
mcp-client get-usage-metrics --period "last_3_months"
```

### Payment Management
```bash
# Set up backup payment method
mcp-client add-payment-method \
  --type "credit_card" \
  --setAsDefault false

# Regular billing account review
mcp-client get-billing-account --includeUsage true
```

### Financial Reporting
```bash
# Monthly invoice review
mcp-client list-invoices \
  --dateRange.startDate "2024-01-01" \
  --dateRange.endDate "2024-01-31" \
  --includeLineItems true

# Outstanding balance tracking
mcp-client list-invoices --status "overdue"
```

This comprehensive documentation provides all the tools needed for effective billing and payment management within the Make.com FastMCP server environment.