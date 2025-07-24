# Notification & Email Management Tools

Comprehensive tools for managing multi-channel notifications, email preferences, notification templates, and custom data structures with advanced scheduling and delivery tracking.

## Tools Overview

| Tool | Description | Type |
|------|-------------|------|
| `create-notification` | Create and send multi-channel notifications | Action |
| `list-notifications` | List notifications with analytics | Read |
| `get-email-preferences` | Get user email preferences | Read |
| `update-email-preferences` | Update notification preferences | Write |
| `create-notification-template` | Create reusable templates | Write |
| `create-data-structure` | Create custom data validation schemas | Write |

## Notification Management

### `create-notification`

Create and send a notification through multiple channels with scheduling support and delivery tracking.

**Parameters:**
```typescript
{
  type: 'system' | 'billing' | 'security' | 'scenario' | 'team' | 'marketing' | 'custom';  // Notification type
  category: 'info' | 'warning' | 'error' | 'success' | 'reminder' | 'alert';  // Notification category
  priority?: 'low' | 'medium' | 'high' | 'critical';  // Priority level (default: medium)
  title: string;                // Notification title (1-200 chars)
  message: string;              // Message content (1-2000 chars)
  data?: object;                // Additional structured data
  recipients: {
    users?: number[];           // User IDs to notify
    teams?: number[];           // Team IDs to notify
    organizations?: number[];   // Organization IDs to notify
    emails?: string[];          // Direct email addresses
  };
  channels: {
    email?: boolean;            // Send via email (default: true)
    inApp?: boolean;            // Show in-app notification (default: true)
    sms?: boolean;              // Send via SMS (default: false)
    webhook?: boolean;          // Send to webhook (default: false)
    slack?: boolean;            // Send to Slack (default: false)
    teams?: boolean;            // Send to Microsoft Teams (default: false)
  };
  schedule?: {
    sendAt?: string;            // Schedule send time (ISO 8601)
    timezone?: string;          // Timezone for scheduling (default: UTC)
    recurring?: {
      frequency: 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';
      interval?: number;        // Interval between recurrences (default: 1)
      daysOfWeek?: number[];    // Days of week (0=Sunday)
      dayOfMonth?: number;      // Day of month (1-31)
      endDate?: string;         // End date for recurrence
    };
  };
  templateId?: number;          // Template ID to use
  templateVariables?: object;   // Template variable values
}
```

**Returns:**
```typescript
{
  notification: {
    id: number;
    type: string;
    category: string;
    priority: string;
    title: string;
    message: string;
    status: 'draft' | 'scheduled' | 'sent' | 'delivered' | 'failed';
    recipients: {
      userCount: number;
      teamCount: number;
      organizationCount: number;
      emailCount: number;
    };
    channels: object;
    delivery: {
      sentAt?: string;
      deliveredAt?: string;
      totalRecipients: number;
      successfulDeliveries: number;
      failedDeliveries: number;
    };
    schedule?: object;
    tracking: {
      opens: number;
      clicks: number;
      unsubscribes: number;
    };
    createdAt: string;
  };
  message: string;
  summary: {
    id: number;
    type: string;
    category: string;
    priority: string;
    status: string;
    channels: string[];
    totalRecipients: number;
    scheduled: boolean;
    scheduledFor?: string;
  };
  delivery: {
    status: string;
    sentAt?: string;
    successfulDeliveries: number;
    failedDeliveries: number;
  };
}
```

**Example:**
```bash
# Send immediate notification to team
mcp-client create-notification \
  --type "system" \
  --category "info" \
  --priority "medium" \
  --title "System Maintenance Complete" \
  --message "The scheduled maintenance has been completed successfully." \
  --recipients.teams "[123, 456]" \
  --channels.email true \
  --channels.inApp true

# Schedule recurring weekly report
mcp-client create-notification \
  --type "team" \
  --category "reminder" \
  --title "Weekly Team Report" \
  --message "Please submit your weekly team report." \
  --recipients.users "[789, 101112]" \
  --channels.email true \
  --schedule.sendAt "2024-01-29T09:00:00Z" \
  --schedule.recurring.frequency "weekly" \
  --schedule.recurring.daysOfWeek "[1]"

# Send critical security alert
mcp-client create-notification \
  --type "security" \
  --category "alert" \
  --priority "critical" \
  --title "Security Alert: Unusual Login Activity" \
  --message "Unusual login activity detected on your account." \
  --recipients.emails "[admin@company.com]" \
  --channels.email true \
  --channels.sms true \
  --channels.slack true

# Use template with variables
mcp-client create-notification \
  --type "billing" \
  --category "reminder" \
  --title "Payment Reminder" \
  --templateId 456 \
  --templateVariables.customerName "Acme Corp" \
  --templateVariables.amount "$1,250.00" \
  --templateVariables.dueDate "2024-02-01" \
  --recipients.organizations "[123]"
```

**Delivery Channels:**
- **Email**: HTML/text email with tracking
- **In-App**: Dashboard notifications
- **SMS**: Text message alerts
- **Webhook**: HTTP POST to configured endpoints
- **Slack**: Slack channel/DM notifications
- **Teams**: Microsoft Teams notifications

**Scheduling Features:**
- **Immediate**: Send notification right away
- **Scheduled**: Send at specific date/time
- **Recurring**: Repeat on schedule (daily, weekly, monthly, etc.)
- **Timezone Support**: Send at local time for recipients
- **End Date**: Stop recurring notifications on date

**Use Cases:**
- System status updates
- Security alerts and warnings
- Billing and payment reminders
- Team collaboration notifications
- Marketing campaigns
- Automated workflow notifications

---

### `list-notifications`

List and filter notifications with delivery status and comprehensive analytics.

**Parameters:**
```typescript
{
  type?: 'system' | 'billing' | 'security' | 'scenario' | 'team' | 'marketing' | 'custom' | 'all';  // Filter by type
  status?: 'draft' | 'scheduled' | 'sent' | 'delivered' | 'failed' | 'cancelled' | 'all';  // Filter by status
  priority?: 'low' | 'medium' | 'high' | 'critical' | 'all';  // Filter by priority
  dateRange?: {
    startDate?: string;       // Start date (YYYY-MM-DD)
    endDate?: string;         // End date (YYYY-MM-DD)
  };
  includeDelivery?: boolean;  // Include delivery statistics (default: true)
  includeTracking?: boolean;  // Include tracking data (default: false)
  limit?: number;             // Max notifications (1-100, default: 20)
  offset?: number;            // Notifications to skip (default: 0)
  sortBy?: 'createdAt' | 'sentAt' | 'priority' | 'title';  // Sort field (default: createdAt)
  sortOrder?: 'asc' | 'desc'; // Sort order (default: desc)
}
```

**Returns:**
```typescript
{
  notifications: Array<{
    id: number;
    type: string;
    category: string;
    priority: string;
    title: string;
    status: string;
    recipients: {
      total: number;
    };
    channels: object;
    delivery: {
      sentAt?: string;
      deliveredAt?: string;
      totalRecipients: number;
      successfulDeliveries: number;
      failedDeliveries: number;
    };
    tracking?: {
      opens: number;
      clicks: number;
      unsubscribes: number;
    };
    createdAt: string;
    createdBy: string;
  }>;
  analytics: {
    totalNotifications: number;
    typeBreakdown: object;
    statusBreakdown: object;
    priorityBreakdown: object;
    deliveryAnalytics?: {
      totalRecipients: number;
      successfulDeliveries: number;
      failedDeliveries: number;
      averageDeliveryRate: number;
    };
    channelUsage: object;
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
# List recent notifications
mcp-client list-notifications --limit 50

# Filter critical security notifications
mcp-client list-notifications \
  --type "security" \
  --priority "critical" \
  --includeTracking true

# Get delivery analytics for date range
mcp-client list-notifications \
  --dateRange.startDate "2024-01-01" \
  --dateRange.endDate "2024-01-31" \
  --includeDelivery true \
  --includeTracking true

# Find failed notifications
mcp-client list-notifications --status "failed"
```

**Analytics Provided:**
- **Type Distribution**: Breakdown by notification type
- **Status Analysis**: Success/failure rates
- **Channel Performance**: Delivery rates by channel
- **Engagement Metrics**: Open/click rates when tracking enabled
- **Time-based Trends**: Delivery patterns over time

**Use Cases:**
- Notification campaign analysis
- Delivery performance monitoring
- User engagement tracking
- System health monitoring
- Compliance reporting

## Email Preference Management

### `get-email-preferences`

Get user email notification preferences and subscription settings with detailed configuration.

**Parameters:**
```typescript
{
  userId?: number;            // User ID (defaults to current user)
  includeStats?: boolean;     // Include email statistics (default: false)
}
```

**Returns:**
```typescript
{
  preferences: {
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
        configuration: object;
      }>;
    };
    timezone: string;
    language: string;
    unsubscribeAll: boolean;
    lastUpdated: string;
  };
  summary: {
    userId: number;
    organizationId: number;
    unsubscribeAll: boolean;
    timezone: string;
    language: string;
    categories: {
      system: boolean;
      billing: boolean;
      scenarios: boolean;
      team: boolean;
      marketing: boolean;
    };
    customChannels: number;
  };
  settings: {
    systemFrequency: string;
    scenarioFrequency: string;
    scenarioFilters: object;
    lastUpdated: string;
  };
}
```

**Example:**
```bash
# Get current user preferences
mcp-client get-email-preferences

# Get preferences for specific user
mcp-client get-email-preferences --userId 123

# Get preferences with statistics
mcp-client get-email-preferences --includeStats true
```

**Preference Categories:**
- **System**: Product updates, maintenance, security alerts
- **Billing**: Invoices, payment reminders, usage alerts
- **Scenarios**: Execution notifications, failures, warnings
- **Team**: Invitations, role changes, team updates
- **Marketing**: Product news, newsletters, webinars

**Frequency Options:**
- **immediate**: Send notifications as they occur
- **hourly**: Digest emails every hour
- **daily**: Daily digest at preferred time
- **weekly**: Weekly summary
- **never**: No email notifications

**Use Cases:**
- User preference management
- Email compliance (unsubscribe handling)
- Notification customization
- Communication audit
- User experience optimization

---

### `update-email-preferences`

Update user email notification preferences and subscription settings with granular control.

**Parameters:**
```typescript
{
  userId?: number;            // User ID (defaults to current user)
  preferences?: {
    system?: {
      enabled?: boolean;
      frequency?: 'immediate' | 'hourly' | 'daily' | 'weekly' | 'never';
      categories?: {
        updates?: boolean;
        maintenance?: boolean;
        security?: boolean;
        announcements?: boolean;
      };
    };
    billing?: {
      enabled?: boolean;
      categories?: {
        invoices?: boolean;
        paymentReminders?: boolean;
        usageAlerts?: boolean;
        planChanges?: boolean;
      };
    };
    scenarios?: {
      enabled?: boolean;
      frequency?: 'immediate' | 'hourly' | 'daily' | 'never';
      categories?: {
        failures?: boolean;
        completions?: boolean;
        warnings?: boolean;
        scheduleChanges?: boolean;
      };
      filters?: {
        onlyMyScenarios?: boolean;
        onlyImportantScenarios?: boolean;
        scenarioIds?: number[];
        teamIds?: number[];
      };
    };
    team?: {
      enabled?: boolean;
      categories?: {
        invitations?: boolean;
        roleChanges?: boolean;
        memberChanges?: boolean;
        teamUpdates?: boolean;
      };
    };
    marketing?: {
      enabled?: boolean;
      categories?: {
        productUpdates?: boolean;
        newsletters?: boolean;
        webinars?: boolean;
        surveys?: boolean;
      };
    };
  };
  timezone?: string;          // User timezone
  language?: string;          // Preferred language
  unsubscribeAll?: boolean;   // Unsubscribe from all emails
}
```

**Returns:**
```typescript
{
  preferences: object;        // Updated preferences
  message: string;
  changes: {
    preferences: boolean;
    timezone: boolean;
    language: boolean;
    unsubscribeAll: boolean;
  };
  summary: {
    userId: number;
    unsubscribeAll: boolean;
    enabledCategories: string[];
    lastUpdated: string;
  };
}
```

**Example:**
```bash
# Enable scenario failure notifications
mcp-client update-email-preferences \
  --preferences.scenarios.enabled true \
  --preferences.scenarios.categories.failures true \
  --preferences.scenarios.frequency "immediate"

# Update timezone and language
mcp-client update-email-preferences \
  --timezone "America/New_York" \
  --language "en-US"

# Disable marketing emails
mcp-client update-email-preferences \
  --preferences.marketing.enabled false

# Set scenario filters
mcp-client update-email-preferences \
  --preferences.scenarios.filters.onlyMyScenarios true \
  --preferences.scenarios.filters.teamIds "[123, 456]"

# Unsubscribe from all emails
mcp-client update-email-preferences --unsubscribeAll true
```

**Compliance Features:**
- **One-click unsubscribe**: Easy opt-out mechanism
- **Granular control**: Category-specific preferences
- **Audit trail**: All preference changes logged
- **Legal compliance**: GDPR, CAN-SPAM compliance

**Use Cases:**
- User onboarding
- Preference management UI
- Compliance with email regulations
- Noise reduction for users
- Notification optimization

## Template & Data Management

### `create-notification-template`

Create a reusable notification template with variables, design, and multi-channel support.

**Parameters:**
```typescript
{
  name: string;               // Template name (1-100 chars)
  description?: string;       // Template description (max 500 chars)
  type: 'email' | 'sms' | 'push' | 'webhook' | 'slack' | 'teams';  // Template type
  category: 'system' | 'billing' | 'scenario' | 'team' | 'marketing' | 'custom';  // Template category
  organizationId?: number;    // Organization ID (for org templates)
  template: {
    subject?: string;         // Email subject template (max 200 chars)
    body: string;             // Template body content
    format?: 'text' | 'html' | 'markdown' | 'json';  // Template format (default: html)
    variables?: Array<{
      name: string;           // Variable name
      type: 'string' | 'number' | 'boolean' | 'date' | 'object';  // Variable type
      required?: boolean;     // Is variable required (default: false)
      defaultValue?: any;     // Default value
      description?: string;   // Variable description
    }>;
  };
  design?: {
    theme?: string;           // Design theme
    colors?: object;          // Color scheme
    fonts?: object;           // Font configuration
    layout?: string;          // Layout template
    customCss?: string;       // Custom CSS
  };
}
```

**Returns:**
```typescript
{
  template: {
    id: number;
    name: string;
    description?: string;
    type: string;
    category: string;
    organizationId?: number;
    isGlobal: boolean;
    template: {
      subject?: string;
      body: string;
      format: string;
      variables: Array<object>;
    };
    design: object;
    testing: {
      lastTested?: string;
      testResults?: object;
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
  };
  message: string;
  summary: {
    id: number;
    name: string;
    type: string;
    category: string;
    isGlobal: boolean;
    variables: number;
    format: string;
  };
  usage: {
    testUrl: string;
    previewUrl: string;
  };
  nextSteps: string[];
}
```

**Example:**
```bash
# Create email template with variables
mcp-client create-notification-template \
  --name "Welcome Email" \
  --type "email" \
  --category "team" \
  --template.subject "Welcome to {{organizationName}}, {{userName}}!" \
  --template.body "<h1>Welcome {{userName}}</h1><p>You've been added to {{teamName}}.</p>" \
  --template.format "html" \
  --template.variables '[
    {"name": "userName", "type": "string", "required": true},
    {"name": "organizationName", "type": "string", "required": true},
    {"name": "teamName", "type": "string", "required": true}
  ]'

# Create Slack template
mcp-client create-notification-template \
  --name "Build Notification" \
  --type "slack" \
  --category "system" \
  --template.body "Build {{buildNumber}} for {{projectName}} has {{status}}." \
  --template.format "text" \
  --template.variables '[
    {"name": "buildNumber", "type": "string", "required": true},
    {"name": "projectName", "type": "string", "required": true},
    {"name": "status", "type": "string", "required": true, "description": "success or failed"}
  ]'

# Create template with design
mcp-client create-notification-template \
  --name "Invoice Template" \
  --type "email" \
  --category "billing" \
  --organizationId 123 \
  --template.subject "Invoice #{{invoiceNumber}} from {{companyName}}" \
  --template.body "<div>Invoice details...</div>" \
  --design.theme "corporate" \
  --design.colors '{"primary": "#003366", "secondary": "#6699CC"}'
```

**Template Features:**
- **Variable Substitution**: Dynamic content with type validation
- **Multi-channel Support**: Email, SMS, Slack, Teams, webhooks
- **Design System**: Themes, colors, fonts, layouts
- **Testing Tools**: Preview and test with sample data
- **Usage Analytics**: Delivery rates and performance metrics
- **Version Control**: Template versioning and rollback

**Variable Types:**
- **string**: Text content
- **number**: Numeric values
- **boolean**: True/false values  
- **date**: Date/time values with formatting
- **object**: Complex structured data

**Use Cases:**
- Standardized communication templates
- Brand consistency across notifications
- Automated email campaigns
- System notification templates
- Multi-language template management

---

### `create-data-structure`

Create a custom data structure for validation and transformation of notification data.

**Parameters:**
```typescript
{
  name: string;               // Structure name (1-100 chars)
  description?: string;       // Structure description (max 500 chars)
  type: 'schema' | 'template' | 'validation' | 'transformation';  // Structure type
  organizationId?: number;    // Organization ID
  teamId?: number;            // Team ID
  scope?: 'global' | 'organization' | 'team' | 'personal';  // Access scope (default: personal)
  structure: {
    schema: any;              // JSON Schema definition
    version?: string;         // Schema version (default: 1.0.0)
    format?: 'json' | 'xml' | 'yaml' | 'csv' | 'custom';  // Data format (default: json)
  };
  validation?: {
    enabled?: boolean;        // Enable validation (default: true)
    strict?: boolean;         // Strict validation mode (default: false)
    rules?: Array<{
      field: string;          // Field path
      type: 'required' | 'format' | 'range' | 'custom';  // Rule type
      parameters?: any;       // Rule parameters
      message: string;        // Error message
    }>;
  };
  transformation?: {
    enabled?: boolean;        // Enable transformation (default: false)
    mappings?: Array<{
      source: string;         // Source field path
      target: string;         // Target field path
      function?: string;      // Transformation function
      parameters?: any;       // Function parameters
    }>;
    filters?: Array<{
      field: string;          // Field to filter
      operator: string;       // Filter operator
      value: any;             // Filter value
    }>;
  };
}
```

**Returns:**
```typescript
{
  dataStructure: {
    id: number;
    name: string;
    description?: string;
    type: string;
    organizationId?: number;
    teamId?: number;
    scope: string;
    structure: {
      schema: any;
      version: string;
      format: string;
    };
    validation: {
      enabled: boolean;
      strict: boolean;
      rules: Array<object>;
    };
    transformation: {
      enabled: boolean;
      mappings: Array<object>;
      filters: Array<object>;
    };
    usage: {
      scenariosUsing: number;
      lastUsed?: string;
      validationCount: number;
      errorRate: number;
    };
    versions: Array<object>;
    createdAt: string;
    updatedAt: string;
    createdBy: number;
  };
  message: string;
  summary: {
    id: number;
    name: string;
    type: string;
    scope: string;
    format: string;
    version: string;
    validationEnabled: boolean;
    transformationEnabled: boolean;
  };
  configuration: {
    validationRules: number;
    transformationMappings: number;
    transformationFilters: number;
  };
  usage: {
    validateUrl: string;
    transformUrl: string;
    testUrl: string;
  };
}
```

**Example:**
```bash
# Create user data validation schema
mcp-client create-data-structure \
  --name "User Profile Schema" \
  --type "validation" \
  --scope "organization" \
  --structure.schema '{
    "type": "object",
    "properties": {
      "name": {"type": "string", "minLength": 1, "maxLength": 100},
      "email": {"type": "string", "format": "email"},
      "role": {"type": "string", "enum": ["admin", "member", "viewer"]}
    },
    "required": ["name", "email", "role"]
  }' \
  --validation.enabled true \
  --validation.strict true

# Create data transformation structure
mcp-client create-data-structure \
  --name "CRM Data Mapper" \
  --type "transformation" \
  --scope "team" \
  --teamId 123 \
  --structure.format "json" \
  --transformation.enabled true \
  --transformation.mappings '[
    {"source": "firstName", "target": "profile.name.first"},
    {"source": "lastName", "target": "profile.name.last"},
    {"source": "email", "target": "contact.email"}
  ]' \
  --transformation.filters '[
    {"field": "status", "operator": "equals", "value": "active"}
  ]'
```

**Structure Types:**
- **schema**: JSON Schema for data validation
- **template**: Data templates with defaults
- **validation**: Custom validation rules
- **transformation**: Data mapping and filtering

**Validation Rules:**
- **required**: Field must be present
- **format**: String format validation (email, date, etc.)
- **range**: Numeric range validation
- **custom**: Custom validation functions

**Use Cases:**
- API data validation
- Data import/export transformation
- Custom notification data structures
- Integration data mapping
- Quality assurance rules

## Error Handling

### Common Notification Errors

**Invalid Recipients**
```json
{
  "error": {
    "code": "NO_RECIPIENTS_SPECIFIED",
    "message": "At least one recipient must be specified",
    "provided": {"users": [], "teams": [], "organizations": [], "emails": []}
  }
}
```

**Channel Configuration Error**
```json
{
  "error": {
    "code": "NO_CHANNELS_ENABLED",
    "message": "At least one delivery channel must be enabled",
    "availableChannels": ["email", "inApp", "sms", "webhook", "slack", "teams"]
  }
}
```

**Template Variable Error**
```json
{
  "error": {
    "code": "MISSING_TEMPLATE_VARIABLE",
    "message": "Required template variable 'userName' not provided",
    "templateId": 123,
    "missingVariables": ["userName", "organizationName"]
  }
}
```

### Email Preference Errors

**Invalid Frequency**
```json
{
  "error": {
    "code": "INVALID_FREQUENCY",
    "message": "Invalid frequency 'instantly' for scenario notifications",
    "field": "preferences.scenarios.frequency",
    "validValues": ["immediate", "hourly", "daily", "never"]
  }
}
```

**User Not Found**
```json
{
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "User with ID 123 not found or access denied",
    "userId": 123
  }
}
```

### Template Errors

**Invalid Template Format**
```json
{
  "error": {
    "code": "INVALID_TEMPLATE_FORMAT",
    "message": "Template body contains invalid HTML syntax",
    "line": 15,
    "error": "Unclosed tag: <div>"
  }
}
```

**Variable Type Mismatch**
```json
{
  "error": {
    "code": "VARIABLE_TYPE_MISMATCH",
    "message": "Variable 'count' expects number but received string",
    "variable": "count",
    "expectedType": "number",
    "receivedType": "string",
    "value": "five"
  }
}
```

## Security & Privacy

### Data Protection
- **Personal Data**: Email addresses and preferences protected
- **Template Security**: XSS protection in template rendering
- **Access Control**: Role-based access to notification features
- **Audit Logging**: All notification activities logged

### Compliance Features
- **GDPR Compliance**: User consent and data protection
- **CAN-SPAM Compliance**: Unsubscribe mechanisms
- **Data Retention**: Configurable retention policies
- **Privacy Controls**: User data access and deletion

### Anti-Spam Measures
- **Rate Limiting**: Prevent notification spam
- **Content Filtering**: Detect and block spam content
- **Recipient Validation**: Email address validation
- **Delivery Monitoring**: Track bounce and complaint rates

## Best Practices

### Notification Design
```bash
# Use appropriate priority levels
mcp-client create-notification \
  --priority "critical" \
  --type "security" \
  --category "alert"

# Include relevant data for context
mcp-client create-notification \
  --data '{"scenarioId": 123, "errorCode": "CONN_TIMEOUT"}'
```

### Template Management
```bash
# Create reusable templates
mcp-client create-notification-template \
  --name "Standard Welcome" \
  --type "email" \
  --category "team"

# Use descriptive variable names
--template.variables '[
  {"name": "recipientName", "type": "string", "required": true},
  {"name": "welcomeMessage", "type": "string", "defaultValue": "Welcome aboard!"}
]'
```

### Email Preferences
```bash
# Respect user preferences
mcp-client get-email-preferences --userId 123

# Provide granular control
mcp-client update-email-preferences \
  --preferences.scenarios.filters.onlyMyScenarios true
```

This comprehensive documentation provides all the tools needed for effective notification and email management within the Make.com FastMCP server environment.