/**
 * Test fixtures and sample data for consistent testing
 * Provides realistic data structures for various Make.com entities
 */

import { 
  MakeScenario, 
  MakeConnection, 
  MakeUser, 
  MakeTemplate,
  MakeExecution,
  MakeVariable,
  MakeWebhook,
  MakeAnalytics,
  MakeAuditLog,
  MakeScenarioLog,
  MakeIncompleteExecution,
  MakeHookLog,
  MakeBillingAccount,
  MakeNotification
} from '../../src/types/index.js';

/**
 * Sample users for testing different roles and permissions
 */
export const testUsers: Record<string, MakeUser> = {
  admin: {
    id: 1001,
    name: 'Admin User',
    email: 'admin@test.com',
    role: 'admin',
    teamId: 12345,
    organizationId: 67890,
    permissions: ['read', 'write', 'admin', 'manage_users', 'manage_billing'],
    isActive: true,
  },
  
  member: {
    id: 1002,
    name: 'Team Member',
    email: 'member@test.com',
    role: 'member',
    teamId: 12345,
    organizationId: 67890,
    permissions: ['read', 'write'],
    isActive: true,
  },
  
  viewer: {
    id: 1003,
    name: 'Viewer Only',
    email: 'viewer@test.com',
    role: 'viewer',
    teamId: 12345,
    organizationId: 67890,
    permissions: ['read'],
    isActive: true,
  },
  
  inactive: {
    id: 1004,
    name: 'Inactive User',
    email: 'inactive@test.com',
    role: 'member',
    teamId: 12345,
    organizationId: 67890,
    permissions: ['read'],
    isActive: false,
  },
};

/**
 * Sample scenarios for testing different states and configurations
 */
export const testScenarios: Record<string, MakeScenario> = {
  active: {
    id: 2001,
    name: 'Active Test Scenario',
    teamId: 12345,
    folderId: 3001,
    blueprint: {
      flow: [
        { id: 1, app: 'webhook', operation: 'trigger' },
        { id: 2, app: 'email', operation: 'send' }
      ]
    },
    scheduling: {
      type: 'indefinitely',
      interval: 900
    },
    isActive: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
  },
  
  inactive: {
    id: 2002,
    name: 'Inactive Test Scenario',
    teamId: 12345,
    folderId: undefined,
    blueprint: {
      flow: [
        { id: 1, app: 'http', operation: 'get' }
      ]
    },
    scheduling: {
      type: 'on-demand'
    },
    isActive: false,
    createdAt: '2024-01-02T00:00:00Z',
    updatedAt: '2024-01-10T08:00:00Z',
  },
  
  scheduled: {
    id: 2003,
    name: 'Scheduled Test Scenario',
    teamId: 12345,
    folderId: 3002,
    blueprint: {
      flow: [
        { id: 1, app: 'scheduler', operation: 'interval' },
        { id: 2, app: 'database', operation: 'select' },
        { id: 3, app: 'email', operation: 'send_bulk' }
      ]
    },
    scheduling: {
      type: 'indefinitely',
      interval: 3600
    },
    isActive: true,
    createdAt: '2024-01-03T00:00:00Z',
    updatedAt: '2024-01-20T14:30:00Z',
  },
};

/**
 * Sample connections for testing different services
 */
export const testConnections: Record<string, MakeConnection> = {
  gmail: {
    id: 4001,
    name: 'Gmail Test Connection',
    accountName: 'test@gmail.com',
    service: 'gmail',
    metadata: {
      scopes: ['read', 'send'],
      auth_type: 'oauth2'
    },
    isValid: true,
    createdAt: '2024-01-01T10:00:00Z',
    updatedAt: '2024-01-01T10:00:00Z',
  },
  
  database: {
    id: 4002,
    name: 'MySQL Test Connection',
    accountName: 'test_db',
    service: 'mysql',
    metadata: {
      host: 'localhost',
      port: 3306,
      database: 'test_db'
    },
    isValid: true,
    createdAt: '2024-01-01T11:00:00Z',
    updatedAt: '2024-01-15T09:00:00Z',
  },
  
  invalid: {
    id: 4003,
    name: 'Invalid Test Connection',
    accountName: 'expired@service.com',
    service: 'custom_api',
    metadata: {
      api_key: 'expired_key',
      last_error: 'Authentication failed'
    },
    isValid: false,
    createdAt: '2024-01-01T12:00:00Z',
    updatedAt: '2024-01-20T08:00:00Z',
  },
};

/**
 * Sample executions for testing different outcomes
 */
export const testExecutions: Record<string, MakeExecution> = {
  successful: {
    id: 5001,
    scenarioId: 2001,
    status: 'success',
    startedAt: '2024-01-15T10:00:00Z',
    finishedAt: '2024-01-15T10:02:30Z',
    operations: 5,
    dataTransfer: 1024,
  },
  
  failed: {
    id: 5002,
    scenarioId: 2001,
    status: 'error',
    startedAt: '2024-01-15T11:00:00Z',
    finishedAt: '2024-01-15T11:00:45Z',
    operations: 2,
    dataTransfer: 256,
    error: {
      message: 'Connection timeout',
      code: 'TIMEOUT',
      details: { timeout: 30000 }
    }
  },
  
  incomplete: {
    id: 5003,
    scenarioId: 2002,
    status: 'incomplete',
    startedAt: '2024-01-15T12:00:00Z',
    operations: 3,
    dataTransfer: 512,
    error: {
      message: 'Processing interrupted',
      code: 'INTERRUPTED'
    }
  }
};

/**
 * Sample templates for testing template management
 */
export const testTemplates: Record<string, MakeTemplate> = {
  public: {
    id: 6001,
    name: 'Email Marketing Template',
    description: 'Automated email marketing campaign',
    category: 'marketing',
    blueprint: {
      flow: [
        { id: 1, app: 'webhook', operation: 'trigger' },
        { id: 2, app: 'filter', operation: 'condition' },
        { id: 3, app: 'email', operation: 'send' }
      ]
    },
    tags: ['email', 'marketing', 'automation'],
    isPublic: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-10T00:00:00Z',
  },
  
  private: {
    id: 6002,
    name: 'Data Sync Template',
    description: 'Sync data between systems',
    category: 'integration',
    blueprint: {
      flow: [
        { id: 1, app: 'scheduler', operation: 'interval' },
        { id: 2, app: 'database', operation: 'select' },
        { id: 3, app: 'api', operation: 'post' }
      ]
    },
    tags: ['sync', 'database', 'api'],
    isPublic: false,
    createdAt: '2024-01-02T00:00:00Z',
    updatedAt: '2024-01-12T00:00:00Z',
  },
};

/**
 * Sample variables for testing variable management
 */
export const testVariables: Record<string, MakeVariable> = {
  global: {
    id: 7001,
    name: 'API_BASE_URL',
    value: 'https://api.example.com',
    type: 'string',
    scope: 'global',
    isEncrypted: false,
    createdAt: '2024-01-01T00:00:00Z',
  },
  
  encrypted: {
    id: 7002,
    name: 'API_SECRET_KEY',
    value: 'encrypted_value_placeholder',
    type: 'string',
    scope: 'team',
    isEncrypted: true,
    createdAt: '2024-01-01T00:00:00Z',
  },
  
  json: {
    id: 7003,
    name: 'CONFIG_OBJECT',
    value: { timeout: 30000, retries: 3 },
    type: 'json',
    scope: 'scenario',
    isEncrypted: false,
    createdAt: '2024-01-01T00:00:00Z',
  },
};

/**
 * Sample analytics data for testing reporting
 */
export const testAnalytics: MakeAnalytics = {
  organizationId: 67890,
  period: {
    startDate: '2024-01-01T00:00:00Z',
    endDate: '2024-01-31T23:59:59Z',
  },
  usage: {
    operations: 50000,
    dataTransfer: 10240,
    executions: 1250,
    successfulExecutions: 1175,
    failedExecutions: 75,
  },
  performance: {
    averageExecutionTime: 45000,
    averageOperationsPerExecution: 40,
    topScenarios: [
      { scenarioId: 2001, name: 'Active Test Scenario', executions: 500, operations: 20000 },
      { scenarioId: 2003, name: 'Scheduled Test Scenario', executions: 300, operations: 15000 },
    ],
  },
  billing: {
    operationsUsed: 50000,
    operationsLimit: 100000,
    dataTransferUsed: 10240,
    dataTransferLimit: 20480,
  },
};

/**
 * Sample billing account for testing billing features
 */
export const testBillingAccount: MakeBillingAccount = {
  id: 8001,
  organizationId: 67890,
  organizationName: 'Test Organization',
  accountStatus: 'active',
  billingPlan: {
    name: 'Professional Plan',
    type: 'professional',
    price: 99.00,
    currency: 'USD',
    billingCycle: 'monthly',
  },
  usage: {
    currentPeriod: {
      startDate: '2024-01-01T00:00:00Z',
      endDate: '2024-01-31T23:59:59Z',
      operations: {
        used: 50000,
        limit: 100000,
        percentage: 50,
      },
    },
  },
  billing: {
    nextBillingDate: '2024-02-01T00:00:00Z',
    currentBalance: 0,
    paymentStatus: 'current',
    autoRenewal: true,
  },
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-15T00:00:00Z',
};

/**
 * Sample notification for testing notification system
 */
export const testNotification: MakeNotification = {
  id: 9001,
  type: 'system',
  category: 'info',
  priority: 'medium',
  title: 'System Maintenance',
  message: 'Scheduled maintenance will occur tonight from 2-4 AM EST.',
  status: 'sent',
  channels: {
    email: true,
    inApp: true,
    sms: false,
    webhook: false,
  },
  delivery: {
    totalRecipients: 100,
    successfulDeliveries: 98,
    failedDeliveries: 2,
  },
  createdAt: '2024-01-15T10:00:00Z',
  updatedAt: '2024-01-15T10:05:00Z',
  createdBy: 1001,
};

/**
 * Sample audit log for testing audit functionality
 */
export const testAuditLog: MakeAuditLog = {
  id: 10001,
  timestamp: '2024-01-15T10:30:00Z',
  userId: 1001,
  userName: 'Admin User',
  action: 'scenario_create',
  resource: 'scenario',
  resourceId: 2001,
  details: {
    scenarioName: 'Test Automation Scenario',
    teamId: 12345,
    changes: {
      name: 'Test Automation Scenario',
      isActive: true,
      scheduling: { type: 'indefinitely', interval: 900 }
    }
  },
  ipAddress: '192.168.1.100',
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
};

/**
 * Sample scenario log for testing scenario logging
 */
export const testScenarioLog: MakeScenarioLog = {
  id: 11001,
  scenarioId: 2001,
  executionId: 5001,
  timestamp: '2024-01-15T12:00:00Z',
  level: 'info',
  message: 'Scenario execution started successfully',
  moduleId: 1,
  moduleName: 'Webhook',
  data: {
    trigger: 'webhook',
    requestId: 'req_12345',
    payload: { user: 'test@example.com', action: 'signup' }
  }
};

/**
 * Sample incomplete execution for testing incomplete execution management
 */
export const testIncompleteExecution: MakeIncompleteExecution = {
  id: 12001,
  scenarioId: 2001,
  scenarioName: 'Test Automation Scenario',
  startedAt: '2024-01-15T11:00:00Z',
  stoppedAt: '2024-01-15T11:05:00Z',
  reason: 'Module timeout after 5 minutes',
  status: 'waiting',
  operations: 15,
  dataTransfer: 2048,
  lastModuleId: 2,
  lastModuleName: 'HTTP Request',
  canResume: true,
  resumeData: {
    moduleState: { requestId: 'pending_12345' },
    pendingOperations: 5
  }
};

/**
 * Sample hook log for testing webhook logging
 */
export const testHookLog: MakeHookLog = {
  id: 13001,
  hookId: 14001,
  timestamp: '2024-01-15T12:30:00Z',
  method: 'POST',
  url: 'https://hook.make.com/webhook/12345',
  headers: {
    'content-type': 'application/json',
    'user-agent': 'TestApp/1.0',
    'x-request-id': 'req_67890'
  },
  body: {
    event: 'user.created',
    user: {
      id: 12345,
      email: 'test@example.com',
      name: 'Test User'
    }
  },
  response: {
    status: 200,
    headers: {
      'content-type': 'application/json'
    },
    body: {
      success: true,
      processed: true
    }
  },
  success: true,
  processingTime: 125,
  executionId: 5001
};

/**
 * Error responses for testing error handling
 */
export const testErrors = {
  unauthorized: {
    success: false,
    error: {
      message: 'Unauthorized access',
      code: 'UNAUTHORIZED',
      details: { statusCode: 401 }
    }
  },
  
  notFound: {
    success: false,
    error: {
      message: 'Resource not found',
      code: 'NOT_FOUND',
      details: { statusCode: 404 }
    }
  },
  
  rateLimited: {
    success: false,
    error: {
      message: 'Rate limit exceeded',
      code: 'RATE_LIMITED',
      details: { 
        statusCode: 429,
        retryAfter: 60,
        limit: 100,
        remaining: 0
      }
    }
  },
  
  serverError: {
    success: false,
    error: {
      message: 'Internal server error',
      code: 'INTERNAL_ERROR',
      details: { statusCode: 500 }
    }
  },
  
  validation: {
    success: false,
    error: {
      message: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: {
        statusCode: 400,
        fields: {
          name: 'Name is required',
          email: 'Invalid email format'
        }
      }
    }
  }
};

/**
 * Generate test data with random variations
 */
export const generateTestData = {
  user: (overrides: Partial<MakeUser> = {}): MakeUser => ({
    ...testUsers.member,
    id: globalThis.testUtils.generateId(),
    ...overrides,
  }),
  
  scenario: (overrides: Partial<MakeScenario> = {}): MakeScenario => ({
    ...testScenarios.active,
    id: globalThis.testUtils.generateId(),
    ...overrides,
  }),
  
  connection: (overrides: Partial<MakeConnection> = {}): MakeConnection => ({
    ...testConnections.gmail,
    id: globalThis.testUtils.generateId(),
    ...overrides,
  }),
  
  execution: (overrides: Partial<MakeExecution> = {}): MakeExecution => ({
    ...testExecutions.successful,
    id: globalThis.testUtils.generateId(),
    ...overrides,
  }),
};

export default {
  testUsers,
  testScenarios,
  testConnections,
  testExecutions,
  testTemplates,
  testVariables,
  testAnalytics,
  testAuditLog,
  testScenarioLog,
  testIncompleteExecution,
  testHookLog,
  testBillingAccount,
  testNotification,
  testErrors,
  generateTestData,
};