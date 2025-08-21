/**
 * @fileoverview Global constants for FastMCP tools
 * Shared constants used across all Make.com FastMCP tools
 */

/**
 * API configuration constants
 */
export const API_CONFIG = {
  /**
   * Default request timeout in milliseconds
   */
  DEFAULT_TIMEOUT: 30000,

  /**
   * Default number of retries for failed requests
   */
  DEFAULT_RETRIES: 3,

  /**
   * Default pagination limit
   */
  DEFAULT_PAGE_SIZE: 100,

  /**
   * Maximum pagination limit
   */
  MAX_PAGE_SIZE: 1000,

  /**
   * Rate limit defaults
   */
  RATE_LIMITS: {
    DEFAULT_REQUESTS_PER_SECOND: 10,
    DEFAULT_BURST_LIMIT: 50,
    DEFAULT_WINDOW_MS: 60000,
  },

  /**
   * Common HTTP status codes
   */
  HTTP_STATUS: {
    OK: 200,
    CREATED: 201,
    NO_CONTENT: 204,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    RATE_LIMITED: 429,
    INTERNAL_ERROR: 500,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503,
    GATEWAY_TIMEOUT: 504,
  },
} as const;

/**
 * FastMCP annotation defaults
 */
export const FASTMCP_ANNOTATIONS = {
  /**
   * Default annotations for read-only tools
   */
  READ_ONLY: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },

  /**
   * Default annotations for write tools
   */
  WRITE: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
  },

  /**
   * Default annotations for destructive tools
   */
  DESTRUCTIVE: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },

  /**
   * Default annotations for idempotent tools
   */
  IDEMPOTENT: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },

  /**
   * Default annotations for list/search tools
   */
  LIST: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },

  /**
   * Default annotations for get/fetch tools
   */
  GET: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },

  /**
   * Default annotations for create tools
   */
  CREATE: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
  },

  /**
   * Default annotations for update tools
   */
  UPDATE: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },

  /**
   * Default annotations for delete tools
   */
  DELETE: {
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false,
  },
} as const;

/**
 * Logging configuration
 */
export const LOGGING_CONFIG = {
  /**
   * Default log levels
   */
  LEVELS: {
    ERROR: 'error',
    WARN: 'warn',
    INFO: 'info',
    DEBUG: 'debug',
    TRACE: 'trace',
  },

  /**
   * Tool operation contexts for logging
   */
  CONTEXTS: {
    TOOL_EXECUTION: 'tool_execution',
    API_REQUEST: 'api_request',
    VALIDATION: 'validation',
    ERROR_HANDLING: 'error_handling',
    AUTHENTICATION: 'authentication',
    CACHE: 'cache',
  },
} as const;

/**
 * Validation constants
 */
export const VALIDATION_CONFIG = {
  /**
   * String length limits
   */
  STRING_LIMITS: {
    MIN_NAME_LENGTH: 1,
    MAX_NAME_LENGTH: 255,
    MIN_DESCRIPTION_LENGTH: 0,
    MAX_DESCRIPTION_LENGTH: 2000,
    MAX_SEARCH_LENGTH: 500,
    MAX_EMAIL_LENGTH: 320,
    MAX_URL_LENGTH: 2048,
  },

  /**
   * Numeric limits
   */
  NUMERIC_LIMITS: {
    MIN_ID: 1,
    MAX_ID: Number.MAX_SAFE_INTEGER,
    MIN_PAGE_SIZE: 1,
    MAX_PAGE_SIZE: 1000,
    MIN_TIMEOUT: 1000,
    MAX_TIMEOUT: 300000,
  },

  /**
   * Regular expressions for validation
   */
  PATTERNS: {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    URL: /^https?:\/\/[^\s$.?#].[^\s]*$/,
    UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    SLUG: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    HEX_COLOR: /^#[0-9A-F]{6}$/i,
    SEMANTIC_VERSION: /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/,
  },
} as const;

/**
 * Cache configuration
 */
export const CACHE_CONFIG = {
  /**
   * Default TTL values in milliseconds
   */
  DEFAULT_TTL: {
    SHORT: 5 * 60 * 1000,      // 5 minutes
    MEDIUM: 30 * 60 * 1000,    // 30 minutes
    LONG: 2 * 60 * 60 * 1000,  // 2 hours
    VERY_LONG: 24 * 60 * 60 * 1000, // 24 hours
  },

  /**
   * Cache key prefixes
   */
  KEY_PREFIXES: {
    API_RESPONSE: 'api_response',
    USER_DATA: 'user_data',
    TEAM_DATA: 'team_data',
    SCENARIO_DATA: 'scenario_data',
    BLUEPRINT_DATA: 'blueprint_data',
    METADATA: 'metadata',
  },

  /**
   * Cache size limits
   */
  LIMITS: {
    MAX_KEY_LENGTH: 250,
    MAX_VALUE_SIZE: 1024 * 1024, // 1MB
    DEFAULT_MAX_ENTRIES: 1000,
  },
} as const;

/**
 * Performance monitoring thresholds
 */
export const PERFORMANCE_CONFIG = {
  /**
   * Response time thresholds in milliseconds
   */
  RESPONSE_TIME_THRESHOLDS: {
    FAST: 500,
    ACCEPTABLE: 2000,
    SLOW: 5000,
    VERY_SLOW: 10000,
  },

  /**
   * Memory usage thresholds in bytes
   */
  MEMORY_THRESHOLDS: {
    LOW: 50 * 1024 * 1024,    // 50MB
    MEDIUM: 100 * 1024 * 1024, // 100MB
    HIGH: 200 * 1024 * 1024,   // 200MB
    CRITICAL: 500 * 1024 * 1024, // 500MB
  },

  /**
   * CPU usage thresholds as percentages
   */
  CPU_THRESHOLDS: {
    LOW: 20,
    MEDIUM: 50,
    HIGH: 80,
    CRITICAL: 95,
  },
} as const;

/**
 * Error message templates
 */
export const ERROR_MESSAGES = {
  VALIDATION: {
    REQUIRED_FIELD: 'Field "{field}" is required',
    INVALID_FORMAT: 'Field "{field}" has invalid format',
    OUT_OF_RANGE: 'Field "{field}" value is out of acceptable range',
    TOO_SHORT: 'Field "{field}" is too short (minimum: {min} characters)',
    TOO_LONG: 'Field "{field}" is too long (maximum: {max} characters)',
    INVALID_EMAIL: 'Field "{field}" must be a valid email address',
    INVALID_URL: 'Field "{field}" must be a valid URL',
    INVALID_JSON: 'Field "{field}" must be valid JSON',
  },

  AUTHENTICATION: {
    INVALID_TOKEN: 'Authentication token is invalid or expired',
    MISSING_TOKEN: 'Authentication token is required',
    TOKEN_EXPIRED: 'Authentication token has expired',
    UNAUTHORIZED: 'You are not authorized to perform this action',
  },

  AUTHORIZATION: {
    FORBIDDEN: 'Access denied: insufficient permissions',
    TEAM_ACCESS_DENIED: 'Access denied: team membership required',
    ORGANIZATION_ACCESS_DENIED: 'Access denied: organization membership required',
    RESOURCE_ACCESS_DENIED: 'Access denied: resource access not allowed',
  },

  NOT_FOUND: {
    GENERIC: '{resource} not found',
    WITH_ID: '{resource} with ID "{id}" not found',
    SCENARIO: 'Scenario with ID "{id}" not found',
    TEAM: 'Team with ID "{id}" not found',
    ORGANIZATION: 'Organization with ID "{id}" not found',
  },

  RATE_LIMITING: {
    EXCEEDED: 'Rate limit exceeded. Please try again later',
    QUOTA_EXCEEDED: 'API quota exceeded for this period',
  },

  NETWORK: {
    TIMEOUT: 'Request timed out after {timeout}ms',
    CONNECTION_ERROR: 'Network connection error',
    SERVICE_UNAVAILABLE: 'Service temporarily unavailable',
  },

  INTERNAL: {
    GENERIC: 'An internal error occurred. Please try again later',
    DATABASE_ERROR: 'Database error occurred',
    CONFIGURATION_ERROR: 'Configuration error detected',
  },
} as const;

/**
 * Tool categories for organization
 */
export const TOOL_CATEGORIES = {
  // Core Make.com operations
  SCENARIOS: 'scenarios',
  CONNECTIONS: 'connections',
  BLUEPRINTS: 'blueprints',
  TEMPLATES: 'templates',

  // Data management
  DATA_STORES: 'data_stores',
  VARIABLES: 'variables',
  FOLDERS: 'folders',

  // Security and compliance
  AUTHENTICATION: 'authentication',
  AUTHORIZATION: 'authorization',
  SECRETS: 'secrets',
  AUDIT: 'audit',

  // Monitoring and analytics
  MONITORING: 'monitoring',
  ANALYTICS: 'analytics',
  PERFORMANCE: 'performance',
  LOGGING: 'logging',

  // Enterprise features
  ENTERPRISE: 'enterprise',
  MULTI_TENANT: 'multi_tenant',
  COMPLIANCE: 'compliance',
  GOVERNANCE: 'governance',

  // Developer tools
  SDK: 'sdk',
  MARKETPLACE: 'marketplace',
  CUSTOM_APPS: 'custom_apps',
  CICD: 'cicd',

  // Administrative
  BILLING: 'billing',
  NOTIFICATIONS: 'notifications',
  PERMISSIONS: 'permissions',
  PROCEDURES: 'procedures',
} as const;

/**
 * Progress reporting intervals
 */
export const PROGRESS_CONFIG = {
  /**
   * Standard progress milestones
   */
  MILESTONES: {
    STARTED: 0,
    VALIDATION_COMPLETE: 10,
    API_REQUEST_SENT: 25,
    DATA_RECEIVED: 50,
    PROCESSING_COMPLETE: 75,
    RESPONSE_FORMATTED: 90,
    COMPLETE: 100,
  },

  /**
   * Update intervals in milliseconds
   */
  UPDATE_INTERVALS: {
    FREQUENT: 100,
    NORMAL: 500,
    SPARSE: 1000,
    MINIMAL: 2000,
  },
} as const;