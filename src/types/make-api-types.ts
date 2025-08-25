/**
 * Make.com API TypeScript Interfaces
 * Based on comprehensive research of Make.com API v2 capabilities
 *
 * Research Reports:
 * - comprehensive-makecom-api-capabilities-research-2025.md
 * - comprehensive-makecom-connections-api-research-2025.md
 * - comprehensive-makecom-data-stores-api-research-2025.md
 * - comprehensive-makecom-webhooks-api-research-2025.md
 */

// ==============================================================================
// Core API Response Types
// ==============================================================================

export interface APIResponse<T> {
  data?: T;
  error?: APIError;
  pagination?: PaginationInfo;
  meta?: ResponseMetadata;
}

export interface APIError {
  status: number;
  error: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp?: string;
}

export interface PaginationInfo {
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
}

export interface ResponseMetadata {
  requestId?: string;
  processedAt?: string;
  version?: string;
}

export interface PaginationParams {
  "pg[offset]"?: number;
  "pg[limit]"?: number;
  "pg[sortBy]"?: string;
  "pg[sortDir]"?: "asc" | "desc";
}

// ==============================================================================
// Organization and Team Management
// ==============================================================================

export interface Organization {
  id: number;
  name: string;
  organizationId: number;
  regionId: string; // Geographic region (eu1, us1, etc.)
  timezoneId: string; // Timezone for scheduling
  countryId: string; // Country for billing/compliance
  teams: Team[];
  users: OrganizationUser[];
  variables: CustomVariable[];
  license: {
    plan: string;
    apiLimit: number;
    features: string[];
  };
}

export interface Team {
  id: number;
  name: string;
  organizationId: number;
  users: TeamUser[];
  scenarios: Scenario[];
  variables: TeamVariable[];
  usage: UsageMetrics;
}

export interface TeamUser {
  userId: number;
  teamId: number;
  roleId: number;
  role: TeamRole;
  permissions: Permission[];
}

export interface OrganizationUser {
  userId: number;
  organizationId: number;
  roleId: number;
  role: OrganizationRole;
  permissions: Permission[];
}

export enum TeamRole {
  TEAM_MEMBER = "team_member",
  TEAM_MONITORING = "team_monitoring",
  TEAM_OPERATOR = "team_operator",
  TEAM_RESTRICTED_MEMBER = "team_restricted_member",
}

export enum OrganizationRole {
  ORG_ADMIN = "org_admin",
  ORG_MEMBER = "org_member",
  ORG_OWNER = "org_owner",
}

export interface Permission {
  id: number;
  name: string;
  resource: string;
  action: string;
}

export interface UsageMetrics {
  operations: number;
  dataTransfer: number;
  lastUpdated: string;
}

// ==============================================================================
// Scenario Management
// ==============================================================================

export interface Scenario {
  id: number;
  name: string;
  teamId: number;
  status: ScenarioStatus;
  scheduling: SchedulingConfig;
  modules: ScenarioModule[];
  connections: Connection[];
  logs: ScenarioLog[];
  blueprint: ScenarioBlueprint;
  createdAt: string;
  updatedAt: string;
}

export enum ScenarioStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  PAUSED = "paused",
  ERROR = "error",
}

export interface SchedulingConfig {
  type: "cron" | "interval" | "webhook" | "manual";
  config: CronConfig | IntervalConfig | WebhookConfig | ManualConfig;
}

export interface CronConfig {
  cron: string;
  timezone?: string;
}

export interface IntervalConfig {
  interval: number; // in minutes
  startDate?: string;
  endDate?: string;
}

export interface WebhookConfig {
  webhookId: string;
  url: string;
}

export interface ManualConfig {
  // Manual execution - no additional config needed
}

export interface ScenarioModule {
  id: number;
  type: string;
  app: string;
  operation: string;
  configuration: Record<string, unknown>;
  connections: string[]; // Connection IDs
}

export interface ScenarioLog {
  id: string;
  scenarioId: number;
  status: "success" | "error" | "warning" | "incomplete";
  startTime: string;
  endTime: string;
  operations: number;
  dataSize: number;
  details: Record<string, unknown>;
}

export interface ScenarioBlueprint {
  name: string;
  flow: FlowNode[];
  connections: ConnectionMap;
  variables: VariableMap;
}

export interface FlowNode {
  id: string;
  type: string;
  app: string;
  operation: string;
  mapper: Record<string, unknown>;
  metadata: Record<string, unknown>;
}

export interface ConnectionMap {
  [nodeId: string]: string; // maps node ID to connection ID
}

export interface VariableMap {
  [key: string]: unknown;
}

// ==============================================================================
// Connection Management
// ==============================================================================

export interface Connection {
  id: string;
  name: string;
  service: string; // e.g., "google-sheets", "slack", "database"
  type: ConnectionType;
  status: ConnectionStatus;
  teamId?: number;
  organizationId?: number;
  metadata: ConnectionMetadata;
  authentication: AuthenticationConfig;
  createdAt: string;
  updatedAt: string;
  lastUsed?: string;
}

export enum ConnectionType {
  OAUTH2 = "oauth2",
  API_KEY = "api_key",
  BASIC_AUTH = "basic_auth",
  CUSTOM = "custom",
  DATABASE = "database",
}

export enum ConnectionStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  ERROR = "error",
  EXPIRED = "expired",
  PENDING = "pending",
}

export interface ConnectionMetadata {
  accountName?: string;
  accountId?: string;
  permissions?: string[];
  features?: string[];
  version?: string;
}

export interface AuthenticationConfig {
  type: ConnectionType;
  config: OAuth2Config | APIKeyConfig | BasicAuthConfig | CustomAuthConfig;
}

export interface OAuth2Config {
  clientId: string;
  clientSecret?: string; // Not included in responses for security
  redirectUri: string;
  scope: string[];
  accessToken?: string; // Not included in responses
  refreshToken?: string; // Not included in responses
  tokenExpiresAt?: string;
}

export interface APIKeyConfig {
  keyName: string;
  keyLocation: "header" | "query" | "body";
  // API key value not included in responses for security
}

export interface BasicAuthConfig {
  username: string;
  // Password not included in responses for security
}

export interface CustomAuthConfig {
  fields: AuthField[];
  // Values not included in responses for security
}

export interface AuthField {
  name: string;
  type: "string" | "password" | "email" | "url";
  required: boolean;
  description?: string;
}

// ==============================================================================
// Webhook Management
// ==============================================================================

export interface Webhook {
  id: string;
  name: string;
  url: string;
  method: HTTPMethod;
  status: WebhookStatus;
  teamId?: string;
  connectionId?: string;
  scenarioId?: string;
  configuration: WebhookConfiguration;
  statistics: WebhookStatistics;
  createdAt: string;
  updatedAt: string;
}

export enum WebhookStatus {
  ENABLED = "enabled",
  DISABLED = "disabled",
  LEARNING = "learning",
  ERROR = "error",
}

export enum HTTPMethod {
  GET = "GET",
  POST = "POST",
  PUT = "PUT",
  PATCH = "PATCH",
  DELETE = "DELETE",
}

export interface WebhookConfiguration {
  typeName: string;
  method: boolean; // method tracking enabled
  header: boolean; // include headers
  stringify: boolean; // JSON stringify option
  maxSize?: number; // maximum payload size
  timeout?: number; // request timeout
}

export interface WebhookStatistics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  lastRequestAt?: string;
  averageResponseTime?: number;
}

// ==============================================================================
// Data Store Management
// ==============================================================================

export interface DataStore {
  id: string;
  name: string;
  teamId: number;
  structure: DataStructure;
  records: DataRecord[];
  permissions: DataStorePermissions;
  statistics: DataStoreStatistics;
  createdAt: string;
  updatedAt: string;
}

export interface DataStructure {
  fields: DataField[];
  indexes: DataIndex[];
  constraints: DataConstraint[];
}

export interface DataField {
  name: string;
  type: DataFieldType;
  required: boolean;
  unique: boolean;
  defaultValue?: unknown;
  validation?: FieldValidation;
}

export enum DataFieldType {
  STRING = "string",
  NUMBER = "number",
  BOOLEAN = "boolean",
  DATE = "date",
  DATETIME = "datetime",
  JSON = "json",
  ARRAY = "array",
}

export interface FieldValidation {
  pattern?: string; // regex pattern
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  enum?: unknown[];
}

export interface DataIndex {
  fields: string[];
  unique: boolean;
  name: string;
}

export interface DataConstraint {
  type: "foreign_key" | "check" | "unique";
  fields: string[];
  reference?: {
    table: string;
    fields: string[];
  };
  condition?: string;
}

export interface DataRecord {
  id: string;
  data: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface DataStorePermissions {
  read: string[];
  write: string[];
  delete: string[];
  admin: string[];
}

export interface DataStoreStatistics {
  totalRecords: number;
  totalSize: number; // in bytes
  lastModified: string;
  averageRecordSize: number;
}

// ==============================================================================
// Template and Blueprint Management
// ==============================================================================

export interface Template {
  id: number;
  name: string;
  description?: string;
  category: string;
  tags: string[];
  scenario: ScenarioBlueprint;
  metadata: TemplateMetadata;
  createdAt: string;
  updatedAt: string;
}

export interface TemplateMetadata {
  creator: number;
  organizationId?: number;
  teamId?: number;
  isPublic: boolean;
  usageCount: number;
  complexity: "simple" | "intermediate" | "advanced";
  estimatedSetupTime: number; // in minutes
  requiredConnections: string[];
}

// ==============================================================================
// Custom Variables
// ==============================================================================

export interface CustomVariable {
  name: string;
  value: string | number | boolean;
  type: VariableType;
  scope: VariableScope;
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

export interface TeamVariable extends CustomVariable {
  teamId: number;
}

export enum VariableType {
  STRING = "string",
  NUMBER = "number",
  BOOLEAN = "boolean",
  JSON = "json",
}

export enum VariableScope {
  ORGANIZATION = "organization",
  TEAM = "team",
  SCENARIO = "scenario",
}

// ==============================================================================
// SDK Apps and Custom Functions
// ==============================================================================

export interface SDKApp {
  id: number;
  name: string;
  description?: string;
  status: AppStatus;
  version: string;
  modules: AppModule[];
  connections: AppConnection[];
  rpcs: RPC[];
  webhooks: AppWebhook[];
  functions: CustomFunction[];
}

export enum AppStatus {
  DEVELOPMENT = "development",
  PUBLISHED = "published",
  APPROVED = "approved",
  DEPRECATED = "deprecated",
}

export interface AppModule {
  id: string;
  name: string;
  type: "trigger" | "action" | "search";
  operations: ModuleOperation[];
}

export interface ModuleOperation {
  name: string;
  operation: string;
  parameters: ParameterConfig[];
  response: ResponseConfig;
}

export interface AppConnection {
  type: ConnectionType;
  configuration: ConnectionConfiguration;
}

export interface ConnectionConfiguration {
  fields: ConfigurationField[];
  oauth2?: OAuth2AppConfig;
  apiKey?: APIKeyAppConfig;
}

export interface ConfigurationField {
  name: string;
  label: string;
  type: string;
  required: boolean;
  help?: string;
}

export interface OAuth2AppConfig {
  authorizationUrl: string;
  tokenUrl: string;
  scope: string[];
}

export interface APIKeyAppConfig {
  location: "header" | "query" | "body";
  name: string;
}

export interface RPC {
  id: string;
  name: string;
  type: RPCType;
  endpoint: string;
  method: HTTPMethod;
  parameters: ParameterConfig[];
  timeout: number; // max 40 seconds
  response: ResponseConfig;
}

export enum RPCType {
  DYNAMIC_OPTIONS = "dynamic-options",
  DYNAMIC_FIELDS = "dynamic-fields",
  DYNAMIC_SAMPLE = "dynamic-sample",
}

export interface ParameterConfig {
  name: string;
  type: string;
  required: boolean;
  description?: string;
  validation?: FieldValidation;
}

export interface ResponseConfig {
  type: string;
  structure: Record<string, unknown>;
  iterate?: string;
  output?: Record<string, unknown>;
}

export interface AppWebhook {
  name: string;
  type: string;
  configuration: WebhookConfiguration;
}

export interface CustomFunction {
  name: string;
  code: string; // JavaScript code
  timeout: 10; // seconds maximum
  maxOutput: 5000; // characters maximum
  environment: {
    javascript: "ES6 supported including arrow functions";
    builtins: "JavaScript built-in objects + Buffer";
    iml: "Access to built-in IML functions via iml namespace";
  };
}

// ==============================================================================
// API Client Configuration
// ==============================================================================

export interface MakeClientConfig {
  // Authentication
  apiToken?: string;
  oauth2?: OAuth2Config;

  // Regional configuration
  zone: "eu1" | "eu2" | "us1" | "us2";
  apiVersion: "v2";

  // Performance configuration
  timeout: number;
  retryConfig: RetryConfig;
  rateLimitConfig: RateLimitConfig;
}

export interface RetryConfig {
  maxRetries: number;
  retryDelay: number;
  backoffMultiplier: number;
  maxRetryDelay: number;
}

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  skipSuccessfulRequests: boolean;
  skipFailedRequests: boolean;
}

// ==============================================================================
// Authentication and Authorization
// ==============================================================================

export interface MakeAPIScopes {
  // Core platform scopes
  "organizations:read": string[];
  "organizations:write": string[];
  "teams:read": string[];
  "teams:write": string[];
  "scenarios:read": string[];
  "scenarios:write": string[];
  "scenarios:run": string[];
  "users:read": string[];
  "users:write": string[];

  // Advanced feature scopes
  "sdk-apps:read": string[];
  "sdk-apps:write": string[];
  "analytics:read": string[];
  "data-stores:read": string[];
  "data-stores:write": string[];
  "templates:read": string[];
  "templates:write": string[];

  // Administrative scopes
  "admin:read": string[];
  "admin:write": string[];
  "system:read": string[];
  "system:write": string[];
}

// ==============================================================================
// Rate Limiting and Error Handling
// ==============================================================================

export interface RateLimits {
  core: 60; // requests per minute
  pro: 120; // requests per minute
  teams: 240; // requests per minute
  enterprise: 1000; // requests per minute
}

export interface RateLimitStatus {
  allowed: boolean;
  remaining: number;
  resetTime: string;
  retryAfter: number;
}

export interface RateLimitError extends APIError {
  retryAfter?: number;
  rateLimitType?: string;
  organizationPlan?: string;
}

// ==============================================================================
// Analytics and Monitoring
// ==============================================================================

export interface AnalyticsData {
  operations: OperationMetrics;
  dataTransfer: DataTransferMetrics;
  errors: ErrorMetrics;
  performance: PerformanceMetrics;
}

export interface OperationMetrics {
  total: number;
  successful: number;
  failed: number;
  byPeriod: PeriodMetrics[];
}

export interface DataTransferMetrics {
  totalBytes: number;
  inboundBytes: number;
  outboundBytes: number;
  byPeriod: PeriodMetrics[];
}

export interface ErrorMetrics {
  totalErrors: number;
  errorsByType: Record<string, number>;
  errorsByStatus: Record<number, number>;
}

export interface PerformanceMetrics {
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  slowestOperations: SlowOperation[];
}

export interface PeriodMetrics {
  period: string;
  value: number;
}

export interface SlowOperation {
  operation: string;
  averageTime: number;
  count: number;
}

// ==============================================================================
// Export All Types
// ==============================================================================

export type {
  // Core types
  APIResponse,
  APIError,
  PaginationInfo,
  ResponseMetadata,
  PaginationParams,

  // Organization and team types
  Organization,
  Team,
  TeamUser,
  OrganizationUser,
  Permission,
  UsageMetrics,

  // Scenario types
  Scenario,
  SchedulingConfig,
  CronConfig,
  IntervalConfig,
  ManualConfig,
  ScenarioModule,
  ScenarioLog,
  ScenarioBlueprint,
  FlowNode,
  ConnectionMap,
  VariableMap,

  // Connection types
  Connection,
  ConnectionMetadata,
  AuthenticationConfig,
  OAuth2Config,
  APIKeyConfig,
  BasicAuthConfig,
  CustomAuthConfig,
  AuthField,

  // Webhook types
  Webhook,
  WebhookConfiguration,
  WebhookStatistics,

  // Data store types
  DataStore,
  DataStructure,
  DataField,
  FieldValidation,
  DataIndex,
  DataConstraint,
  DataRecord,
  DataStorePermissions,
  DataStoreStatistics,

  // Template types
  Template,
  TemplateMetadata,

  // Variable types
  CustomVariable,
  TeamVariable,

  // SDK App types
  SDKApp,
  AppModule,
  ModuleOperation,
  AppConnection,
  ConnectionConfiguration,
  ConfigurationField,
  OAuth2AppConfig,
  APIKeyAppConfig,
  RPC,
  ParameterConfig,
  ResponseConfig,
  AppWebhook,
  CustomFunction,

  // Configuration types
  MakeClientConfig,
  RetryConfig,
  RateLimitConfig,
  MakeAPIScopes,

  // Rate limiting types
  RateLimits,
  RateLimitStatus,
  RateLimitError,

  // Analytics types
  AnalyticsData,
  OperationMetrics,
  DataTransferMetrics,
  ErrorMetrics,
  PerformanceMetrics,
  PeriodMetrics,
  SlowOperation,
};
