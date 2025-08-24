/**
 * Make.com OAuth 2.1 Configuration for FastMCP Server
 * Production-ready OAuth 2.1 + PKCE configuration for Make.com API integration
 * Based on comprehensive OAuth research and Make.com API specifications
 */

import { z } from "zod";

// Make.com OAuth Configuration Schema
const MakeOAuthConfigSchema = z.object({
  clientId: z.string().min(1, "Make.com OAuth client ID is required"),
  clientSecret: z.string().optional(), // Optional for PKCE public clients
  redirectUri: z.string().url("Valid redirect URI is required"),
  scope: z
    .string()
    .default(
      "scenario:read scenario:write connection:read connection:write webhook:manage team:read user:read",
    ),
  tokenEndpoint: z
    .string()
    .url()
    .default("https://www.make.com/oauth/v2/token"),
  authEndpoint: z
    .string()
    .url()
    .default("https://www.make.com/oauth/v2/authorize"),
  revokeEndpoint: z
    .string()
    .url()
    .default("https://www.make.com/oauth/v2/revoke"),
  userinfoEndpoint: z
    .string()
    .url()
    .default("https://www.make.com/oauth/v2/oidc/userinfo"),
  usePKCE: z.boolean().default(true), // Always enabled for security
});

export type MakeOAuthConfig = z.infer<typeof MakeOAuthConfigSchema>;

/**
 * Get validated Make.com OAuth configuration from environment variables
 * @returns Validated Make.com OAuth configuration
 */
export function getMakeOAuthConfig(): MakeOAuthConfig {
  const config = {
    clientId: process.env.MAKE_OAUTH_CLIENT_ID,
    clientSecret: process.env.MAKE_OAUTH_CLIENT_SECRET,
    redirectUri:
      process.env.MAKE_OAUTH_REDIRECT_URI ||
      "http://localhost:3000/auth/make/callback",
    scope: process.env.MAKE_OAUTH_SCOPE,
    tokenEndpoint: process.env.MAKE_OAUTH_TOKEN_ENDPOINT,
    authEndpoint: process.env.MAKE_OAUTH_AUTH_ENDPOINT,
    revokeEndpoint: process.env.MAKE_OAUTH_REVOKE_ENDPOINT,
    userinfoEndpoint: process.env.MAKE_OAUTH_USERINFO_ENDPOINT,
    usePKCE: process.env.MAKE_OAUTH_USE_PKCE !== "false", // Default to true
  };

  return MakeOAuthConfigSchema.parse(config);
}

/**
 * Make.com OAuth Scopes
 * Based on FastMCP requirements and Make.com API capabilities
 */
export const MAKE_OAUTH_SCOPES = {
  // Core scenario management
  SCENARIO_READ: "scenario:read",
  SCENARIO_WRITE: "scenario:write",
  SCENARIO_EXECUTE: "scenario:execute",

  // Connection management
  CONNECTION_READ: "connection:read",
  CONNECTION_WRITE: "connection:write",

  // Webhook management
  WEBHOOK_MANAGE: "webhook:manage",

  // Team/organization access
  TEAM_READ: "team:read",
  TEAM_WRITE: "team:write",

  // User profile
  USER_READ: "user:read",

  // Advanced permissions
  BLUEPRINT_READ: "blueprint:read",
  BLUEPRINT_WRITE: "blueprint:write",
  EXECUTION_READ: "execution:read",
  EXECUTION_WRITE: "execution:write",
} as const;

/**
 * Default scope combinations for different use cases
 */
export const MAKE_OAUTH_SCOPE_SETS = {
  // Basic read-only access
  READ_ONLY: [
    MAKE_OAUTH_SCOPES.SCENARIO_READ,
    MAKE_OAUTH_SCOPES.CONNECTION_READ,
    MAKE_OAUTH_SCOPES.USER_READ,
  ].join(" "),

  // Standard FastMCP operations
  STANDARD: [
    MAKE_OAUTH_SCOPES.SCENARIO_READ,
    MAKE_OAUTH_SCOPES.SCENARIO_WRITE,
    MAKE_OAUTH_SCOPES.CONNECTION_READ,
    MAKE_OAUTH_SCOPES.CONNECTION_WRITE,
    MAKE_OAUTH_SCOPES.WEBHOOK_MANAGE,
    MAKE_OAUTH_SCOPES.USER_READ,
  ].join(" "),

  // Full access for enterprise use
  FULL: [
    MAKE_OAUTH_SCOPES.SCENARIO_READ,
    MAKE_OAUTH_SCOPES.SCENARIO_WRITE,
    MAKE_OAUTH_SCOPES.SCENARIO_EXECUTE,
    MAKE_OAUTH_SCOPES.CONNECTION_READ,
    MAKE_OAUTH_SCOPES.CONNECTION_WRITE,
    MAKE_OAUTH_SCOPES.WEBHOOK_MANAGE,
    MAKE_OAUTH_SCOPES.TEAM_READ,
    MAKE_OAUTH_SCOPES.TEAM_WRITE,
    MAKE_OAUTH_SCOPES.USER_READ,
    MAKE_OAUTH_SCOPES.BLUEPRINT_READ,
    MAKE_OAUTH_SCOPES.BLUEPRINT_WRITE,
    MAKE_OAUTH_SCOPES.EXECUTION_READ,
    MAKE_OAUTH_SCOPES.EXECUTION_WRITE,
  ].join(" "),
} as const;

/**
 * Make.com Rate Limits by Plan Type
 * Based on roadmap analysis and Make.com API specifications
 */
export const MAKE_RATE_LIMITS = {
  CORE: {
    requests: 60, // requests per minute
    concurrent: 5, // concurrent requests
    dailyOps: 1000, // daily operations
  },
  PRO: {
    requests: 120, // requests per minute
    concurrent: 10, // concurrent requests
    dailyOps: 10000, // daily operations
  },
  TEAMS: {
    requests: 240, // requests per minute
    concurrent: 20, // concurrent requests
    dailyOps: 100000, // daily operations
  },
  ENTERPRISE: {
    requests: 1000, // requests per minute
    concurrent: 50, // concurrent requests
    dailyOps: 1000000, // daily operations
  },
} as const;

/**
 * Make.com OAuth Error Codes
 * Standard OAuth 2.1 error responses from Make.com
 */
export const MAKE_OAUTH_ERRORS = {
  INVALID_REQUEST: "invalid_request",
  INVALID_CLIENT: "invalid_client",
  INVALID_GRANT: "invalid_grant",
  UNAUTHORIZED_CLIENT: "unauthorized_client",
  UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",
  INVALID_SCOPE: "invalid_scope",
  ACCESS_DENIED: "access_denied",
  UNSUPPORTED_RESPONSE_TYPE: "unsupported_response_type",
  SERVER_ERROR: "server_error",
  TEMPORARILY_UNAVAILABLE: "temporarily_unavailable",
} as const;

/**
 * Production environment validation
 * Ensures OAuth configuration meets production security requirements
 */
export function validateProductionConfig(config: MakeOAuthConfig): {
  valid: boolean;
  warnings: string[];
  errors: string[];
} {
  const warnings: string[] = [];
  const errors: string[] = [];

  // HTTPS requirement in production
  if (process.env.NODE_ENV === "production") {
    if (!config.redirectUri.startsWith("https://")) {
      errors.push("Redirect URI must use HTTPS in production");
    }

    if (!config.clientSecret && config.usePKCE === false) {
      errors.push("Client secret required in production when PKCE is disabled");
    }
  }

  // PKCE validation
  if (!config.usePKCE) {
    warnings.push("PKCE disabled - consider enabling for enhanced security");
  }

  // Scope validation
  if (!config.scope.includes(MAKE_OAUTH_SCOPES.USER_READ)) {
    warnings.push("user:read scope recommended for user identification");
  }

  return {
    valid: errors.length === 0,
    warnings,
    errors,
  };
}

export default getMakeOAuthConfig;
