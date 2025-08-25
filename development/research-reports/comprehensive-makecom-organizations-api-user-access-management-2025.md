# Make.com Organizations API for User and Access Management - Comprehensive Research Report 2025

**Research Date**: August 25, 2025  
**Task ID**: task_1756147893626_abyjq81ci  
**Research Focus**: Comprehensive analysis of Make.com Organizations API for User and Access Management system FastMCP implementation  
**Research Status**: COMPREHENSIVE - Complete investigation of Organizations API, authentication, billing, and integration patterns

## Executive Summary

This comprehensive research provides detailed analysis of Make.com's Organizations API capabilities for User and Access Management systems, specifically focusing on organization CRUD operations, user management, authentication patterns, billing integration, and FastMCP implementation considerations. The research reveals a sophisticated API architecture with robust organization-level management capabilities, detailed permission systems, and comprehensive user access control features.

## 1. Organizations API Endpoints - Complete Reference

### 1.1 Core Organization CRUD Operations

**Base URL Structure**: `{zone_url}/api/v2/organizations`

#### Organization Management Endpoints

```typescript
// List Organizations
GET /api/v2/organizations
// Query Parameters:
// - cols[]: Specify columns to return in response
// - pg[sortBy]: Field to sort results by
// - pg[offset]: Pagination offset for results
// - pg[limit]: Maximum number of results per page
// Response: Collection of organizations where user has membership

// Create Organization (Admin only)
POST /api/v2/organizations
// Required Body Parameters:
{
  "name": "string",           // Organization display name
  "regionId": "string",       // Make region instance (eu1, us1, eu2, us2)
  "timezoneId": "string",     // Timezone for scheduling operations
  "countryId": "string"       // Country for billing/compliance
}

// Get Organization Details
GET /api/v2/organizations/{organizationId}
// Returns: Complete organization data including teams, users, settings

// Update Organization
PATCH /api/v2/organizations/{organizationId}
// Body: Fields to update (name, timezoneId, countryId, etc.)

// Delete Organization
DELETE /api/v2/organizations/{organizationId}
// Note: Requires organization owner permissions
```

#### Organization Response Data Model

```typescript
interface OrganizationResponse {
  organizations: Array<{
    id: number;
    name: string;
    organizationId: number;
    regionId: string; // Geographic zone (eu1, us1, eu2, us2)
    timezoneId: string; // Organization default timezone
    countryId: string; // Country for billing/legal
    teams: Array<{
      id: number;
      name: string;
      memberCount?: number;
    }>;
    usageData?: {
      operations: number;
      dataTransfer: number;
      period: string;
    };
  }>;
  totalCount: number;
  hasMore: boolean;
}
```

### 1.2 Organization User Management Endpoints

#### User Invitation System

```typescript
// Invite User to Organization
POST /api/v2/organizations/{organizationId}/invite
// Required Body:
{
  "email": "string",          // User email address (required)
  "name": "string",           // User display name (required)
  "usersRoleId": "number",    // Organization role ID (optional)
  "teamsId[]": "number[]"     // Team assignments during invitation (optional)
}

// Get Organization Invitation Details
GET /api/v2/organizations/invitation
// Query Parameters:
// - invitationToken: Token from invitation email
// Response: Invitation details for acceptance

// Accept Organization Invitation
POST /api/v2/organizations/accept-invitation
// Body:
{
  "invitationToken": "string",  // Token from invitation email
  "accept": true               // Accept or decline invitation
}

// List Organization Invitations (Admin)
GET /api/v2/organizations/{organizationId}/invitations
// Returns: Pending invitations for organization

// Cancel Organization Invitation
DELETE /api/v2/organizations/{organizationId}/invitations/{invitationId}
// Note: Only organization admins can cancel invitations
```

#### Organization User Role Management

```typescript
// Get User Organization Roles
GET /api/v2/users/{userId}/user-organization-roles
// Returns: All organization roles for specified user

// Get User Role in Organization
GET /api/v2/users/{userId}/user-organization-roles/{organizationId}
// Returns: Specific user role details in organization

// Update User Organization Role
POST /api/v2/users/{userId}/user-organization-roles/{organizationId}
// Body:
{
  "usersRoleId": number       // New role ID for user
}
// Note: Only organization owners and admins can modify roles

// Transfer Organization Ownership
POST /api/v2/organizations/{organizationId}/transfer-ownership
// Body:
{
  "newOwnerId": number        // User ID of new owner
}
// Note: Only current organization owner can transfer ownership
```

### 1.3 Organization Settings and Configuration

#### Organization Variables Management

```typescript
// List Organization Variables
GET /api/v2/organizations/{organizationId}/variables
// Returns: All custom variables defined for organization

// Create Organization Variable
POST /api/v2/organizations/{organizationId}/variables
// Body:
{
  "name": "string",           // Variable name (unique within org)
  "value": "string|number|boolean", // Variable value
  "type": "string|number|boolean",  // Data type
  "description": "string"     // Optional description
}

// Update Organization Variable
PATCH /api/v2/organizations/{organizationId}/variables/{variableName}
// Body: Fields to update (value, description, etc.)

// Delete Organization Variable
DELETE /api/v2/organizations/{organizationId}/variables/{variableName}

// Get Variable Update History
GET /api/v2/organizations/{organizationId}/variables/{variableName}/history
// Returns: Audit trail of variable changes
```

#### Organization Usage Analytics

```typescript
// Get Organization Usage Data
GET / api / v2 / organizations / { organizationId } / usage;
// Query Parameters:
// - period: "day" | "week" | "month" (default: "month")
// - startDate: ISO date string (optional)
// - endDate: ISO date string (optional)
// Returns: Operations and data transfer usage for past 30 days across all teams

interface OrganizationUsage {
  usage: Array<{
    date: string; // ISO date
    operations: number; // Operations count
    dataTransfer: number; // Data transfer in bytes
    teams: Array<{
      teamId: number;
      teamName: string;
      operations: number;
      dataTransfer: number;
    }>;
  }>;
  totals: {
    operations: number;
    dataTransfer: number;
    period: string;
  };
}
```

## 2. Organization Data Models and Schema

### 2.1 Core Organization Entity

```typescript
interface Organization {
  id: number;
  name: string;
  organizationId: number; // Legacy compatibility field
  regionId: string; // Geographic region (eu1, us1, eu2, us2)
  timezoneId: string; // Default timezone for scheduling
  countryId: string; // Country for billing/compliance
  createdAt: string; // ISO date string
  updatedAt: string; // ISO date string

  // Relationships
  teams: Team[];
  users: OrganizationUser[];
  variables: OrganizationVariable[];

  // Settings
  settings: OrganizationSettings;

  // Usage and billing
  subscription?: OrganizationSubscription;
  usage?: OrganizationUsageData;
}

interface OrganizationSettings {
  name: string;
  regionId: string;
  timezoneId: string;
  countryId: string;

  // Advanced settings
  defaultScenarioSettings?: {
    scheduling: string;
    errorHandling: string;
    logging: boolean;
  };

  // Security settings
  ssoEnabled?: boolean;
  mfaRequired?: boolean;
  ipWhitelist?: string[];

  // Notification settings
  emailNotifications?: boolean;
  webhookNotifications?: boolean;
}

interface OrganizationVariable {
  name: string;
  value: string | number | boolean;
  type: "string" | "number" | "boolean";
  description?: string;
  createdAt: string;
  updatedAt: string;
  createdBy: number; // User ID who created variable
  updatedBy: number; // User ID who last updated variable
}
```

### 2.2 Organization User and Role Models

```typescript
interface OrganizationUser {
  id: number;
  userId: number;
  organizationId: number;
  usersRoleId: number;

  // User details
  email: string;
  name: string;
  avatar?: string;

  // Role information
  role: OrganizationRole;

  // Membership details
  joinedAt: string; // ISO date string
  invitedAt?: string; // ISO date string
  invitedBy?: number; // User ID of inviter
  status: "active" | "pending" | "suspended";

  // Team memberships within organization
  teamMemberships: TeamMembership[];
}

interface OrganizationRole {
  id: number;
  name: string;
  type: "owner" | "admin" | "member";
  permissions: OrganizationPermissions;
  description?: string;
}

interface OrganizationPermissions {
  // Organization management
  canUpdateOrganization: boolean;
  canDeleteOrganization: boolean;
  canManageSettings: boolean;

  // User management
  canInviteUsers: boolean;
  canRemoveUsers: boolean;
  canChangeUserRoles: boolean;
  canTransferOwnership: boolean;

  // Team management
  canCreateTeams: boolean;
  canDeleteTeams: boolean;
  canManageAllTeams: boolean;

  // Variables and configuration
  canManageVariables: boolean;
  canViewUsage: boolean;

  // Billing (if available)
  canViewBilling: boolean;
  canManageBilling: boolean;
}
```

### 2.3 Team Integration Models

```typescript
interface Team {
  id: number;
  name: string;
  organizationId: number;
  description?: string;

  // Team members and roles
  members: TeamMember[];

  // Team-specific settings
  variables: TeamVariable[];
  usage: TeamUsageData;

  // Metadata
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

interface TeamMember {
  userId: number;
  teamId: number;
  roleId: number;
  role: TeamRole;

  // Membership details
  joinedAt: string;
  addedBy: number;
  status: "active" | "pending";
}

interface TeamRole {
  id: number;
  name: string;
  type:
    | "team_member"
    | "team_monitoring"
    | "team_operator"
    | "team_restricted_member";
  permissions: TeamPermissions;
}

interface TeamPermissions {
  // Scenario management
  canCreateScenarios: boolean;
  canEditScenarios: boolean;
  canDeleteScenarios: boolean;
  canRunScenarios: boolean;
  canPublishScenarios: boolean;

  // Team management
  canManageTeamMembers: boolean;
  canManageTeamSettings: boolean;

  // Data access
  canViewTeamData: boolean;
  canExportTeamData: boolean;

  // Variables
  canManageTeamVariables: boolean;
}
```

## 3. Authentication and Authorization Deep Dive

### 3.1 API Authentication Methods

#### Primary Authentication: API Tokens

```typescript
interface APIAuthentication {
  method: "Bearer Token";
  header: "Authorization: Bearer {token}";
  tokenType: "Personal Access Token";

  // Token management
  tokenCreation: {
    location: "Profile > Profile > API tab";
    requirements: ["Paid Make account", "Token label", "Scope selection"];
    validity: "Permanent until revoked";
  };

  // Token security
  tokenSecurity: {
    storage: "Secure storage required";
    rotation: "Manual rotation recommended";
    monitoring: "Access logging available";
  };
}
```

#### API Token Configuration

```typescript
interface APITokenConfig {
  label: string; // Human-readable token identifier
  scopes: APIScope[]; // Granted permissions
  createdAt: string; // Creation timestamp
  lastUsed?: string; // Last access timestamp

  // Token metadata
  ipRestrictions?: string[]; // Allowed IP addresses
  expiresAt?: string; // Optional expiration

  // Usage tracking
  requestCount: number;
  lastRequestAt?: string;
}
```

### 3.2 Organization-Level API Scopes

#### Core Organization Scopes

```typescript
const ORGANIZATION_API_SCOPES = {
  // Read permissions
  "organizations:read": {
    description: "Read organization data and membership",
    permissions: [
      "Get all organizations user belongs to",
      "Get installed apps in organizations",
      "Get organization invitations",
      "Get user roles in organizations",
      "Get basic organization details",
      "View organization settings (read-only)",
    ],
  },

  // Write permissions
  "organizations:write": {
    description: "Manage organization settings and membership",
    permissions: [
      "Create new organizations (admin-only)",
      "Update organization settings",
      "Delete organizations",
      "Accept organization invitations",
      "Add members to organizations",
      "Remove members from organizations",
      "Transfer organization ownership",
    ],
    requirements: ["organizations:read scope also required"],
  },

  // Variable management
  "organizations-variables:read": {
    description: "Read organization variables and history",
    permissions: [
      "Retrieve organization variable data",
      "Get history of custom organization variable updates",
      "View variable metadata and audit trails",
    ],
  },

  "organizations-variables:write": {
    description: "Manage organization variables",
    permissions: [
      "Create custom organization variables",
      "Update custom organization variables",
      "Delete custom organization variables",
    ],
    requirements: ["organizations-variables:read scope also required"],
  },
};
```

#### User Management Scopes

```typescript
const USER_MANAGEMENT_SCOPES = {
  "user:read": {
    description: "Read user profile and membership data",
    permissions: [
      "Retrieve user profile details",
      "Get user API tokens list",
      "Check organization invitations",
      "View user team memberships",
      "Access user role information",
    ],
  },

  "user:write": {
    description: "Manage user roles and membership",
    permissions: [
      "Set user roles in teams",
      "Set user roles in organizations",
      "Transfer organization ownership",
      "Update user profile information",
      "Revoke user API tokens",
    ],
    requirements: ["user:read scope also required"],
  },
};
```

### 3.3 Multi-Organization Authentication Patterns

#### Organization Context Switching

```typescript
interface OrganizationContext {
  // Current organization context
  currentOrganizationId: number;

  // Available organizations
  availableOrganizations: Array<{
    id: number;
    name: string;
    role: string;
    permissions: string[];
  }>;

  // Context switching
  switchOrganization(organizationId: number): Promise<void>;
  getOrganizationPermissions(organizationId: number): string[];
}

// Example implementation pattern
class MakeAPIClient {
  private currentOrgId?: number;

  async setOrganizationContext(organizationId: number): Promise<void> {
    // Validate user has access to organization
    const orgs = await this.getUserOrganizations();
    const hasAccess = orgs.some((org) => org.id === organizationId);

    if (!hasAccess) {
      throw new Error("No access to organization");
    }

    this.currentOrgId = organizationId;
  }

  async makeRequest(
    endpoint: string,
    options?: RequestInit,
  ): Promise<Response> {
    const headers = {
      Authorization: `Bearer ${this.apiToken}`,
      "X-Organization-Context": this.currentOrgId?.toString(),
      ...options?.headers,
    };

    return fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
    });
  }
}
```

### 3.4 Security Considerations for Organization Access

#### Access Control Matrix

```typescript
interface SecurityConfiguration {
  // Token-based access control
  tokenSecurity: {
    minimumScopes: string[]; // Required scopes for organization access
    scopeValidation: boolean; // Validate scopes on each request
    tokenRotation: {
      recommended: boolean;
      intervalDays: number;
    };
  };

  // Organization-level security
  organizationSecurity: {
    ipWhitelist?: string[]; // Allowed IP addresses
    mfaRequired: boolean; // Multi-factor authentication
    ssoIntegration?: {
      enabled: boolean;
      provider: string;
      domains: string[];
    };
  };

  // Audit and monitoring
  auditLogging: {
    enabled: boolean;
    events: string[]; // Types of events to log
    retention: number; // Days to retain logs
  };
}
```

#### Permission Validation Patterns

```typescript
// Permission validation helper
class OrganizationPermissionValidator {
  static async validateAccess(
    userId: number,
    organizationId: number,
    requiredPermission: string,
  ): Promise<boolean> {
    // Get user's role in organization
    const userRole = await this.getUserOrganizationRole(userId, organizationId);

    if (!userRole) {
      return false; // User not member of organization
    }

    // Check if role has required permission
    return userRole.permissions.includes(requiredPermission);
  }

  static async requirePermission(
    userId: number,
    organizationId: number,
    permission: string,
  ): Promise<void> {
    const hasPermission = await this.validateAccess(
      userId,
      organizationId,
      permission,
    );

    if (!hasPermission) {
      throw new Error(`Insufficient permissions: ${permission} required`);
    }
  }
}
```

## 4. Billing and Subscription Management (Limited API Access)

### 4.1 Available Subscription Endpoints

**Note**: Based on research, Make.com has limited public API access to billing information. Most subscription management appears to be handled through the web interface.

```typescript
// Subscription information (Read-only)
GET / api / v2 / organizations / { organizationId } / subscription;
// Returns: Current subscription details for organization

interface OrganizationSubscription {
  id: number;
  organizationId: number;
  planName: string; // "Free", "Core", "Pro", "Teams", "Enterprise"
  planType: "monthly" | "annual";

  // Usage limits
  operationsLimit: number; // Operations per month
  dataTransferLimit: number; // Data transfer limit in MB

  // Billing information (limited)
  status: "active" | "trial" | "suspended" | "cancelled";
  currentPeriodStart: string; // ISO date
  currentPeriodEnd: string; // ISO date

  // Feature availability
  features: {
    advancedScenarios: boolean;
    customFunctions: boolean;
    webhooks: boolean;
    apiAccess: boolean;
    prioritySupport: boolean;
  };

  // Usage tracking
  currentUsage: {
    operations: number;
    dataTransfer: number;
    period: string;
  };
}
```

### 4.2 Subscription Data Models

```typescript
interface BillingInformation {
  // Limited billing data available through API
  subscription: OrganizationSubscription;

  // Usage tracking
  usage: {
    current: UsagePeriod;
    previous: UsagePeriod[];
  };

  // Billing alerts (if configured)
  alerts: BillingAlert[];
}

interface UsagePeriod {
  startDate: string;
  endDate: string;
  operations: number;
  dataTransfer: number;
  overageCharges?: number;
}

interface BillingAlert {
  id: number;
  type: "usage_warning" | "usage_limit" | "payment_failed";
  threshold: number;
  enabled: boolean;
  recipients: string[]; // Email addresses
}
```

### 4.3 Usage Monitoring Integration

```typescript
// Enhanced usage monitoring for organizations
interface UsageMonitoringService {
  // Real-time usage tracking
  getCurrentUsage(organizationId: number): Promise<UsageData>;

  // Usage forecasting
  predictUsage(organizationId: number, days: number): Promise<Usageforecast>;

  // Alert management
  setUsageAlert(organizationId: number, alert: BillingAlert): Promise<void>;

  // Reporting
  generateUsageReport(
    organizationId: number,
    period: "week" | "month" | "quarter",
  ): Promise<UsageReport>;
}
```

## 5. Integration Patterns for FastMCP Implementation

### 5.1 Recommended FastMCP Tool Architecture

#### Core Organization Management Tools

```typescript
// FastMCP tool definitions for organization management
interface OrganizationManagementTools {
  // Organization CRUD
  list_organizations: {
    name: "list_organizations";
    description: "List all organizations where user has membership";
    inputSchema: {
      type: "object";
      properties: {
        includeTeams?: boolean; // Include team information
        includeUsage?: boolean; // Include usage statistics
        sortBy?: "name" | "created" | "usage";
        limit?: number; // Pagination limit
        offset?: number; // Pagination offset
      };
    };
  };

  create_organization: {
    name: "create_organization";
    description: "Create a new organization (admin only)";
    inputSchema: {
      type: "object";
      properties: {
        name: string; // Required: Organization name
        regionId: string; // Required: Geographic region
        timezoneId: string; // Required: Default timezone
        countryId: string; // Required: Country for billing
      };
      required: ["name", "regionId", "timezoneId", "countryId"];
    };
  };

  update_organization: {
    name: "update_organization";
    description: "Update organization settings";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        name?: string; // Optional: New name
        timezoneId?: string; // Optional: New timezone
        countryId?: string; // Optional: New country
      };
      required: ["organizationId"];
    };
  };

  delete_organization: {
    name: "delete_organization";
    description: "Delete organization (owner only)";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        confirmDelete: boolean; // Required: Confirmation flag
      };
      required: ["organizationId", "confirmDelete"];
    };
  };
}
```

#### User Management Tools

```typescript
interface UserManagementTools {
  // User invitation and management
  invite_user_to_organization: {
    name: "invite_user_to_organization";
    description: "Invite user to organization with specific role";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        email: string; // Required: User email
        name: string; // Required: User name
        roleId?: number; // Optional: Organization role ID
        teamIds?: number[]; // Optional: Team assignments
      };
      required: ["organizationId", "email", "name"];
    };
  };

  update_user_organization_role: {
    name: "update_user_organization_role";
    description: "Update user's role in organization";
    inputSchema: {
      type: "object";
      properties: {
        userId: number; // Required: User ID
        organizationId: number; // Required: Organization ID
        roleId: number; // Required: New role ID
      };
      required: ["userId", "organizationId", "roleId"];
    };
  };

  remove_user_from_organization: {
    name: "remove_user_from_organization";
    description: "Remove user from organization";
    inputSchema: {
      type: "object";
      properties: {
        userId: number; // Required: User ID
        organizationId: number; // Required: Organization ID
        transferData?: boolean; // Optional: Transfer user data
      };
      required: ["userId", "organizationId"];
    };
  };

  transfer_organization_ownership: {
    name: "transfer_organization_ownership";
    description: "Transfer organization ownership to another user";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        newOwnerId: number; // Required: New owner user ID
        confirmTransfer: boolean; // Required: Confirmation flag
      };
      required: ["organizationId", "newOwnerId", "confirmTransfer"];
    };
  };
}
```

#### Organization Variables and Configuration Tools

```typescript
interface OrganizationConfigurationTools {
  // Variable management
  list_organization_variables: {
    name: "list_organization_variables";
    description: "List all custom variables in organization";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        includeHistory?: boolean; // Optional: Include change history
      };
      required: ["organizationId"];
    };
  };

  create_organization_variable: {
    name: "create_organization_variable";
    description: "Create custom variable in organization";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        name: string; // Required: Variable name
        value: string | number | boolean; // Required: Variable value
        type: "string" | "number" | "boolean"; // Required: Data type
        description?: string; // Optional: Description
      };
      required: ["organizationId", "name", "value", "type"];
    };
  };

  update_organization_variable: {
    name: "update_organization_variable";
    description: "Update organization variable value";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        variableName: string; // Required: Variable name
        value: string | number | boolean; // Required: New value
        description?: string; // Optional: Updated description
      };
      required: ["organizationId", "variableName", "value"];
    };
  };

  delete_organization_variable: {
    name: "delete_organization_variable";
    description: "Delete organization variable";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        variableName: string; // Required: Variable name
        confirmDelete: boolean; // Required: Confirmation flag
      };
      required: ["organizationId", "variableName", "confirmDelete"];
    };
  };
}
```

#### Analytics and Usage Tools

```typescript
interface OrganizationAnalyticsTools {
  // Usage monitoring
  get_organization_usage: {
    name: "get_organization_usage";
    description: "Get organization usage statistics";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        period?: "day" | "week" | "month"; // Optional: Time period
        startDate?: string; // Optional: Start date (ISO)
        endDate?: string; // Optional: End date (ISO)
        includeTeamBreakdown?: boolean; // Optional: Include per-team data
      };
      required: ["organizationId"];
    };
  };

  get_organization_subscription: {
    name: "get_organization_subscription";
    description: "Get organization subscription and billing information";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
      };
      required: ["organizationId"];
    };
  };

  generate_usage_report: {
    name: "generate_usage_report";
    description: "Generate detailed usage report for organization";
    inputSchema: {
      type: "object";
      properties: {
        organizationId: number; // Required: Organization ID
        reportType: "summary" | "detailed" | "comparative";
        period: "week" | "month" | "quarter";
        format?: "json" | "csv"; // Optional: Output format
      };
      required: ["organizationId", "reportType", "period"];
    };
  };
}
```

### 5.2 FastMCP Implementation Architecture

#### Core Service Classes

```typescript
// Main Make.com API client for organization management
class MakeOrganizationAPIClient {
  private apiToken: string;
  private baseUrl: string;
  private currentOrgId?: number;

  constructor(config: MakeAPIConfig) {
    this.apiToken = config.apiToken;
    this.baseUrl = config.baseUrl;
  }

  // Organization management methods
  async listOrganizations(
    options?: ListOrganizationsOptions,
  ): Promise<OrganizationResponse> {
    const url = new URL("/api/v2/organizations", this.baseUrl);

    if (options?.includeTeams) {
      url.searchParams.append("cols[]", "teams");
    }
    if (options?.sortBy) {
      url.searchParams.append("pg[sortBy]", options.sortBy);
    }
    if (options?.limit) {
      url.searchParams.append("pg[limit]", options.limit.toString());
    }
    if (options?.offset) {
      url.searchParams.append("pg[offset]", options.offset.toString());
    }

    const response = await this.makeRequest("GET", url.toString());
    return response.json();
  }

  async createOrganization(
    data: CreateOrganizationRequest,
  ): Promise<Organization> {
    const response = await this.makeRequest(
      "POST",
      "/api/v2/organizations",
      data,
    );
    return response.json();
  }

  async updateOrganization(
    organizationId: number,
    data: UpdateOrganizationRequest,
  ): Promise<Organization> {
    const response = await this.makeRequest(
      "PATCH",
      `/api/v2/organizations/${organizationId}`,
      data,
    );
    return response.json();
  }

  async deleteOrganization(organizationId: number): Promise<void> {
    await this.makeRequest("DELETE", `/api/v2/organizations/${organizationId}`);
  }

  // User management methods
  async inviteUser(
    organizationId: number,
    invitation: UserInvitation,
  ): Promise<InvitationResponse> {
    const response = await this.makeRequest(
      "POST",
      `/api/v2/organizations/${organizationId}/invite`,
      invitation,
    );
    return response.json();
  }

  async updateUserRole(
    userId: number,
    organizationId: number,
    roleId: number,
  ): Promise<void> {
    await this.makeRequest(
      "POST",
      `/api/v2/users/${userId}/user-organization-roles/${organizationId}`,
      {
        usersRoleId: roleId,
      },
    );
  }

  async transferOwnership(
    organizationId: number,
    newOwnerId: number,
  ): Promise<void> {
    await this.makeRequest(
      "POST",
      `/api/v2/organizations/${organizationId}/transfer-ownership`,
      {
        newOwnerId,
      },
    );
  }

  // Variables management methods
  async listVariables(organizationId: number): Promise<OrganizationVariable[]> {
    const response = await this.makeRequest(
      "GET",
      `/api/v2/organizations/${organizationId}/variables`,
    );
    return response.json();
  }

  async createVariable(
    organizationId: number,
    variable: CreateVariableRequest,
  ): Promise<OrganizationVariable> {
    const response = await this.makeRequest(
      "POST",
      `/api/v2/organizations/${organizationId}/variables`,
      variable,
    );
    return response.json();
  }

  async updateVariable(
    organizationId: number,
    variableName: string,
    data: UpdateVariableRequest,
  ): Promise<OrganizationVariable> {
    const response = await this.makeRequest(
      "PATCH",
      `/api/v2/organizations/${organizationId}/variables/${variableName}`,
      data,
    );
    return response.json();
  }

  async deleteVariable(
    organizationId: number,
    variableName: string,
  ): Promise<void> {
    await this.makeRequest(
      "DELETE",
      `/api/v2/organizations/${organizationId}/variables/${variableName}`,
    );
  }

  // Usage and analytics methods
  async getUsage(
    organizationId: number,
    options?: UsageOptions,
  ): Promise<OrganizationUsage> {
    const url = new URL(
      `/api/v2/organizations/${organizationId}/usage`,
      this.baseUrl,
    );

    if (options?.period) {
      url.searchParams.append("period", options.period);
    }
    if (options?.startDate) {
      url.searchParams.append("startDate", options.startDate);
    }
    if (options?.endDate) {
      url.searchParams.append("endDate", options.endDate);
    }

    const response = await this.makeRequest("GET", url.toString());
    return response.json();
  }

  async getSubscription(
    organizationId: number,
  ): Promise<OrganizationSubscription> {
    const response = await this.makeRequest(
      "GET",
      `/api/v2/organizations/${organizationId}/subscription`,
    );
    return response.json();
  }

  // Helper methods
  private async makeRequest(
    method: string,
    url: string,
    body?: any,
  ): Promise<Response> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.apiToken}`,
      "Content-Type": "application/json",
    };

    if (this.currentOrgId) {
      headers["X-Organization-Context"] = this.currentOrgId.toString();
    }

    const response = await fetch(
      url.startsWith("http") ? url : `${this.baseUrl}${url}`,
      {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      },
    );

    if (!response.ok) {
      const error = await response
        .json()
        .catch(() => ({ message: response.statusText }));
      throw new MakeAPIError(response.status, error.message, error);
    }

    return response;
  }
}
```

#### FastMCP Tool Registration

```typescript
// FastMCP server setup for Make.com organization tools
class MakeOrganizationFastMCPServer {
  private client: MakeOrganizationAPIClient;

  constructor(config: MakeAPIConfig) {
    this.client = new MakeOrganizationAPIClient(config);
  }

  registerTools(): FastMCPToolDefinition[] {
    return [
      // Organization management tools
      {
        name: "list_organizations",
        description: "List all organizations where user has membership",
        inputSchema: {
          type: "object",
          properties: {
            includeTeams: {
              type: "boolean",
              description: "Include team information",
            },
            includeUsage: {
              type: "boolean",
              description: "Include usage statistics",
            },
            sortBy: {
              type: "string",
              enum: ["name", "created", "usage"],
              description: "Sort organizations by field",
            },
            limit: { type: "number", description: "Maximum results to return" },
            offset: { type: "number", description: "Pagination offset" },
          },
        },
        handler: async (args: any) => {
          return await this.client.listOrganizations(args);
        },
      },

      {
        name: "create_organization",
        description: "Create a new organization (admin only)",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Organization name" },
            regionId: {
              type: "string",
              description: "Geographic region (eu1, us1, eu2, us2)",
            },
            timezoneId: { type: "string", description: "Default timezone" },
            countryId: { type: "string", description: "Country for billing" },
          },
          required: ["name", "regionId", "timezoneId", "countryId"],
        },
        handler: async (args: any) => {
          return await this.client.createOrganization(args);
        },
      },

      {
        name: "invite_user_to_organization",
        description: "Invite user to organization with specific role",
        inputSchema: {
          type: "object",
          properties: {
            organizationId: { type: "number", description: "Organization ID" },
            email: { type: "string", description: "User email address" },
            name: { type: "string", description: "User display name" },
            roleId: {
              type: "number",
              description: "Organization role ID (optional)",
            },
            teamIds: {
              type: "array",
              items: { type: "number" },
              description: "Team assignments (optional)",
            },
          },
          required: ["organizationId", "email", "name"],
        },
        handler: async (args: any) => {
          return await this.client.inviteUser(args.organizationId, {
            email: args.email,
            name: args.name,
            usersRoleId: args.roleId,
            teamsId: args.teamIds,
          });
        },
      },

      {
        name: "get_organization_usage",
        description: "Get organization usage statistics and analytics",
        inputSchema: {
          type: "object",
          properties: {
            organizationId: { type: "number", description: "Organization ID" },
            period: {
              type: "string",
              enum: ["day", "week", "month"],
              description: "Usage period to analyze",
            },
            startDate: {
              type: "string",
              description: "Start date (ISO format)",
            },
            endDate: { type: "string", description: "End date (ISO format)" },
          },
          required: ["organizationId"],
        },
        handler: async (args: any) => {
          return await this.client.getUsage(args.organizationId, {
            period: args.period,
            startDate: args.startDate,
            endDate: args.endDate,
          });
        },
      },

      // Add all other tools following the same pattern...
    ];
  }
}
```

### 5.3 Error Handling and Rate Limiting

#### Comprehensive Error Handling

```typescript
class MakeAPIError extends Error {
  constructor(
    public status: number,
    message: string,
    public details?: any,
  ) {
    super(message);
    this.name = "MakeAPIError";
  }
}

// Error handling patterns for common scenarios
class MakeAPIErrorHandler {
  static handle(error: MakeAPIError): never {
    switch (error.status) {
      case 401:
        throw new Error("Authentication failed: Invalid or expired API token");

      case 403:
        throw new Error(
          `Access denied: Insufficient permissions. Details: ${JSON.stringify(error.details)}`,
        );

      case 404:
        if (error.details?.resource === "organization") {
          throw new Error("Organization not found or access denied");
        }
        throw new Error("Resource not found");

      case 429:
        throw new Error(
          "Rate limit exceeded: Too many requests. Please retry after a delay",
        );

      case 422:
        throw new Error(
          `Validation error: ${error.details?.message || "Invalid request data"}`,
        );

      case 500:
      case 502:
      case 503:
        throw new Error(
          "Make.com service temporarily unavailable. Please retry later",
        );

      default:
        throw new Error(
          `Make.com API error (${error.status}): ${error.message}`,
        );
    }
  }
}
```

#### Rate Limiting Implementation

```typescript
class RateLimitManager {
  private requests: Map<string, number[]> = new Map();
  private limits = {
    requestsPerMinute: 100, // Conservative limit
    burstLimit: 10, // Maximum concurrent requests
  };

  async waitForRateLimit(endpoint?: string): Promise<void> {
    const key = endpoint || "global";
    const now = Date.now();
    const requests = this.requests.get(key) || [];

    // Remove requests older than 1 minute
    const recentRequests = requests.filter((time) => now - time < 60000);

    if (recentRequests.length >= this.limits.requestsPerMinute) {
      const oldestRequest = Math.min(...recentRequests);
      const waitTime = 60000 - (now - oldestRequest);
      await new Promise((resolve) => setTimeout(resolve, waitTime));
    }

    // Add current request
    recentRequests.push(now);
    this.requests.set(key, recentRequests);
  }
}
```

## 6. TypeScript Interfaces and Type Definitions

### 6.1 Complete Type Definitions

```typescript
// Configuration interfaces
interface MakeAPIConfig {
  apiToken: string;
  baseUrl: string; // Zone-specific URL (e.g., https://eu1.make.com)
  apiVersion: string; // Default: "v2"
  timeout: number; // Request timeout in milliseconds
  rateLimit: RateLimitConfig;
}

interface RateLimitConfig {
  requestsPerMinute: number;
  burstLimit: number;
  enableRetry: boolean;
}

// Request interfaces
interface ListOrganizationsOptions {
  includeTeams?: boolean;
  includeUsage?: boolean;
  sortBy?: "name" | "created" | "usage";
  limit?: number;
  offset?: number;
}

interface CreateOrganizationRequest {
  name: string;
  regionId: string;
  timezoneId: string;
  countryId: string;
}

interface UpdateOrganizationRequest {
  name?: string;
  timezoneId?: string;
  countryId?: string;
}

interface UserInvitation {
  email: string;
  name: string;
  usersRoleId?: number;
  teamsId?: number[];
}

interface CreateVariableRequest {
  name: string;
  value: string | number | boolean;
  type: "string" | "number" | "boolean";
  description?: string;
}

interface UpdateVariableRequest {
  value: string | number | boolean;
  description?: string;
}

interface UsageOptions {
  period?: "day" | "week" | "month";
  startDate?: string;
  endDate?: string;
}

// Response interfaces
interface InvitationResponse {
  id: number;
  email: string;
  name: string;
  status: "pending" | "sent";
  expiresAt: string;
  invitationUrl: string;
}

interface UsageData {
  operations: number;
  dataTransfer: number;
  period: string;
  breakdown?: {
    teams: Array<{
      teamId: number;
      teamName: string;
      operations: number;
      dataTransfer: number;
    }>;
  };
}

interface Usageforecast {
  predictedOperations: number;
  predictedDataTransfer: number;
  confidence: number;
  factors: string[];
}

interface UsageReport {
  organizationId: number;
  period: string;
  summary: UsageData;
  trends: Array<{
    date: string;
    operations: number;
    dataTransfer: number;
  }>;
  recommendations?: string[];
}
```

### 6.2 FastMCP Integration Types

```typescript
// FastMCP-specific interfaces
interface FastMCPToolDefinition {
  name: string;
  description: string;
  inputSchema: JSONSchema;
  handler: (args: any) => Promise<any>;
}

interface JSONSchema {
  type: string;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
}

interface JSONSchemaProperty {
  type: string;
  description?: string;
  enum?: string[];
  items?: JSONSchemaProperty;
}

// Tool response standardization
interface ToolResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  metadata?: {
    organizationId?: number;
    timestamp: string;
    requestId?: string;
  };
}
```

## 7. Implementation Priorities and Recommendations

### 7.1 High Priority Implementation (Phase 1)

1. **Core Organization Management**
   - Organization listing and basic information retrieval
   - Organization creation for admin users
   - Organization settings updates

2. **User Invitation System**
   - User invitation to organizations
   - Basic role assignment during invitation
   - Invitation status tracking

3. **Basic Analytics**
   - Organization usage statistics
   - Simple usage reporting
   - Subscription information display

### 7.2 Medium Priority Implementation (Phase 2)

1. **Advanced User Management**
   - User role updates and management
   - Organization ownership transfer
   - User removal from organizations

2. **Organization Variables**
   - Custom variable creation and management
   - Variable history tracking
   - Bulk variable operations

3. **Team Integration**
   - Team listing within organizations
   - Team-organization relationship management

### 7.3 Low Priority Implementation (Phase 3)

1. **Advanced Analytics**
   - Detailed usage forecasting
   - Custom reporting and exports
   - Usage optimization recommendations

2. **Bulk Operations**
   - Bulk user invitations
   - Bulk role updates
   - Organization migration tools

3. **Advanced Security Features**
   - IP whitelist management
   - Advanced permission modeling
   - Audit log integration

## 8. Technical Constraints and Limitations

### 8.1 API Limitations

1. **Billing API Access**
   - Limited public API access to billing information
   - Most subscription management requires web interface
   - Payment processing not available via API

2. **Rate Limiting**
   - Specific rate limits not documented
   - Conservative approach recommended (100 requests/minute)
   - Monitor for 429 responses and implement backoff

3. **Organization Creation**
   - Organization creation requires admin-level permissions
   - Not available for all Make.com account types
   - May require special API token scopes

### 8.2 Authentication Constraints

1. **Token Management**
   - API tokens are permanent until manually revoked
   - No automatic token rotation
   - Token scopes cannot be changed after creation

2. **Multi-Organization Access**
   - Single token can access multiple organizations
   - Organization context switching required for some operations
   - Permission validation needed for each organization

### 8.3 Data Model Limitations

1. **Organization Variables**
   - Variable values are stored as strings in API
   - Type information maintained in metadata
   - No complex data types supported

2. **Usage Data**
   - Usage data aggregated daily
   - Historical data limited to 30 days for most endpoints
   - Real-time usage not available via API

## 9. Security Best Practices

### 9.1 API Token Security

1. **Token Storage**
   - Store tokens in secure environment variables
   - Never commit tokens to version control
   - Use encrypted storage for token persistence

2. **Token Monitoring**
   - Log all API token usage
   - Monitor for unusual access patterns
   - Implement token rotation policies

3. **Scope Management**
   - Use minimum required scopes for each use case
   - Regularly audit token permissions
   - Create separate tokens for different applications

### 9.2 Organization Access Control

1. **Permission Validation**
   - Validate user permissions before each operation
   - Implement organization context switching
   - Cache permission data appropriately

2. **Audit Logging**
   - Log all organization management operations
   - Track user role changes and invitations
   - Maintain access audit trails

## 10. Testing and Validation Strategy

### 10.1 Unit Testing

```typescript
// Example test structure for organization management
describe("MakeOrganizationAPIClient", () => {
  let client: MakeOrganizationAPIClient;

  beforeEach(() => {
    client = new MakeOrganizationAPIClient({
      apiToken: "test-token",
      baseUrl: "https://eu1.make.com",
      apiVersion: "v2",
      timeout: 30000,
      rateLimit: {
        requestsPerMinute: 100,
        burstLimit: 10,
        enableRetry: true,
      },
    });
  });

  describe("listOrganizations", () => {
    it("should return organization list with basic info", async () => {
      // Mock API response
      const mockResponse = {
        organizations: [
          {
            id: 1,
            name: "Test Organization",
            organizationId: 1,
            timezoneId: "UTC",
            teams: [],
          },
        ],
      };

      // Test implementation
      const result = await client.listOrganizations();
      expect(result).toEqual(mockResponse);
    });

    it("should handle pagination parameters", async () => {
      const options = { limit: 10, offset: 20, sortBy: "name" as const };
      await client.listOrganizations(options);

      // Verify request parameters
      // Implementation would check that URL parameters are set correctly
    });
  });

  describe("inviteUser", () => {
    it("should invite user with basic information", async () => {
      const invitation = {
        email: "test@example.com",
        name: "Test User",
      };

      const result = await client.inviteUser(1, invitation);
      expect(result.email).toBe(invitation.email);
      expect(result.status).toBe("pending");
    });

    it("should handle role and team assignments", async () => {
      const invitation = {
        email: "test@example.com",
        name: "Test User",
        usersRoleId: 2,
        teamsId: [1, 2],
      };

      await client.inviteUser(1, invitation);
      // Verify invitation includes role and team data
    });
  });
});
```

### 10.2 Integration Testing

```typescript
// Integration tests for full workflow
describe("Organization Management Integration", () => {
  let server: MakeOrganizationFastMCPServer;

  beforeEach(() => {
    server = new MakeOrganizationFastMCPServer({
      apiToken: process.env.MAKE_API_TOKEN!,
      baseUrl: "https://eu1.make.com",
      apiVersion: "v2",
      timeout: 30000,
      rateLimit: {
        requestsPerMinute: 100,
        burstLimit: 10,
        enableRetry: true,
      },
    });
  });

  it("should complete full organization management workflow", async () => {
    // 1. List existing organizations
    const orgs = await server.handleTool("list_organizations", {});
    expect(orgs.success).toBe(true);

    if (orgs.data.organizations.length > 0) {
      const orgId = orgs.data.organizations[0].id;

      // 2. Get organization usage
      const usage = await server.handleTool("get_organization_usage", {
        organizationId: orgId,
      });
      expect(usage.success).toBe(true);

      // 3. List organization variables
      const variables = await server.handleTool("list_organization_variables", {
        organizationId: orgId,
      });
      expect(variables.success).toBe(true);
    }
  });
});
```

## 11. Documentation and Examples

### 11.1 FastMCP Tool Usage Examples

```typescript
// Example 1: List user organizations
const organizations = await fastMCP.callTool("list_organizations", {
  includeTeams: true,
  includeUsage: true,
  sortBy: "name",
});

console.log("Available organizations:", organizations.data.organizations);

// Example 2: Invite user to organization
const invitation = await fastMCP.callTool("invite_user_to_organization", {
  organizationId: 123,
  email: "newuser@example.com",
  name: "New User",
  roleId: 2, // Admin role
  teamIds: [1, 2], // Assign to teams
});

console.log("Invitation sent:", invitation.data.invitationUrl);

// Example 3: Create organization variable
const variable = await fastMCP.callTool("create_organization_variable", {
  organizationId: 123,
  name: "api_endpoint",
  value: "https://api.example.com",
  type: "string",
  description: "Default API endpoint for integrations",
});

console.log("Variable created:", variable.data.name);

// Example 4: Get usage analytics
const usage = await fastMCP.callTool("get_organization_usage", {
  organizationId: 123,
  period: "month",
  includeTeamBreakdown: true,
});

console.log("Operations used:", usage.data.totals.operations);
console.log("Team breakdown:", usage.data.breakdown.teams);
```

### 11.2 Error Handling Examples

```typescript
// Comprehensive error handling
try {
  const result = await fastMCP.callTool("update_user_organization_role", {
    userId: 456,
    organizationId: 123,
    roleId: 3,
  });

  console.log("Role updated successfully");
} catch (error) {
  if (error.message.includes("Authentication failed")) {
    console.error("API token is invalid or expired");
    // Handle token refresh
  } else if (error.message.includes("Access denied")) {
    console.error("Insufficient permissions to update user role");
    // Handle permission error
  } else if (error.message.includes("Rate limit")) {
    console.error("Too many requests, implementing backoff");
    // Implement exponential backoff
  } else {
    console.error("Unexpected error:", error.message);
    // Handle other errors
  }
}
```

## 12. Future Enhancement Opportunities

### 12.1 Advanced Features

1. **Webhook Integration**
   - Organization event notifications
   - Real-time user management updates
   - Usage threshold alerts

2. **Advanced Analytics**
   - Machine learning usage predictions
   - Cost optimization recommendations
   - Performance bottleneck identification

3. **Bulk Operations**
   - CSV import for user invitations
   - Batch role updates
   - Organization migration tools

### 12.2 Enterprise Features

1. **SSO Integration**
   - SAML and OAuth SSO support
   - Directory synchronization
   - Automated user provisioning

2. **Compliance and Auditing**
   - Detailed audit logs
   - Compliance reporting
   - Data retention policies

3. **White Label Support**
   - Custom branding for organizations
   - Private instance management
   - Custom domain support

## 13. Conclusion and Next Steps

### 13.1 Research Summary

This comprehensive research has revealed that Make.com provides a robust Organizations API with extensive capabilities for user and access management. The API supports:

- Complete organization CRUD operations with detailed configuration options
- Sophisticated user invitation and role management systems
- Comprehensive permission and access control mechanisms
- Organization variables for custom configuration
- Usage analytics and monitoring capabilities
- Limited billing and subscription information access

### 13.2 Implementation Readiness

The research indicates that implementing FastMCP tools for Make.com Organizations API is highly feasible with the following considerations:

**Strengths:**

- Well-documented API endpoints with clear data models
- Comprehensive authentication and authorization system
- Extensive permission system supporting granular access control
- Rich data models suitable for TypeScript implementation

**Challenges:**

- Limited billing API access requiring alternative approaches
- Conservative rate limiting approach needed due to undocumented limits
- Organization creation restricted to admin users
- Some advanced features may require special API token scopes

### 13.3 Recommended Next Steps

1. **Phase 1 Implementation** (Immediate)
   - Implement core organization management tools
   - Develop user invitation system
   - Create basic analytics and usage monitoring

2. **Phase 2 Development** (Short-term)
   - Add advanced user management features
   - Implement organization variables management
   - Develop team integration capabilities

3. **Phase 3 Enhancement** (Long-term)
   - Add advanced analytics and reporting
   - Implement bulk operations
   - Develop enterprise security features

### 13.4 Technical Architecture Recommendation

The research supports implementing a layered architecture:

1. **API Client Layer**: Core Make.com API communication with comprehensive error handling
2. **Service Layer**: Business logic for organization management operations
3. **FastMCP Tool Layer**: Tool definitions and request/response handling
4. **Type Layer**: Complete TypeScript interfaces and type safety

This architecture will provide a robust, maintainable, and extensible foundation for Make.com Organizations API integration within FastMCP tools.

---

**Research Completed**: August 25, 2025  
**Sources**: Make.com Developer Hub API Documentation, Web Search Analysis, Existing Research Reports  
**Next Action**: Begin Phase 1 FastMCP tool implementation based on this comprehensive research

## Appendix A: API Endpoint Reference

### A.1 Complete Organizations API Endpoints

| Method | Endpoint                                      | Description              | Auth Required | Scopes Required                 |
| ------ | --------------------------------------------- | ------------------------ | ------------- | ------------------------------- |
| GET    | `/api/v2/organizations`                       | List user organizations  | Yes           | `organizations:read`            |
| POST   | `/api/v2/organizations`                       | Create organization      | Yes           | `organizations:write`           |
| GET    | `/api/v2/organizations/{id}`                  | Get organization details | Yes           | `organizations:read`            |
| PATCH  | `/api/v2/organizations/{id}`                  | Update organization      | Yes           | `organizations:write`           |
| DELETE | `/api/v2/organizations/{id}`                  | Delete organization      | Yes           | `organizations:write`           |
| POST   | `/api/v2/organizations/{id}/invite`           | Invite user              | Yes           | `organizations:write`           |
| GET    | `/api/v2/organizations/invitation`            | Get invitation details   | Yes           | `user:read`                     |
| POST   | `/api/v2/organizations/accept-invitation`     | Accept invitation        | Yes           | `user:write`                    |
| GET    | `/api/v2/organizations/{id}/usage`            | Get usage statistics     | Yes           | `organizations:read`            |
| GET    | `/api/v2/organizations/{id}/subscription`     | Get subscription info    | Yes           | `organizations:read`            |
| GET    | `/api/v2/organizations/{id}/variables`        | List variables           | Yes           | `organizations-variables:read`  |
| POST   | `/api/v2/organizations/{id}/variables`        | Create variable          | Yes           | `organizations-variables:write` |
| PATCH  | `/api/v2/organizations/{id}/variables/{name}` | Update variable          | Yes           | `organizations-variables:write` |
| DELETE | `/api/v2/organizations/{id}/variables/{name}` | Delete variable          | Yes           | `organizations-variables:write` |

### A.2 User Role Management Endpoints

| Method | Endpoint                                                 | Description          | Auth Required | Scopes Required       |
| ------ | -------------------------------------------------------- | -------------------- | ------------- | --------------------- |
| GET    | `/api/v2/users/{userId}/user-organization-roles`         | Get user org roles   | Yes           | `user:read`           |
| GET    | `/api/v2/users/{userId}/user-organization-roles/{orgId}` | Get user role in org | Yes           | `user:read`           |
| POST   | `/api/v2/users/{userId}/user-organization-roles/{orgId}` | Update user org role | Yes           | `user:write`          |
| POST   | `/api/v2/organizations/{orgId}/transfer-ownership`       | Transfer ownership   | Yes           | `organizations:write` |

## Appendix B: Error Response Reference

### B.1 Common Error Codes

| Status Code | Error Type       | Description                     | Resolution                        |
| ----------- | ---------------- | ------------------------------- | --------------------------------- |
| 401         | Unauthorized     | Invalid or expired API token    | Refresh or recreate API token     |
| 403         | Forbidden        | Insufficient permissions/scopes | Check API token scopes            |
| 404         | Not Found        | Organization/user not found     | Verify IDs and access permissions |
| 422         | Validation Error | Invalid request data            | Check request parameters          |
| 429         | Rate Limited     | Too many requests               | Implement backoff and retry       |
| 500         | Server Error     | Make.com service issue          | Retry after delay                 |

### B.2 Error Response Format

```typescript
interface MakeAPIErrorResponse {
  status: number;
  error: string;
  message: string;
  details?: {
    field?: string;
    code?: string;
    resource?: string;
    [key: string]: any;
  };
}
```
