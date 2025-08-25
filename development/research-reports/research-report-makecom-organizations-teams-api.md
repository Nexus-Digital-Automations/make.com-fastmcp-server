# Make.com Organizations and Teams Management API Research Report

**Research Date**: August 25, 2025  
**Purpose**: Comprehensive analysis of Make.com API capabilities for organization and team management for FastMCP TypeScript integration  
**Task ID**: task_1756143010442_bkig5c93u

## Executive Summary

This research provides detailed analysis of Make.com's Organizations and Teams Management API capabilities, focusing on administrative functions, user management, permissions, and integration requirements for FastMCP server implementation.

## 1. Organization Management Endpoints

### Core Organization API Endpoints

**Base URL Structure**: `{zone_url}/api/{version}` (e.g., `https://eu1.make.com/api/v2`)

#### 1.1 Organization CRUD Operations

```typescript
// List Organizations
GET / organizations;
// Parameters:
// - cols[]: Optional columns to return
// - pg[sortBy]: Sorting field
// - pg[offset]: Pagination offset
// - pg[limit]: Results per page
```

```typescript
// Create Organization
POST /organizations
// Required Parameters:
{
  "name": "string",           // Organization name
  "regionId": "string",       // Make region instance ID
  "timezoneId": "string",     // Timezone ID
  "countryId": "string"       // Country ID
}
```

#### 1.2 Organization User Management

```typescript
// Invite Users to Organization
POST /organizations/{organizationId}/invite
// Parameters:
{
  "email": "string",          // User email (required)
  "name": "string",           // User name (required)
  "usersRoleId": "number",    // Optional user role ID
  "teamsId[]": "number[]"     // Optional team assignments
}
```

#### 1.3 Organization Variables Management

```typescript
// Organization Variables Endpoints
GET / organizations / { organizationId } / variables;
POST / organizations / { organizationId } / variables;
PATCH / organizations / { organizationId } / variables / { variableName };
DELETE / organizations / { organizationId } / variables / { variableName };
```

#### 1.4 Organization Usage and Analytics

```typescript
// Organization Usage Data
GET / organizations / { organizationId } / usage;
// Retrieves daily operations and data transfer usage across all teams
// for the past 30 days within the organization
```

### Organization Response Format

```typescript
interface OrganizationResponse {
  organizations: Array<{
    id: number;
    name: string;
    organizationId: number;
    timezoneId: string;
    teams: Array<{
      id: number;
      name: string;
    }>;
  }>;
}
```

## 2. Team Management API

### 2.1 Team CRUD Operations

Based on API scopes documentation, the following team operations are supported:

```typescript
// Core Team Endpoints (inferred from API scopes)
GET / teams; // List all teams in organization
POST / teams; // Create new team
GET / teams / { teamId }; // Get team details
PUT / teams / { teamId }; // Update team
DELETE / teams / { teamId }; // Delete team
```

### 2.2 Team Usage Analytics

```typescript
// Team Usage Endpoint (confirmed)
GET / teams / { teamId } / usage;
// Retrieves daily operations and data transfer usage for all scenarios
// within specified team over past 30 days
```

### 2.3 Team Variables Management

```typescript
// Team Variables Endpoints (inferred from API scopes)
GET / teams / { teamId } / variables;
POST / teams / { teamId } / variables;
PUT / teams / { teamId } / variables / { variableName };
DELETE / teams / { teamId } / variables / { variableName };
```

## 3. Team User Roles and Permissions

### 3.1 User Team Role Endpoints

```typescript
// List User Roles in Team
GET / teams / { teamId } / user - team - roles;
// Parameters:
// - teamId (integer, required): Team identifier
// - Optional query parameters for filtering, sorting, pagination

// Get User Team Role Details
GET / teams / { teamId } / user - team - roles / { userId };
// Parameters:
// - teamId (string, required): Team identifier
// - userId (string, required): User identifier

// Update User Role in Team
POST / users / { userId } / user - team - roles / { teamId };
// Updates user role in specified team

// Get User's Team Roles
GET / users / { userId } / user - team - roles;
// Gets all team roles for specified user

// Get User Role Detail in Team
GET / users / { userId } / user - team - roles / { teamId };
// Gets user role detail in specified team
```

### 3.2 Team Role Types and Permissions

```typescript
enum TeamRole {
  TEAM_MEMBER = "team_member", // Full access, cannot manage members
  TEAM_MONITORING = "team_monitoring", // Read-only access
  TEAM_OPERATOR = "team_operator", // Read-only + scenario control
  TEAM_RESTRICTED_MEMBER = "team_restricted_member", // Full access, no publish/modify team
}

interface UserTeamRole {
  usersRoleId: number;
  userId: number;
  teamId: number;
  changeable: boolean;
}
```

### 3.3 Role Permissions Matrix

| Role                   | Read Access | Scenario Control | Member Management | Team Management | Publish Scenarios |
| ---------------------- | ----------- | ---------------- | ----------------- | --------------- | ----------------- |
| Team Member            | ✅          | ✅               | ❌                | ❌              | ✅                |
| Team Monitoring        | ✅          | ❌               | ❌                | ❌              | ❌                |
| Team Operator          | ✅          | ✅               | ❌                | ❌              | ❌                |
| Team Restricted Member | ✅          | ✅               | ❌                | ❌              | ❌                |

## 4. Organization Structure and Hierarchy

### 4.1 Organizational Hierarchy

```typescript
interface OrganizationStructure {
  organization: {
    id: number;
    name: string;
    regionId: string;
    timezoneId: string;
    countryId: string;
    teams: Team[];
    users: OrganizationUser[];
  };
}

interface Team {
  id: number;
  name: string;
  organizationId: number;
  users: TeamUser[];
  scenarios: Scenario[];
  variables: TeamVariable[];
}
```

### 4.2 User Membership Hierarchy

- **Organization Level**: Users can be members of multiple organizations
- **Team Level**: Users can be members of multiple teams within an organization
- **Role Assignment**: Users have both organization-level and team-level roles

## 5. Organization Settings and Configuration

### 5.1 Organization Configuration Options

```typescript
interface OrganizationSettings {
  name: string;
  regionId: string; // Make region instance (eu1, us1, etc.)
  timezoneId: string; // Timezone for operation scheduling
  countryId: string; // Country for billing/compliance
  subscriptionSettings: {
    // Subscription and billing configuration
  };
}
```

### 5.2 Custom Variables System

Both organizations and teams support custom variables for configuration:

```typescript
interface CustomVariable {
  name: string;
  value: string | number | boolean;
  type: "string" | "number" | "boolean";
  createdAt: string;
  updatedAt: string;
}
```

## 6. Team Invitations and Onboarding

### 6.1 Invitation Process

Based on organization-level invitation endpoints, team invitations follow similar patterns:

```typescript
// Organization Invitation (confirmed)
POST /organizations/{organizationId}/invite
{
  "email": "string",
  "name": "string",
  "usersRoleId": "number",
  "teamsId[]": "number[]"     // Assign to specific teams during invitation
}

// Team-level invitations (inferred pattern)
POST /teams/{teamId}/invite
{
  "email": "string",
  "name": "string",
  "roleId": "number"
}
```

### 6.2 Invitation Management

```typescript
// Invitation status tracking (inferred)
GET / organizations / { organizationId } / invitations;
GET / teams / { teamId } / invitations;

interface Invitation {
  id: number;
  email: string;
  name: string;
  status: "pending" | "accepted" | "expired";
  roleId: number;
  invitedBy: number;
  createdAt: string;
  expiresAt: string;
}
```

## 7. User Roles within Organizations

### 7.1 Organization-Level Roles

```typescript
// Organization User Role Endpoints
GET / organizations / { organizationId } / user - organization - roles;
GET / users / { userId } / user - organization - roles;
POST / users / { userId } / user - organization - roles / { organizationId };
```

### 7.2 Organization Role Types

Based on typical organization management patterns:

- **Organization Owner**: Full administrative control
- **Organization Admin**: Administrative permissions without ownership transfer
- **Organization Member**: Basic access to organization resources

## 8. API Scopes and Access Control

### 8.1 Required API Scopes

#### Organization Management Scopes

```typescript
const ORGANIZATION_SCOPES = {
  // Read Permissions
  "organizations:read": [
    "Get all organizations user belongs to",
    "Get installed apps",
    "Get invitations",
    "Get user roles",
    "Get basic organization details",
  ],

  // Write Permissions
  "organizations:write": [
    "Create new organizations (admin-only)",
    "Update organizations",
    "Delete organizations",
    "Accept organization invitations",
    "Add members to organizations",
  ],

  // Organization Variables
  "organizations-variables:read": [
    "Retrieve organization variable data",
    "Get history of custom organization variable updates",
  ],

  "organizations-variables:write": [
    "Create custom organization variables",
    "Update custom organization variables",
    "Delete custom organization variables",
  ],
};
```

#### Team Management Scopes

```typescript
const TEAM_SCOPES = {
  // Read Permissions
  "teams:read": [
    "Get all teams in an organization",
    "Get team details",
    "Get all team roles",
    "Get specific team role details",
  ],

  // Write Permissions
  "teams:write": ["Create new teams", "Update teams", "Delete teams"],

  // Team Variables
  "teams-variables:read": [
    "Retrieve team variable data",
    "Get history of custom team variable updates",
  ],

  "team-variables:write": [
    "Create custom team variables",
    "Update custom team variables",
    "Delete custom team variables",
  ],
};
```

### 8.2 Authentication Requirements

```typescript
interface APIAuthentication {
  method: "Bearer Token";
  header: "Authorization: Bearer {token}";
  requirements: [
    "Paid Make account required",
    "Appropriate API scopes enabled",
    "Valid authentication token",
  ];
}
```

## 9. FastMCP TypeScript Integration Guidance

### 9.1 Recommended FastMCP Tool Structure

```typescript
// Organization Management Tools
interface OrganizationTools {
  listOrganizations: FastMCPTool;
  createOrganization: FastMCPTool;
  inviteUserToOrganization: FastMCPTool;
  manageOrganizationVariables: FastMCPTool;
  getOrganizationUsage: FastMCPTool;
}

// Team Management Tools
interface TeamTools {
  listTeams: FastMCPTool;
  createTeam: FastMCPTool;
  updateTeam: FastMCPTool;
  deleteTeam: FastMCPTool;
  manageTeamUsers: FastMCPTool;
  manageTeamVariables: FastMCPTool;
  getTeamUsage: FastMCPTool;
}

// User Role Management Tools
interface UserRoleTools {
  getUserTeamRoles: FastMCPTool;
  updateUserTeamRole: FastMCPTool;
  getUserOrganizationRoles: FastMCPTool;
  updateUserOrganizationRole: FastMCPTool;
}
```

### 9.2 Implementation Priorities for FastMCP

**High Priority** (Core administrative functions):

1. Organization listing and management
2. Team creation and management
3. User role assignment and management
4. Basic invitation system

**Medium Priority** (Enhanced functionality):

1. Custom variables management
2. Usage analytics and reporting
3. Advanced invitation management

**Low Priority** (Advanced features):

1. Subscription management integration
2. Advanced analytics and reporting
3. Bulk operations

### 9.3 Error Handling Considerations

```typescript
interface MakeAPIError {
  status: number;
  error: string;
  message: string;
  details?: Record<string, unknown>;
}

// Common error scenarios to handle:
// - 401: Unauthorized (invalid token)
// - 403: Forbidden (insufficient scopes)
// - 404: Not found (invalid organization/team ID)
// - 429: Rate limit exceeded
// - 500: Server errors
```

## 10. Implementation Recommendations

### 10.1 FastMCP Tool Categories

```typescript
// Suggested tool organization for FastMCP server
const TOOL_CATEGORIES = {
  organization_management: [
    "list_organizations",
    "create_organization",
    "invite_user_to_organization",
    "manage_organization_variables",
  ],

  team_management: ["list_teams", "create_team", "update_team", "delete_team"],

  user_role_management: [
    "get_user_team_roles",
    "update_user_team_role",
    "list_team_members",
  ],

  analytics: ["get_organization_usage", "get_team_usage"],
};
```

### 10.2 Configuration Requirements

```typescript
interface FastMCPMakeConfig {
  apiToken: string; // Make.com API token
  baseURL: string; // Zone-specific base URL (e.g., eu1.make.com)
  apiVersion: string; // API version (v2)
  defaultTimeout: number; // Request timeout in ms
  rateLimit: {
    requestsPerMinute: number;
    burstLimit: number;
  };
}
```

## 11. Next Steps for Implementation

1. **Authentication Setup**: Implement Make.com API token management and scope validation
2. **Core Organization Tools**: Start with organization listing and basic management
3. **Team Management**: Implement team CRUD operations
4. **User Role Management**: Add user role assignment and management tools
5. **Error Handling**: Implement comprehensive error handling for all API scenarios
6. **Testing**: Create test suites for all implemented tools
7. **Documentation**: Generate FastMCP tool documentation with usage examples

## 12. Research Limitations

**Data Availability**: Some specific endpoint details were not available in public documentation and were inferred from API scopes and patterns.

**API Versioning**: This research focused on API v2; future versions may have different endpoints.

**Rate Limits**: Specific rate limiting details were not found in the research but should be confirmed during implementation.

---

**Research Completed**: August 25, 2025  
**Sources**: Make.com Developer Hub API Documentation  
**Next Action**: Begin FastMCP tool implementation based on this research
