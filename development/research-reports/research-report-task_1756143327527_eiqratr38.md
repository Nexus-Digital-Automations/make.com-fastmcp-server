# Make.com User Management and API Token Management Research Report

**Task ID:** task_1756143327527_eiqratr38  
**Research Date:** August 25, 2025  
**Focus Areas:** User Management, API Token Management, Authentication, Permissions, Audit Logs

## Executive Summary

Make.com provides a comprehensive REST API for user management, authentication, and organizational administration. The platform supports multiple authentication methods including API tokens and OAuth 2.0, with granular permission controls through role-based access management. This research documents all available endpoints, authentication methods, and integration capabilities for FastMCP TypeScript implementation.

## 1. User Management Endpoints

### 1.1 User Profile Management

#### Current User Information

- **Endpoint:** `GET /api/v2/users/me`
- **Authentication:** API Token required
- **Purpose:** Retrieve authenticated user's profile information
- **Response:** User details, preferences, organization memberships

#### User Organization Roles

- **Endpoint:** `GET /users/{userId}/user-organization-roles`
- **Parameters:**
  - `userId` (required): Target user ID
  - `cols[]` (optional): Specify columns to return
- **Purpose:** List user roles across all organizations
- **Authentication:** Requires appropriate organization admin permissions

#### Specific Organization Role Details

- **Endpoint:** `GET /users/{userId}/user-organization-roles/{organizationId}`
- **Parameters:**
  - `userId` (required): Target user ID
  - `organizationId` (required): Organization ID
  - `cols[]` (optional): Specify columns to return
- **Purpose:** Get detailed role information for user in specific organization

#### Update User Organization Role

- **Endpoint:** `POST /users/{userId}/user-organization-roles/{organizationId}`
- **Parameters:**
  - `userId` (required): Target user ID
  - `organizationId` (required): Organization ID
  - `usersRoleId` (body): New role ID to assign
  - `confirmed` (query): Confirm user removal
  - `deleteConnections` (query): Delete user's connections when removing
- **Purpose:** Update or remove user's role in organization
- **Restrictions:** Only organization owners/admins can modify roles

#### Transfer Organization Ownership

- **Endpoint:** `POST /users/{userId}/user-organization-roles/{organizationId}/transfer`
- **Parameters:**
  - `userId` (required): New owner user ID
  - `organizationId` (required): Organization ID
- **Purpose:** Transfer organization ownership to another user
- **Restrictions:** Only current organization owner can transfer

### 1.2 User Permissions and Roles

#### Role Hierarchy (3 Levels)

1. **Instance Level:** Administrative interface access, app development, support roles
2. **Organization Level:** Asset access (scenarios, data stores), member management
3. **Team Level:** Lowest level access to team-specific assets and scenarios

#### Available Organization Roles

- **Owner:** Full organization control, billing, user management
- **Admin:** User management, organization settings, cannot delete organization
- **Member:** Basic access to assigned teams and scenarios
- **Viewer:** Read-only access to organization resources

#### Team Roles

- **Team Admin:** Team management, member roles, team settings
- **Member:** Access to team scenarios and resources
- **Viewer:** Read-only access to team resources

## 2. API Token Management

### 2.1 Token Lifecycle Management

#### List User's API Tokens

- **Endpoint:** `GET /api/v2/users/me/api-tokens`
- **Authentication:** API Token required
- **Purpose:** Retrieve all API tokens for authenticated user
- **Response Format:**
  ```json
  {
    "tokens": [
      {
        "token": "api_token_string",
        "label": "Token Description",
        "scope": ["apps:read", "scenarios:write"],
        "createdAt": "2025-08-25T10:30:00Z",
        "timestamp": "1756143327527"
      }
    ]
  }
  ```

#### Create New API Token

- **Endpoint:** `POST /api/v2/users/me/api-tokens`
- **Required Parameters:**
  - `label` (string): Human-readable token description
  - `scope` (array): Array of permission scopes
- **Response:** New token details including the actual token value
- **Example Request:**
  ```json
  {
    "label": "FastMCP Integration Token",
    "scope": [
      "scenarios:read",
      "scenarios:write",
      "organizations:read",
      "users:read",
      "audit-logs:read"
    ]
  }
  ```

#### Delete API Token

- **Endpoint:** `DELETE /api/v2/users/me/api-tokens/{timestamp}`
- **Parameters:**
  - `timestamp` (string, required): Exact creation timestamp of token
- **Purpose:** Revoke specific API token
- **Response:** Confirmation of deleted token timestamp

### 2.2 API Scopes System

#### Scope Categories

1. **Read Scopes:** Allow GET requests, resource listing, detail retrieval
2. **Write Scopes:** Allow POST, PUT, PATCH, DELETE operations

#### Available Scopes (Key Examples)

- `scenarios:read` / `scenarios:write` - Scenario management
- `organizations:read` / `organizations:write` - Organization access
- `users:read` / `users:write` - User management
- `audit-logs:read` - Audit log access
- `teams:read` / `teams:write` - Team management
- `connections:read` / `connections:write` - Connection management
- `webhooks:read` / `webhooks:write` - Webhook management

## 3. User Invitations and Onboarding

### 3.1 Organization Invitations

#### Invite User to Organization

- **Endpoint:** `POST /organizations/{organizationId}/invite`
- **Parameters:**
  - `organizationId` (required): Target organization ID
  - `email` (required): Invitee email address
  - `userRoleId` (required): Organization role ID to assign
  - `teamIds` (optional): Array of team IDs to add user to
- **Purpose:** Send email invitation to join organization
- **Default Team Role:** New users get "member" role in assigned teams

#### Get Invitation Details

- **Endpoint:** `GET /organizations/invitation`
- **Parameters:**
  - `hash` (required): Invitation hash from email link
- **Purpose:** Retrieve invitation information before acceptance

#### Accept Invitation

- **Endpoint:** `POST /organizations/accept-invitation`
- **Parameters:**
  - `hash` (required): Invitation hash
- **Purpose:** Accept organization invitation and create user account

### 3.2 Invitation Status Tracking

- Invitations can be tracked through organization audit logs
- Status includes: sent, accepted, expired, declined
- Email notifications automatically sent to invitees

## 4. Authentication Methods

### 4.1 API Token Authentication

#### Implementation

```typescript
// Header format for API requests
headers: {
  'Authorization': 'Token YOUR_API_TOKEN_HERE',
  'Content-Type': 'application/json'
}
```

#### Token Security

- Tokens are user-specific and scope-limited
- No expiration by default (manual revocation required)
- Should be stored securely and rotated regularly

### 4.2 OAuth 2.0 Authentication

#### Supported Protocols

- **OIDC (OpenID Connect):** Full identity layer support
- **PKCE (Proof Key for Code Exchange):** Mandatory for SPAs and mobile apps
- **Authorization Code Flow:** With refresh token support

#### OAuth Endpoints

- **Authorization:** `https://www.make.com/oauth/v2/authorize`
- **Token:** `https://www.make.com/oauth/v2/token`
- **User Info:** `https://www.make.com/oauth/v2/oidc/userinfo`
- **Token Revocation:** `https://www.make.com/oauth/v2/revoke`
- **JWKS URI:** `https://www.make.com/oauth/v2/oidc/jwks`
- **Discovery:** `https://www.make.com/.well-known/openid-configuration`

#### Client Registration Process

1. Complete OAuth client registration form
2. Specify required API scopes
3. Provide application details and redirect URIs
4. Submit for review (10 business day approval process)
5. Receive client credentials upon approval

#### Implementation Requirements

- Public clients MUST use PKCE
- Confidential clients receive client secret
- Support for refresh token rotation
- OIDC discovery endpoint available

### 4.3 Single Sign-On (SSO)

#### Supported SSO Methods

- **OAuth 2.0:** For third-party integrations
- **SAML 2.0:** Enterprise identity provider integration
- **Microsoft Azure Active Directory:** Direct integration support

#### Configuration

- SSO setup available through organization administration
- Supports automated user provisioning
- Role mapping from identity provider to Make.com roles

## 5. User Activity and Audit Logs

### 5.1 Audit Log Endpoints

#### Organization Audit Logs

- **Endpoint:** `GET /audit-logs/organization/{organizationId}`
- **Purpose:** Retrieve audit entries for organization events
- **Access Control:** Requires Admin or Owner role in organization
- **Response:** Paginated list of audit events with full context

#### Team Audit Logs

- **Endpoint:** `GET /audit-logs/team/{teamId}`
- **Purpose:** Retrieve audit entries for team-specific events
- **Access Control:** Requires Team Admin role
- **Response:** Team-scoped audit events and activities

#### Audit Log Filters

- **Organization Filters:** `GET /audit-logs/organization/{organizationId}/filters`
- **Team Filters:** `GET /audit-logs/team/{teamId}/filters`
- **Purpose:** Get available filter options for audit log queries

#### Specific Audit Log Entry

- **Endpoint:** `GET /audit-logs/{uuid}`
- **Purpose:** Retrieve detailed information for specific audit event
- **Response:** Complete event context, changes, and metadata

### 5.2 Audit Event Types

#### User Management Events

- `user_invited` - User invitation sent
- `user_joined` - User accepted invitation
- `user_role_changed` - User role modified
- `user_removed` - User removed from organization/team

#### Resource Management Events

- `scenario_created` - New scenario created
- `scenario_updated` - Scenario modified
- `scenario_deleted` - Scenario removed
- `webhook_created` - Webhook created
- `webhook_updated` - Webhook modified
- `webhook_disabled` - Webhook disabled
- `connection_created` - New connection established
- `connection_updated` - Connection modified

### 5.3 Filtering and Search Capabilities

#### Available Filters

- **Date Range:** `dateFrom`, `dateTo` parameters
- **Event Type:** Filter by specific event names
- **User Actions:** Filter by specific user (author parameter)
- **Resource Type:** Filter by affected resource type
- **Pagination:** `pg[offset]`, `pg[limit]` for large datasets

#### Response Format

```json
{
  "auditLogs": [
    {
      "uuid": "audit_log_uuid",
      "triggeredAt": "2025-08-25T10:30:00Z",
      "organizationId": "org_123",
      "teamId": "team_456",
      "actor": {
        "userId": "user_789",
        "userName": "john.doe@company.com",
        "userRole": "Admin"
      },
      "event": "user_role_changed",
      "targetId": "user_target_id",
      "changes": {
        "oldRole": "Member",
        "newRole": "Admin"
      },
      "metadata": {}
    }
  ],
  "pagination": {
    "offset": 0,
    "limit": 50,
    "total": 150
  }
}
```

## 6. User Settings and Preferences

### 6.1 Profile Settings

- User timezone preferences
- Notification settings
- Language preferences
- Account security settings

### 6.2 Organization Preferences

- Default organization selection
- Organization-specific notification preferences
- Resource access preferences

### 6.3 API Access Preferences

- Preferred API token scopes
- OAuth application authorizations
- Third-party integration permissions

## 7. Organization Management

### 7.1 Organization CRUD Operations

#### List Organizations

- **Endpoint:** `GET /organizations`
- **Purpose:** Retrieve all organizations user belongs to
- **Parameters:** Column selection, sorting, pagination
- **Response:** Array of organization details with user roles

#### Create Organization

- **Endpoint:** `POST /organizations`
- **Required Parameters:**
  - `name`: Organization name
  - `regionId`: Data region ID
  - `timezoneId`: Default timezone
  - `countryId`: Country/locale setting
- **Purpose:** Create new organization with user as owner

#### Get Organization Details

- **Endpoint:** `GET /organizations/{organizationId}`
- **Purpose:** Retrieve comprehensive organization information
- **Response:** Full organization details, settings, statistics

#### Update Organization

- **Endpoint:** `PATCH /organizations/{organizationId}`
- **Updateable Fields:** name, timezone, country settings
- **Purpose:** Modify organization configuration

#### Delete Organization

- **Endpoint:** `DELETE /organizations/{organizationId}`
- **Requirements:** Confirmation if active scenarios exist
- **Purpose:** Permanently remove organization

### 7.2 Organization Administration

#### User Management in Organizations

- Invite users with specific roles
- Assign users to teams automatically
- Manage organization-level permissions
- Transfer ownership between users

#### Resource Management

- Organization variables and settings
- Usage statistics and billing information
- Subscription and plan management
- Team creation and management

## 8. FastMCP TypeScript Integration Guide

### 8.1 Authentication Implementation

```typescript
interface MakeAuthConfig {
  apiToken?: string;
  oauthConfig?: {
    clientId: string;
    clientSecret?: string; // Only for confidential clients
    redirectUri: string;
    scopes: string[];
  };
}

class MakeAuthManager {
  private config: MakeAuthConfig;
  private baseUrl = "https://eu1.make.com/api/v2";

  constructor(config: MakeAuthConfig) {
    this.config = config;
  }

  // API Token authentication headers
  getAuthHeaders(): Record<string, string> {
    return {
      Authorization: `Token ${this.config.apiToken}`,
      "Content-Type": "application/json",
    };
  }

  // OAuth authorization URL generation
  generateAuthUrl(): string {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.config.oauthConfig.clientId,
      redirect_uri: this.config.oauthConfig.redirectUri,
      scope: this.config.oauthConfig.scopes.join(" "),
    });
    return `https://www.make.com/oauth/v2/authorize?${params}`;
  }
}
```

### 8.2 User Management Implementation

```typescript
interface MakeUser {
  id: string;
  email: string;
  name: string;
  organizationRoles: OrganizationRole[];
  teamRoles: TeamRole[];
}

interface OrganizationRole {
  organizationId: string;
  organizationName: string;
  role: "Owner" | "Admin" | "Member" | "Viewer";
}

class MakeUserManager {
  private authManager: MakeAuthManager;

  constructor(authManager: MakeAuthManager) {
    this.authManager = authManager;
  }

  async getCurrentUser(): Promise<MakeUser> {
    const response = await fetch(`${this.baseUrl}/users/me`, {
      headers: this.authManager.getAuthHeaders(),
    });
    return response.json();
  }

  async getUserOrganizationRoles(userId: string): Promise<OrganizationRole[]> {
    const response = await fetch(
      `${this.baseUrl}/users/${userId}/user-organization-roles`,
      { headers: this.authManager.getAuthHeaders() },
    );
    return response.json();
  }

  async updateUserRole(
    userId: string,
    organizationId: string,
    newRoleId: string,
  ): Promise<void> {
    await fetch(
      `${this.baseUrl}/users/${userId}/user-organization-roles/${organizationId}`,
      {
        method: "POST",
        headers: this.authManager.getAuthHeaders(),
        body: JSON.stringify({ usersRoleId: newRoleId }),
      },
    );
  }
}
```

### 8.3 API Token Management Implementation

```typescript
interface ApiToken {
  token: string;
  label: string;
  scope: string[];
  createdAt: string;
  timestamp: string;
}

class MakeTokenManager {
  private authManager: MakeAuthManager;

  async listApiTokens(): Promise<ApiToken[]> {
    const response = await fetch(`${this.baseUrl}/users/me/api-tokens`, {
      headers: this.authManager.getAuthHeaders(),
    });
    return response.json();
  }

  async createApiToken(label: string, scopes: string[]): Promise<ApiToken> {
    const response = await fetch(`${this.baseUrl}/users/me/api-tokens`, {
      method: "POST",
      headers: this.authManager.getAuthHeaders(),
      body: JSON.stringify({ label, scope: scopes }),
    });
    return response.json();
  }

  async deleteApiToken(timestamp: string): Promise<void> {
    await fetch(`${this.baseUrl}/users/me/api-tokens/${timestamp}`, {
      method: "DELETE",
      headers: this.authManager.getAuthHeaders(),
    });
  }
}
```

### 8.4 Audit Log Integration

```typescript
interface AuditLogEntry {
  uuid: string;
  triggeredAt: string;
  organizationId: string;
  teamId?: string;
  actor: {
    userId: string;
    userName: string;
    userRole: string;
  };
  event: string;
  targetId: string;
  changes?: Record<string, any>;
}

class MakeAuditManager {
  private authManager: MakeAuthManager;

  async getOrganizationAuditLogs(
    organizationId: string,
    filters?: {
      dateFrom?: string;
      dateTo?: string;
      event?: string;
      author?: string;
    },
  ): Promise<AuditLogEntry[]> {
    const params = new URLSearchParams(filters as any);
    const response = await fetch(
      `${this.baseUrl}/audit-logs/organization/${organizationId}?${params}`,
      { headers: this.authManager.getAuthHeaders() },
    );
    return response.json();
  }

  async getTeamAuditLogs(
    teamId: string,
    filters?: Record<string, string>,
  ): Promise<AuditLogEntry[]> {
    const params = new URLSearchParams(filters);
    const response = await fetch(
      `${this.baseUrl}/audit-logs/team/${teamId}?${params}`,
      { headers: this.authManager.getAuthHeaders() },
    );
    return response.json();
  }
}
```

### 8.5 Organization Management Implementation

```typescript
interface Organization {
  id: string;
  name: string;
  regionId: string;
  timezoneId: string;
  countryId: string;
  userRole: string;
}

interface InvitationRequest {
  email: string;
  userRoleId: string;
  teamIds?: string[];
}

class MakeOrganizationManager {
  private authManager: MakeAuthManager;

  async listOrganizations(): Promise<Organization[]> {
    const response = await fetch(`${this.baseUrl}/organizations`, {
      headers: this.authManager.getAuthHeaders(),
    });
    return response.json();
  }

  async createOrganization(
    orgData: Partial<Organization>,
  ): Promise<Organization> {
    const response = await fetch(`${this.baseUrl}/organizations`, {
      method: "POST",
      headers: this.authManager.getAuthHeaders(),
      body: JSON.stringify(orgData),
    });
    return response.json();
  }

  async inviteUser(
    organizationId: string,
    invitation: InvitationRequest,
  ): Promise<void> {
    await fetch(`${this.baseUrl}/organizations/${organizationId}/invite`, {
      method: "POST",
      headers: this.authManager.getAuthHeaders(),
      body: JSON.stringify(invitation),
    });
  }
}
```

## 9. Security Considerations

### 9.1 API Token Security

- Store tokens securely (environment variables, secure storage)
- Implement token rotation policies
- Use minimum required scopes for each use case
- Monitor token usage through audit logs

### 9.2 OAuth Security

- Always use PKCE for public clients
- Validate redirect URIs strictly
- Implement proper CSRF protection
- Use secure storage for refresh tokens

### 9.3 Access Control

- Implement proper role-based access in applications
- Validate user permissions before operations
- Log all administrative actions
- Regular permission audits

## 10. Implementation Recommendations

### 10.1 FastMCP Tool Structure

```typescript
// Recommended tool organization
export const makeTools = {
  // Authentication tools
  "make-auth-status": getCurrentAuthStatus,
  "make-create-token": createApiToken,
  "make-revoke-token": revokeApiToken,

  // User management tools
  "make-get-user": getCurrentUser,
  "make-list-user-roles": getUserOrganizationRoles,
  "make-update-user-role": updateUserRole,

  // Organization tools
  "make-list-orgs": listOrganizations,
  "make-invite-user": inviteUserToOrganization,
  "make-create-org": createOrganization,

  // Audit tools
  "make-audit-org": getOrganizationAuditLogs,
  "make-audit-team": getTeamAuditLogs,
  "make-audit-detail": getAuditLogDetail,
};
```

### 10.2 Error Handling

- Implement comprehensive error handling for API responses
- Handle rate limiting (429 status codes)
- Provide meaningful error messages to users
- Log errors for debugging and monitoring

### 10.3 Caching Strategy

- Cache user information and roles for performance
- Implement cache invalidation on role changes
- Cache organization lists with appropriate TTL
- Use conditional requests (ETags) where supported

## 11. Conclusion

Make.com provides a comprehensive and well-structured API for user management, authentication, and organizational administration. The platform supports modern authentication methods including API tokens and OAuth 2.0, with granular permission controls and comprehensive audit logging.

Key strengths for FastMCP integration:

- **Complete API Coverage**: All user management operations are available via API
- **Modern Authentication**: OAuth 2.0 with OIDC and PKCE support
- **Granular Permissions**: Role-based access control at multiple levels
- **Comprehensive Auditing**: Full audit trail for compliance and monitoring
- **Enterprise Features**: SSO, organization management, team administration

The API is well-documented and follows REST conventions, making it suitable for robust FastMCP tool implementations. The authentication system provides flexibility for both simple API token usage and complex OAuth integrations.

For FastMCP implementation, prioritize:

1. Core authentication and token management tools
2. User profile and role management capabilities
3. Organization and team administration features
4. Audit log access for compliance and monitoring

This comprehensive API foundation enables building powerful Make.com integration tools within the FastMCP framework.
