# User Permissions & Role Management Tools

Comprehensive tools for managing users, teams, organizations, and role-based access control in Make.com with audit logging and invitation management.

## Tools Overview

| Tool | Description | Type |
|------|-------------|------|
| `get-current-user` | Get current user information | Read |
| `list-users` | List users with role information | Read |
| `get-user` | Get detailed user information | Read |
| `update-user-role` | Update user roles and permissions | Write |
| `list-teams` | List teams with filtering | Read |
| `get-team` | Get detailed team information | Read |
| `create-team` | Create new team | Write |
| `update-team` | Update team information | Write |
| `delete-team` | Remove team | Write |
| `list-organizations` | List user organizations | Read |
| `get-organization` | Get organization details | Read |
| `create-organization` | Create new organization | Write |
| `update-organization` | Update organization info | Write |
| `delete-organization` | Remove organization | Write |
| `invite-user` | Invite user to team/organization | Action |

## User Management

### `get-current-user`

Get current user information and permissions for the authenticated session.

**Parameters:**
```typescript
{} // No parameters required
```

**Returns:**
```typescript
{
  user: {
    id: number;
    name: string;
    email: string;
    role: 'admin' | 'member' | 'viewer';
    permissions: string[];
    teams: Team[];
    organizations: Organization[];
    preferences: object;
    lastLoginAt: string;
    createdAt: string;
  };
}
```

**Example:**
```bash
# Get current user info
mcp-client get-current-user
```

**Use Cases:**
- Authentication verification
- Permission checking
- User profile display
- Session validation

---

### `list-users`

List and filter users with role and permission information across teams and organizations.

**Parameters:**
```typescript
{
  teamId?: number;            // Filter by team ID
  organizationId?: number;    // Filter by organization ID
  role?: 'admin' | 'member' | 'viewer';  // Filter by user role
  isActive?: boolean;         // Filter by active status
  search?: string;            // Search users by name or email
  limit?: number;             // Max users (1-100, default: 20)
  offset?: number;            // Users to skip (default: 0)
}
```

**Returns:**
```typescript
{
  users: User[];
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
# List all admin users
mcp-client list-users --role "admin" --isActive true

# Search for users in specific team
mcp-client list-users --teamId 123 --search "john"

# List organization members
mcp-client list-users --organizationId 456 --limit 50
```

**Use Cases:**
- User directory management
- Role auditing
- Team member discovery
- Access control review

---

### `get-user`

Get detailed information about a specific user including roles, permissions, and team memberships.

**Parameters:**
```typescript
{
  userId: number;             // User ID (required)
}
```

**Returns:**
```typescript
{
  user: {
    id: number;
    name: string;
    email: string;
    role: string;
    permissions: string[];
    teams: TeamMembership[];
    organizations: OrganizationMembership[];
    lastLoginAt: string;
    createdAt: string;
    isActive: boolean;
  };
}
```

**Example:**
```bash
# Get user details
mcp-client get-user --userId 12345
```

**Use Cases:**
- User profile management
- Permission verification
- Membership audit
- Support and troubleshooting

---

### `update-user-role`

Update user role and permissions within teams or organizations with audit logging.

**Parameters:**
```typescript
{
  userId: number;             // User ID (required)
  role: 'admin' | 'member' | 'viewer';  // New role (required)
  teamId?: number;            // Team ID for role assignment
  permissions?: string[];     // Specific permissions to grant
}
```

**Returns:**
```typescript
{
  user: User;
  message: string;
}
```

**Example:**
```bash
# Promote user to admin
mcp-client update-user-role \
  --userId 12345 \
  --role "admin" \
  --teamId 123

# Grant specific permissions
mcp-client update-user-role \
  --userId 12345 \
  --role "member" \
  --permissions "scenario:read,scenario:write,analytics:read"
```

**Role Hierarchy:**
- **admin**: Full access including user management
- **member**: Standard access with read/write permissions
- **viewer**: Read-only access to assigned resources

**Use Cases:**
- Role promotion/demotion
- Permission management
- Team restructuring
- Access control updates

## Team Management

### `list-teams`

List and filter teams with optional organization scoping.

**Parameters:**
```typescript
{
  organizationId?: number;    // Filter by organization ID
  search?: string;            // Search teams by name
  limit?: number;             // Max teams (1-100, default: 20)
  offset?: number;            // Teams to skip (default: 0)
}
```

**Returns:**
```typescript
{
  teams: Team[];
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
# List all teams
mcp-client list-teams

# List teams in organization
mcp-client list-teams --organizationId 456

# Search teams
mcp-client list-teams --search "development"
```

**Use Cases:**
- Team directory
- Organization structure view
- Team discovery
- Administrative oversight

---

### `get-team`

Get detailed information about a specific team including members and settings.

**Parameters:**
```typescript
{
  teamId: number;             // Team ID (required)
}
```

**Returns:**
```typescript
{
  team: {
    id: number;
    name: string;
    description: string;
    organizationId: number;
    members: TeamMember[];
    settings: object;
    createdAt: string;
    updatedAt: string;
  };
}
```

**Example:**
```bash
# Get team details
mcp-client get-team --teamId 123
```

**Use Cases:**
- Team profile management
- Member list review
- Team configuration
- Administrative operations

---

### `create-team`

Create a new team with optional organization assignment.

**Parameters:**
```typescript
{
  name: string;               // Team name (1-100 chars, required)
  description?: string;       // Team description (max 500 chars)
  organizationId?: number;    // Organization ID
}
```

**Returns:**
```typescript
{
  team: Team;
  message: string;
}
```

**Example:**
```bash
# Create basic team
mcp-client create-team --name "Development Team"

# Create team with description and organization
mcp-client create-team \
  --name "Marketing Team" \
  --description "Responsible for marketing campaigns and analytics" \
  --organizationId 456
```

**Use Cases:**
- Team provisioning
- Organizational restructuring
- Project-based team creation
- Department setup

---

### `update-team`

Update team information including name and description.

**Parameters:**
```typescript
{
  teamId: number;             // Team ID (required)
  name?: string;              // New team name (1-100 chars)
  description?: string;       // New team description (max 500 chars)
}
```

**Returns:**
```typescript
{
  team: Team;
  message: string;
}
```

**Example:**
```bash
# Update team name
mcp-client update-team --teamId 123 --name "Backend Development Team"

# Update description
mcp-client update-team \
  --teamId 123 \
  --description "Backend services and API development"
```

**Use Cases:**
- Team rebranding
- Description updates
- Organizational changes
- Administrative maintenance

---

### `delete-team`

Delete a team with member transfer and safety checks.

**Parameters:**
```typescript
{
  teamId: number;             // Team ID (required)
}
```

**Returns:**
```typescript
{
  message: string;
}
```

**Example:**
```bash
# Delete team
mcp-client delete-team --teamId 123
```

**Safety Features:**
- Checks for active team members
- Validates team resource dependencies
- Provides member transfer options
- Audit trail creation

**Use Cases:**
- Team dissolution
- Organizational restructuring
- Cleanup operations
- Merger consolidation

## Organization Management

### `list-organizations`

List user organizations with optional filtering.

**Parameters:**
```typescript
{
  search?: string;            // Search organizations by name
  limit?: number;             // Max organizations (1-100, default: 20)
  offset?: number;            // Organizations to skip (default: 0)
}
```

**Returns:**
```typescript
{
  organizations: Organization[];
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
# List all organizations
mcp-client list-organizations

# Search organizations
mcp-client list-organizations --search "acme"
```

**Use Cases:**
- Organization directory
- Multi-tenant management
- Account selection
- Administrative overview

---

### `get-organization`

Get detailed information about a specific organization.

**Parameters:**
```typescript
{
  organizationId: number;     // Organization ID (required)
}
```

**Returns:**
```typescript
{
  organization: {
    id: number;
    name: string;
    description: string;
    settings: object;
    teams: Team[];
    members: OrganizationMember[];
    billing: BillingInfo;
    createdAt: string;
    updatedAt: string;
  };
}
```

**Example:**
```bash
# Get organization details
mcp-client get-organization --organizationId 456
```

**Use Cases:**
- Organization profile management
- Structure overview
- Settings configuration
- Billing information access

---

### `create-organization`

Create a new organization with initial configuration.

**Parameters:**
```typescript
{
  name: string;               // Organization name (1-100 chars, required)
  description?: string;       // Organization description (max 500 chars)
}
```

**Returns:**
```typescript
{
  organization: Organization;
  message: string;
}
```

**Example:**
```bash
# Create organization
mcp-client create-organization \
  --name "Acme Corporation" \
  --description "Leading provider of innovative solutions"
```

**Use Cases:**
- Multi-tenant setup
- Customer onboarding
- Corporate structure creation
- New business unit establishment

---

### `update-organization`

Update organization information and settings.

**Parameters:**
```typescript
{
  organizationId: number;     // Organization ID (required)
  name?: string;              // New organization name (1-100 chars)
  description?: string;       // New description (max 500 chars)
}
```

**Returns:**
```typescript
{
  organization: Organization;
  message: string;
}
```

**Example:**
```bash
# Update organization name
mcp-client update-organization \
  --organizationId 456 \
  --name "Acme Industries"
```

**Use Cases:**
- Rebranding operations
- Information updates
- Corporate restructuring
- Administrative maintenance

---

### `delete-organization`

Delete an organization with comprehensive safety checks.

**Parameters:**
```typescript
{
  organizationId: number;     // Organization ID (required)
}
```

**Returns:**
```typescript
{
  message: string;
}
```

**Example:**
```bash
# Delete organization
mcp-client delete-organization --organizationId 456
```

**Safety Features:**
- Validates no active subscriptions
- Checks for dependent resources
- Requires explicit member transfer
- Creates comprehensive audit trail

**Use Cases:**
- Account closure
- Merger consolidation
- Cleanup operations
- Business shutdown

## User Invitation System

### `invite-user`

Invite a user to join a team or organization with role assignment.

**Parameters:**
```typescript
{
  email: string;              // Email address (required)
  role?: 'admin' | 'member' | 'viewer';  // Role to assign (default: member)
  teamId?: number;            // Team ID to invite to
  organizationId?: number;    // Organization ID to invite to
  permissions?: string[];     // Specific permissions to grant
}
```

**Returns:**
```typescript
{
  invitation: {
    id: string;
    email: string;
    role: string;
    teamId?: number;
    organizationId?: number;
    inviteUrl: string;
    expiresAt: string;
    status: 'pending';
  };
  message: string;
}
```

**Example:**
```bash
# Invite user to team
mcp-client invite-user \
  --email "john@company.com" \
  --role "member" \
  --teamId 123

# Invite organization admin
mcp-client invite-user \
  --email "admin@company.com" \
  --role "admin" \
  --organizationId 456

# Invite with specific permissions
mcp-client invite-user \
  --email "viewer@company.com" \
  --role "viewer" \
  --teamId 123 \
  --permissions "scenario:read,analytics:read"
```

**Invitation Features:**
- Email notification system
- Configurable expiration times
- Role pre-assignment
- Permission specification
- Invitation tracking

**Use Cases:**
- Team member onboarding
- External collaborator access
- Temporary access provisioning
- Bulk user invitation

## Permission System

### Role Definitions

**Admin Role:**
- Full system access
- User management capabilities
- Organization/team administration
- Billing and subscription management
- System configuration access

**Member Role:**
- Standard operational access
- Scenario creation and management
- Connection management
- Analytics access (team scope)
- Limited user management

**Viewer Role:**
- Read-only access
- Scenario viewing
- Analytics viewing
- No modification capabilities
- No user management

### Permission Scoping

**Global Permissions:**
- System-wide access control
- Cross-organization visibility
- Platform administration

**Organization Permissions:**
- Organization-scoped access
- Multi-team visibility
- Organization administration

**Team Permissions:**
- Team-scoped access
- Resource isolation
- Team-specific operations

## Error Handling

### User Management Errors

**User Not Found**
```json
{
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "User with ID 12345 not found",
    "userId": 12345
  }
}
```

**Insufficient Permissions**
```json
{
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS",
    "message": "You don't have permission to manage users in this organization",
    "requiredPermission": "user:manage",
    "currentRole": "member"
  }
}
```

**Role Assignment Error**
```json
{
  "error": {
    "code": "INVALID_ROLE_ASSIGNMENT",
    "message": "Cannot assign admin role without organization permissions",
    "requestedRole": "admin",
    "userPermissions": ["team:member"]
  }
}
```

### Team/Organization Errors

**Team Not Found**
```json
{
  "error": {
    "code": "TEAM_NOT_FOUND", 
    "message": "Team with ID 123 not found or access denied",
    "teamId": 123
  }
}
```

**Duplicate Team Name**
```json
{
  "error": {
    "code": "TEAM_NAME_EXISTS",
    "message": "Team name 'Development Team' already exists in this organization",
    "name": "Development Team",
    "organizationId": 456
  }
}
```

### Invitation Errors

**Invalid Email**
```json
{
  "error": {
    "code": "INVALID_EMAIL",
    "message": "Email address 'invalid-email' is not valid",
    "email": "invalid-email"
  }
}
```

**Existing User**
```json
{
  "error": {
    "code": "USER_ALREADY_MEMBER",
    "message": "User with email 'john@company.com' is already a member of this team",
    "email": "john@company.com",
    "teamId": 123
  }
}
```

## Security Best Practices

### Access Control
- Implement principle of least privilege
- Regular permission audits
- Role-based access control (RBAC)
- Multi-factor authentication support

### User Management
- Strong password policies
- Account lockout mechanisms
- Session management
- Activity monitoring

### Audit Logging
- All permission changes logged
- User action tracking
- Administrative operation audit
- Compliance reporting

## Monitoring and Analytics

### User Activity
- Login/logout tracking
- Permission usage monitoring
- Role change history
- Access pattern analysis

### Team/Organization Metrics
- Membership growth tracking
- Role distribution analysis
- Permission utilization
- Administrative activity monitoring

This comprehensive documentation provides administrators and developers with all the tools needed for effective user, team, and organization management within the Make.com FastMCP server environment.