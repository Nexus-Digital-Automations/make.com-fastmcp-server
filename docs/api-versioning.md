# API Versioning Strategy - Make.com FastMCP Server

## Overview

The Make.com FastMCP Server implements a comprehensive API versioning strategy to ensure backward compatibility, smooth migrations, and long-term maintainability. This document outlines our versioning approach, compatibility guidelines, and migration strategies.

## Table of Contents

1. [Versioning Philosophy](#versioning-philosophy)
2. [Versioning Scheme](#versioning-scheme)
3. [Versioning Implementation](#versioning-implementation)
4. [Backward Compatibility Guidelines](#backward-compatibility-guidelines)
5. [Breaking Changes Policy](#breaking-changes-policy)
6. [Migration Strategies](#migration-strategies)
7. [Deprecation Process](#deprecation-process)
8. [Tool Version Management](#tool-version-management)
9. [Client Integration](#client-integration)
10. [Examples](#examples)

## Versioning Philosophy

### Core Principles

1. **Stability First**: Existing integrations should continue to work without modification
2. **Predictable Evolution**: Version changes follow clear, documented patterns
3. **Migration Support**: Comprehensive tooling and documentation for upgrades
4. **Semantic Clarity**: Version numbers convey meaningful information about compatibility
5. **Developer Experience**: Versioning enhances rather than complicates the development workflow

### Strategic Goals

- **Minimize Breaking Changes**: Prefer additive changes and deprecation over immediate removal
- **Clear Migration Paths**: Every breaking change includes migration documentation
- **Tool-Level Granularity**: Different tools can evolve at different speeds
- **Client Flexibility**: Support multiple API versions simultaneously where practical

## Versioning Scheme

### Semantic Versioning (SemVer)

We follow [Semantic Versioning 2.0.0](https://semver.org/) with FastMCP-specific interpretations:

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

#### Version Component Meanings

- **MAJOR** (`X.0.0`): Breaking changes to tool interfaces, authentication, or core functionality
- **MINOR** (`0.X.0`): New tools, new tool parameters, or enhanced functionality (backward compatible)
- **PATCH** (`0.0.X`): Bug fixes, security patches, performance improvements (backward compatible)
- **PRERELEASE**: Alpha, beta, or release candidate versions (`1.2.0-beta.1`)
- **BUILD**: Build metadata for CI/CD purposes (`1.2.0+20240115.1`)

#### FastMCP-Specific Interpretations

**MAJOR Version Changes:**
- Removal of existing tools
- Changes to tool parameter schemas that break existing calls
- Authentication method changes
- Core server configuration breaking changes
- Make.com API client breaking changes

**MINOR Version Changes:**
- Addition of new tools
- Addition of optional parameters to existing tools
- New response fields (backward compatible)
- Performance improvements
- New capabilities or features

**PATCH Version Changes:**
- Bug fixes in existing tools
- Security vulnerability patches
- Error message improvements
- Documentation updates
- Internal refactoring without API changes

### Version Lifecycle

```
Alpha → Beta → Release Candidate → Stable → Maintenance → End of Life
```

#### Lifecycle Stages

1. **Alpha** (`1.3.0-alpha.1`): Early development, frequent breaking changes
2. **Beta** (`1.3.0-beta.1`): Feature-complete, API stabilizing, limited breaking changes
3. **Release Candidate** (`1.3.0-rc.1`): Production-ready, no new features, only critical fixes
4. **Stable** (`1.3.0`): Production release with full support
5. **Maintenance**: Security and critical bug fixes only
6. **End of Life**: No further updates, migration required

## Versioning Implementation

### Header-Based Versioning

The server supports version specification via HTTP headers:

```http
# Request specific API version
MCP-Version: 1.2.0

# Request minimum compatible version
MCP-Min-Version: 1.1.0

# Request version range
MCP-Version-Range: >=1.1.0 <2.0.0
```

#### Default Behavior

- **No Version Header**: Uses latest stable version
- **Invalid Version**: Returns error with supported versions
- **Unsupported Version**: Returns error with migration guidance

### Tool-Level Versioning

Individual tools can specify their own version requirements:

```typescript
// Tool definition with version metadata
this.server.addTool({
  name: 'create-scenario',
  description: 'Create a new Make.com scenario',
  version: '1.2.0',
  minimumServerVersion: '1.0.0',
  deprecatedIn: '2.0.0',
  removedIn: '3.0.0',
  parameters: scenarioSchema,
  // ... rest of tool definition
});
```

### Server Version Information

The `server-info` tool provides comprehensive version details:

```json
{
  "version": "1.2.3",
  "apiVersion": "1.2",
  "minSupportedVersion": "1.0.0",
  "maxSupportedVersion": "1.2.3",
  "supportedVersions": ["1.0.x", "1.1.x", "1.2.x"],
  "tools": {
    "create-scenario": {
      "version": "1.2.0",
      "status": "stable",
      "deprecatedIn": null,
      "removedIn": null
    },
    "legacy-tool": {
      "version": "1.0.0", 
      "status": "deprecated",
      "deprecatedIn": "1.1.0",
      "removedIn": "2.0.0"
    }
  }
}
```

## Backward Compatibility Guidelines

### Compatible Changes (Safe)

These changes are allowed in MINOR and PATCH versions:

#### Tool Enhancements
- **Adding new tools**: New functionality without affecting existing tools
- **Adding optional parameters**: With sensible defaults
- **Adding response fields**: Non-breaking additions to tool outputs
- **Improving error messages**: More descriptive error information
- **Performance optimizations**: Faster execution without behavioral changes

#### Schema Extensions
```typescript
// Before (v1.1.0)
const createScenarioSchema = z.object({
  name: z.string(),
  teamId: z.number().optional()
});

// After (v1.2.0) - Compatible
const createScenarioSchema = z.object({
  name: z.string(),
  teamId: z.number().optional(),
  description: z.string().optional(), // New optional field
  tags: z.array(z.string()).optional() // New optional field
});
```

#### Response Enhancements
```typescript
// Before (v1.1.0)
return {
  scenarioId: 12345,
  status: 'created'
};

// After (v1.2.0) - Compatible
return {
  scenarioId: 12345,
  status: 'created',
  createdAt: '2024-01-15T10:30:00Z', // New field
  permissions: ['read', 'write']       // New field
};
```

### Breaking Changes (Major Version Required)

These changes require a MAJOR version increment:

#### Tool Modifications
- **Removing tools**: Any tool removal
- **Renaming tools**: Name changes break existing integrations
- **Changing parameter types**: Type changes break validation
- **Making optional parameters required**: Breaks existing calls
- **Removing response fields**: Clients may depend on these fields

#### Authentication Changes
- **Changing authentication methods**: OAuth to API key, etc.
- **Modifying header requirements**: New required headers
- **Permission model changes**: Role/scope requirement changes

#### Configuration Breaking Changes
- **Environment variable renames**: Deployment configuration changes
- **Default value changes**: Behavioral changes in existing deployments
- **Required configuration additions**: New mandatory settings

## Breaking Changes Policy

### Change Classification

#### Level 1: Critical Breaking Changes
- Security vulnerability fixes requiring immediate API changes
- Make.com API breaking changes that must be reflected
- Data corruption or integrity issues

**Policy**: Immediate patch release with migration guide and tooling

#### Level 2: Major Feature Breaking Changes  
- Tool interface improvements requiring parameter changes
- Authentication system upgrades
- Performance optimizations requiring API changes

**Policy**: Include in next major version with 6-month advance notice

#### Level 3: Cleanup Breaking Changes
- Removal of deprecated tools
- Legacy parameter cleanup
- Unused feature removal

**Policy**: Include in major version after 12-month deprecation period

### Communication Timeline

#### For Major Breaking Changes

1. **T-6 months**: Announce planned changes, publish migration guide
2. **T-3 months**: Release beta version with new APIs
3. **T-1 month**: Release candidate with final API
4. **T-0**: Stable release
5. **T+6 months**: Previous major version enters maintenance mode
6. **T+12 months**: Previous major version end-of-life

#### For Critical Security Changes

1. **T-0**: Immediate patch release
2. **T+1 week**: Detailed migration documentation
3. **T+1 month**: Migration tooling and support
4. **T+3 months**: Legacy version end-of-life (if necessary)

## Migration Strategies

### Tool Migration Patterns

#### 1. Parallel Tool Implementation

For major tool changes, implement both versions temporarily:

```typescript
// Legacy tool (deprecated)
this.server.addTool({
  name: 'create-scenario',
  description: 'Create a new Make.com scenario (DEPRECATED)',
  deprecated: true,
  deprecatedIn: '1.2.0',
  removedIn: '2.0.0',
  replacedBy: 'create-scenario-v2',
  // ... legacy implementation
});

// New tool
this.server.addTool({
  name: 'create-scenario-v2',
  description: 'Create a new Make.com scenario with enhanced features',
  version: '1.2.0',
  // ... new implementation
});
```

#### 2. Parameter Evolution

Handle parameter changes gracefully:

```typescript
// Version-aware parameter handling
const handleCreateScenario = async (params: any, context: ToolContext) => {
  const clientVersion = parseVersion(context.session.clientVersion);
  
  if (clientVersion.major < 2) {
    // Legacy parameter format
    const legacyParams = migrateLegacyParams(params);
    return createScenarioLegacy(legacyParams);
  } else {
    // New parameter format
    return createScenarioV2(params);
  }
};
```

#### 3. Response Transformation

Adapt responses based on client version:

```typescript
const formatResponse = (data: ScenarioData, clientVersion: Version) => {
  const baseResponse = {
    scenarioId: data.id,
    status: data.status
  };
  
  if (clientVersion.minor >= 2) {
    // Enhanced response for newer clients
    return {
      ...baseResponse,
      createdAt: data.createdAt,
      permissions: data.permissions,
      metadata: data.metadata
    };
  }
  
  return baseResponse; // Legacy response format
};
```

### Database/State Migration

For server-side state changes:

```typescript
class MigrationManager {
  async migrateToVersion(targetVersion: string): Promise<void> {
    const currentVersion = await this.getCurrentVersion();
    const migrations = this.getMigrationsPath(currentVersion, targetVersion);
    
    for (const migration of migrations) {
      await this.runMigration(migration);
    }
  }
  
  private async runMigration(migration: Migration): Promise<void> {
    try {
      await migration.up();
      await this.recordMigration(migration.version);
    } catch (error) {
      await migration.down(); // Rollback on failure
      throw error;
    }
  }
}
```

## Deprecation Process

### Deprecation Lifecycle

1. **Announcement**: Communicate deprecation with timeline
2. **Warning Period**: Add deprecation warnings to responses
3. **Documentation**: Update docs with migration guidance
4. **Tooling**: Provide migration scripts/tools
5. **Removal**: Remove in next major version

### Deprecation Warnings

#### HTTP Headers
```http
# Response includes deprecation information
Deprecation: true
Sunset: Sat, 31 Dec 2024 23:59:59 GMT
Link: </docs/api-versioning#migration-guide>; rel="deprecation"
Warning: 299 - "Tool 'create-scenario' is deprecated. Use 'create-scenario-v2' instead."
```

#### Tool Response Format
```json
{
  "result": { /* normal tool response */ },
  "warnings": [
    {
      "type": "deprecation",
      "message": "This tool is deprecated and will be removed in v2.0.0",
      "deprecatedIn": "1.2.0",
      "removedIn": "2.0.0",
      "replacement": "create-scenario-v2",
      "migrationGuide": "https://docs.example.com/migration-guide#create-scenario"
    }
  ]
}
```

### Deprecation Announcement Template

```markdown
## Deprecation Notice: [Tool/Feature Name]

**Summary**: [Brief description of what's being deprecated]

**Timeline**: 
- Deprecated in: v1.2.0 (January 15, 2024)
- Will be removed in: v2.0.0 (July 15, 2024)
- Migration deadline: June 15, 2024

**Reason**: [Why this change is necessary]

**Replacement**: [What users should use instead]

**Migration Guide**: [Link to detailed migration instructions]

**Impact**: [Who is affected and how]

**Support**: [How to get help with migration]
```

## Tool Version Management

### Version Metadata

Each tool includes comprehensive version information:

```typescript
interface ToolVersionMetadata {
  version: string;           // Tool version
  minimumServerVersion: string; // Minimum server version required
  introducedIn: string;      // When this tool was first added
  deprecatedIn?: string;     // When deprecated (if applicable)
  removedIn?: string;        // When it will be removed
  replacedBy?: string;       // Replacement tool name
  changlog: ChangelogEntry[]; // Version history
}

interface ChangelogEntry {
  version: string;
  date: string;
  changes: string[];
  breakingChanges?: string[];
  migrationNotes?: string;
}
```

### Tool Evolution Example

```typescript
// Tool definition with full version history
const createScenarioTool = {
  name: 'create-scenario',
  version: '1.3.0',
  minimumServerVersion: '1.0.0',
  introducedIn: '1.0.0',
  metadata: {
    changelog: [
      {
        version: '1.0.0',
        date: '2024-01-01',
        changes: ['Initial implementation'],
        breakingChanges: []
      },
      {
        version: '1.1.0', 
        date: '2024-02-01',
        changes: ['Added optional description parameter'],
        breakingChanges: []
      },
      {
        version: '1.2.0',
        date: '2024-03-01',
        changes: ['Added scheduling options', 'Enhanced error responses'],
        breakingChanges: []
      },
      {
        version: '1.3.0',
        date: '2024-04-01',
        changes: ['Added blueprint validation', 'Improved performance'],
        breakingChanges: []
      }
    ]
  }
};
```

### Version-Specific Tool Behavior

```typescript
class VersionedTool {
  async execute(params: unknown, context: ToolContext) {
    const clientVersion = this.parseClientVersion(context);
    
    // Route to appropriate implementation
    switch (clientVersion.major) {
      case 1:
        return this.executeV1(params, context);
      case 2:
        return this.executeV2(params, context);
      default:
        throw new UnsupportedVersionError(
          `Client version ${clientVersion} not supported. ` +
          `Supported versions: 1.x, 2.x`
        );
    }
  }
  
  private async executeV1(params: unknown, context: ToolContext) {
    // Version 1 implementation with legacy compatibility
    const validatedParams = this.validateParamsV1(params);
    const result = await this.createScenarioV1(validatedParams);
    return this.formatResponseV1(result);
  }
  
  private async executeV2(params: unknown, context: ToolContext) {
    // Version 2 implementation with enhanced features
    const validatedParams = this.validateParamsV2(params);
    const result = await this.createScenarioV2(validatedParams);
    return this.formatResponseV2(result);
  }
}
```

## Client Integration

### Version Negotiation

Clients should implement proper version negotiation:

```typescript
// Client-side version handling
class MakeFastMCPClient {
  private supportedVersions = ['1.0.0', '1.1.0', '1.2.0'];
  private preferredVersion = '1.2.0';
  
  async connect() {
    // Get server capabilities
    const serverInfo = await this.callTool('server-info');
    const compatibleVersion = this.negotiateVersion(
      serverInfo.supportedVersions,
      this.supportedVersions
    );
    
    if (!compatibleVersion) {
      throw new Error('No compatible API version found');
    }
    
    this.apiVersion = compatibleVersion;
  }
  
  private negotiateVersion(serverVersions: string[], clientVersions: string[]): string | null {
    // Find highest compatible version
    for (const clientVersion of clientVersions.reverse()) {
      if (serverVersions.some(sv => this.isCompatible(sv, clientVersion))) {
        return clientVersion;
      }
    }
    return null;
  }
  
  async callTool(name: string, params?: any) {
    return this.request({
      method: 'tools/call',
      params: { name, arguments: params },
      headers: {
        'MCP-Version': this.apiVersion
      }
    });
  }
}
```

### Migration Helpers

Provide client-side migration utilities:

```typescript
// Migration utility for clients
class APIVersionMigrator {
  static migrateParams(toolName: string, params: any, fromVersion: string, toVersion: string): any {
    const migrationPath = this.getMigrationPath(toolName, fromVersion, toVersion);
    
    return migrationPath.reduce((migratedParams, migration) => {
      return migration.transform(migratedParams);
    }, params);
  }
  
  static migrateResponse(toolName: string, response: any, fromVersion: string, toVersion: string): any {
    // Transform response format for backward compatibility
    const transformer = this.getResponseTransformer(toolName, fromVersion, toVersion);
    return transformer(response);
  }
}

// Usage in client code
const migratedParams = APIVersionMigrator.migrateParams(
  'create-scenario',
  legacyParams,
  '1.0.0',
  '1.2.0'
);
```

## Examples

### Example 1: Adding a New Optional Parameter

**Scenario**: Adding an optional `description` parameter to `create-scenario`

**Before (v1.0.0)**:
```typescript
const createScenarioSchema = z.object({
  name: z.string().min(1).max(255),
  teamId: z.number().int().positive().optional()
});
```

**After (v1.1.0)** - Compatible change:
```typescript
const createScenarioSchema = z.object({
  name: z.string().min(1).max(255),
  teamId: z.number().int().positive().optional(),
  description: z.string().max(1000).optional() // New optional parameter
});
```

**Client Impact**: None - existing calls continue to work unchanged.

### Example 2: Tool Parameter Type Change (Breaking)

**Scenario**: Changing `teamId` from number to string for better UUID support

**v1.x (Legacy)**:
```typescript
const createScenarioSchemaV1 = z.object({
  name: z.string(),
  teamId: z.number().int().positive().optional()
});
```

**v2.0 (Breaking)**:
```typescript
const createScenarioSchemaV2 = z.object({
  name: z.string(),
  teamId: z.string().uuid().optional() // Breaking change: number → string
});
```

**Migration Strategy**:
```typescript
// Server handles both formats during transition
const handleCreateScenario = async (params: any, context: ToolContext) => {
  const clientVersion = parseVersion(context.headers['MCP-Version']);
  
  if (clientVersion.major < 2) {
    // Convert legacy number teamId to string UUID
    if (typeof params.teamId === 'number') {
      params.teamId = await this.resolveTeamUUID(params.teamId);
    }
  }
  
  // Proceed with standardized parameters
  return this.createScenario(params);
};
```

### Example 3: Tool Replacement

**Scenario**: Replacing `get-scenario-logs` with enhanced `get-execution-analytics`

**Phase 1** - v1.5.0 (Introduce new tool):
```typescript
// Add new enhanced tool
this.server.addTool({
  name: 'get-execution-analytics',
  description: 'Get enhanced execution analytics with filtering and aggregation',
  version: '1.5.0',
  parameters: enhancedAnalyticsSchema
});

// Keep legacy tool with deprecation warning
this.server.addTool({
  name: 'get-scenario-logs',
  description: 'Get scenario execution logs (DEPRECATED - use get-execution-analytics)',
  deprecated: true,
  deprecatedIn: '1.5.0',
  removedIn: '2.0.0',
  replacedBy: 'get-execution-analytics'
});
```

**Phase 2** - v2.0.0 (Remove legacy tool):
```typescript
// Legacy tool removed
// Only get-execution-analytics available
```

**Migration Documentation**:
```markdown
## Migrating from get-scenario-logs to get-execution-analytics

### What Changed
- Enhanced filtering capabilities
- Aggregation and grouping options  
- Standardized response format
- Better performance for large datasets

### Parameter Mapping
| Old Parameter | New Parameter | Notes |
|---------------|---------------|-------|
| `scenarioId` | `scenarioId` | No change |
| `startDate` | `filters.dateRange.start` | Moved to filters object |
| `endDate` | `filters.dateRange.end` | Moved to filters object |
| `limit` | `pagination.limit` | Moved to pagination object |

### Code Example
```typescript
// Before (get-scenario-logs)
const logs = await client.callTool('get-scenario-logs', {
  scenarioId: 12345,
  startDate: '2024-01-01',
  endDate: '2024-01-31',
  limit: 100
});

// After (get-execution-analytics)
const analytics = await client.callTool('get-execution-analytics', {
  scenarioId: 12345,
  filters: {
    dateRange: {
      start: '2024-01-01',
      end: '2024-01-31'
    }
  },
  pagination: {
    limit: 100
  }
});
```
```

### Example 4: Server Configuration Evolution

**Scenario**: Enhancing authentication configuration

**v1.x Configuration**:
```bash
# Simple API key authentication
AUTH_ENABLED=true
AUTH_SECRET=simple_secret_key
```

**v2.0 Configuration** (Breaking):
```bash
# Enhanced authentication with multiple providers
AUTH_ENABLED=true
AUTH_PROVIDERS=apikey,oauth2,jwt
AUTH_APIKEY_SECRET=api_key_secret
AUTH_OAUTH2_CLIENT_ID=oauth_client_id
AUTH_OAUTH2_CLIENT_SECRET=oauth_client_secret
AUTH_JWT_SECRET=jwt_secret
AUTH_JWT_ISSUER=https://auth.example.com
```

**Migration Script**:
```bash
#!/bin/bash
# migrate-auth-config.sh

echo "Migrating authentication configuration from v1.x to v2.0"

# Backup existing config
cp .env .env.v1.backup

# Convert AUTH_SECRET to AUTH_APIKEY_SECRET
if grep -q "^AUTH_SECRET=" .env; then
    AUTH_SECRET_VALUE=$(grep "^AUTH_SECRET=" .env | cut -d'=' -f2)
    echo "AUTH_APIKEY_SECRET=$AUTH_SECRET_VALUE" >> .env.new
    echo "AUTH_PROVIDERS=apikey" >> .env.new
fi

# Copy other settings
grep -v "^AUTH_SECRET=" .env >> .env.new

# Replace old config
mv .env.new .env

echo "Migration complete. Review .env file and configure additional auth providers if needed."
```

---

This comprehensive API versioning strategy ensures that the Make.com FastMCP Server can evolve while maintaining stability and providing clear migration paths for all users.