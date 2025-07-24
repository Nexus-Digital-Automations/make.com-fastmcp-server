# Scenario Management Tools

Comprehensive CRUD operations for Make.com scenarios with advanced filtering, scheduling, and execution capabilities.

## Tools Overview

| Tool | Description | Type |
|------|-------------|------|
| `list-scenarios` | List and search scenarios with filtering | Read |
| `get-scenario` | Get detailed scenario information | Read |
| `create-scenario` | Create a new scenario | Write |
| `update-scenario` | Update existing scenario configuration | Write |
| `delete-scenario` | Delete a scenario (with safety checks) | Write |
| `clone-scenario` | Clone existing scenario with new name | Write |
| `run-scenario` | Execute scenario and monitor completion | Action |

## Tools Reference

### `list-scenarios`

List and search Make.com scenarios with advanced filtering options.

**Parameters:**
```typescript
{
  teamId?: string;        // Filter by team ID
  folderId?: string;      // Filter by folder ID  
  limit?: number;         // Items to return (1-100, default: 10)
  offset?: number;        // Items to skip (default: 0)
  search?: string;        // Search term for scenario names
  active?: boolean;       // Filter by active/inactive status
}
```

**Returns:**
```typescript
{
  scenarios: Scenario[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
  filters: object;        // Applied filters
  timestamp: string;
}
```

**Example:**
```bash
# List active scenarios for a specific team
mcp-client list-scenarios --teamId "team123" --active true --limit 50
```

**Use Cases:**
- Dashboard scenario listings
- Bulk scenario management
- Team-specific scenario views
- Automated scenario discovery

---

### `get-scenario`

Get detailed information about a specific Make.com scenario with optional blueprint and execution history.

**Parameters:**
```typescript
{
  scenarioId: string;           // Scenario ID (required)
  includeBlueprint?: boolean;   // Include full blueprint (default: false)
  includeExecutions?: boolean;  // Include recent executions (default: false)
}
```

**Returns:**
```typescript
{
  scenario: Scenario;
  blueprint?: object;           // Full scenario configuration
  recentExecutions?: Execution[]; // Last 10 executions
  timestamp: string;
}
```

**Example:**
```bash
# Get scenario with blueprint and execution history
mcp-client get-scenario --scenarioId "12345" --includeBlueprint true --includeExecutions true
```

**Use Cases:**
- Scenario debugging
- Configuration backup
- Performance analysis
- Execution monitoring

---

### `create-scenario`

Create a new Make.com scenario with optional configuration and scheduling.

**Parameters:**
```typescript
{
  name: string;                 // Scenario name (1-100 chars, required)
  teamId?: string;             // Team to create in
  folderId?: string;           // Folder for organization
  blueprint?: object;          // Scenario configuration JSON
  scheduling?: {
    type: 'immediately' | 'interval' | 'cron';
    interval?: number;         // Minutes for interval scheduling
    cron?: string;            // Cron expression for cron scheduling
  };
}
```

**Returns:**
```typescript
{
  scenario: Scenario;
  message: string;
  timestamp: string;
}
```

**Example:**
```bash
# Create a basic scenario
mcp-client create-scenario --name "Data Sync Process" --teamId "team123"

# Create with scheduling
mcp-client create-scenario \
  --name "Daily Report" \
  --scheduling.type "cron" \
  --scheduling.cron "0 9 * * *"
```

**Use Cases:**
- Automated scenario provisioning
- Template-based scenario creation
- Bulk scenario setup
- Development workflows

---

### `update-scenario`

Update an existing Make.com scenario configuration including name, status, blueprint, and scheduling.

**Parameters:**
```typescript
{
  scenarioId: string;          // Scenario ID (required)
  name?: string;               // New scenario name (1-100 chars)
  active?: boolean;            // Set active/inactive status
  blueprint?: object;          // Updated scenario configuration
  scheduling?: {
    type: 'immediately' | 'interval' | 'cron';
    interval?: number;
    cron?: string;
  };
}
```

**Returns:**
```typescript
{
  scenario: Scenario;
  updates: object;             // Applied updates
  message: string;
  timestamp: string;
}
```

**Example:**
```bash
# Activate a scenario
mcp-client update-scenario --scenarioId "12345" --active true

# Update name and scheduling
mcp-client update-scenario \
  --scenarioId "12345" \
  --name "Updated Process" \
  --scheduling.type "interval" \
  --scheduling.interval 30
```

**Use Cases:**
- Scenario maintenance
- Configuration updates  
- Status management
- Schedule modifications

---

### `delete-scenario`

Delete a Make.com scenario with safety checks to prevent accidental deletion of active scenarios.

**Parameters:**
```typescript
{
  scenarioId: string;         // Scenario ID (required)
  force?: boolean;           // Force delete active scenario (default: false)
}
```

**Returns:**
```typescript
{
  scenarioId: string;
  message: string;
  force: boolean;
  timestamp: string;
}
```

**Example:**
```bash
# Safe delete (requires scenario to be inactive)
mcp-client delete-scenario --scenarioId "12345"

# Force delete active scenario
mcp-client delete-scenario --scenarioId "12345" --force true
```

**Safety Features:**
- Prevents deletion of active scenarios unless forced
- Confirms scenario exists before deletion
- Provides clear error messages for protection

**Use Cases:**
- Cleanup of unused scenarios
- Batch scenario removal
- Development environment cleanup
- Emergency scenario removal

---

### `clone-scenario`

Clone an existing Make.com scenario with a new name and optional team/folder placement.

**Parameters:**
```typescript
{
  scenarioId: string;         // Source scenario ID (required)
  name: string;              // Name for cloned scenario (1-100 chars, required)
  teamId?: string;           // Target team (defaults to source team)
  folderId?: string;         // Target folder
  active?: boolean;          // Activate cloned scenario (default: false)
}
```

**Returns:**
```typescript
{
  originalScenarioId: string;
  clonedScenario: Scenario;
  message: string;
  timestamp: string;
}
```

**Example:**
```bash
# Basic clone
mcp-client clone-scenario --scenarioId "12345" --name "Dev Copy"

# Clone to different team and activate
mcp-client clone-scenario \
  --scenarioId "12345" \
  --name "Production Copy" \
  --teamId "prod-team" \
  --active true
```

**Use Cases:**
- Development/testing environments
- Scenario templates
- Cross-team scenario sharing
- Backup scenario creation

---

### `run-scenario`

Execute a Make.com scenario with optional wait for completion and timeout handling.

**Parameters:**
```typescript
{
  scenarioId: string;         // Scenario ID (required)
  wait?: boolean;            // Wait for completion (default: true)
  timeout?: number;          // Timeout in seconds (1-300, default: 60)
}
```

**Returns:**
```typescript
{
  scenarioId: string;
  executionId: string;
  status: 'started' | 'success' | 'error';
  execution?: object;        // Full execution details if completed
  duration?: number;         // Execution time in ms
  message: string;
  timeout?: boolean;         // True if execution timed out
  timestamp: string;
}
```

**Example:**
```bash
# Run and wait for completion
mcp-client run-scenario --scenarioId "12345" --timeout 120

# Start scenario without waiting
mcp-client run-scenario --scenarioId "12345" --wait false
```

**Execution Monitoring:**
- Polls execution status every 2 seconds
- Reports progress during execution
- Returns detailed results on completion
- Handles timeout gracefully

**Use Cases:**
- Manual scenario execution
- Testing and debugging
- Automated workflow triggers
- Performance testing

## Error Handling

### Common Errors

**Invalid Scenario ID**
```json
{
  "error": {
    "code": "SCENARIO_NOT_FOUND",
    "message": "Scenario with ID '12345' not found",
    "scenarioId": "12345"
  }
}
```

**Permission Denied**
```json
{
  "error": {
    "code": "INSUFFICIENT_PERMISSIONS", 
    "message": "You don't have permission to modify this scenario",
    "requiredPermission": "scenario:write"
  }
}
```

**Active Scenario Protection**
```json
{
  "error": {
    "code": "SCENARIO_ACTIVE",
    "message": "Cannot delete active scenario. Set active=false first or use force=true",
    "scenarioId": "12345",
    "status": "active"
  }
}
```

### Validation Errors

- **name**: 1-100 characters required
- **scenarioId**: Must be valid scenario ID
- **limit**: 1-100 range enforced
- **timeout**: 1-300 seconds range enforced
- **scheduling.interval**: Must be positive number

## Rate Limiting

Scenario operations have the following rate limits:
- **Read operations**: 100/minute
- **Write operations**: 20/minute  
- **Run operations**: 10/minute

## Performance Tips

1. **Use pagination** for large scenario lists
2. **Filter by team/folder** to reduce response size
3. **Include blueprint only when needed** (large data)
4. **Use batch operations** for multiple scenarios
5. **Monitor execution timeout** for long-running scenarios

## Security Considerations

- Scenarios contain sensitive configuration data
- Blueprint data may include API keys and credentials
- Execution logs may contain business data
- Use appropriate team/organization scoping
- Audit scenario modifications

## Best Practices

### Naming Conventions
```bash
# Environment prefixes
"PROD: Customer Data Sync"
"DEV: Payment Processing"
"TEST: Email Campaign"

# Purpose-based naming
"Daily Sales Report"
"Real-time Inventory Update"
"Weekly Analytics Digest"
```

### Error Recovery
```bash
# Always check scenario exists before operations
mcp-client get-scenario --scenarioId "12345"

# Use force flag carefully for deletions
mcp-client delete-scenario --scenarioId "12345" --force true

# Monitor long executions with appropriate timeout
mcp-client run-scenario --scenarioId "12345" --timeout 180
```

### Bulk Operations
```bash
# List scenarios first
scenarios=$(mcp-client list-scenarios --teamId "dev-team" --active false)

# Then process each scenario
for scenario_id in $scenarios; do
  mcp-client delete-scenario --scenarioId "$scenario_id"
done
```