# Scenario Management Examples

This directory demonstrates comprehensive scenario management operations using the Make.com FastMCP server. Learn how to create, read, update, delete, clone, and execute scenarios with real-world examples.

## 📁 What You'll Learn

- **CRUD Operations**: Complete scenario lifecycle management
- **Blueprint Configuration**: Understanding scenario structure and flow
- **Scheduling Setup**: Configure when and how scenarios run
- **Execution Monitoring**: Track scenario performance and results
- **Error Handling**: Manage failures and troubleshoot issues
- **Best Practices**: Patterns for reliable scenario management

## 🚀 Quick Start

```bash
# Run the complete demo
./run-example.sh

# Test specific operations
./run-example.sh --operation list
./run-example.sh --operation create --name "My Test Scenario"
./run-example.sh --operation execute --scenarioId "scn_12345"
```

## 📚 Available Examples

### 1. Basic CRUD Operations (`basic-crud.js`)

**What it demonstrates**:
- List scenarios with filtering and pagination
- Create new scenarios with custom blueprints
- Update scenario properties and configuration
- Delete scenarios with safety checks

**Run the example**:
```bash
node basic-crud.js
# or
./run-example.sh --demo basic-crud
```

**Key learning points**:
- Understanding scenario data structure
- Using search and filter parameters
- Blueprint configuration basics
- Safe deletion practices

### 2. Advanced Filtering (`advanced-filtering.js`)

**What it demonstrates**:
- Complex search queries with multiple parameters
- Team and folder-based organization
- Status-based filtering (active/inactive)
- Pagination strategies for large datasets

**Run the example**:
```bash
node advanced-filtering.js
# or
./run-example.sh --demo advanced-filtering
```

**Input parameters**:
```json
{
  "teamId": "team123",
  "search": "data sync",
  "active": true,
  "limit": 20,
  "offset": 0
}
```

### 3. Scenario Execution (`run-and-monitor.js`)

**What it demonstrates**:
- Trigger scenario execution
- Monitor execution progress
- Handle execution timeouts
- Analyze execution results and performance

**Run the example**:
```bash
node run-and-monitor.js
# or
./run-example.sh --demo execution
```

**Features**:
- Real-time progress tracking
- Execution result analysis
- Error handling and recovery
- Performance metrics collection

### 4. Blueprint Management (`blueprint-operations.js`)

**What it demonstrates**:
- Understanding scenario blueprints
- Creating custom workflow configurations
- Modifying existing blueprints
- Blueprint validation and testing

**Run the example**:
```bash
node blueprint-operations.js
# or
./run-example.sh --demo blueprints
```

**Blueprint structure**:
```json
{
  "flow": [
    {
      "id": 1,
      "app": "webhook",
      "operation": "trigger",
      "parameters": {}
    },
    {
      "id": 2,
      "app": "email",
      "operation": "send",
      "parameters": {
        "to": "user@example.com",
        "subject": "Notification"
      }
    }
  ]
}
```

### 5. Scheduling Configuration (`scheduling-examples.js`)

**What it demonstrates**:
- Different scheduling types (immediate, interval, cron)
- Schedule validation and testing
- Updating scenario schedules
- Schedule optimization strategies

**Run the example**:
```bash
node scheduling-examples.js
# or
./run-example.sh --demo scheduling
```

**Scheduling options**:
```json
{
  "immediately": {
    "type": "immediately"
  },
  "interval": {
    "type": "interval",
    "interval": 900
  },
  "cron": {
    "type": "cron",
    "cron": "0 9 * * 1-5"
  }
}
```

### 6. Batch Operations (`batch-operations.js`)

**What it demonstrates**:
- Creating multiple scenarios efficiently
- Bulk status updates (activate/deactivate)
- Batch execution with monitoring
- Error handling for bulk operations

**Run the example**:
```bash
node batch-operations.js
# or
./run-example.sh --demo batch
```

## 📊 Interactive Demo Features

### Step-by-Step Mode
Walk through operations with detailed explanations:

```bash
./run-example.sh --step-by-step
```

This mode will:
1. Explain each operation before executing
2. Show expected inputs and outputs
3. Wait for confirmation between steps
4. Provide troubleshooting tips

### Custom Data Mode
Use your own test data:

```bash
./run-example.sh --custom-data ./my-scenarios.json
```

### Error Simulation Mode
Test error handling scenarios:

```bash
./run-example.sh --simulate-errors
```

## 🛠️ Customization Guide

### Using Your Own Data

1. **Create custom scenario data**:
```json
{
  "scenarios": [
    {
      "name": "My Custom Scenario",
      "blueprint": {
        "flow": [
          // Your custom flow here
        ]
      },
      "scheduling": {
        "type": "interval",
        "interval": 1800
      }
    }
  ]
}
```

2. **Update environment variables**:
```bash
export MAKE_TEAM_ID="your-team-id"
export MAKE_FOLDER_ID="your-folder-id"
```

3. **Run with custom parameters**:
```bash
./run-example.sh --teamId "$MAKE_TEAM_ID" --folderId "$MAKE_FOLDER_ID"
```

### Adapting for Different Use Cases

**E-commerce Integration**:
```bash
./run-example.sh --template e-commerce --name "Order Processing"
```

**Marketing Automation**:
```bash
./run-example.sh --template marketing --name "Email Campaign"
```

**Data Synchronization**:
```bash
./run-example.sh --template data-sync --name "Daily Sync Job"
```

## 🔍 Expected Outputs

### Successful Scenario Creation
```json
{
  "scenario": {
    "id": 2001,
    "name": "Test Scenario",
    "teamId": 12345,
    "isActive": false,
    "blueprint": {
      "flow": [
        {
          "id": 1,
          "app": "webhook",
          "operation": "trigger"
        }
      ]
    },
    "createdAt": "2024-01-15T10:00:00Z"
  },
  "message": "Scenario created successfully"
}
```

### Scenario List Response
```json
{
  "scenarios": [
    {
      "id": 2001,
      "name": "Active Test Scenario",
      "isActive": true,
      "lastExecution": "2024-01-15T09:30:00Z"
    }
  ],
  "pagination": {
    "total": 15,
    "limit": 10,
    "offset": 0,
    "hasMore": true
  }
}
```

### Execution Result
```json
{
  "scenarioId": 2001,
  "executionId": 5001,
  "status": "success",
  "duration": 2500,
  "operations": 5,
  "dataTransfer": 1024,
  "message": "Scenario execution completed successfully"
}
```

## 🚨 Error Handling Examples

### Common Error Scenarios

**Scenario Not Found**:
```json
{
  "error": {
    "message": "Scenario with ID scn_99999 not found",
    "code": "NOT_FOUND",
    "suggestions": [
      "Verify the scenario ID is correct",
      "Check if you have permission to access this scenario",
      "Ensure the scenario hasn't been deleted"
    ]
  }
}
```

**Permission Denied**:
```json
{
  "error": {
    "message": "Insufficient permissions to delete scenario",
    "code": "PERMISSION_DENIED",
    "requiredPermission": "scenario:delete",
    "userPermissions": ["scenario:read", "scenario:write"]
  }
}
```

**Validation Error**:
```json
{
  "error": {
    "message": "Invalid blueprint configuration",
    "code": "VALIDATION_ERROR",
    "details": {
      "blueprint.flow[0].app": "Required field missing",
      "blueprint.flow[1].operation": "Invalid operation type"
    }
  }
}
```

## 🧪 Testing Your Implementation

### Validation Tests
Run built-in validation tests:

```bash
# Test all operations
./run-example.sh --test

# Test specific operations
./run-example.sh --test --operation create,list,execute

# Test error scenarios
./run-example.sh --test --errors
```

### Performance Benchmarks
Measure operation performance:

```bash
# Benchmark scenario operations
./run-example.sh --benchmark

# Test with different data sizes
./run-example.sh --benchmark --scenarios 100,500,1000
```

## 📈 Performance Tips

### Optimizing Scenario Operations

1. **Use pagination** for large scenario lists
2. **Filter at the API level** rather than client-side
3. **Batch operations** when possible
4. **Cache frequently accessed scenarios**
5. **Monitor execution performance** and optimize blueprints

### Example Optimization
```javascript
// Instead of loading all scenarios and filtering
const allScenarios = await listScenarios({ limit: 1000 });
const activeScenarios = allScenarios.filter(s => s.isActive);

// Use server-side filtering
const activeScenarios = await listScenarios({ 
  active: true, 
  limit: 50 
});
```

## 🔗 Related Examples

- **Advanced Workflows** (`../../advanced-workflows/`) - Complex scenario patterns
- **Error Handling** (`../../troubleshooting/`) - Comprehensive error management
- **Performance Monitoring** (`../../performance-monitoring/`) - Scenario analytics
- **Integration Patterns** (`../../integration-patterns/`) - Real-world use cases

## 🤝 Next Steps

After mastering scenario management:

1. **Connection Management** - Learn to manage external service connections
2. **Template Operations** - Work with reusable scenario templates
3. **Advanced Workflows** - Build complex automation patterns
4. **Performance Monitoring** - Track and optimize scenario performance

---

**Ready to dive in?** Start with `basic-crud.js` to learn the fundamental scenario operations!