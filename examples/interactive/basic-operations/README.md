# Basic Operations Examples

This directory contains fundamental examples that demonstrate core Make.com FastMCP server operations. These examples are perfect for learning the basics and getting started with the FastMCP tools.

## 📁 Directory Structure

```
basic-operations/
├── README.md                    # This file
├── scenario-management/         # Scenario CRUD operations
├── connection-management/       # Connection handling examples
├── user-management/            # User and team operations
├── template-operations/        # Template management
└── shared/                     # Shared utilities and data
```

## 🚀 Quick Start

All examples in this directory use the test data from `tests/fixtures/test-data.ts` to ensure consistent, realistic scenarios. Each example includes:

- **Step-by-step instructions** with clear explanations
- **Runnable scripts** that work with your local FastMCP server
- **Expected outputs** for validation
- **Common variations** and customization options
- **Error handling** demonstrations

### Prerequisites

1. **FastMCP Server Running**: Your Make.com FastMCP server should be running on `localhost:3000`
2. **Test Environment**: Configured with test API credentials
3. **MCP CLI**: `npm install -g @modelcontextprotocol/cli`

### Running Examples

```bash
# Navigate to any example directory
cd scenario-management

# Run the interactive demo
./run-example.sh

# Or run specific operations
./run-example.sh --operation create
./run-example.sh --operation list --limit 5
```

## 📚 Available Examples

### 1. Scenario Management (`scenario-management/`)
Learn the fundamentals of scenario operations:
- **Create**: Build new scenarios with blueprints and scheduling
- **Read**: List and filter scenarios with advanced search
- **Update**: Modify scenario properties and configurations
- **Delete**: Safely remove scenarios with validation
- **Clone**: Duplicate scenarios with customization
- **Execute**: Run scenarios and monitor execution

**Key Learning Points**:
- Scenario blueprint structure
- Scheduling configuration options
- Status management and lifecycle
- Team and folder organization
- Execution monitoring and troubleshooting

### 2. Connection Management (`connection-management/`)
Master connection handling for external services:
- **List Connections**: Filter and search app connections
- **Create Connections**: Set up new service integrations
- **Update Credentials**: Modify connection parameters securely
- **Test Connections**: Validate connection health
- **Webhook Management**: Configure and monitor webhooks

**Key Learning Points**:
- Service-specific credential handling
- Connection validation and testing
- Security best practices for credentials
- Webhook configuration and monitoring
- Error handling for connection failures

### 3. User Management (`user-management/`)
Understand user and team operations:
- **User Profiles**: Retrieve and update user information
- **Team Operations**: Manage team membership and permissions
- **Permission Management**: Handle role-based access control
- **Organization Settings**: Configure organization-level settings

**Key Learning Points**:
- User roles and permissions
- Team hierarchy and organization
- Permission management patterns
- Security and access control

### 4. Template Operations (`template-operations/`)
Work with scenario templates and blueprints:
- **Browse Templates**: Search and filter available templates
- **Create Templates**: Build reusable scenario blueprints
- **Customize Templates**: Adapt templates for specific needs
- **Template Validation**: Ensure template compatibility

**Key Learning Points**:
- Template structure and metadata
- Blueprint customization techniques
- Template sharing and distribution
- Version management for templates

## 🎯 Learning Path

For beginners, we recommend following this learning sequence:

### Phase 1: Foundation (Start Here)
1. **Scenario Management** - `scenario-management/basic-crud.js`
2. **Connection Management** - `connection-management/list-and-filter.js`
3. **User Management** - `user-management/get-current-user.js`

### Phase 2: Operations
1. **Scenario Execution** - `scenario-management/run-and-monitor.js`
2. **Connection Testing** - `connection-management/test-connections.js`
3. **Template Usage** - `template-operations/use-templates.js`

### Phase 3: Advanced Patterns
1. **Batch Operations** - `scenario-management/batch-operations.js`
2. **Error Handling** - `connection-management/error-recovery.js`
3. **Custom Templates** - `template-operations/create-templates.js`

## 🛠️ Example Structure

Each example follows a consistent structure:

```
example-name/
├── README.md              # Detailed explanation and use cases
├── demo-data.json         # Sample input data
├── run-example.sh         # Main execution script
├── run-example.js         # Node.js implementation
├── expected-output.json   # Validation data
├── variations/            # Alternative implementations
│   ├── with-error-handling.js
│   ├── with-pagination.js
│   └── batch-operations.js
└── customization-guide.md # How to adapt for your use case
```

## 📊 Interactive Features

### Live Demo Mode
Run examples with interactive prompts:

```bash
# Interactive scenario creation
./run-example.sh --interactive --operation create

# Step-by-step execution with explanations
./run-example.sh --step-by-step --explain
```

### Parameter Customization
Customize examples with your data:

```bash
# Use custom team ID
./run-example.sh --teamId "your-team-123"

# Custom search filters
./run-example.sh --operation list --search "production" --active true
```

### Output Formats
Choose your preferred output format:

```bash
# JSON output (default)
./run-example.sh --format json

# Table format for easy reading
./run-example.sh --format table

# Detailed format with explanations
./run-example.sh --format detailed
```

## 🔧 Troubleshooting

### Common Issues

**Connection Errors**
```bash
# Check server status
curl http://localhost:3000/health

# Verify MCP connection
echo '{"method": "tools/list"}' | npx @modelcontextprotocol/cli chat
```

**Authentication Problems**
```bash
# Test API configuration
./shared/test-auth.sh

# Check environment variables
./shared/check-config.sh
```

**Permission Issues**
```bash
# Verify user permissions
./user-management/check-permissions.sh

# Test with different user roles
./shared/switch-user.sh --role viewer
```

### Getting Help

- **Example-specific issues**: Check the README in each example directory
- **API errors**: Refer to `../troubleshooting/api-errors.md`
- **Configuration problems**: See `../troubleshooting/setup-issues.md`
- **Performance issues**: Check `../performance-monitoring/` examples

## 🎨 Customization

### Adapting Examples

1. **Environment Configuration**: Update `.env` files with your credentials
2. **Data Customization**: Modify `demo-data.json` files with your test data
3. **Parameter Adjustment**: Change default values in scripts
4. **Output Modification**: Customize result processing and formatting

### Creating Variations

Use the provided templates to create custom examples:

```bash
# Generate a new example
node ../shared/generate-example.js \
  --type basic \
  --name "custom-scenario-filter" \
  --operations "list,filter"

# Copy and customize existing example
cp -r scenario-management/basic-crud my-custom-crud
# Edit files to match your requirements
```

## 📈 Next Steps

After mastering these basic operations, continue to:

1. **Advanced Workflows** (`../advanced-workflows/`) - Complex automation patterns
2. **Integration Patterns** (`../integration-patterns/`) - Real-world business scenarios
3. **Performance Monitoring** (`../performance-monitoring/`) - Analytics and optimization
4. **Security Examples** (`../security-examples/`) - Authentication and permissions

## 🤝 Contributing

Found an issue or want to add a new example?

1. Follow the standard example structure
2. Include comprehensive documentation
3. Add validation data and error cases
4. Test with clean environment
5. Submit with clear use case description

---

**Ready to start?** Begin with `scenario-management/` to learn the fundamental operations that power the Make.com FastMCP server!