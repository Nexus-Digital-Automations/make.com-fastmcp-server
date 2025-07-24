# Interactive Examples & Demo Scenarios

This directory contains runnable examples and demo scenarios that showcase the full capabilities of the Make.com FastMCP server. All examples use realistic test data and can be easily adapted for your specific needs.

## 📁 Directory Structure

```
interactive/
├── README.md                    # This file
├── basic-operations/            # Basic CRUD operations
├── advanced-workflows/          # Complex automation workflows  
├── integration-patterns/        # Common integration scenarios
├── performance-monitoring/      # Analytics and monitoring examples
├── security-examples/          # Authentication and security demos
├── templates/                  # Reusable template projects
└── troubleshooting/            # Debugging and error handling
```

## 🚀 Quick Start

### Prerequisites

1. **FastMCP Server Running**: Ensure your Make.com FastMCP server is running locally
2. **API Credentials**: Have your Make.com API key configured in `.env`
3. **MCP Client**: Install the MCP CLI for testing: `npm install -g @modelcontextprotocol/cli`

### Running Examples

Each example directory contains:
- **README.md**: Detailed explanation and use cases
- **demo-data.json**: Sample data for testing
- **run-example.sh**: Executable script to run the demo
- **expected-output.json**: Expected results for validation

### Basic Test

```bash
# Test server connectivity
echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# Run your first interactive demo
cd basic-operations/scenario-management
./run-example.sh
```

## 📚 Available Example Categories

### 1. Basic Operations
- **Scenario Management**: Create, read, update, delete scenarios
- **Connection Management**: Set up and manage app connections
- **User Management**: Handle users, teams, and permissions
- **Template Operations**: Work with scenario templates

### 2. Advanced Workflows
- **Multi-Step Automation**: Complex scenario chains
- **Error Handling**: Robust error recovery patterns
- **Performance Optimization**: Efficient API usage
- **Batch Operations**: Handle multiple resources

### 3. Integration Patterns
- **E-commerce Automation**: Order processing, inventory sync
- **Marketing Automation**: Email campaigns, lead nurturing
- **Data Synchronization**: Cross-platform data sync
- **Webhook Processing**: Real-time event handling

### 4. Performance Monitoring
- **Analytics Dashboard**: Usage metrics and insights
- **Real-time Monitoring**: Live scenario performance
- **Audit Trails**: Security and compliance logging
- **Performance Optimization**: Identify bottlenecks

### 5. Security Examples
- **Authentication Setup**: Secure server configuration
- **Permission Management**: Role-based access control
- **API Security**: Rate limiting and validation
- **Credential Management**: Secure storage patterns

## 🎯 Interactive Features

### Live Demo Mode
Many examples support live demo mode where you can:
- **Step-by-step execution**: Walk through operations one at a time
- **Interactive prompts**: Customize parameters during execution
- **Real-time feedback**: See immediate results and explanations
- **Error simulation**: Test error handling scenarios

### Template Customization
Examples include template generators that:
- **Auto-configure**: Set up examples with your API credentials
- **Parameterize scenarios**: Easy customization for your use case
- **Generate variations**: Create multiple test scenarios
- **Export configurations**: Save setups for reuse

### Performance Benchmarking
Advanced examples include benchmarking tools to:
- **Measure API performance**: Track response times and throughput
- **Load testing**: Simulate concurrent operations
- **Resource utilization**: Monitor server performance
- **Optimization recommendations**: Get actionable insights

## 🛠️ Development Tools

### Example Generator
Create new examples using the built-in generator:

```bash
# Generate a new example
node tools/generate-example.js --type=integration --name="Custom API Sync"

# Generate from template
node tools/generate-example.js --from-template=e-commerce --customize
```

### Validation Tools
Validate and test examples:

```bash
# Validate all examples
npm run validate-examples

# Test specific example
npm run test-example -- --path=basic-operations/scenario-management

# Run benchmarks
npm run benchmark-examples
```

### Mock Data Generator
Generate realistic test data:

```bash
# Generate scenario data
node tools/generate-mock-data.js --type=scenarios --count=10

# Generate user data
node tools/generate-mock-data.js --type=users --organization=12345
```

## 📊 Example Categories Detail

### Basic Operations Examples
Perfect for learning the fundamentals:
- Simple API calls with clear explanations
- Step-by-step tutorials with expected outputs
- Common patterns and best practices
- Error handling demonstrations

### Advanced Workflow Examples
Showcase complex automation scenarios:
- Multi-service integrations
- Conditional logic and branching
- State management across operations
- Performance optimization techniques

### Integration Pattern Examples
Real-world business scenarios:
- Complete e-commerce automation workflow
- Marketing campaign automation
- Customer support ticket routing
- Data pipeline orchestration

### Performance Monitoring Examples
Operational excellence patterns:
- Real-time dashboard creation
- Alerting and notification setup
- Performance trend analysis
- Capacity planning tools

## 🎨 Customization Guide

### Adapting Examples
Every example can be customized by:

1. **Environment Configuration**: Update `.env` values
2. **Parameter Modification**: Edit `demo-data.json` files
3. **Workflow Customization**: Modify scenario blueprints
4. **Output Formatting**: Adjust result processing

### Creating Custom Examples
Follow the template structure:

```
my-custom-example/
├── README.md              # Description and setup
├── demo-data.json         # Test data
├── run-example.sh         # Execution script
├── expected-output.json   # Validation data
└── customization-guide.md # Adaptation instructions
```

## 🔧 Troubleshooting

### Common Issues

**Connection Errors**
```bash
# Check server status
curl http://localhost:3000/health

# Verify API configuration
echo '{"method": "tools/call", "params": {"name": "test-configuration"}}' | npx @modelcontextprotocol/cli chat
```

**Permission Errors**
```bash
# Check current user permissions
echo '{"method": "tools/call", "params": {"name": "get-current-user"}}' | npx @modelcontextprotocol/cli chat
```

**Rate Limiting**
```bash
# Check rate limiter status
echo '{"method": "tools/call", "params": {"name": "server-info"}}' | npx @modelcontextprotocol/cli chat
```

### Getting Help

- **Example Issues**: Check individual example README files
- **API Questions**: Refer to the main project documentation
- **Custom Scenarios**: Use the template generator for starting points
- **Performance Problems**: Run the built-in diagnostics

## 🤝 Contributing Examples

We welcome community contributions! To add new examples:

1. **Follow the Template**: Use the standard example structure
2. **Include Documentation**: Clear README with use cases
3. **Add Test Data**: Realistic sample data
4. **Provide Validation**: Expected outputs for testing
5. **Test Thoroughly**: Ensure examples work in clean environments

### Example Submission Checklist

- [ ] README with clear description and use case
- [ ] Runnable demo script with error handling
- [ ] Sample data that doesn't require real API keys
- [ ] Expected output for validation
- [ ] Customization instructions
- [ ] Compatible with current FastMCP server version

---

**Ready to explore?** Start with the `basic-operations` examples and work your way up to the advanced patterns. Each example is designed to teach specific concepts while providing practical, real-world value.