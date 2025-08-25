# Make.com Custom Apps Development and Management API Research Report

**Research Date:** August 25, 2025  
**Research Focus:** Comprehensive analysis of Make.com Custom Apps development and management API capabilities for FastMCP TypeScript integration

## Executive Summary

Make.com provides comprehensive custom app development capabilities through their Custom Apps framework, with support for JSON-based configuration, Visual Studio Code extension, and various API endpoints for managing custom applications. The platform emphasizes developer-friendly tools while maintaining some limitations in public API access for custom app management.

## 1. Custom App Creation and Management

### Development Approaches

Make.com supports two primary development methods:

1. **Web Interface**: Direct development through Make's web interface
2. **Visual Studio Code Extension**: Make Apps Editor extension with Git integration and local development capabilities

### Core Development Model

- **Configuration-Based**: Apps are defined using JSON configuration files
- **API Requirement**: Target service must have an API (only requirement)
- **Platform Generation**: Make automatically generates connections and modules from configuration
- **Immediate Testing**: Modules can be tested directly in scenarios

### Development Workflow

```json
{
  "development_process": {
    "step_1": "Write JSON configuration",
    "step_2": "Platform generates connections and modules",
    "step_3": "Test modules in scenarios",
    "step_4": "Deploy and share (if needed)"
  }
}
```

## 2. API Structure and Authentication

### Base API Structure

- **URL Format**: `{zone_url}/api/{api_version}/{api_endpoint}`
- **Example**: `https://eu1.make.com/api/v2/users/me`
- **Current Version**: v2
- **Geographic Zones**: eu1, eu2, us1, us2

### Authentication Methods

- **API Tokens**: Primary authentication method
- **OAuth 2.0**: Authorization code flow with refresh tokens
- **Client Types**: Confidential and public clients supported

### SDK Apps API Resources

Make.com provides specific API endpoints for SDK Apps management:

```
SDK Apps
├── SDK Apps > Invites
├── SDK Apps > Modules
├── SDK Apps > RPCs
├── SDK Apps > Functions
├── SDK Apps > Connections
└── SDK Apps > Webhooks
```

### API Scopes for Custom Apps

```json
{
  "read_scopes": [
    "Getting all custom apps for authenticated user",
    "Getting information from specific configuration sections",
    "Getting invitation details for an app"
  ],
  "write_scopes": [
    "Creating custom apps",
    "Managing configuration of custom apps",
    "Cloning custom apps",
    "Requesting review of custom apps",
    "Rolling back changes made in custom apps",
    "Uninstalling custom apps from organizations",
    "Deleting custom apps"
  ]
}
```

## 3. App Modules

### Module Types Supported

- **Action Modules**: Perform specific actions in external services
- **Search Modules**: Query and retrieve data from external services
- **Trigger Modules**: Polling-based triggers for data changes
- **Instant Trigger Modules**: Webhook-based real-time triggers
- **Universal Modules**: REST and GraphQL support
- **Responder Modules**: Generate responses for incoming requests
- **Webhook Modules**: Handle incoming webhook data

### Module Configuration

Modules support various configuration options:

- Parameter definitions
- Interface specifications
- Dynamic field generation
- Error handling
- Response formatting

## 4. App Connections

### Connection Types Supported

Make.com supports multiple authentication patterns:

```json
{
  "connection_types": {
    "basic_connection": "Username/password authentication",
    "jwt": "JSON Web Token authentication",
    "oauth_1.0": "OAuth 1.0 flow",
    "oauth_2.0": "OAuth 2.0 authorization code flow"
  }
}
```

### Connection Management

- Connections are automatically generated from JSON configuration
- Support for custom authorization headers
- Token refresh mechanisms for OAuth
- Secure credential storage

## 5. App Webhooks

### Webhook API Endpoints

```json
{
  "webhook_endpoints": {
    "list_hooks": "GET /hooks",
    "create_hook": "POST /hooks",
    "get_hook": "GET /hooks/{hookId}",
    "update_hook": "PATCH /hooks/{hookId}",
    "delete_hook": "DELETE /hooks/{hookId}",
    "ping_hook": "GET /hooks/{hookId}/ping",
    "learn_start": "POST /hooks/{hookId}/learn-start",
    "learn_stop": "POST /hooks/{hookId}/learn-stop",
    "enable_hook": "POST /hooks/{hookId}/enable",
    "disable_hook": "POST /hooks/{hookId}/disable",
    "set_hook_data": "POST /hooks/{hookId}/set-data"
  }
}
```

### Webhook Types

- **Gateway Webhook**: Standard HTTP webhooks
- **Gateway Mailhook**: Email-based webhooks

### Webhook Configuration

```json
{
  "webhook_config": {
    "name": "String (max 128 characters)",
    "teamId": "String",
    "typeName": "String",
    "method": "Boolean - method tracking",
    "header": "Boolean - header inclusion",
    "stringify": "Boolean - JSON stringify option"
  }
}
```

### Advanced Features

- Learning mode for automatic payload structure detection
- Enable/disable functionality
- Connection and form ID associations
- Scenario assignment capabilities

## 6. Remote Procedure Calls (RPCs)

### RPC Definition and Purpose

**Definition**: "The Remote Procedure Call, shortly RPC, is a function call, which executes a call to fetch additional data inside a module."

**Key Characteristics**:

- Cannot be directly selected or invoked by users
- Used for fetching additional data within modules
- Execute within module context only

### RPC Types

#### 1. Dynamic Options RPC

- **Purpose**: Populate dropdown lists and select fields dynamically
- **Use Case**: Loading options from external API based on user selection

#### 2. Dynamic Fields RPC

- **Purpose**: Generate dynamic fields inside a module
- **Usage**: Both parameters and interface generation
- **Implementation Example**:

```json
{
  "response": {
    "iterate": "{{body}}",
    "output": {
      "name": "{{item.key}}",
      "label": "{{item.label}}",
      "type": "text",
      "required": "{{item.isRequired == 1}}"
    }
  }
}
```

#### 3. Dynamic Sample RPC

- **Purpose**: Generate sample data for module testing and validation
- **Use Case**: Providing realistic test data during development

### RPC Limitations and Best Practices

```json
{
  "limits": {
    "max_execution_timeout": "40 seconds",
    "recommended_request_count": "3 calls per RPC",
    "recommended_record_count": "3 * number of objects per page"
  },
  "best_practices": [
    "Limit the number of requests",
    "Manage pagination efficiently",
    "Optimize data retrieval within timeout constraints",
    "Handle potential timeout scenarios"
  ]
}
```

### Field Type Conversion

RPCs often require converting external service field types to Make types:

```json
{
  "type_conversion": {
    "from_service": "string",
    "to_make": "text",
    "custom_iml_required": "For complex type mappings"
  }
}
```

## 7. App Publishing and Distribution

### Publishing Process

Make.com uses a direct sharing model rather than a traditional marketplace:

#### Publishing Options

1. **Private Apps**: Available only to creator by default
2. **Public Apps**: Shared via direct invitation links
3. **Approved Apps**: Reviewed by Make for wider distribution

#### Publishing Workflow

```json
{
  "publishing_steps": {
    "step_1": "Click 'Publish' button",
    "step_2": "Generate public link",
    "step_3": "Share invitation URL directly",
    "limitation": "No traditional marketplace discovery"
  }
}
```

### Distribution Limitations

- **No Public Marketplace**: Make doesn't operate a traditional app marketplace
- **Direct Sharing Only**: Distribution through invitation URLs
- **No Unpublishing**: Once published, apps cannot be unpublished (but can be modified)

## 8. App Versioning and Updates

### Version Management Models

#### Private/Public Apps

- **Immediate Updates**: Changes take immediate effect in running scenarios
- **No Review Required**: Direct deployment to users
- **Real-time Impact**: Active scenarios immediately use updated configuration

#### Approved Apps

- **Review Process**: Changes visible only to developer until approved
- **Contact Required**: Must contact Make to release changes
- **Safe Testing**: Developers can safely test new functions before release

### Update Process

```json
{
  "update_workflow": {
    "private_apps": {
      "development": "Make changes",
      "deployment": "Immediate effect",
      "user_impact": "Instant"
    },
    "approved_apps": {
      "development": "Make and test changes",
      "review": "Contact Make for approval",
      "deployment": "After approval",
      "user_impact": "After review cycle"
    }
  }
}
```

### Rollback Capabilities

- **Limited Documentation**: Rollback capabilities not explicitly detailed
- **Manual Process**: Developers likely need to manually revert changes
- **No Automated Rollback**: No apparent automated rollback mechanisms

## 9. Developer Training and Resources

### Custom Apps Development Training

- **Format**: Online course with video content
- **Duration**: 4.5 hours across 39 lessons
- **Access**: Available at `partnertraining.make.com/courses/custom-apps-development-training`
- **Prerequisites**: Recommended completion of Make Levels 1-4
- **Cost**: Free

### Development Tools

#### Visual Studio Code Extension

- **Name**: Make Apps Editor
- **Features**:
  - Git integration support
  - Local development capabilities
  - JSON configuration editing
  - Direct sync with Make platform
  - Beta local development features

#### Web Interface

- **Direct editing** through Make's web interface
- **Immediate testing** in scenario builder
- **Configuration management** through GUI

### Recent Updates (2024-2025)

- **AI Assistant**: Generate HTTP modules using AI assistance
- **Local Development**: Beta local development features in VS Code extension
- **Enhanced Collaboration**: Improved Git integration and version control

## 10. FastMCP Integration Recommendations

### TypeScript Implementation Strategy

#### 1. API Client Structure

```typescript
interface MakeCustomAppClient {
  // Core app management
  createApp(config: AppConfig): Promise<App>;
  updateApp(appId: string, config: Partial<AppConfig>): Promise<App>;
  getApp(appId: string): Promise<App>;
  deleteApp(appId: string): Promise<void>;

  // Module management
  createModule(appId: string, module: ModuleConfig): Promise<Module>;
  updateModule(
    appId: string,
    moduleId: string,
    config: Partial<ModuleConfig>,
  ): Promise<Module>;

  // Connection management
  createConnection(
    appId: string,
    connection: ConnectionConfig,
  ): Promise<Connection>;

  // Webhook management
  createWebhook(config: WebhookConfig): Promise<Webhook>;
  updateWebhook(
    hookId: string,
    config: Partial<WebhookConfig>,
  ): Promise<Webhook>;

  // RPC management
  createRPC(appId: string, rpc: RPCConfig): Promise<RPC>;
}
```

#### 2. Configuration Types

```typescript
interface AppConfig {
  name: string;
  description?: string;
  modules: ModuleConfig[];
  connections: ConnectionConfig[];
  rpcs?: RPCConfig[];
}

interface ModuleConfig {
  name: string;
  type: "action" | "search" | "trigger" | "instant" | "universal" | "responder";
  parameters: ParameterConfig[];
  interface?: InterfaceConfig[];
}

interface RPCConfig {
  name: string;
  type: "dynamic-options" | "dynamic-fields" | "dynamic-sample";
  endpoint: string;
  method: "GET" | "POST";
  parameters?: ParameterConfig[];
}
```

#### 3. Rate Limiting Considerations

- **RPC Timeout**: 40-second maximum execution time
- **Request Limits**: Recommended 3 calls per RPC
- **Record Limits**: 3 \* objects per page

#### 4. Authentication Implementation

```typescript
interface MakeAuthConfig {
  apiToken?: string;
  oauth2?: {
    clientId: string;
    clientSecret: string;
    refreshToken: string;
  };
  zone: "eu1" | "eu2" | "us1" | "us2";
}
```

### Implementation Priorities

#### Phase 1: Core API Integration

1. Basic app CRUD operations
2. Authentication setup
3. Error handling and rate limiting

#### Phase 2: Module Management

1. Module creation and configuration
2. Parameter and interface handling
3. Testing integration

#### Phase 3: Advanced Features

1. RPC implementation (Dynamic Options, Fields, Sample)
2. Webhook management
3. Connection handling

#### Phase 4: Publishing and Versioning

1. App publishing workflows
2. Version management
3. Update mechanisms

## 11. Current Limitations and Considerations

### API Limitations

- **Limited Public API**: Some custom app management operations may not be fully exposed via public API
- **Review Process**: Approved apps require Make's manual review for updates
- **No Marketplace**: Direct sharing only, no discovery mechanism

### Development Constraints

- **JSON Configuration**: All app logic must be expressed in JSON format
- **40-Second RPC Timeout**: Strict execution time limits for RPCs
- **Platform Dependency**: Heavy reliance on Make's platform for app execution

### Integration Challenges

- **Documentation Gaps**: Some API endpoints may not be fully documented
- **Version Control**: Limited version control features for app configurations
- **Testing Environment**: Limited local testing capabilities

## Conclusion

Make.com provides a robust foundation for custom app development with comprehensive support for modules, connections, webhooks, and RPCs. The platform's emphasis on JSON configuration and automatic generation makes it developer-friendly, while the VS Code extension and training resources provide excellent development support.

For FastMCP integration, the focus should be on:

1. Implementing core app management API calls
2. Supporting the various module types and configurations
3. Handling RPC implementations for dynamic content
4. Managing webhook configurations effectively
5. Providing proper authentication and rate limiting

The platform's limitations around public API access and marketplace distribution should be considered when designing the FastMCP integration, focusing on private/organizational use cases and direct sharing mechanisms.

---

**Note**: This research is based on publicly available documentation as of August 2025. Some API endpoints and features may require direct contact with Make.com or may not be publicly documented. Consider reaching out to Make.com's developer support for the most current and complete API specifications.
