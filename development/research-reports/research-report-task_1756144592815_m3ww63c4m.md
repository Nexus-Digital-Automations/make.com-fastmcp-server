# Make.com Custom Functions (IML) and Templates API Research Report

**Task ID**: task_1756144592815_m3ww63c4m  
**Research Date**: 2025-08-25  
**Research Scope**: Comprehensive analysis of Make.com's IML custom functions and Templates API capabilities for FastMCP TypeScript integration

## Executive Summary

This research provides a comprehensive analysis of Make.com's Custom Functions (IML - Integromat Markup Language) and Templates API capabilities. Key findings include current limitations with IML custom functions due to security concerns, robust Templates API endpoints, and extensive webhook management capabilities suitable for FastMCP TypeScript integration.

## 1. Custom Functions (IML) Management API

### Current Status (2025)

- **⚠️ CRITICAL**: Custom IML functions are currently **DISABLED** for all customers and partners due to security vulnerabilities
- **Migration Process**: Make.com is gradually re-enabling custom IML functions through app migration to new technology
- **Access Requirements**: Enterprise/Team plan required, must contact Make support for enablement

### API Endpoints for Custom Functions

#### Core Function Management

```typescript
// Base URL: https://eu1.make.com/api/v2/functions
// Authentication: Bearer token required

interface CustomFunctionEndpoints {
  // List all custom functions for a team
  listFunctions: "GET /functions";

  // Create new custom function
  createFunction: "POST /functions";

  // Validate function code before creation
  evalFunction: "POST /functions/eval";

  // Get function details and usage
  getFunction: "GET /functions/{functionId}";

  // Update existing function
  updateFunction: "PATCH /functions/{functionId}";

  // Delete function
  deleteFunction: "DELETE /functions/{functionId}";

  // Get function update history
  getFunctionHistory: "GET /functions/{functionId}/history";
}
```

#### Request/Response Formats

**Create Function Request:**

```json
{
  "name": "functionName",
  "description": "Function description",
  "code": "function functionName(param) { return result; }"
}
```

**Function Validation Request:**

```json
{
  "code": "function checkType(arg) { return (typeof(arg)); }"
}
```

**Function Response:**

```json
{
  "id": "function_id",
  "name": "functionName",
  "description": "Function description",
  "code": "function code",
  "scenarios": ["scenario_ids"],
  "history": [
    {
      "version": "1.0",
      "author": "user_id",
      "timestamp": "2025-01-01T00:00:00Z",
      "changes": "Initial creation"
    }
  ]
}
```

### TypeScript Integration Patterns

```typescript
interface MakeCustomFunction {
  id: string;
  name: string;
  description: string;
  code: string;
  teamId: string;
  scenarios?: string[];
  createdAt: string;
  updatedAt: string;
}

class MakeCustomFunctionManager {
  private apiKey: string;
  private baseUrl: string = "https://eu1.make.com/api/v2";

  async createFunction(
    func: Partial<MakeCustomFunction>,
  ): Promise<MakeCustomFunction> {
    const response = await fetch(`${this.baseUrl}/functions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(func),
    });
    return response.json();
  }

  async validateFunction(
    code: string,
  ): Promise<{ valid: boolean; errors?: string[] }> {
    const response = await fetch(`${this.baseUrl}/functions/eval`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    return response.json();
  }
}
```

## 2. IML Language Capabilities

### Syntax Overview

- **Mustache-like markup**: Expressions written between `{{` and `}}`
- **JavaScript-like syntax**: Supports complex expressions and operations
- **Array indexing**: Uses 1-based indexing (unlike JavaScript's 0-based)
- **Special indices**: `-1` for last element, `[2]` for specific positions

### Core IML Features

#### Expression Syntax

```javascript
// Basic property access
{{body.data}}

// Array access (1-based indexing)
{{body.data[1].prop}}  // First element
{{body.data[-1].prop}} // Last element
{{body.data[2].prop}}  // Second element

// Conditional expressions
{{if(condition, trueValue, falseValue)}}
{{ifempty(value, defaultValue)}}

// Function calls within IML
{{iml.parseDate(dateString)}}
```

#### Custom Function Integration

```javascript
// Custom functions accessible via iml namespace
function customTransform(data) {
  return iml.parseDate(data.timestamp);
}

// Usage in IML expressions
{
  {
    customTransform(body.data);
  }
}
```

### Technical Limitations

- **Execution Timeout**: 10 seconds maximum
- **Output Limit**: 5000 characters maximum
- **JavaScript Subset**: Only built-in objects + Buffer available
- **No External Libraries**: Cannot import npm packages or external dependencies
- **ES6 Support**: Arrow functions, destructuring, and modern syntax supported

### Debugging Capabilities

#### Browser Debugging

```javascript
function debugExample(data) {
  debug("Processing data:", data);
  const result = processData(data);
  debug("Result:", result);
  return result;
}
```

#### VS Code Integration

- First-class JSON support with syntax highlighting
- Automatic validation and parameter type checking
- Predefined project structure for custom apps

## 3. Function Deployment and Execution

### Deployment Process

1. **Create Function**: Use API to create and validate function code
2. **Team Association**: Functions belong to specific teams
3. **Scenario Integration**: Functions can be used across team scenarios
4. **Version Control**: Automatic history tracking for all changes

### Execution Environment

- **Isolated Sandbox**: Functions run in secure, isolated environment
- **Built-in Functions Access**: All IML functions available via `iml` namespace
- **Performance Constraints**: 10-second timeout enforced
- **Memory Limits**: Output restricted to 5000 characters

### Integration with Scenarios

```typescript
interface ScenarioIntegration {
  // Functions can be called from any module within team scenarios
  usage: "IML expressions within modules";

  // Access pattern
  pattern: "{{customFunctionName(parameters)}}";

  // Error handling
  errorHandling: "Function errors break scenario execution";

  // Performance impact
  timeout: "10 seconds maximum per function call";
}
```

## 4. Function Libraries and Sharing

### Team-Based Organization

- **Team Scope**: Functions belong to specific teams
- **Access Control**: Team members can view/use, Team Admins can create/edit
- **Cross-Team Sharing**: Not directly supported, requires team management
- **Version History**: Complete change tracking with rollback capabilities

### Sharing Mechanisms

```typescript
interface FunctionSharing {
  teamLevel: {
    access: "All team members can view and use functions";
    permissions: "Team Admin role required for create/edit";
    visibility: "Functions visible across all team scenarios";
  };

  crossTeam: {
    support: "Limited - functions tied to specific teams";
    workaround: "Manual duplication across teams required";
  };

  publicSharing: {
    availability: "No public function library or marketplace";
    distribution: "Team-based only";
  };
}
```

### Library Organization Patterns

```typescript
interface FunctionLibraryStructure {
  categories: string[]; // User-defined via naming conventions
  naming: {
    recommended: "categoryName_functionName";
    examples: [
      "date_formatTimestamp",
      "string_cleanText",
      "math_calculatePercentage",
    ];
  };

  documentation: {
    required: "Function description field";
    best_practices: "Include parameter types and return value description";
  };
}
```

## 5. Template Management API

### Core Template Endpoints

```typescript
interface TemplateAPI {
  // List templates for team/organization
  listTemplates: "GET /templates";

  // Create new template
  createTemplate: "POST /templates";

  // Get template details
  getTemplate: "GET /templates/{templateId}";

  // Update template
  updateTemplate: "PATCH /templates/{templateId}";

  // Delete template
  deleteTemplate: "DELETE /templates/{templateId}";

  // Get template blueprint (scenario configuration)
  getBlueprint: "GET /templates/{templateId}/blueprint";

  // Publish template for sharing
  publishTemplate: "POST /templates/{templateId}/publish";

  // Request approval for public template
  requestApproval: "POST /templates/{templateId}/request-approval";
}
```

### Template Structure

```typescript
interface MakeTemplate {
  id: string;
  teamId: number;
  name: string;
  description: string;
  language: string; // 'en', 'es', 'fr', etc.
  blueprint: string; // JSON string containing scenario configuration
  scheduling: string; // JSON string with execution schedule
  isPublic: boolean;
  isApproved: boolean;
  publishedId?: string;
  approvedId?: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}
```

### Template Creation Example

```typescript
async function createTemplate(
  templateData: Partial<MakeTemplate>,
): Promise<MakeTemplate> {
  const response = await fetch(`${baseUrl}/templates`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      teamId: templateData.teamId,
      name: templateData.name,
      description: templateData.description,
      language: templateData.language || "en",
      blueprint: JSON.stringify(templateData.blueprint),
      scheduling: JSON.stringify({
        type: "indefinitely",
        interval: 900,
      }),
    }),
  });

  return response.json();
}
```

## 6. Template Publishing and Distribution

### Publishing Workflow

```typescript
interface TemplatePublishing {
  workflow: {
    1: "Create template";
    2: "Test template functionality";
    3: "Request approval via API";
    4: "Make.com review process";
    5: "Approval and public availability";
  };

  states: {
    private: "Team-only visibility";
    published: "Awaiting approval";
    approved: "Publicly available";
  };
}
```

### Distribution Mechanisms

#### Team Templates

```typescript
interface TeamTemplateSharing {
  scope: "Team members within organization";
  permissions: "Team Admin required for creation";
  access: "All team members can use templates";
  sharing: "Public links available for team templates";
}
```

#### Public Templates

```typescript
interface PublicTemplateSharing {
  marketplace: "Over 7,500 public templates available";
  categories: "Organized by use case and app integrations";
  approval: "Make.com review process required";
  distribution: "Available to all Make.com users globally";
}
```

## 7. Template Versioning

### Version Management

```typescript
interface TemplateVersioning {
  limitations: {
    editing: "Cannot edit published templates directly";
    workflow: "Must unpublish -> edit -> republish";
    rollback: "Limited rollback capabilities";
  };

  bestPractices: {
    backup: "Create duplicate templates before publishing";
    testing: "Thoroughly test before publishing";
    documentation: "Maintain version notes in description";
  };
}
```

### Version Control Implementation

```typescript
class TemplateVersionManager {
  async createVersion(
    templateId: string,
    changes: Partial<MakeTemplate>,
  ): Promise<MakeTemplate> {
    // Get current template
    const current = await this.getTemplate(templateId);

    // Create backup if published
    if (current.isPublic) {
      await this.createBackup(current);
      await this.unpublishTemplate(templateId);
    }

    // Update template
    const updated = await this.updateTemplate(templateId, changes);

    // Re-publish if needed
    if (current.isPublic) {
      await this.publishTemplate(templateId);
    }

    return updated;
  }

  private async createBackup(template: MakeTemplate): Promise<MakeTemplate> {
    const backup = {
      ...template,
      name: `${template.name} - Backup ${new Date().toISOString()}`,
      isPublic: false,
    };
    delete backup.id;
    return this.createTemplate(backup);
  }
}
```

## 8. Integration with Scenarios

### Scenario-Template Relationship

```typescript
interface ScenarioTemplateIntegration {
  creation: {
    fromTemplate: "POST /scenarios with templateId parameter";
    customization: "Templates provide base configuration";
    instantiation: "Creates new scenario from template blueprint";
  };

  blueprint: {
    format: "JSON string containing complete scenario configuration";
    components: ["modules", "routes", "filters", "variables", "connections"];
    customization: "Full editing capabilities after template instantiation";
  };
}
```

### Scenario Creation from Template

```typescript
async function createScenarioFromTemplate(
  templateId: string,
  teamId: number,
): Promise<Scenario> {
  const response = await fetch(`${baseUrl}/scenarios`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      teamId: teamId,
      templateId: templateId,
    }),
  });

  return response.json();
}
```

## 9. FastMCP TypeScript Integration Architecture

### Recommended Integration Pattern

```typescript
// FastMCP Server Integration for Make.com
import { FastMCP } from "@punkpeye/fastmcp";
import { MakeAPIClient } from "./make-api-client";

class MakeFastMCPServer extends FastMCP {
  private makeClient: MakeAPIClient;

  constructor(apiKey: string) {
    super();
    this.makeClient = new MakeAPIClient(apiKey);
    this.setupTools();
  }

  private setupTools() {
    // Custom Functions Management
    this.addTool(
      "create-custom-function",
      {
        description: "Create a new custom IML function in Make.com",
        schema: {
          type: "object",
          properties: {
            name: { type: "string" },
            description: { type: "string" },
            code: { type: "string" },
          },
        },
      },
      async (params) => {
        return this.makeClient.createCustomFunction(params);
      },
    );

    // Template Management
    this.addTool(
      "create-template",
      {
        description: "Create a new scenario template in Make.com",
        schema: {
          type: "object",
          properties: {
            name: { type: "string" },
            description: { type: "string" },
            blueprint: { type: "string" },
            teamId: { type: "number" },
          },
        },
      },
      async (params) => {
        return this.makeClient.createTemplate(params);
      },
    );

    // Webhook Management
    this.addTool(
      "create-webhook",
      {
        description: "Create and configure webhooks for Make.com scenarios",
        schema: {
          type: "object",
          properties: {
            name: { type: "string" },
            url: { type: "string" },
            method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE"] },
          },
        },
      },
      async (params) => {
        return this.makeClient.createWebhook(params);
      },
    );
  }
}
```

### API Client Implementation

```typescript
export class MakeAPIClient {
  private apiKey: string;
  private baseUrl: string = "https://eu1.make.com/api/v2";

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(
        `Make.com API Error: ${response.status} ${response.statusText}`,
      );
    }

    return response.json();
  }

  // Custom Functions
  async createCustomFunction(
    func: Partial<MakeCustomFunction>,
  ): Promise<MakeCustomFunction> {
    return this.request("/functions", {
      method: "POST",
      body: JSON.stringify(func),
    });
  }

  async validateFunction(
    code: string,
  ): Promise<{ valid: boolean; errors?: string[] }> {
    return this.request("/functions/eval", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  // Templates
  async createTemplate(template: Partial<MakeTemplate>): Promise<MakeTemplate> {
    return this.request("/templates", {
      method: "POST",
      body: JSON.stringify(template),
    });
  }

  async publishTemplate(templateId: string): Promise<void> {
    return this.request(`/templates/${templateId}/publish`, {
      method: "POST",
    });
  }

  // Scenarios
  async createScenario(scenarioData: any): Promise<any> {
    return this.request("/scenarios", {
      method: "POST",
      body: JSON.stringify(scenarioData),
    });
  }
}
```

## 10. Authentication and Security

### API Authentication

```typescript
interface MakeAuthentication {
  methods: {
    token: "Bearer token authentication";
    oauth2: "OAuth 2.0 with authorization code flow";
    pkce: "PKCE for public clients";
  };

  requirements: {
    account: "Paid Make.com account required";
    scopes: "Appropriate API scopes must be enabled";
    teams: "Team plan for advanced features";
  };
}
```

### Security Considerations

```typescript
interface SecurityConsiderations {
  customFunctions: {
    sandbox: "Functions run in isolated environment";
    timeout: "10-second execution limit";
    output: "5000 character limit";
    libraries: "No external library access";
  };

  api: {
    rateLimit: "Rate limiting enforced (specific limits not documented)";
    authentication: "Bearer token or OAuth 2.0 required";
    encryption: "HTTPS required for all requests";
  };

  webhooks: {
    payloadLimit: "5MB maximum payload size";
    logging: "3 days for standard, 30 days for enterprise";
    security: "Webhook signature verification recommended";
  };
}
```

## 11. Implementation Recommendations

### Development Priorities

1. **Phase 1**: Basic API client with authentication and error handling
2. **Phase 2**: Template management and scenario creation tools
3. **Phase 3**: Custom function management (when re-enabled)
4. **Phase 4**: Advanced webhook and workflow automation features

### FastMCP Tool Structure

```typescript
interface RecommendedMCPTools {
  // Core Management
  "make-list-templates": "List available templates";
  "make-create-template": "Create new scenario template";
  "make-publish-template": "Publish template for sharing";

  // Scenario Management
  "make-create-scenario": "Create scenario from template";
  "make-run-scenario": "Execute scenario";
  "make-get-execution-log": "Retrieve execution logs";

  // Function Management (when available)
  "make-create-function": "Create custom IML function";
  "make-validate-function": "Validate function code";
  "make-deploy-function": "Deploy function to team";

  // Webhook Management
  "make-create-webhook": "Setup webhook endpoints";
  "make-configure-webhook": "Configure webhook settings";
  "make-test-webhook": "Test webhook connectivity";
}
```

## Conclusion

Make.com provides a comprehensive API for template management and workflow automation, though custom IML functions are currently limited due to security concerns. The Templates API offers robust capabilities for creating, managing, and sharing automation scenarios. For FastMCP TypeScript integration, focus should be on template management and scenario automation tools while monitoring the re-enablement of custom IML functions.

The platform's webhook capabilities and extensive API coverage make it well-suited for integration with FastMCP servers, providing powerful workflow automation tools for AI agents and applications.

## References

- [Make.com Developer Hub](https://developers.make.com/)
- [Custom IML Functions Documentation](https://developers.make.com/custom-apps-documentation/app-structure/iml-functions)
- [Templates API Reference](https://developers.make.com/api-documentation/api-reference/templates)
- [Custom Functions API Reference](https://developers.make.com/api-documentation/api-reference/custom-functions)
- [Make.com API Documentation](https://developers.make.com/api-documentation)
