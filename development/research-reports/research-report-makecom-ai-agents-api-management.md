# Make.com AI Agents Management API Research Report

**Research Date:** August 25, 2025  
**Task ID:** task_1756141544458_i4q6d08k6  
**Focus:** Make.com AI agents management API capabilities for FastMCP TypeScript integration

## Executive Summary

Make.com launched AI Agents in April 2025, providing comprehensive API-driven AI agent management capabilities. The platform offers REST API endpoints for AI agent lifecycle management, context management, LLM provider integration, and sophisticated access control systems through their MCP (Model Context Protocol) server implementation.

## 1. AI Agent Endpoints

### 1.1 AI Agents Context API (Open Beta)

**Base URL:** `https://eu1.make.com/api/v2/ai-agents/v1/contexts`

#### List Context

- **Method:** GET
- **Endpoint:** `/api/v2/ai-agents/v1/contexts`
- **Required Parameters:**
  - `agentId` (UUID) - The ID of the AI agent
  - `teamId` (number) - The team identifier
- **Response:** 200 OK - List of contexts retrieved
- **Status:** Open beta (functionality and availability may change)

#### Create Context

- **Method:** POST
- **Endpoint:** `/api/v2/ai-agents/v1/contexts`
- **Content-Type:** multipart/form-data
- **Required Parameters:**
  - `teamId` (number) - The team identifier
- **Optional Parameters:**
  - `agentId` (UUID) - The AI agent identifier
  - `file` (file) - Optional file upload for context
- **Response:** 201 Created - Context created successfully
- **Status:** Open beta

#### Delete Context

- **Method:** DELETE
- **Endpoint:** `/api/v2/ai-agents/v1/contexts/{contextId}`
- **Required Parameters:**
  - `contextId` (UUID) - The context identifier
  - `teamId` (number) - The team identifier
- **Response:** 204 No Content - Context deleted successfully
- **Status:** Open beta

### 1.2 API Structure

The Make API follows REST API design principles with:

- Resource-oriented URLs
- Standard HTTP methods (GET, POST, DELETE, PUT, PATCH)
- JSON request/response format
- Comprehensive error handling with appropriate HTTP status codes

## 2. Agent Context Management

### 2.1 Context Capabilities

- **Context Storage:** File-based context storage with multipart/form-data uploads
- **Context Retrieval:** UUID-based context identification and retrieval
- **Context Lifecycle:** Full CRUD operations for context management
- **Team-Based Isolation:** Context is scoped to teams for access control

### 2.2 Context Implementation Details

- Contexts are identified by UUID for strong referencing
- Team-based scoping ensures proper access control
- File uploads supported for rich context data
- Beta status indicates active development and potential changes

## 3. LLM Provider Integration

### 3.1 Supported LLM Providers

#### OpenAI Integration

- **Default Model:** GPT-4.1 (balanced predictability and low latency)
- **Configuration:** Environment variable `OPENAI_DEFAULT_MODEL` for global defaults
- **Model Flexibility:** Support for all OpenAI-compatible models
- **Fallback Behavior:** Generic ModelSettings for non-GPT-5 models

#### Anthropic Claude Integration

- **API Access:** Requires API access request at anthropic.com/earlyaccess
- **Authentication:** Bearer token authentication with Claude API
- **Module Integration:** Dedicated Anthropic Claude modules in Make.com
- **Configuration:** Environment-based API key management

#### Multi-Provider Support via LiteLLM

- **Claude Models:** `litellm/anthropic/claude-3-5-sonnet-20240620`
- **Gemini Models:** `litellm/gemini/gemini-2.5-flash-preview-04-17`
- **Unified Interface:** Consistent API across different providers
- **Provider Switching:** Seamless switching between providers without code changes

### 3.2 Model Configuration Options

- **System Prompts:** Global system prompts with scenario-specific customization
- **Temperature Control:** Model temperature settings for response variability
- **Token Limits:** Max token configuration for response length control
- **Model Selection:** Runtime model selection based on task requirements

## 4. Agent Lifecycle Management

### 4.1 Agent Creation and Deployment

- **Goal-Driven Design:** Agents are goal-driven automations powered by LLMs
- **Tool Attachment:** Agents can be equipped with various tools from Make's ecosystem
- **Reusability:** Agents are reusable across multiple workflows
- **Team Sharing:** Agents are shared across all team members

### 4.2 Agent Management Operations

- **View Agents:** List existing agents available to the team
- **Create Agents:** Build new agents with custom configurations
- **Duplicate Agents:** Clone existing agents for similar use cases
- **Configure Agents:** Modify agent settings and parameters
- **Delete Agents:** Remove agents when no longer needed

### 4.3 Agent Execution Model

- **Non-Deterministic Tasks:** Agents handle complex, adaptive tasks
- **Real-Time Adaptation:** Agents adapt to changing conditions dynamically
- **Reasoning-Based Actions:** Agents make decisions based on LLM reasoning
- **Tool Selection:** Agents autonomously select appropriate tools for tasks

## 5. Agent Configuration

### 5.1 Core Configuration Options

- **LLM Selection:** Choose from multiple LLM providers and models
- **System Prompts:** Global and scenario-specific prompt configuration
- **Tool Integration:** Access to 2,500+ app integrations and 30,000+ actions
- **Response Settings:** Temperature, max tokens, and other model parameters

### 5.2 Advanced Configuration

- **Scenario Integration:** Agents work within Make's scenario framework
- **Conditional Logic:** Advanced workflow logic based on AI responses
- **Chain Operations:** Multiple AI services chained for complex operations
- **Custom Properties:** User-defined properties for agent customization

## 6. Agent Execution and Invocation

### 6.1 Execution Triggers

- **Task-Based Activation:** Agents receive tasks and act autonomously
- **Webhook Integration:** HTTP-based triggers for agent activation
- **Scenario Integration:** Agents work within existing Make scenarios
- **API-Driven Invocation:** Direct API calls to trigger agent execution

### 6.2 Execution Flow

1. **Task Reception:** Agent receives a goal or task description
2. **Tool Analysis:** Agent analyzes available tools and capabilities
3. **Decision Making:** LLM-powered reasoning for action selection
4. **Tool Execution:** Agent executes selected tools with appropriate parameters
5. **Result Processing:** Agent processes results and determines next actions
6. **Goal Achievement:** Agent continues until task completion or timeout

### 6.3 Integration with Workflows

- **Scenario Embedding:** Agents can be embedded within Make scenarios
- **Workflow Orchestration:** Agents coordinate multiple workflow steps
- **Data Flow Management:** Agents handle data transformation between steps
- **Error Recovery:** Agents can adapt to errors and retry operations

## 7. Agent Monitoring and Analytics

### 7.1 Built-in Monitoring Features

- **Analytics Dashboard:** Comprehensive insights into workflow utilization and performance
- **Scenario History:** Detailed logs of agent execution and decision-making
- **Tool Usage Tracking:** Monitor which tools are used and their outcomes
- **Performance Metrics:** Real-time performance data and bottleneck identification

### 7.2 Logging and Debugging

- **Execution Logs:** Detailed logs of agent reasoning and actions
- **Input/Output Tracking:** Complete record of data flow through agents
- **Error Reporting:** Comprehensive error logging with context
- **Decision Tracing:** Audit trail of agent decision-making processes

### 7.3 Team and Organization Oversight

- **Team Member Actions:** Logs of who makes changes and when
- **Make Grid (Beta):** Bird's-eye view of entire automation landscape
- **Operational Limits:** Team-based limits and controls
- **Usage Analytics:** Understanding of automation patterns and efficiency

## 8. Authentication and Permissions

### 8.1 API Authentication

- **Token-Based:** User authentication tokens with relevant scopes
- **Scope-Based Access:** Granular permissions through API scopes
- **Role-Based Control:** Different access levels based on user roles

### 8.2 Available API Scopes

#### Administration Scopes

- `admin:read` - Access to all administrative resources
- `admin:write` - Perform all administrative actions
- `apps:read/write` - Manage native app configurations
- `system:read/write` - Modify platform settings

#### Standard User Scopes

- **Analytics:** Read/write access to analytics data
- **Connections:** Manage API connections and credentials
- **Scenarios:** Control over automation scenarios
- **Teams:** Team management and member operations
- **Users:** User information and management
- **Custom Functions:** Create and manage custom code functions
- **Hooks:** Webhook management and configuration
- **Organizations:** Organization-level access and settings

### 8.3 AI Agent Specific Permissions

- **Team-Based Sharing:** Agents shared across team members
- **Cross-Organization Access:** MCP tokens can access multiple organizations
- **Granular Tool Access:** Restrict agent access to specific tools or scenarios

## 9. MCP Server Integration and Access Control

### 9.1 Model Context Protocol (MCP) Server

- **Cloud-Based Gateway:** Connects AI agents to Make scenarios through standardized protocol
- **No Infrastructure Management:** Eliminates need for API endpoint management
- **Standardized Protocol:** MCP standardizes AI discovery of API endpoints
- **Scenario Integration:** Converts Make scenarios into callable tools for AI agents

### 9.2 Tool Access Control Levels

#### Organization Level Access

- **URL Pattern:** `https://<MAKE_ZONE>/mcp/api/v1/u/<MCP_TOKEN>/sse?organizationId=<id>`
- **Scope:** AI can see all scenarios in any team within specified organization
- **Use Case:** Broad organizational access for enterprise AI agents

#### Team Level Access

- **URL Pattern:** `https://<MAKE_ZONE>/mcp/api/v1/u/<MCP_TOKEN>/sse?teamId=<id>`
- **Scope:** AI can see all scenarios within specific team
- **Use Case:** Team-specific AI agents with limited scope

#### Scenario Level Access

- **URL Pattern:** `https://<MAKE_ZONE>/mcp/api/v1/u/<MCP_TOKEN>/sse?scenarioId=<id>`
- **Scope:** AI can see only specified scenario
- **Use Case:** Highly restricted AI agents for specific tasks

### 9.3 Access Control Features

- **Multiple Values:** Array syntax for multiple scenario IDs: `?scenarioId[]=<id1>&scenarioId[]=<id2>`
- **Mutual Exclusivity:** Parameters cannot be combined (organization, team, scenario)
- **Default Behavior:** Without restrictions, MCP token grants access to all tools across all organizations
- **Security Model:** Token-based authentication with granular access controls

## 10. Implementation Guidance for FastMCP TypeScript Integration

### 10.1 API Client Architecture

```typescript
interface MakeAIAgentsClient {
  // Context Management
  listContexts(agentId: string, teamId: number): Promise<Context[]>;
  createContext(
    teamId: number,
    agentId?: string,
    file?: File,
  ): Promise<Context>;
  deleteContext(contextId: string, teamId: number): Promise<void>;

  // Agent Management
  listAgents(teamId: number): Promise<Agent[]>;
  createAgent(config: AgentConfig): Promise<Agent>;
  updateAgent(agentId: string, config: Partial<AgentConfig>): Promise<Agent>;
  deleteAgent(agentId: string): Promise<void>;

  // Execution
  executeAgent(
    agentId: string,
    task: string,
    context?: string,
  ): Promise<ExecutionResult>;
  getExecutionStatus(executionId: string): Promise<ExecutionStatus>;
  getExecutionLogs(executionId: string): Promise<ExecutionLog[]>;
}
```

### 10.2 Authentication Implementation

```typescript
interface AuthConfig {
  apiKey: string;
  baseUrl: string;
  scopes: string[];
  teamId?: number;
  organizationId?: number;
}

class MakeAuthenticator {
  constructor(private config: AuthConfig) {}

  async authenticate(): Promise<AuthToken> {
    // Implement OAuth or API key authentication
  }

  async refreshToken(): Promise<AuthToken> {
    // Handle token refresh for long-running agents
  }
}
```

### 10.3 MCP Server Integration

```typescript
interface MCPServerConfig {
  makeZone: string;
  mcpToken: string;
  accessLevel: "organization" | "team" | "scenario";
  resourceIds: string[];
}

class MCPServerClient {
  constructor(private config: MCPServerConfig) {}

  async connectToMCPServer(): Promise<MCPConnection> {
    const url = this.buildMCPUrl();
    return new EventSource(url);
  }

  private buildMCPUrl(): string {
    const { makeZone, mcpToken, accessLevel, resourceIds } = this.config;
    const baseUrl = `https://${makeZone}/mcp/api/v1/u/${mcpToken}/sse`;

    switch (accessLevel) {
      case "organization":
        return `${baseUrl}?organizationId=${resourceIds[0]}`;
      case "team":
        return `${baseUrl}?teamId=${resourceIds[0]}`;
      case "scenario":
        const scenarioParams = resourceIds
          .map((id) => `scenarioId[]=${id}`)
          .join("&");
        return `${baseUrl}?${scenarioParams}`;
    }
  }
}
```

### 10.4 Error Handling and Retry Logic

```typescript
interface APIError {
  status: number;
  code: string;
  message: string;
  details?: any;
}

class MakeAPIErrorHandler {
  static isRetryable(error: APIError): boolean {
    return [429, 502, 503, 504].includes(error.status);
  }

  static async handleWithRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number = 3,
    baseDelay: number = 1000,
  ): Promise<T> {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        if (attempt === maxRetries || !this.isRetryable(error as APIError)) {
          throw error;
        }
        await this.delay(baseDelay * Math.pow(2, attempt));
      }
    }
    throw new Error("Max retries exceeded");
  }

  private static delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
```

### 10.5 Data Models

```typescript
interface Context {
  id: string;
  agentId?: string;
  teamId: number;
  content?: string;
  fileUrl?: string;
  createdAt: Date;
  updatedAt: Date;
}

interface Agent {
  id: string;
  name: string;
  description: string;
  teamId: number;
  llmProvider: "openai" | "claude" | "custom";
  modelName: string;
  systemPrompt: string;
  temperature: number;
  maxTokens: number;
  tools: string[];
  createdAt: Date;
  updatedAt: Date;
}

interface AgentConfig {
  name: string;
  description: string;
  teamId: number;
  llmProvider: "openai" | "claude" | "custom";
  modelName: string;
  systemPrompt: string;
  temperature?: number;
  maxTokens?: number;
  tools?: string[];
}

interface ExecutionResult {
  id: string;
  agentId: string;
  task: string;
  status: "running" | "completed" | "failed";
  result?: any;
  error?: string;
  executionTime: number;
  tokensUsed: number;
  createdAt: Date;
  completedAt?: Date;
}
```

## 11. Key Findings and Recommendations

### 11.1 Strengths

- **Comprehensive API Coverage:** Full lifecycle management through REST APIs
- **Advanced Access Control:** Granular permissions through scopes and MCP server integration
- **Multi-LLM Support:** Flexible provider selection with unified interface
- **Enterprise Features:** Team management, analytics, and monitoring built-in
- **MCP Integration:** Standardized protocol for AI-scenario connectivity

### 11.2 Limitations

- **Beta Status:** Context API is in beta with potential changes
- **Documentation Gaps:** Some advanced features lack detailed documentation
- **Access Requirements:** Some providers (Claude) require special access requests
- **Mutual Exclusivity:** MCP access control parameters cannot be combined

### 11.3 FastMCP Integration Recommendations

1. **Implement Comprehensive Error Handling:** Given beta status of some APIs
2. **Use Scope-Based Authentication:** Implement least-privilege access patterns
3. **Build Flexible LLM Abstraction:** Support multiple providers with fallbacks
4. **Implement Robust Monitoring:** Leverage Make's analytics for agent performance
5. **Plan for API Evolution:** Build adaptable interfaces for beta API changes
6. **Use MCP Server for Security:** Leverage access control for production deployments

### 11.4 Next Steps for Implementation

1. **API Client Development:** Build TypeScript client with comprehensive error handling
2. **Authentication Layer:** Implement scope-based authentication with token management
3. **MCP Integration:** Build MCP server connectivity for secure scenario access
4. **Monitoring Integration:** Connect to Make's analytics for performance tracking
5. **Testing Framework:** Develop comprehensive testing with Make's sandbox environment

## Conclusion

Make.com provides a sophisticated AI agents management platform with comprehensive API coverage, flexible LLM integration, and enterprise-grade access controls. The MCP server integration offers a unique approach to connecting AI agents with automation scenarios securely. For FastMCP TypeScript integration, the platform provides sufficient API endpoints and features to build a robust AI agent management system, though careful attention to beta API stability and comprehensive error handling will be essential for production deployment.
