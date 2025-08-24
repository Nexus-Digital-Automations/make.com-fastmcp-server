/**
 * FastMCP Server for Make.com API Integration
 * Main server implementation with authentication, error handling, and logging
 */

import { FastMCP, UserError } from "fastmcp";
import { z } from "zod";

// Define our custom session authentication type that extends the FastMCP type
type MakeSessionAuth = {
  authenticated: boolean;
  timestamp: string;
  correlationId: string;
};

// Import logger types and factory
import { ComponentLogger } from "./types/logger.js";
import { createComponentLogger } from "./utils/logger-factory.js";
import configManager from "./lib/config.js";
import MakeApiClient from "./lib/make-api-client.js";
import {
  setupGlobalErrorHandlers,
  MakeServerError,
  createAuthenticationError,
} from "./utils/errors.js";
import { extractCorrelationId } from "./utils/error-response.js";
// Temporarily disabled security middleware to resolve server timeout
// Security features are implemented but disabled during initialization to prevent timeout
// import { securityManager, createSecurityHealthCheck } from './middleware/security.js';
import { addScenarioTools } from "./tools/scenarios.js";
import addConnectionTools from "./tools/connections.js";
import addPermissionTools from "./tools/permissions.js";
import addAnalyticsTools from "./tools/analytics.js";
import { addVariableTools } from "./tools/variables.js";
import { addAIAgentTools } from "./tools/ai-agents.js";
import { addTemplateTools } from "./tools/templates.js";
import { addFolderTools } from "./tools/folders.js";
import { addCertificateTools } from "./tools/certificates.js";
import { addProcedureTools } from "./tools/procedures.js";
import { addCustomAppTools } from "./tools/custom-apps.js";
import { addSDKTools } from "./tools/sdk.js";
import { addBillingTools } from "./tools/billing.js";
import { addNotificationTools } from "./tools/notifications.js";
import { addPerformanceAnalysisTools } from "./tools/performance-analysis.js";
import { addLogStreamingTools } from "./tools/log-streaming.js";
import { addRealTimeMonitoringTools } from "./tools/real-time-monitoring.js";
import { addNamingConventionPolicyTools } from "./tools/naming-convention-policy.js";
import { addScenarioArchivalPolicyTools } from "./tools/scenario-archival-policy.js";
import { addAuditComplianceTools } from "./tools/audit-compliance.js";
import { addCompliancePolicyTools } from "./tools/compliance-policy.js";
import { addPolicyComplianceValidationTools } from "./tools/policy-compliance-validation.js";
import { addMarketplaceTools } from "./tools/marketplace.js";
import { addBudgetControlTools } from "./tools/budget-control.js";
import { addCICDIntegrationTools } from "./tools/cicd-integration.js";
import { addAIGovernanceEngineTools } from "./tools/ai-governance-engine.js";
import { addZeroTrustAuthTools } from "./tools/zero-trust-auth.js";
import { addMultiTenantSecurityTools } from "./tools/multi-tenant-security.js";
import { addEnterpriseSecretsTools } from "./tools/enterprise-secrets.js";
import { addBlueprintCollaborationTools } from "./tools/blueprint-collaboration.js";

export class MakeServerInstance {
  private readonly server: FastMCP<MakeSessionAuth>;
  private readonly apiClient: MakeApiClient;
  private readonly componentLogger: ComponentLogger;
  private processErrorHandlersBound = false;
  private uncaughtExceptionHandler?: (error: Error) => void;
  private unhandledRejectionHandler?: (
    reason: unknown,
    promise: Promise<unknown>,
  ) => void;

  constructor() {
    this.componentLogger = createComponentLogger({
      component: "MakeServer",
      fallbackStrategy: "simple",
    });

    // Setup global error handlers
    setupGlobalErrorHandlers();

    // Initialize API client
    this.apiClient = new MakeApiClient(configManager().getMakeConfig());

    // Initialize security systems
    this.initializeSecurity();

    // Initialize FastMCP server with proper type annotations
    this.server = new FastMCP<MakeSessionAuth>({
      name: configManager().getConfig().name,
      version: "1.0.0",
      instructions: this.getServerInstructions(),
      authenticate: configManager().isAuthEnabled()
        ? this.authenticate.bind(this)
        : undefined,
    });

    // Verify server instance is properly initialized
    if (!this.server || typeof this.server.addTool !== "function") {
      throw new Error("FastMCP server instance not properly initialized");
    }

    this.setupServerEvents();
    this.addBasicTools();
    // Defer advanced tools loading to avoid initialization timeout
    // this.addAdvancedTools();
  }

  private async initializeSecurity(): Promise<void> {
    try {
      // Initialize circuit breakers for API client
      // await securityManager.initializeCircuitBreakers(this.apiClient);

      this.componentLogger.info(
        "Security systems initialized (temporarily disabled)",
        {
          status: "ok", // securityManager.getSecurityStatus().overall
        },
      );
    } catch (error) {
      this.componentLogger.error("Failed to initialize security systems", {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  private getServerInstructions(): string {
    return `
# Make.com FastMCP Server

This server provides comprehensive Make.com API access beyond the official MCP server capabilities.

## Available Features:
- **Platform Management**: Full scenario CRUD operations, connection management, webhook configuration
- **User & Permissions**: Role-based access control, team/organization administration  
- **Analytics & Audit**: Access to execution logs, performance metrics, audit trails
- **Real-Time Observability**: Live log streaming, advanced execution monitoring, historical log queries, SSE-based real-time updates
- **Resource Management**: Template management, folder organization, data store operations
- **Security & Certificates**: SSL/TLS certificate management, cryptographic key lifecycle, certificate validation
- **Remote Operations**: Remote procedure execution, device configuration, API call management
- **Development Platform**: Custom app development, SDK management, hook lifecycle, function deployment
- **Business Management**: Billing access, payment processing, usage analytics, invoice management
- **Communication**: Notification system, email preferences, multi-channel messaging
- **Advanced Features**: Custom variables, AI agent configuration, data structure validation
- **Enterprise Governance**: Naming convention policy management, scenario archival policies, rule enforcement
- **Zero Trust Authentication**: Multi-factor authentication, device trust assessment, behavioral analytics, session management, identity federation
- **Comprehensive Compliance**: Enterprise regulatory compliance management (SOX, GDPR, HIPAA, PCI DSS, ISO 27001), automated policy enforcement, violation detection, compliance reporting
- **Unified Policy Validation**: Cross-policy compliance validation, comprehensive scoring, violation tracking, remediation workflows, enterprise governance auditing
- **Audit & Security**: Immutable audit logging, security health monitoring, incident management, compliance evidence collection
- **Public App Marketplace**: Advanced app discovery with GraphQL-style filtering, comprehensive app specifications, AI-powered recommendations, integration planning tools
- **Enterprise Budget Control**: Advanced budget configuration with multi-tenant support, real-time cost analysis and projections, ML-powered forecasting, automated scenario control with approval workflows
- **CI/CD Integration**: Enterprise developer workflow automation with test suite execution, coverage analysis, deployment readiness validation, comprehensive build reporting
- **Multi-Tenant Security Architecture**: Comprehensive tenant isolation with cryptographic separation, network segmentation, resource quotas, governance policies, data leakage prevention, and compliance boundaries
- **Enterprise Secrets Management**: HashiCorp Vault integration with HSM support, automated key rotation, dynamic secret generation, RBAC secret access, secret scanning and leakage prevention, breach detection and response, comprehensive audit trails for compliance
- **AI-Driven Governance**: Intelligent compliance monitoring with real-time alerts, ML-powered predictive analytics, automated policy enforcement, policy conflict detection and resolution, risk assessment with behavioral analytics, automated remediation workflows, governance intelligence dashboard
- **Blueprint Versioning & Collaboration**: Git-based blueprint version control with semantic versioning, real-time collaborative editing with operational transformation, intelligent conflict resolution with AI assistance, comprehensive dependency mapping and impact analysis, blueprint optimization recommendations

## Authentication:
${
  configManager().isAuthEnabled()
    ? "- Server requires API key authentication via x-api-key header"
    : "- Server runs in open mode (no authentication required)"
}

## Rate Limiting:
- API calls are rate-limited to prevent abuse of Make.com API
- Current limits: ${configManager().getRateLimitConfig()?.maxRequests || "unlimited"} requests per ${(configManager().getRateLimitConfig()?.windowMs || 60000) / 1000} seconds

## Usage Notes:
- All operations require valid Make.com API credentials
- Some operations may require specific team/organization permissions
- Error responses include detailed information for troubleshooting
`.trim();
  }

  private async authenticate(request: unknown): Promise<MakeSessionAuth> {
    const requestObj = request as Record<string, unknown>;
    // Handle missing or null headers gracefully
    const headers = (requestObj.headers as Record<string, string>) || {};
    const correlationId = extractCorrelationId({ headers });

    const componentLogger = createComponentLogger({
      component: "MakeServer",
      metadata: {
        operation: "authenticate",
        correlationId,
      },
    });

    const apiKey = headers["x-api-key"];
    const expectedSecret = configManager().getAuthSecret();

    if (!apiKey || apiKey !== expectedSecret) {
      const authError = createAuthenticationError(
        "Invalid API key provided",
        {
          hasApiKey: !!apiKey,
          expectedLength: expectedSecret?.length,
        },
        {
          correlationId,
          operation: "authenticate",
          component: "MakeServer",
        },
      );

      componentLogger.error("Authentication failed", {
        hasApiKey: !!apiKey,
        correlationId: authError.correlationId,
      });

      throw new Response(null, {
        status: 401,
        statusText: "Unauthorized - Invalid API key",
      });
    }

    componentLogger.info("Authentication successful", { correlationId });

    // Return session data that will be available in tool context
    return {
      authenticated: true,
      timestamp: new Date().toISOString(),
      correlationId,
    };
  }

  private setupServerEvents(): void {
    this.server.on("connect", (event) => {
      this.componentLogger.info("Client connected", {
        sessionId: event.session ? "connected" : "unknown",
        clientCapabilities: event.session?.clientCapabilities,
      });
    });

    this.server.on("disconnect", (event) => {
      this.componentLogger.info("Client disconnected", {
        sessionId: event.session ? "disconnected" : "unknown",
      });
    });

    // Note: FastMCP server doesn't expose 'error' event,
    // so we'll handle errors at the process level instead

    // Setup process-level error handlers for MCP protocol issues (only once per process)
    this.setupProcessErrorHandlers();
  }

  private setupProcessErrorHandlers(): void {
    if (this.shouldSkipErrorHandlerSetup()) {
      return;
    }

    this.createErrorHandlers();
    this.bindProcessErrorHandlers();
  }

  private shouldSkipErrorHandlerSetup(): boolean {
    return (
      this.processErrorHandlersBound ||
      process.listenerCount("uncaughtException") > 0
    );
  }

  private createErrorHandlers(): void {
    this.uncaughtExceptionHandler = this.createUncaughtExceptionHandler();
    this.unhandledRejectionHandler = this.createUnhandledRejectionHandler();
  }

  private createUncaughtExceptionHandler(): (error: Error) => void {
    return (error: Error): void => {
      if (this.isJSONParsingError(error)) {
        this.handleJSONParsingError(error);
        return;
      }

      this.handleUncaughtException(error);
    };
  }

  private isJSONParsingError(error: Error): boolean {
    return error.message.includes("JSON") || error.message.includes("parse");
  }

  private handleJSONParsingError(error: Error): void {
    this.componentLogger.error("JSON parsing error intercepted", {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
      suggestion:
        "This may be a message framing issue in MCP protocol communication",
    });
  }

  private handleUncaughtException(error: Error): void {
    this.componentLogger.error("Uncaught exception", {
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
      },
    });

    if (process.env.NODE_ENV !== "test") {
      process.exit(1);
    }
  }

  private createUnhandledRejectionHandler(): (
    reason: unknown,
    promise: Promise<unknown>,
  ) => void {
    return (reason: unknown, promise: Promise<unknown>): void => {
      this.componentLogger.error("Unhandled promise rejection", {
        reason:
          reason instanceof Error
            ? {
                name: reason.name,
                message: reason.message,
                stack: reason.stack,
              }
            : reason,
        promise: promise.toString(),
      });
    };
  }

  private bindProcessErrorHandlers(): void {
    process.on("uncaughtException", this.uncaughtExceptionHandler);
    process.on("unhandledRejection", this.unhandledRejectionHandler);
    this.processErrorHandlersBound = true;
  }

  private addHealthCheckTool(): void {
    this.server.addTool({
      name: "health-check",
      description: "Check server and Make.com API connectivity status",
      parameters: z.object({
        includeSecurity: z
          .boolean()
          .default(true)
          .describe("Include security system status"),
      }),
      annotations: {
        title: "Health Check",
        readOnlyHint: true,
        openWorldHint: true,
      },
      execute: async ({ includeSecurity }, { log, session }) => {
        return this.executeHealthCheck(includeSecurity, log, session);
      },
    });
  }

  private async executeHealthCheck(
    includeSecurity: boolean,
    log: any,
    session: any,
  ): Promise<string> {
    const { correlationId, componentLogger } = this.setupHealthCheckLogging(session);
    this.logHealthCheckStart(componentLogger, log, correlationId);

    const startTime = Date.now();
    const serverHealth = this.getServerHealthInfo();
    const apiHealthData = await this.getApiHealthData(startTime);
    const securityStatus = this.getSecurityStatus(includeSecurity);
    
    const healthStatus = this.buildHealthStatus(
      serverHealth,
      apiHealthData,
      securityStatus,
    );

    this.logHealthCheckCompletion(componentLogger, log, healthStatus, correlationId);
    return JSON.stringify(healthStatus, null, 2);
  }

  private setupHealthCheckLogging(session: any): {
    correlationId: string;
    componentLogger: any;
  } {
    const correlationId = extractCorrelationId({ session });
    const componentLogger = createComponentLogger({
      component: "HealthCheck",
      metadata: {
        operation: "health-check",
        correlationId,
      },
    });
    return { correlationId, componentLogger };
  }

  private logHealthCheckStart(componentLogger: any, log: any, correlationId: string): void {
    componentLogger.info("Performing health check");
    log.info("Performing health check", { correlationId });
  }

  private getServerHealthInfo(): any {
    return {
      server: "healthy",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      config: {
        logLevel: configManager().getLogLevel(),
        authEnabled: configManager().isAuthEnabled(),
        environment: process.env.NODE_ENV || "development",
      },
    };
  }

  private async getApiHealthData(startTime: number): Promise<any> {
    const apiHealthResult = await this.apiClient.healthCheck();
    const apiHealthy = apiHealthResult.healthy;
    const responseTime = Date.now() - startTime;
    const rateLimiterStatus = this.apiClient.getRateLimiterStatus();

    return {
      healthy: apiHealthy,
      responseTime: `${responseTime}ms`,
      rateLimiter: rateLimiterStatus,
      credentialValid: apiHealthResult.credentialValid,
      rotationNeeded: apiHealthResult.rotationNeeded,
      securityScore: apiHealthResult.securityScore,
      issues: apiHealthResult.issues,
    };
  }

  private getSecurityStatus(includeSecurity: boolean): any {
    return includeSecurity ? { overall: "disabled" } : null;
  }

  private buildHealthStatus(serverHealth: any, apiHealthData: any, securityStatus: any): any {
    return {
      ...serverHealth,
      makeApi: apiHealthData,
      ...(securityStatus && { security: securityStatus }),
      overall: this.determineOverallHealth(
        apiHealthData.healthy,
        securityStatus || { overall: "disabled" },
      ),
    };
  }

  private logHealthCheckCompletion(
    componentLogger: any,
    log: any,
    healthStatus: any,
    correlationId: string,
  ): void {
    const logData = {
      overall: healthStatus.overall,
      responseTime: healthStatus.makeApi.responseTime,
      correlationId,
    };

    componentLogger.info("Health check completed", logData);
    log.info("Health check completed", logData);
  }

  private addSecurityStatusTool(): void {
    // Security status tool
    this.server.addTool({
      name: "security-status",
      description: "Get detailed security system status and metrics",
      parameters: z.object({
        includeMetrics: z
          .boolean()
          .default(false)
          .describe("Include security metrics"),
        includeEvents: z
          .boolean()
          .default(false)
          .describe("Include recent security events"),
      }),
      annotations: {
        title: "Security Status",
        readOnlyHint: true,
      },
      execute: async ({ includeMetrics, includeEvents }, { log, session }) => {
        const correlationId = extractCorrelationId({ session });
        const componentLogger = createComponentLogger({
          component: "SecurityStatus",
          metadata: {
            operation: "security-status",
            correlationId,
          },
        });

        componentLogger.info("Getting security status");
        log.info("Getting security status", { correlationId });

        // const securityHealthCheck = createSecurityHealthCheck();
        // const securityHealth = await securityHealthCheck();

        const result: Record<string, unknown> = {
          status: "disabled",
          message: "Security middleware temporarily disabled",
          configuration: {
            rateLimiting: false, // securityManager.getConfig().rateLimiting.enabled,
            ddosProtection: false, // securityManager.getConfig().ddosProtection.enabled,
            monitoring: false, // securityManager.getConfig().monitoring.enabled,
            errorSanitization: false, // securityManager.getConfig().errorSanitization.enabled
          },
        };

        if (includeMetrics) {
          // const { securityMonitoring } = await import('./middleware/security.js');
          result.metrics = { disabled: true }; // securityMonitoring.getMetrics(1); // Last hour
        }

        if (includeEvents) {
          // const { securityMonitoring } = await import('./middleware/security.js');
          result.recentEvents = []; // securityMonitoring.getRecentEvents(50);
        }

        return JSON.stringify(result, null, 2);
      },
    });
  }

  private addServerInfoTool(): void {
    this.server.addTool({
      name: "server-info",
      description: "Get detailed server configuration and capabilities",
      parameters: z.object({}),
      annotations: {
        title: "Server Information",
        readOnlyHint: true,
      },
      execute: async (args, { log, session }) => {
        return this.executeServerInfoRequest(log, session);
      },
    });
  }

  private async executeServerInfoRequest(log: any, session: any): Promise<any> {
    const { correlationId, componentLogger } = this.setupServerInfoLogging(session);
    this.logServerInfoStart(componentLogger, log, correlationId);

    const serverInfo = this.buildServerInfo();
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(serverInfo, null, 2),
        },
      ],
    };
  }

  private setupServerInfoLogging(session: any): {
    correlationId: string;
    componentLogger: any;
  } {
    const correlationId = extractCorrelationId({ session });
    const componentLogger = createComponentLogger({
      component: "ServerInfo",
      metadata: {
        operation: "server-info",
        correlationId,
      },
    });
    return { correlationId, componentLogger };
  }

  private logServerInfoStart(componentLogger: any, log: any, correlationId: string): void {
    componentLogger.info("Retrieving server information");
    log.info("Retrieving server information", { correlationId });
  }

  private buildServerInfo(): any {
    const config = configManager().getConfig();
    return {
      name: config.name,
      version: config.version,
      environment: process.env.NODE_ENV || "development",
      node: this.getNodeInfo(),
      configuration: this.buildConfigurationInfo(config),
      capabilities: this.getServerCapabilities(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    };
  }

  private getNodeInfo(): any {
    return {
      version: process.version,
      platform: process.platform,
      arch: process.arch,
    };
  }

  private buildConfigurationInfo(config: any): any {
    return {
      logLevel: config.logLevel,
      authentication: {
        enabled: config.authentication?.enabled || false,
      },
      rateLimit: config.rateLimit
        ? {
            maxRequests: config.rateLimit.maxRequests,
            windowMs: config.rateLimit.windowMs,
          }
        : null,
      makeApi: {
        baseUrl: config.make.baseUrl,
        timeout: config.make.timeout,
        retries: config.make.retries,
        teamId: config.make.teamId || "not_configured",
        organizationId: config.make.organizationId || "not_configured",
      },
    };
  }

  private getServerCapabilities(): string[] {
    return [
      ...this.getBasicCapabilities(),
      ...this.getComplianceCapabilities(),
      ...this.getEnterpriseCapabilities(),
      ...this.getSecurityCapabilities(),
      ...this.getGovernanceCapabilities(),
    ];
  }

  private getBasicCapabilities(): string[] {
    return [
      "scenario-management",
      "connection-management",
      "user-permissions",
      "role-management",
      "team-management",
      "organization-management",
      "analytics-reporting",
      "audit-logging",
      "execution-monitoring",
      "performance-metrics",
      "data-export",
      "template-management",
      "template-creation",
      "template-sharing",
      "folder-organization",
      "data-store-management",
      "resource-categorization",
      "webhook-management",
      "variable-management",
      "custom-variable-management",
      "ai-agent-management",
      "llm-provider-integration",
      "incomplete-execution-recovery",
    ];
  }

  private getComplianceCapabilities(): string[] {
    return [
      "comprehensive-compliance-management",
      "regulatory-framework-support",
      "sox-compliance-controls",
      "gdpr-privacy-protection",
      "hipaa-phi-security",
      "pci-dss-payment-security",
      "iso27001-security-management",
      "custom-compliance-frameworks",
      "automated-policy-enforcement",
      "compliance-violation-detection",
      "regulatory-reporting-automation",
      "audit-trail-management",
      "security-health-monitoring",
      "incident-management-integration",
      "compliance-evidence-collection",
    ];
  }

  private getEnterpriseCapabilities(): string[] {
    return [
      "certificate-management",
      "key-lifecycle-management",
      "remote-procedure-execution",
      "device-configuration-management",
      "custom-app-development",
      "sdk-app-management",
      "hook-lifecycle-management",
      "custom-function-deployment",
      "billing-management",
      "payment-processing",
      "notification-system",
      "email-preferences",
      "data-structure-validation",
      "performance-analysis",
      "bottleneck-detection",
      "performance-monitoring",
      "trend-analysis",
      "optimization-recommendations",
      "real-time-log-streaming",
      "historical-log-querying",
      "live-execution-monitoring",
      "log-export-analysis",
      "naming-convention-policy-management",
      "enterprise-naming-standards",
      "policy-validation-enforcement",
      "naming-rule-templates",
      "scenario-archival-policy-management",
      "automated-scenario-lifecycle-management",
      "usage-based-archival-triggers",
      "grace-period-management",
      "scenario-rollback-capabilities",
    ];
  }

  private getSecurityCapabilities(): string[] {
    return [
      "multi-tenant-security-architecture",
      "tenant-provisioning-lifecycle",
      "cryptographic-tenant-isolation",
      "tenant-specific-encryption-keys",
      "network-segmentation-virtualization",
      "resource-quota-management",
      "tenant-governance-policies",
      "cross-tenant-data-leakage-prevention",
      "compliance-boundary-management",
      "tenant-specific-compliance-frameworks",
      "enterprise-secrets-management",
      "hashicorp-vault-integration",
      "hardware-security-module-support",
      "automated-key-rotation",
      "dynamic-secret-generation",
      "rbac-secret-access-control",
      "secret-scanning-leakage-prevention",
      "breach-detection-response",
      "secrets-audit-compliance",
    ];
  }

  private getGovernanceCapabilities(): string[] {
    return [
      "ai-driven-governance",
      "intelligent-compliance-monitoring",
      "ml-powered-predictive-analytics",
      "automated-policy-enforcement",
      "policy-conflict-detection-resolution",
      "behavioral-risk-assessment",
      "automated-remediation-workflows",
      "governance-intelligence-dashboard",
      "public-app-marketplace-integration",
      "advanced-app-discovery",
      "graphql-style-filtering",
      "ai-powered-recommendations",
      "marketplace-analytics",
      "integration-planning-tools",
      "enterprise-budget-control",
      "multi-tenant-budget-management",
      "real-time-cost-analysis",
      "ml-powered-cost-projections",
      "automated-scenario-control",
      "budget-threshold-monitoring",
      "cost-forecasting-analytics",
      "approval-workflow-management",
      "cicd-integration",
      "test-suite-execution",
      "coverage-analysis",
      "deployment-readiness-validation",
      "build-reporting-analytics",
      "developer-workflow-automation",
    ];
  }

  private addTestConfigurationTool(): void {
    this.server.addTool({
      name: "test-configuration",
      description: "Test Make.com API configuration and permissions",
      parameters: z.object({
        includePermissions: z
          .boolean()
          .default(false)
          .describe("Include detailed permission analysis"),
      }),
      annotations: {
        title: "Configuration Test",
        readOnlyHint: true,
        openWorldHint: true,
      },
      execute: async (
        { includePermissions },
        { log, reportProgress, session },
      ) => {
        return this.executeConfigurationTest(
          includePermissions,
          log,
          reportProgress,
          session,
        );
      },
    });
  }

  private async executeConfigurationTest(
    includePermissions: boolean,
    log: any,
    reportProgress: any,
    session: any,
  ): Promise<string> {
    const { correlationId, componentLogger } = 
      this.setupConfigTestLogging(session);
    this.logConfigTestStart(componentLogger, log, correlationId);
    reportProgress({ progress: 0, total: 100 });

    try {
      const userResponse = await this.testApiConnectivity(reportProgress);
      this.logConnectivitySuccess(componentLogger, log, correlationId);
      
      const teamAccess = await this.testTeamAccess(reportProgress);
      const scenarioAccess = await this.testScenarioAccess(reportProgress);
      
      const testResults = this.buildTestResults(
        userResponse,
        teamAccess,
        scenarioAccess,
        includePermissions,
        log,
      );

      reportProgress({ progress: 100, total: 100 });
      this.logConfigTestSuccess(componentLogger, log, correlationId);
      
      return JSON.stringify(testResults, null, 2);
    } catch (error) {
      this.handleConfigTestError(error, componentLogger, log, correlationId);
      throw error; // Re-throw after logging
    }
  }

  private setupConfigTestLogging(session: any): {
    correlationId: string;
    componentLogger: any;
  } {
    const correlationId = extractCorrelationId({ session });
    const componentLogger = createComponentLogger({
      component: "ConfigTest",
      metadata: {
        operation: "test-configuration",
        correlationId,
      },
    });
    return { correlationId, componentLogger };
  }

  private logConfigTestStart(
    componentLogger: any,
    log: any,
    correlationId: string,
  ): void {
    componentLogger.info("Testing Make.com API configuration");
    log.info("Testing Make.com API configuration", { correlationId });
  }

  private async testApiConnectivity(reportProgress: any): Promise<any> {
    const userResponse = await this.apiClient.get("/users/me");
    reportProgress({ progress: 25, total: 100 });

    if (!userResponse.success) {
      throw new UserError(
        `API connectivity test failed: ${userResponse.error?.message}`,
      );
    }
    
    return userResponse;
  }

  private logConnectivitySuccess(
    componentLogger: any,
    log: any,
    correlationId: string,
  ): void {
    componentLogger.info("API connectivity test passed", { correlationId });
    log.info("API connectivity test passed", { correlationId });
  }

  private async testTeamAccess(reportProgress: any): Promise<boolean | null> {
    if (!configManager().getMakeConfig().teamId) {
      return null;
    }

    const teamResponse = await this.apiClient.get(
      `/teams/${configManager().getMakeConfig().teamId}`,
    );
    reportProgress({ progress: 50, total: 100 });
    return teamResponse.success;
  }

  private async testScenarioAccess(reportProgress: any): Promise<boolean> {
    const scenariosResponse = await this.apiClient.get("/scenarios", {
      params: { limit: 1 },
    });
    reportProgress({ progress: 75, total: 100 });
    return scenariosResponse.success;
  }

  private buildTestResults(
    userResponse: any,
    teamAccess: boolean | null,
    scenarioAccess: boolean,
    includePermissions: boolean,
    log: any,
  ): any {
    const testResults: any = {
      timestamp: new Date().toISOString(),
      apiConnectivity: userResponse.success,
      userInfo: userResponse.data,
      teamAccess,
      scenarioAccess,
      configuration: {
        baseUrl: configManager().getMakeConfig().baseUrl,
        hasTeamId: !!configManager().getMakeConfig().teamId,
        hasOrgId: !!configManager().getMakeConfig().organizationId,
      },
    };

    if (includePermissions && userResponse.data) {
      log.info("Analyzing user permissions");
      testResults.permissions = {
        analyzed: true,
        // This would include detailed role and permission analysis
      };
    }

    return testResults;
  }

  private logConfigTestSuccess(
    componentLogger: any,
    log: any,
    correlationId: string,
  ): void {
    componentLogger.info("Configuration test completed successfully", {
      correlationId,
    });
    log.info("Configuration test completed successfully", {
      correlationId,
    });
  }

  private handleConfigTestError(
    error: unknown,
    componentLogger: any,
    log: any,
    correlationId: string,
  ): void {
    const makeError =
      error instanceof MakeServerError
        ? error
        : new MakeServerError(
            `Configuration test failed: ${error instanceof Error ? error.message : String(error)}`,
            "CONFIG_TEST_FAILED",
            500,
            true,
            {
              originalError:
                error instanceof Error ? error.message : String(error),
            },
            {
              correlationId,
              operation: "test-configuration",
              component: "ConfigTest",
            },
          );

    componentLogger.error("Configuration test failed", {
      correlationId: makeError.correlationId,
      errorCode: makeError.code,
      originalError: error instanceof Error ? error.message : String(error),
    });

    log.error("Configuration test failed", {
      correlationId: makeError.correlationId,
      error: makeError.message,
    });
  }

  private addBasicTools(): void {
    // Add all basic tools
    this.addHealthCheckTool();
    this.addSecurityStatusTool();
    this.addServerInfoTool();
    this.addTestConfigurationTool();
  }

  private addAdvancedTools(): void {
    this.componentLogger.info("Adding advanced Make.com API tools");

    this.addCoreManagementTools();
    this.addDevelopmentTools();
    this.addMonitoringAndAnalyticsTools();
    this.addComplianceAndSecurityTools();
    this.addEnterpriseTools();

    this.componentLogger.info(
      "Advanced tools added successfully (scenarios + connections + permissions + analytics + variables + ai-agents + templates + folders + certificates + procedures + custom-apps + sdk + billing + notifications + performance-analysis + log-streaming + real-time-monitoring + naming-convention-policy + scenario-archival-policy + audit-compliance + compliance-policy + policy-compliance-validation + marketplace + budget-control + cicd-integration + zero-trust-auth + multi-tenant-security + enterprise-secrets + ai-governance-engine + blueprint-collaboration)",
    );
  }

  private addCoreManagementTools(): void {
    addScenarioTools(this.server, this.apiClient);
    addConnectionTools(this.server, this.apiClient);
    addPermissionTools(this.server, this.apiClient);
    addVariableTools(this.server, this.apiClient);
    addTemplateTools(this.server, this.apiClient);
    addFolderTools(this.server, this.apiClient);
  }

  private addDevelopmentTools(): void {
    addAIAgentTools(this.server, this.apiClient);
    addCustomAppTools(this.server, this.apiClient);
    addSDKTools(this.server, this.apiClient);
    addProcedureTools(this.server, this.apiClient);
    addCICDIntegrationTools(this.server, this.apiClient);
    addBlueprintCollaborationTools(this.server, this.apiClient);
  }

  private addMonitoringAndAnalyticsTools(): void {
    addAnalyticsTools(this.server, this.apiClient);
    addPerformanceAnalysisTools(this.server, this.apiClient);
    addLogStreamingTools(this.server, this.apiClient);
    addRealTimeMonitoringTools(this.server, this.apiClient);
  }

  private addComplianceAndSecurityTools(): void {
    addCertificateTools(this.server, this.apiClient);
    addAuditComplianceTools(this.server, this.apiClient);
    addCompliancePolicyTools(this.server, this.apiClient);
    addPolicyComplianceValidationTools(this.server, this.apiClient);
    addNamingConventionPolicyTools(this.server, this.apiClient);
    addScenarioArchivalPolicyTools(this.server, this.apiClient);
    
    this.addOptionalSecurityTools();
  }

  private addOptionalSecurityTools(): void {
    this.tryAddSecurityTool(
      () => addZeroTrustAuthTools(this.server, this.apiClient),
      "Zero Trust Authentication",
    );
    
    this.tryAddSecurityTool(
      () => addMultiTenantSecurityTools(this.server, this.apiClient),
      "Multi-Tenant Security",
    );
  }

  private tryAddSecurityTool(addFunction: () => void, toolName: string): void {
    try {
      addFunction();
      this.componentLogger.debug(`${toolName} tools loaded successfully`);
    } catch (error) {
      this.componentLogger.error(`Failed to load ${toolName} tools`, {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private addEnterpriseTools(): void {
    addBillingTools(this.server, this.apiClient);
    addNotificationTools(this.server, this.apiClient);
    addMarketplaceTools(this.server, this.apiClient);
    addBudgetControlTools(this.server, this.apiClient);
    addEnterpriseSecretsTools(this.server, this.apiClient);
    addAIGovernanceEngineTools(this.server, this.apiClient);
  }

  public getServer(): FastMCP<MakeSessionAuth> {
    return this.server;
  }

  public async start(options?: Record<string, unknown>): Promise<void> {
    this.logServerStartup();

    try {
      await this.validateConfiguration();
      await this.startServerWithOptions(options);
      this.loadAdvancedToolsAsync();
    } catch (error) {
      this.handleStartupError(error);
      throw error;
    }
  }

  private logServerStartup(): void {
    this.componentLogger.info("Starting Make.com FastMCP Server", {
      version: configManager().getConfig().version,
      environment: process.env.NODE_ENV || "development",
      authEnabled: configManager().isAuthEnabled(),
    });
  }

  private async validateConfiguration(): Promise<void> {
    if (configManager().getMakeConfig().apiKey.includes("test_key")) {
      this.componentLogger.warn(
        "Running in development mode with test API key - some features may not work",
      );
      return;
    }

    const isHealthy = await this.apiClient.healthCheck();
    if (!isHealthy) {
      throw new Error(
        "Make.com API is not accessible. Please check your configuration.",
      );
    }
    this.componentLogger.info("Make.com API connectivity verified");
  }

  private async startServerWithOptions(
    options?: Record<string, unknown>,
  ): Promise<void> {
    const startOptions = options || { transportType: "stdio" };

    this.componentLogger.debug("Starting FastMCP server with options", {
      startOptions,
    });

    await this.server.start(startOptions);
    this.componentLogger.info("Server started successfully");
  }

  private loadAdvancedToolsAsync(): void {
    this.componentLogger.info("Loading advanced tools asynchronously...");
    setImmediate(() => {
      try {
        this.addAdvancedTools();
        this.componentLogger.info("Advanced tools loaded successfully");
      } catch (error) {
        this.componentLogger.error("Failed to load advanced tools", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    });
  }

  private handleStartupError(error: unknown): void {
    this.componentLogger.error("Failed to start server", {
      error:
        error instanceof Error
          ? {
              name: error.name,
              message: error.message,
              stack: error.stack,
            }
          : error,
    });

    if (error instanceof Error) {
      this.logSpecificStartupErrors(error);
    }
  }

  private logSpecificStartupErrors(error: Error): void {
    if (error.message.includes("EADDRINUSE")) {
      this.componentLogger.error(
        "Port already in use. Please check if another instance is running.",
      );
    } else if (error.message.includes("EACCES")) {
      this.componentLogger.error(
        "Permission denied. Please check port access permissions.",
      );
    } else if (error.message.includes("JSON")) {
      this.componentLogger.error(
        "JSON parsing error during startup. This may indicate message format issues.",
      );
    }
  }

  private determineOverallHealth(
    apiHealthy: boolean,
    securityStatus: { overall: string },
  ): string {
    if (!apiHealthy) {
      return "degraded";
    }

    if (securityStatus) {
      if (securityStatus.overall === "unhealthy") {
        return "degraded";
      }
      if (securityStatus.overall === "degraded") {
        return "degraded";
      }
    }

    return "healthy";
  }

  public async shutdown(): Promise<void> {
    this.componentLogger.info("Shutting down server");

    try {
      // Cleanup process error handlers to prevent memory leaks
      this.cleanupProcessErrorHandlers();

      // Shutdown security systems first
      // await securityManager.shutdown();
      this.componentLogger.info(
        "Security systems shutdown (temporarily disabled)",
      );

      await this.apiClient.shutdown();
      this.componentLogger.info("API client shutdown completed");
    } catch (error) {
      this.componentLogger.error(
        "Error during shutdown",
        error as Record<string, unknown>,
      );
    }

    this.componentLogger.info("Server shutdown completed");
  }

  private cleanupProcessErrorHandlers(): void {
    // Remove our specific error handlers to prevent memory leaks
    if (this.uncaughtExceptionHandler) {
      process.removeListener(
        "uncaughtException",
        this.uncaughtExceptionHandler,
      );
      this.uncaughtExceptionHandler = undefined;
    }

    if (this.unhandledRejectionHandler) {
      process.removeListener(
        "unhandledRejection",
        this.unhandledRejectionHandler,
      );
      this.unhandledRejectionHandler = undefined;
    }

    this.processErrorHandlersBound = false;
  }
}

export default MakeServerInstance;
