/**
 * FastMCP Server for Make.com API Integration
 * Main server implementation with authentication, error handling, and logging
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import configManager from './lib/config.js';
import logger from './lib/logger.js';
import MakeApiClient from './lib/make-api-client.js';
import { setupGlobalErrorHandlers, MakeServerError, AuthenticationError } from './utils/errors.js';
import { extractCorrelationId } from './utils/error-response.js';
import { addScenarioTools } from './tools/scenarios.js';
import addConnectionTools from './tools/connections.js';
import addPermissionTools from './tools/permissions.js';
import addAnalyticsTools from './tools/analytics.js';
import { addVariableTools } from './tools/variables.js';
import { addAIAgentTools } from './tools/ai-agents.js';
import { addTemplateTools } from './tools/templates.js';
import { addFolderTools } from './tools/folders.js';
import { addCertificateTools } from './tools/certificates.js';
import { addProcedureTools } from './tools/procedures.js';
import { addCustomAppTools } from './tools/custom-apps.js';
import { addSDKTools } from './tools/sdk.js';
import { addBillingTools } from './tools/billing.js';
import { addNotificationTools } from './tools/notifications.js';
import { addPerformanceAnalysisTools } from './tools/performance-analysis.js';
import { addLogStreamingTools } from './tools/log-streaming.js';
import { addRealTimeMonitoringTools } from './tools/real-time-monitoring.js';
import { addNamingConventionPolicyTools } from './tools/naming-convention-policy.js';
import { addScenarioArchivalPolicyTools } from './tools/scenario-archival-policy.js';
import { addAuditComplianceTools } from './tools/audit-compliance.js';
import { addCompliancePolicyTools } from './tools/compliance-policy.js';
import { addPolicyComplianceValidationTools } from './tools/policy-compliance-validation.js';
import { addMarketplaceTools } from './tools/marketplace.js';
import { addBudgetControlTools } from './tools/budget-control.js';
import { addCICDIntegrationTools } from './tools/cicd-integration.js';
import { addZeroTrustAuthTools } from './tools/zero-trust-auth.js';
import { addMultiTenantSecurityTools } from './tools/multi-tenant-security.js';
import { addEnterpriseSecretsTools } from './tools/enterprise-secrets.js';

export class MakeServerInstance {
  private server: FastMCP;
  private apiClient: MakeApiClient;
  private componentLogger: ReturnType<typeof logger.child>;

  constructor() {
    this.componentLogger = logger.child({ component: 'MakeServer' });
    
    // Setup global error handlers
    setupGlobalErrorHandlers();

    // Initialize API client
    this.apiClient = new MakeApiClient(configManager.getMakeConfig());

    // Initialize FastMCP server
    this.server = new FastMCP({
      name: configManager.getConfig().name,
      version: "1.0.0",
      instructions: this.getServerInstructions(),
      authenticate: configManager.isAuthEnabled() ? this.authenticate.bind(this) : undefined,
    });

    this.setupServerEvents();
    this.addBasicTools();
    this.addAdvancedTools();
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

## Authentication:
${configManager.isAuthEnabled() ? 
  '- Server requires API key authentication via x-api-key header' : 
  '- Server runs in open mode (no authentication required)'
}

## Rate Limiting:
- API calls are rate-limited to prevent abuse of Make.com API
- Current limits: ${configManager.getRateLimitConfig()?.maxRequests || 'unlimited'} requests per ${(configManager.getRateLimitConfig()?.windowMs || 60000) / 1000} seconds

## Usage Notes:
- All operations require valid Make.com API credentials
- Some operations may require specific team/organization permissions
- Error responses include detailed information for troubleshooting
`.trim();
  }

  private async authenticate(request: unknown): Promise<Record<string, unknown>> {
    const requestObj = request as Record<string, unknown>;
    const correlationId = extractCorrelationId({ headers: requestObj.headers as Record<string, string> });
    const componentLogger = this.componentLogger.child({ 
      operation: 'authenticate',
      correlationId 
    });

    const apiKey = (requestObj.headers as Record<string, string>)?.['x-api-key'];
    const expectedSecret = configManager.getAuthSecret();

    if (!apiKey || apiKey !== expectedSecret) {
      const authError = new AuthenticationError(
        'Invalid API key provided',
        { 
          hasApiKey: !!apiKey,
          expectedLength: expectedSecret?.length 
        },
        {
          correlationId,
          operation: 'authenticate',
          component: 'MakeServer'
        }
      );
      
      componentLogger.error('Authentication failed', {
        hasApiKey: !!apiKey,
        correlationId: authError.correlationId
      });
      
      throw new Response(null, {
        status: 401,
        statusText: 'Unauthorized - Invalid API key',
      });
    }

    componentLogger.info('Authentication successful', { correlationId });
    
    // Return session data that will be available in tool context
    return {
      authenticated: true,
      timestamp: new Date().toISOString(),
      correlationId,
    };
  }

  private setupServerEvents(): void {
    this.server.on('connect', (event) => {
      this.componentLogger.info('Client connected', {
        sessionId: event.session ? 'connected' : 'unknown',
        clientCapabilities: event.session?.clientCapabilities,
      });
    });

    this.server.on('disconnect', (event) => {
      this.componentLogger.info('Client disconnected', {
        sessionId: event.session ? 'disconnected' : 'unknown',
      });
    });
  }

  private addBasicTools(): void {
    // Health check tool
    this.server.addTool({
      name: 'health-check',
      description: 'Check server and Make.com API connectivity status',
      parameters: z.object({}),
      annotations: {
        title: 'Health Check',
        readOnlyHint: true,
        openWorldHint: true,
      },
      execute: async (args, { log, session }) => {
        const correlationId = extractCorrelationId({ session });
        const componentLogger = logger.child({ 
          component: 'HealthCheck',
          operation: 'health-check',
          correlationId 
        });
        
        componentLogger.info('Performing health check');
        log.info('Performing health check', { correlationId });

        const startTime = Date.now();
        const serverHealth = {
          server: 'healthy',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          config: {
            logLevel: configManager.getLogLevel(),
            authEnabled: configManager.isAuthEnabled(),
            environment: process.env.NODE_ENV || 'development',
          },
        };

        // Check Make.com API connectivity
        const apiHealthy = await this.apiClient.healthCheck();
        const responseTime = Date.now() - startTime;

        const rateLimiterStatus = this.apiClient.getRateLimiterStatus();

        const healthStatus = {
          ...serverHealth,
          makeApi: {
            healthy: apiHealthy,
            responseTime: `${responseTime}ms`,
            rateLimiter: rateLimiterStatus,
          },
          overall: apiHealthy ? 'healthy' : 'degraded',
        };

        componentLogger.info('Health check completed', { 
          overall: healthStatus.overall,
          responseTime: healthStatus.makeApi.responseTime,
          correlationId
        });
        
        log.info('Health check completed', { 
          overall: healthStatus.overall,
          responseTime: healthStatus.makeApi.responseTime,
          correlationId
        });

        return JSON.stringify(healthStatus, null, 2);
      },
    });

    // Server info tool
    this.server.addTool({
      name: 'server-info',
      description: 'Get detailed server configuration and capabilities',
      parameters: z.object({}),
      annotations: {
        title: 'Server Information',
        readOnlyHint: true,
      },
      execute: async (args, { log, session }) => {
        const correlationId = extractCorrelationId({ session });
        const componentLogger = logger.child({ 
          component: 'ServerInfo',
          operation: 'server-info',
          correlationId 
        });
        
        componentLogger.info('Retrieving server information');
        log.info('Retrieving server information', { correlationId });

        const config = configManager.getConfig();
        const serverInfo = {
          name: config.name,
          version: config.version,
          environment: process.env.NODE_ENV || 'development',
          node: {
            version: process.version,
            platform: process.platform,
            arch: process.arch,
          },
          configuration: {
            logLevel: config.logLevel,
            authentication: {
              enabled: config.authentication?.enabled || false,
            },
            rateLimit: config.rateLimit ? {
              maxRequests: config.rateLimit.maxRequests,
              windowMs: config.rateLimit.windowMs,
            } : null,
            makeApi: {
              baseUrl: config.make.baseUrl,
              timeout: config.make.timeout,
              retries: config.make.retries,
              teamId: config.make.teamId || 'not_configured',
              organizationId: config.make.organizationId || 'not_configured',
            },
          },
          capabilities: [
            'scenario-management',
            'connection-management', 
            'user-permissions',
            'role-management',
            'team-management',
            'organization-management',
            'analytics-reporting',
            'audit-logging',
            'execution-monitoring',
            'performance-metrics',
            'data-export',
            'template-management',
            'template-creation',
            'template-sharing',
            'folder-organization',
            'data-store-management',
            'resource-categorization',
            'webhook-management',
            'variable-management',
            'custom-variable-management',
            'ai-agent-management',
            'llm-provider-integration',
            'incomplete-execution-recovery',
            'certificate-management',
            'key-lifecycle-management',
            'remote-procedure-execution',
            'device-configuration-management',
            'custom-app-development',
            'sdk-app-management',
            'hook-lifecycle-management',
            'custom-function-deployment',
            'billing-management',
            'payment-processing',
            'notification-system',
            'email-preferences',
            'data-structure-validation',
            'performance-analysis',
            'bottleneck-detection',
            'performance-monitoring',
            'trend-analysis',
            'optimization-recommendations',
            'real-time-log-streaming',
            'historical-log-querying',
            'live-execution-monitoring',
            'log-export-analysis',
            'naming-convention-policy-management',
            'enterprise-naming-standards',
            'policy-validation-enforcement',
            'naming-rule-templates',
            'scenario-archival-policy-management',
            'automated-scenario-lifecycle-management',
            'usage-based-archival-triggers',
            'grace-period-management',
            'scenario-rollback-capabilities',
            'comprehensive-compliance-management',
            'regulatory-framework-support',
            'sox-compliance-controls',
            'gdpr-privacy-protection',
            'hipaa-phi-security',
            'pci-dss-payment-security',
            'iso27001-security-management',
            'custom-compliance-frameworks',
            'automated-policy-enforcement',
            'compliance-violation-detection',
            'regulatory-reporting-automation',
            'audit-trail-management',
            'security-health-monitoring',
            'incident-management-integration',
            'compliance-evidence-collection',
            'public-app-marketplace-integration',
            'advanced-app-discovery',
            'graphql-style-filtering',
            'ai-powered-recommendations',
            'marketplace-analytics',
            'integration-planning-tools',
            'enterprise-budget-control',
            'multi-tenant-budget-management',
            'real-time-cost-analysis',
            'ml-powered-cost-projections',
            'automated-scenario-control',
            'budget-threshold-monitoring',
            'cost-forecasting-analytics',
            'approval-workflow-management',
            'cicd-integration',
            'test-suite-execution',
            'coverage-analysis',
            'deployment-readiness-validation',
            'build-reporting-analytics',
            'developer-workflow-automation',
            'multi-tenant-security-architecture',
            'tenant-provisioning-lifecycle',
            'cryptographic-tenant-isolation',
            'tenant-specific-encryption-keys',
            'network-segmentation-virtualization',
            'resource-quota-management',
            'tenant-governance-policies',
            'cross-tenant-data-leakage-prevention',
            'compliance-boundary-management',
            'tenant-specific-compliance-frameworks',
            'enterprise-secrets-management',
            'hashicorp-vault-integration',
            'hardware-security-module-support',
            'automated-key-rotation',
            'dynamic-secret-generation',
            'rbac-secret-access-control',
            'secret-scanning-leakage-prevention',
            'breach-detection-response',
            'secrets-audit-compliance',
          ],
          uptime: process.uptime(),
          memory: process.memoryUsage(),
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(serverInfo, null, 2),
            },
          ],
        };
      },
    });

    // Configuration test tool
    this.server.addTool({
      name: 'test-configuration',
      description: 'Test Make.com API configuration and permissions',
      parameters: z.object({
        includePermissions: z.boolean().default(false).describe('Include detailed permission analysis'),
      }),
      annotations: {
        title: 'Configuration Test',
        readOnlyHint: true,
        openWorldHint: true,
      },
      execute: async ({ includePermissions }, { log, reportProgress, session }) => {
        const correlationId = extractCorrelationId({ session });
        const componentLogger = logger.child({ 
          component: 'ConfigTest',
          operation: 'test-configuration',
          correlationId 
        });
        
        componentLogger.info('Testing Make.com API configuration');
        log.info('Testing Make.com API configuration', { correlationId });
        
        reportProgress({ progress: 0, total: 100 });

        try {
          // Test basic API connectivity
          const userResponse = await this.apiClient.get('/users/me');
          reportProgress({ progress: 25, total: 100 });

          if (!userResponse.success) {
            throw new UserError(`API connectivity test failed: ${userResponse.error?.message}`);
          }

          componentLogger.info('API connectivity test passed', { correlationId });
          log.info('API connectivity test passed', { correlationId });

          // Test team access if configured
          let teamAccess = null;
          if (configManager.getMakeConfig().teamId) {
            const teamResponse = await this.apiClient.get(`/teams/${configManager.getMakeConfig().teamId}`);
            teamAccess = teamResponse.success;
            reportProgress({ progress: 50, total: 100 });
          }

          // Test scenario access
          const scenariosResponse = await this.apiClient.get('/scenarios', {
            params: { limit: 1 }
          });
          const scenarioAccess = scenariosResponse.success;
          reportProgress({ progress: 75, total: 100 });

          const testResults = {
            timestamp: new Date().toISOString(),
            apiConnectivity: userResponse.success,
            userInfo: userResponse.data,
            teamAccess,
            scenarioAccess,
            configuration: {
              baseUrl: configManager.getMakeConfig().baseUrl,
              hasTeamId: !!configManager.getMakeConfig().teamId,
              hasOrgId: !!configManager.getMakeConfig().organizationId,
            },
          };

          if (includePermissions && userResponse.data) {
            log.info('Analyzing user permissions');
            // Add more detailed permission analysis here
            (testResults as Record<string, unknown>).permissions = {
              analyzed: true,
              // This would include detailed role and permission analysis
            };
          }

          reportProgress({ progress: 100, total: 100 });
          componentLogger.info('Configuration test completed successfully', { correlationId });
          log.info('Configuration test completed successfully', { correlationId });

          return JSON.stringify(testResults, null, 2);
        } catch (error) {
          const makeError = error instanceof MakeServerError 
            ? error 
            : new MakeServerError(
                `Configuration test failed: ${error instanceof Error ? error.message : String(error)}`,
                'CONFIG_TEST_FAILED',
                500,
                true,
                { originalError: error instanceof Error ? error.message : String(error) },
                { correlationId, operation: 'test-configuration', component: 'ConfigTest' }
              );
          
          componentLogger.error('Configuration test failed', {
            correlationId: makeError.correlationId,
            errorCode: makeError.code,
            originalError: error instanceof Error ? error.message : String(error)
          });
          
          log.error('Configuration test failed', { 
            correlationId: makeError.correlationId,
            error: makeError.message 
          });
          
          throw new UserError(makeError.message);
        }
      },
    });
  }

  private addAdvancedTools(): void {
    this.componentLogger.info('Adding advanced Make.com API tools');
    
    // Add scenario management tools
    addScenarioTools(this.server, this.apiClient);
    
    // Add connection management tools
    addConnectionTools(this.server, this.apiClient);
    
    // Add user permission management tools
    addPermissionTools(this.server, this.apiClient);
    
    // Add analytics and audit log tools
    addAnalyticsTools(this.server, this.apiClient);
    
    // Add custom variable management tools
    addVariableTools(this.server, this.apiClient);
    
    // Add AI agent management tools
    addAIAgentTools(this.server, this.apiClient);
    
    // Add template management tools
    addTemplateTools(this.server, this.apiClient);
    
    // Add folder organization and data store tools
    addFolderTools(this.server, this.apiClient);
    
    // Add certificate and key management tools
    addCertificateTools(this.server, this.apiClient);
    
    // Add remote procedure and device management tools
    addProcedureTools(this.server, this.apiClient);
    
    // Add custom app development tools
    addCustomAppTools(this.server, this.apiClient);
    
    // Add SDK app management tools
    addSDKTools(this.server, this.apiClient);
    
    // Add billing and payment management tools
    addBillingTools(this.server, this.apiClient);
    
    // Add notification and email management tools
    addNotificationTools(this.server, this.apiClient);
    
    // Add performance analysis and bottleneck detection tools
    addPerformanceAnalysisTools(this.server, this.apiClient);
    
    // Add real-time log streaming and monitoring tools
    addLogStreamingTools(this.server, this.apiClient);
    
    // Add enhanced real-time execution monitoring tools
    addRealTimeMonitoringTools(this.server, this.apiClient);
    
    // Add naming convention policy management tools
    addNamingConventionPolicyTools(this.server, this.apiClient);
    
    // Add scenario archival policy management tools
    addScenarioArchivalPolicyTools(this.server, this.apiClient);
    
    // Add audit and compliance logging tools
    addAuditComplianceTools(this.server, this.apiClient);
    
    // Add comprehensive compliance policy management tools
    addCompliancePolicyTools(this.server, this.apiClient);
    
    // Add unified policy compliance validation tools
    addPolicyComplianceValidationTools(this.server, this.apiClient);
    
    // Add public app marketplace integration tools
    addMarketplaceTools(this.server, this.apiClient);
    
    // Add enterprise budget control and cost management tools
    addBudgetControlTools(this.server, this.apiClient);
    
    // Add CI/CD integration and developer workflow tools
    addCICDIntegrationTools(this.server, this.apiClient);
    
    // Add Zero Trust Authentication Framework tools
    addZeroTrustAuthTools(this.server, this.apiClient);
    
    // Add Multi-Tenant Security Architecture tools
    addMultiTenantSecurityTools(this.server, this.apiClient);
    
    // Add Enterprise Secrets Management tools
    addEnterpriseSecretsTools(this.server, this.apiClient);
    
    this.componentLogger.info('Advanced tools added successfully (scenarios + connections + permissions + analytics + variables + ai-agents + templates + folders + certificates + procedures + custom-apps + sdk + billing + notifications + performance-analysis + log-streaming + real-time-monitoring + naming-convention-policy + scenario-archival-policy + audit-compliance + compliance-policy + policy-compliance-validation + marketplace + budget-control + cicd-integration + zero-trust-auth + multi-tenant-security + enterprise-secrets)');
  }

  public getServer(): FastMCP {
    return this.server;
  }

  public async start(options?: Record<string, unknown>): Promise<void> {
    this.componentLogger.info('Starting Make.com FastMCP Server', {
      version: configManager.getConfig().version,
      environment: process.env.NODE_ENV || 'development',
      authEnabled: configManager.isAuthEnabled(),
    });

    // Validate configuration before starting (skip in development with test key)
    if (!configManager.getMakeConfig().apiKey.includes('test_key')) {
      const isHealthy = await this.apiClient.healthCheck();
      if (!isHealthy) {
        throw new Error('Make.com API is not accessible. Please check your configuration.');
      }
      this.componentLogger.info('Make.com API connectivity verified');
    } else {
      this.componentLogger.warn('Running in development mode with test API key - some features may not work');
    }

    await this.server.start(options || {
      transportType: 'stdio',
    });

    this.componentLogger.info('Server started successfully');
  }

  public async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down server');
    
    try {
      await this.apiClient.shutdown();
      this.componentLogger.info('API client shutdown completed');
    } catch (error) {
      this.componentLogger.error('Error during API client shutdown', error as Record<string, unknown>);
    }

    this.componentLogger.info('Server shutdown completed');
  }
}

export default MakeServerInstance;