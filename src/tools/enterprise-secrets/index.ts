/**
 * @fileoverview Enterprise Secrets Management Tools - Modular Entry Point
 * 
 * This is the main export file for the refactored enterprise secrets module.
 * It provides comprehensive enterprise-grade secrets management functionality through
 * a modular architecture with dependency injection.
 * 
 * Key Features:
 * - HashiCorp Vault server provisioning and configuration
 * - Hardware Security Module (HSM) integration (PKCS#11, Azure Key Vault, AWS CloudHSM)
 * - Automated key rotation with scheduled and event-driven policies
 * - Dynamic secret generation for databases, APIs, and cloud services
 * - Role-based secret access control with fine-grained permissions
 * - Secret scanning and leakage prevention with breach detection
 * - Comprehensive audit trails for compliance (SOC2, PCI DSS, GDPR)
 * - Real-time monitoring and automated response systems
 * 
 * @version 2.0.0 - Refactored modular architecture
 * @author FastMCP Enterprise Team
 * @see {@link https://www.vaultproject.io/docs} HashiCorp Vault Documentation
 * @see {@link https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/} Azure Key Vault HSM
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { ToolContext, createToolContextLogger } from '../shared/types/tool-context.js';

// Import all available tool creators - Core Infrastructure
import { createConfigureVaultServerTool } from './tools/configure-vault-server.js';
import { createConfigureHSMIntegrationTool } from './tools/configure-hsm-integration.js';
import { createManageSecretEnginesTool } from './tools/manage-secret-engines.js';

// Import key management and rotation tools
import { createConfigureKeyRotationTool } from './tools/configure-key-rotation.js';
import { createGenerateDynamicSecretsTool } from './tools/generate-dynamic-secrets.js';

// Import access control and security tools
import { createManageRBACPoliciesTool } from './tools/manage-rbac-policies.js';
import { createScanSecretLeakageTool } from './tools/scan-secret-leakage.js';
import { createConfigureBreachDetectionTool } from './tools/configure-breach-detection.js';

// Import audit and compliance tools
import { createConfigureAuditSystemTool } from './tools/configure-audit-system.js';
import { createGenerateComplianceReportTool } from './tools/generate-compliance-report.js';

// Import version information and metadata
import { MODULE_METADATA } from './constants.js';

// Import tool metadata for documentation
import { enterpriseSecretsToolMetadata } from './tools/index.js';

/**
 * Type definition for Make session authentication
 */
type MakeSessionAuth = {
  authenticated: boolean;
  timestamp: string;
  correlationId: string;
};

/**
 * Add all Enterprise Secrets Management tools to FastMCP server
 * 
 * This function implements the modular tool registration pattern with
 * dependency injection, providing enterprise-grade secrets management
 * capabilities through HashiCorp Vault integration.
 * 
 * @param server - FastMCP server instance with Make session authentication
 * @param apiClient - Make.com API client for integration capabilities
 * @throws {Error} When tool registration fails or dependencies are missing
 * 
 * @example
 * ```typescript
 * import { FastMCP } from 'fastmcp';
 * import MakeApiClient from '../lib/make-api-client.js';
 * import { addEnterpriseSecretsTools } from './tools/enterprise-secrets/index.js';
 * 
 * const server = new FastMCP();
 * const apiClient = new MakeApiClient();
 * 
 * // Register all enterprise secrets management tools
 * addEnterpriseSecretsTools(server, apiClient);
 * ```
 */
export function addEnterpriseSecretsTools(server: FastMCP<MakeSessionAuth>, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ 
    component: 'EnterpriseSecretsManagement',
    version: MODULE_METADATA.VERSION,
    apiVersion: MODULE_METADATA.API_VERSION
  });

  componentLogger.info('Initializing enterprise secrets management tools', {
    version: MODULE_METADATA.VERSION,
    features: Object.keys(MODULE_METADATA.FEATURES).filter(
      key => MODULE_METADATA.FEATURES[key as keyof typeof MODULE_METADATA.FEATURES]
    ),
    toolCount: 10
  });

  // Create shared tool context for dependency injection
  const toolContext: ToolContext = {
    server: server as never, // Type-safe cast for compatibility
    apiClient,
    logger: createToolContextLogger(componentLogger)
  };

  try {
    // Register Core Infrastructure Tools
    const vaultServerTool = createConfigureVaultServerTool(toolContext);
    const hsmIntegrationTool = createConfigureHSMIntegrationTool(toolContext);
    const secretEnginesTool = createManageSecretEnginesTool(toolContext);

    // Register Key Management Tools
    const keyRotationTool = createConfigureKeyRotationTool(toolContext);
    const dynamicSecretsTool = createGenerateDynamicSecretsTool(toolContext);

    // Register Access Control and Security Tools
    const rbacPoliciesTool = createManageRBACPoliciesTool(toolContext);
    const secretLeakageTool = createScanSecretLeakageTool(toolContext);
    const breachDetectionTool = createConfigureBreachDetectionTool(toolContext);

    // Register Audit and Compliance Tools
    const auditSystemTool = createConfigureAuditSystemTool(toolContext);
    const complianceReportTool = createGenerateComplianceReportTool(toolContext);

    // Collect all tools for registration
    const tools = [
      vaultServerTool,
      hsmIntegrationTool,
      secretEnginesTool,
      keyRotationTool,
      dynamicSecretsTool,
      rbacPoliciesTool,
      secretLeakageTool,
      breachDetectionTool,
      auditSystemTool,
      complianceReportTool
    ];

    // Register each tool with the FastMCP server
    tools.forEach(modernTool => {
      server.addTool({
        name: modernTool.name,
        description: modernTool.description,
        parameters: modernTool.parameters,
        annotations: {
          title: modernTool.annotations.title,
          readOnlyHint: modernTool.annotations.readOnlyHint,
          ...(modernTool.annotations.destructiveHint && { 
            destructiveHint: modernTool.annotations.destructiveHint 
          }),
          ...(modernTool.annotations.idempotentHint && { 
            idempotentHint: modernTool.annotations.idempotentHint 
          }),
          openWorldHint: modernTool.annotations.openWorldHint,
        },
        execute: async (args: unknown, context: { 
          log?: unknown; 
          reportProgress?: unknown 
        }): Promise<string> => {
          return modernTool.execute(args, context as never); // Type cast for compatibility
        }
      });
    });

    // Log successful registration with detailed information
    componentLogger.info('Enterprise Secrets Management tools registered successfully', {
      toolsRegistered: tools.map(tool => tool.name),
      totalTools: tools.length,
      metadata: enterpriseSecretsToolMetadata,
      capabilities: {
        vaultIntegration: MODULE_METADATA.FEATURES.VAULT_INTEGRATION,
        hsmSupport: MODULE_METADATA.FEATURES.HSM_SUPPORT,
        complianceReporting: MODULE_METADATA.FEATURES.COMPLIANCE_REPORTING,
        auditLogging: MODULE_METADATA.FEATURES.AUDIT_LOGGING,
        keyRotation: MODULE_METADATA.FEATURES.KEY_ROTATION,
        rbac: MODULE_METADATA.FEATURES.RBAC,
        secretScanning: MODULE_METADATA.FEATURES.SECRET_SCANNING,
        breachDetection: MODULE_METADATA.FEATURES.BREACH_DETECTION
      }
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;

    componentLogger.error('Failed to register enterprise secrets management tools', {
      error: errorMessage,
      stack: errorStack,
      version: MODULE_METADATA.VERSION
    });

    // Re-throw with additional context for debugging
    throw new Error(`Enterprise Secrets Management initialization failed: ${errorMessage}`);
  }
}

/**
 * Export the main function as default for convenient importing
 */
export default addEnterpriseSecretsTools;

/**
 * Export version and metadata information
 */
export { MODULE_METADATA, enterpriseSecretsToolMetadata };

/**
 * Export array of tool names for backward compatibility with tests
 */
export const enterpriseSecretsTools = [
  'configure-vault-server',
  'configure-hsm-integration', 
  'manage-secret-engines',
  'configure-key-rotation',
  'generate-dynamic-secrets',
  'manage-rbac-policies',
  'scan-secret-leakage',
  'configure-breach-detection',
  'configure-audit-system',
  'generate-compliance-report'
];

/**
 * Export utility modules for advanced usage
 */
export {
  VaultServerManager,
  VaultOperations,
  vaultManager,
  HSMIntegrationManager,
  HSMOperations, 
  hsmManager,
  SecurityValidator,
  EnterpriseAuditLogger,
  AuditUtils,
  enterpriseAuditLogger,
  EnterpriseUtilityFactory,
  CommonUtils,
  ENTERPRISE_UTILS_VERSION
} from './utils/index.js';

export type {
  SecurityValidationResult,
  PasswordPolicyResult,
  EnterpriseSecretsAuditEvent,
  AuditRiskLevel,
  ComplianceFramework,
  EnterpriseAuditEventDetails
} from './utils/index.js';

/**
 * Export type definitions for external usage
 */
export * from './types/index.js';

/**
 * Export schema definitions for validation
 */
export * from './schemas/index.js';

/**
 * Export constants for configuration
 */
export * from './constants.js';