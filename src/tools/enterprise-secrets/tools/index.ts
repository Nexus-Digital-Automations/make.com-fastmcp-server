/**
 * @fileoverview Enterprise Secrets Tools Index
 * Aggregates all enterprise secrets management tool implementations
 */

import { ToolContext, ToolDefinition, ToolFactory } from '../../shared/types/tool-context.js';
import { createConfigureVaultServerTool } from './configure-vault-server.js';
import { createConfigureHSMIntegrationTool } from './configure-hsm-integration.js';
import { createManageSecretEnginesTool } from './manage-secret-engines.js';
import { createConfigureKeyRotationTool } from './configure-key-rotation.js';
import { createGenerateDynamicSecretsTool } from './generate-dynamic-secrets.js';
import { createManageRBACPoliciesTool } from './manage-rbac-policies.js';
import { createScanSecretLeakageTool } from './scan-secret-leakage.js';
import { createConfigureBreachDetectionTool } from './configure-breach-detection.js';
import { createConfigureAuditSystemTool } from './configure-audit-system.js';
import { createGenerateComplianceReportTool } from './generate-compliance-report.js';

/**
 * All enterprise secrets management tool factories
 */
export const enterpriseSecretsToolFactories: ToolFactory[] = [
  createConfigureVaultServerTool,
  createConfigureHSMIntegrationTool,
  createManageSecretEnginesTool,
  createConfigureKeyRotationTool,
  createGenerateDynamicSecretsTool,
  createManageRBACPoliciesTool,
  createScanSecretLeakageTool,
  createConfigureBreachDetectionTool,
  createConfigureAuditSystemTool,
  createGenerateComplianceReportTool,
];

/**
 * Create all enterprise secrets management tools
 */
export function createEnterpriseSecretsTools(context: ToolContext): ToolDefinition[] {
  return enterpriseSecretsToolFactories.map(factory => factory(context));
}

/**
 * Get enterprise secrets tool names
 */
export function getEnterpriseSecretsToolNames(): string[] {
  return [
    'configure-vault-server',
    'configure-hsm-integration',
    'manage-secret-engines',
    'configure-key-rotation',
    'generate-dynamic-secrets',
    'manage-rbac-policies',
    'scan-secret-leakage',
    'configure-breach-detection',
    'configure-audit-system',
    'generate-compliance-report',
  ];
}

/**
 * Export individual tool factories
 */
export {
  createConfigureVaultServerTool,
  createConfigureHSMIntegrationTool,
  createManageSecretEnginesTool,
  createConfigureKeyRotationTool,
  createGenerateDynamicSecretsTool,
  createManageRBACPoliciesTool,
  createScanSecretLeakageTool,
  createConfigureBreachDetectionTool,
  createConfigureAuditSystemTool,
  createGenerateComplianceReportTool,
};

/**
 * Tool metadata for documentation and discovery
 */
export const enterpriseSecretsToolMetadata = {
  category: 'Enterprise Security',
  description: 'Comprehensive enterprise secrets management with HashiCorp Vault integration',
  toolCount: enterpriseSecretsToolFactories.length,
  features: [
    'HashiCorp Vault server provisioning and configuration',
    'Hardware Security Module (HSM) integration',
    'Automated key rotation with scheduled and event-driven policies',
    'Dynamic secret generation for databases, APIs, and cloud services',
    'Role-based secret access control with fine-grained permissions',
    'Secret scanning and leakage prevention with breach detection',
    'Comprehensive audit trails for compliance (SOC2, PCI DSS, GDPR)',
    'Real-time monitoring and automated response systems',
  ],
  compliance: ['SOC2', 'PCI DSS', 'GDPR', 'FIPS 140-2', 'Common Criteria'],
  integrations: ['AWS CloudHSM', 'Azure Key Vault', 'PKCS#11', 'Consul', 'Kubernetes'],
};