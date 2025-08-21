/**
 * @fileoverview Enterprise Secrets Management - Compatibility Layer
 * 
 * This file provides backward compatibility for the legacy enterprise-secrets.ts interface.
 * The actual implementation has been moved to the modular architecture under
 * ./enterprise-secrets/index.ts for better maintainability and organization.
 * 
 * @deprecated Use ./enterprise-secrets/index.js directly for new implementations
 * @see ./enterprise-secrets/index.js for the modern modular implementation
 */

// Re-export everything from the modular implementation for backward compatibility
export { 
  addEnterpriseSecretsTools as default, 
  addEnterpriseSecretsTools,
  MODULE_METADATA,
  enterpriseSecretsToolMetadata 
} from './enterprise-secrets/index.js';

// Re-export utility modules for existing consumers  
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
} from './enterprise-secrets/utils/index.js';

// Re-export specific types to avoid conflicts
export type {
  SecurityValidationResult,
  PasswordPolicyResult,
  EnterpriseSecretsAuditEvent,
  AuditRiskLevel,
  ComplianceFramework as EnterpriseComplianceFramework,
  EnterpriseAuditEventDetails
} from './enterprise-secrets/utils/index.js';

// Re-export type definitions from types module
export * from './enterprise-secrets/types/index.js';

// Re-export schema definitions
export * from './enterprise-secrets/schemas/index.js';