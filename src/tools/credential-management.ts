/**
 * FastMCP Tools for Secure Credential Management
 * Provides tools for managing encrypted credentials, rotation, and audit logging
 */

import { z } from 'zod';
import { secureConfigManager } from '../lib/secure-config.js';
import { credentialManager, encryptionService } from '../utils/encryption.js';
import logger from '../lib/logger.js';

const componentLogger = logger.child({ component: 'CredentialManagementTools' });

// Input schemas for credential management tools
const StoreCredentialSchema = z.object({
  type: z.enum(['api_key', 'secret', 'token', 'certificate']),
  service: z.string().min(1, 'Service name is required'),
  value: z.string().min(1, 'Credential value is required'),
  autoRotate: z.boolean().optional().default(false),
  rotationIntervalDays: z.number().min(1).max(365).optional().default(90),
  userId: z.string().optional(),
});

const GetCredentialSchema = z.object({
  credentialId: z.string().min(1, 'Credential ID is required'),
  userId: z.string().optional(),
});

const RotateCredentialSchema = z.object({
  credentialId: z.string().min(1, 'Credential ID is required'),
  newValue: z.string().optional(),
  gracePeriodHours: z.number().min(1).max(168).optional().default(24),
  userId: z.string().optional(),
});

const ListCredentialsSchema = z.object({
  service: z.string().optional(),
  type: z.enum(['api_key', 'secret', 'token', 'certificate']).optional(),
  status: z.enum(['active', 'rotating', 'deprecated', 'revoked']).optional(),
});

const AuditQuerySchema = z.object({
  credentialId: z.string().optional(),
  userId: z.string().optional(),
  event: z.enum(['credential_accessed', 'credential_rotated', 'credential_expired', 'unauthorized_access']).optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  limit: z.number().min(1).max(1000).optional().default(100),
});

const MigrateCredentialsSchema = z.object({
  userId: z.string().optional(),
});

/**
 * Store a new encrypted credential
 */
export const storeCredentialTool = {
  name: 'store_credential',
  description: 'Store a new credential with encryption and optional auto-rotation',
  inputSchema: StoreCredentialSchema,
  handler: async (input: z.infer<typeof StoreCredentialSchema>) => {
    try {
      const rotationInterval = input.autoRotate 
        ? input.rotationIntervalDays * 24 * 60 * 60 * 1000 
        : undefined;

      const credentialId = await secureConfigManager.storeCredential(
        input.type,
        input.service,
        input.value,
        {
          autoRotate: input.autoRotate,
          rotationInterval,
          userId: input.userId,
        }
      );

      componentLogger.info('Credential stored via MCP tool', {
        credentialId,
        type: input.type,
        service: input.service,
        autoRotate: input.autoRotate,
        userId: input.userId,
      });

      return {
        success: true,
        credentialId,
        message: `Credential stored successfully with ID: ${credentialId}`,
        autoRotate: input.autoRotate,
        rotationIntervalDays: input.rotationIntervalDays,
      };
    } catch (error) {
      componentLogger.error('Failed to store credential via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        type: input.type,
        service: input.service,
        userId: input.userId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to store credential',
      };
    }
  },
};

/**
 * Retrieve credential status and metadata (without exposing the actual credential)
 */
export const getCredentialStatusTool = {
  name: 'get_credential_status',
  description: 'Get credential metadata and security status without exposing the actual credential value',
  inputSchema: GetCredentialSchema,
  handler: async (input: z.infer<typeof GetCredentialSchema>) => {
    try {
      const status = secureConfigManager.getCredentialStatus(input.credentialId);
      
      if (status.status === 'not_found') {
        return {
          success: false,
          error: `Credential ${input.credentialId} not found`,
        };
      }

      componentLogger.info('Credential status retrieved via MCP tool', {
        credentialId: input.credentialId,
        status: status.status,
        userId: input.userId,
      });

      return {
        success: true,
        credentialId: input.credentialId,
        status: status.status,
        metadata: {
          type: status.metadata?.type,
          service: status.metadata?.service,
          createdAt: status.metadata?.createdAt,
          lastUsed: status.metadata?.lastUsed,
          encrypted: status.metadata?.encrypted,
        },
        rotation: {
          nextRotation: status.nextRotation,
          daysUntilRotation: status.daysUntilRotation,
          policy: status.rotationPolicy,
        },
      };
    } catch (error) {
      componentLogger.error('Failed to get credential status via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        credentialId: input.credentialId,
        userId: input.userId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get credential status',
      };
    }
  },
};

/**
 * Rotate a credential immediately
 */
export const rotateCredentialTool = {
  name: 'rotate_credential',
  description: 'Immediately rotate a credential, optionally providing a new value',
  inputSchema: RotateCredentialSchema,
  handler: async (input: z.infer<typeof RotateCredentialSchema>) => {
    try {
      const gracePeriod = input.gracePeriodHours * 60 * 60 * 1000; // Convert to milliseconds

      const newCredentialId = await secureConfigManager.rotateCredential(
        input.credentialId,
        {
          newValue: input.newValue,
          gracePeriod,
          userId: input.userId,
        }
      );

      componentLogger.info('Credential rotated via MCP tool', {
        oldCredentialId: input.credentialId,
        newCredentialId,
        gracePeriodHours: input.gracePeriodHours,
        userId: input.userId,
      });

      return {
        success: true,
        oldCredentialId: input.credentialId,
        newCredentialId,
        gracePeriodHours: input.gracePeriodHours,
        message: `Credential rotated successfully. New ID: ${newCredentialId}`,
      };
    } catch (error) {
      componentLogger.error('Failed to rotate credential via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        credentialId: input.credentialId,
        userId: input.userId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to rotate credential',
      };
    }
  },
};

/**
 * List credentials with filtering options
 */
export const listCredentialsTool = {
  name: 'list_credentials',
  description: 'List all credentials with optional filtering by service, type, or status',
  inputSchema: ListCredentialsSchema,
  handler: async (input: z.infer<typeof ListCredentialsSchema>) => {
    try {
      const credentials = credentialManager.listCredentials({
        service: input.service,
        type: input.type,
        status: input.status,
      });

      const credentialList = credentials.map(cred => ({
        id: cred.id,
        type: cred.type,
        service: cred.service,
        createdAt: cred.createdAt,
        lastUsed: cred.lastUsed,
        status: cred.rotationInfo.status,
        encrypted: cred.encrypted,
        nextRotation: cred.rotationInfo.expiresAt,
      }));

      componentLogger.info('Credentials listed via MCP tool', {
        count: credentialList.length,
        filters: input,
      });

      return {
        success: true,
        credentials: credentialList,
        count: credentialList.length,
        filters: input,
      };
    } catch (error) {
      componentLogger.error('Failed to list credentials via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        filters: input,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to list credentials',
      };
    }
  },
};

/**
 * Get security audit events
 */
export const getAuditEventsTool = {
  name: 'get_audit_events',
  description: 'Retrieve security audit events with optional filtering',
  inputSchema: AuditQuerySchema,
  handler: async (input: z.infer<typeof AuditQuerySchema>) => {
    try {
      const filter = {
        credentialId: input.credentialId,
        userId: input.userId,
        event: input.event,
        startDate: input.startDate ? new Date(input.startDate) : undefined,
        endDate: input.endDate ? new Date(input.endDate) : undefined,
        limit: input.limit,
      };

      const events = secureConfigManager.getSecurityEvents(filter);

      componentLogger.info('Audit events retrieved via MCP tool', {
        count: events.length,
        filters: filter,
      });

      return {
        success: true,
        events: events.map(event => ({
          timestamp: event.timestamp,
          event: event.event,
          credentialId: event.credentialId,
          userId: event.userId,
          source: event.source,
          success: event.success,
          metadata: event.metadata,
        })),
        count: events.length,
        filters: filter,
      };
    } catch (error) {
      componentLogger.error('Failed to get audit events via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        filters: input,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get audit events',
      };
    }
  },
};

/**
 * Migrate existing plain-text credentials to encrypted storage
 */
export const migrateCredentialsTool = {
  name: 'migrate_credentials',
  description: 'Migrate existing plain-text credentials to encrypted storage',
  inputSchema: MigrateCredentialsSchema,
  handler: async (input: z.infer<typeof MigrateCredentialsSchema>) => {
    try {
      const result = await secureConfigManager.migrateToSecureStorage(input.userId);

      componentLogger.info('Credentials migrated via MCP tool', {
        migrated: result.migrated,
        errors: result.errors,
        userId: input.userId,
      });

      return {
        success: true,
        migrated: result.migrated,
        errors: result.errors,
        message: `Migration completed. ${result.migrated.length} credentials migrated successfully.`,
      };
    } catch (error) {
      componentLogger.error('Failed to migrate credentials via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: input.userId,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to migrate credentials',
      };
    }
  },
};

/**
 * Generate a new secure API key or secret
 */
export const generateCredentialTool = {
  name: 'generate_credential',
  description: 'Generate a new secure API key or secret using cryptographically secure methods',
  inputSchema: z.object({
    type: z.enum(['api_key', 'secret']),
    prefix: z.string().optional().default('mcp'),
    length: z.number().min(16).max(128).optional().default(32),
  }),
  handler: async (input: {
    type: 'api_key' | 'secret';
    prefix?: string;
    length?: number;
  }) => {
    try {
      let generated: string;
      
      if (input.type === 'api_key') {
        generated = encryptionService.generateApiKey(input.prefix, input.length);
      } else {
        generated = encryptionService.generateSecureSecret(input.length);
      }

      componentLogger.info('Credential generated via MCP tool', {
        type: input.type,
        length: generated.length,
        prefix: input.prefix,
      });

      return {
        success: true,
        type: input.type,
        credential: generated,
        length: generated.length,
        message: `New ${input.type} generated successfully`,
      };
    } catch (error) {
      componentLogger.error('Failed to generate credential via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        type: input.type,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to generate credential',
      };
    }
  },
};

/**
 * Cleanup expired credentials and audit events
 */
export const cleanupCredentialsTool = {
  name: 'cleanup_credentials',
  description: 'Clean up expired credentials and old audit events',
  inputSchema: z.object({}),
  handler: async () => {
    try {
      const result = secureConfigManager.cleanup();

      componentLogger.info('Credential cleanup performed via MCP tool', {
        expiredCredentials: result.expiredCredentials,
        oldEvents: result.oldEvents,
      });

      return {
        success: true,
        expiredCredentials: result.expiredCredentials,
        oldEvents: result.oldEvents,
        message: `Cleanup completed. Removed ${result.expiredCredentials} expired credentials and ${result.oldEvents} old events.`,
      };
    } catch (error) {
      componentLogger.error('Failed to cleanup credentials via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to cleanup credentials',
      };
    }
  },
};

// Export all credential management tools
export const credentialManagementTools = [
  storeCredentialTool,
  getCredentialStatusTool,
  rotateCredentialTool,
  listCredentialsTool,
  getAuditEventsTool,
  migrateCredentialsTool,
  generateCredentialTool,
  cleanupCredentialsTool,
];

export default credentialManagementTools;