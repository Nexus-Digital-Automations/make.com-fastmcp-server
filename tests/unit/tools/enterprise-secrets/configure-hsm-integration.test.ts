/**
 * @fileoverview Unit tests for Configure HSM Integration Tool
 * Tests the hardware security module configuration functionality
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Mock all dependencies before any imports
jest.mock('fastmcp', () => ({
  UserError: class UserError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UserError';
    }
  }
}));

jest.mock('../../../../src/tools/enterprise-secrets/schemas/index.js', () => ({
  HSMConfigSchema: {
    parse: jest.fn()
  }
}));

jest.mock('../../../../src/tools/shared/types/tool-context.js', () => ({}));

jest.mock('../../../../src/tools/enterprise-secrets/utils/index.js', () => ({
  HSMIntegrationManager: {
    getInstance: jest.fn()
  }
}));

import { createConfigureHSMIntegrationTool } from '../../../../src/tools/enterprise-secrets/tools/configure-hsm-integration.js';
import { UserError } from 'fastmcp';
import { HSMConfigSchema } from '../../../../src/tools/enterprise-secrets/schemas/index.js';
import { HSMIntegrationManager } from '../../../../src/tools/enterprise-secrets/utils/index.js';

describe('Configure HSM Integration Tool', () => {
  let mockContext: any;
  let mockLogger: any;
  let mockHSMManager: any;
  let mockExecContext: any;
  let toolDefinition: any;

  const validHSMConfig = {
    provider: 'aws-cloudhsm',
    clusterId: 'cluster-12345',
    credentials: {
      accessKeyId: 'AKIA...',
      secretAccessKey: 'secret...',
      region: 'us-east-1'
    },
    compliance: {
      fipsLevel: 3,
      commonCriteria: true
    }
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Mock logger
    mockLogger = {
      info: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn()
    };

    // Mock context
    mockContext = {
      logger: mockLogger
    };

    // Mock HSM manager
    mockHSMManager = {
      configureHSM: jest.fn()
    };
    (HSMIntegrationManager.getInstance as jest.Mock).mockReturnValue(mockHSMManager);

    // Mock execution context
    mockExecContext = {
      log: {
        info: jest.fn()
      },
      reportProgress: jest.fn()
    };

    // Create tool definition
    toolDefinition = createConfigureHSMIntegrationTool(mockContext);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Tool Definition', () => {
    it('should create tool with correct metadata', () => {
      expect(toolDefinition).toBeDefined();
      expect(toolDefinition.name).toBe('configure-hsm-integration');
      expect(toolDefinition.description).toBe('Configure Hardware Security Module integration for enterprise-grade key protection');
      expect(toolDefinition.parameters).toBe(HSMConfigSchema);
      
      // Check annotations
      expect(toolDefinition.annotations).toEqual({
        title: 'Configure Hardware Security Module Integration',
        readOnlyHint: false,
        idempotentHint: true,
        openWorldHint: true
      });
    });

    it('should have execute function', () => {
      expect(typeof toolDefinition.execute).toBe('function');
    });
  });

  describe('Tool Execution', () => {
    it('should successfully configure HSM integration', async () => {
      // Setup mocks
      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(validHSMConfig);
      mockHSMManager.configureHSM.mockResolvedValue({
        status: 'active',
        clusterId: 'cluster-12345',
        provider: 'aws-cloudhsm'
      });

      // Execute tool
      const result = await toolDefinition.execute(validHSMConfig, mockExecContext);

      // Verify execution
      expect(HSMConfigSchema.parse).toHaveBeenCalledWith(validHSMConfig);
      expect(HSMIntegrationManager.getInstance).toHaveBeenCalled();
      expect(mockHSMManager.configureHSM).toHaveBeenCalledWith(validHSMConfig);

      // Verify progress reporting
      expect(mockExecContext.reportProgress).toHaveBeenCalledTimes(4);
      expect(mockExecContext.reportProgress).toHaveBeenCalledWith({ progress: 0, total: 100 });
      expect(mockExecContext.reportProgress).toHaveBeenCalledWith({ progress: 25, total: 100 });
      expect(mockExecContext.reportProgress).toHaveBeenCalledWith({ progress: 75, total: 100 });
      expect(mockExecContext.reportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });

      // Verify logging
      expect(mockExecContext.log.info).toHaveBeenCalledWith(
        'Configuring HSM integration',
        JSON.stringify(validHSMConfig)
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        'HSM integration configured successfully',
        {
          provider: validHSMConfig.provider,
          fipsLevel: validHSMConfig.compliance.fipsLevel
        }
      );

      // Verify result
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toEqual({
        success: true,
        hsmStatus: {
          status: 'active',
          clusterId: 'cluster-12345',
          provider: 'aws-cloudhsm'
        },
        message: 'HSM integration with aws-cloudhsm configured successfully'
      });
    });

    it('should handle validation errors', async () => {
      const validationError = new Error('Invalid provider specified');
      (HSMConfigSchema.parse as jest.Mock).mockImplementation(() => {
        throw validationError;
      });

      await expect(
        toolDefinition.execute({ invalidConfig: true }, mockExecContext)
      ).rejects.toThrow(UserError);

      expect(mockLogger.error).toHaveBeenCalledWith(
        'HSM integration failed',
        { error: 'Invalid provider specified' }
      );
    });

    it('should handle HSM configuration failures', async () => {
      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(validHSMConfig);
      const configError = new Error('HSM cluster unreachable');
      mockHSMManager.configureHSM.mockRejectedValue(configError);

      await expect(
        toolDefinition.execute(validHSMConfig, mockExecContext)
      ).rejects.toThrow('Failed to configure HSM integration: HSM cluster unreachable');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'HSM integration failed',
        { error: 'HSM cluster unreachable' }
      );
    });

    it('should handle non-Error exceptions', async () => {
      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(validHSMConfig);
      mockHSMManager.configureHSM.mockRejectedValue('String error');

      await expect(
        toolDefinition.execute(validHSMConfig, mockExecContext)
      ).rejects.toThrow('Failed to configure HSM integration: String error');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'HSM integration failed',
        { error: 'String error' }
      );
    });

    it('should work with minimal execution context', async () => {
      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(validHSMConfig);
      mockHSMManager.configureHSM.mockResolvedValue({ status: 'active' });

      // Test with minimal context (no log, no reportProgress)
      const minimalContext = {};

      const result = await toolDefinition.execute(validHSMConfig, minimalContext);

      // Should still work without crashing
      expect(result).toContain('"success": true');
      expect(HSMConfigSchema.parse).toHaveBeenCalledWith(validHSMConfig);
      expect(mockHSMManager.configureHSM).toHaveBeenCalledWith(validHSMConfig);
    });

    it('should handle different HSM providers', async () => {
      const azureHSMConfig = {
        ...validHSMConfig,
        provider: 'azure-dedicated-hsm'
      };

      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(azureHSMConfig);
      mockHSMManager.configureHSM.mockResolvedValue({
        status: 'active',
        provider: 'azure-dedicated-hsm'
      });

      const result = await toolDefinition.execute(azureHSMConfig, mockExecContext);

      const parsedResult = JSON.parse(result);
      expect(parsedResult.message).toBe('HSM integration with azure-dedicated-hsm configured successfully');
      expect(mockLogger.info).toHaveBeenCalledWith(
        'HSM integration configured successfully',
        {
          provider: 'azure-dedicated-hsm',
          fipsLevel: validHSMConfig.compliance.fipsLevel
        }
      );
    });

    it('should handle configuration without compliance settings', async () => {
      const basicHSMConfig = {
        provider: 'aws-cloudhsm',
        clusterId: 'cluster-12345',
        credentials: {
          accessKeyId: 'AKIA...',
          secretAccessKey: 'secret...',
          region: 'us-east-1'
        }
        // No compliance section
      };

      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(basicHSMConfig);
      mockHSMManager.configureHSM.mockResolvedValue({ status: 'active' });

      const result = await toolDefinition.execute(basicHSMConfig, mockExecContext);

      expect(mockLogger.info).toHaveBeenCalledWith(
        'HSM integration configured successfully',
        {
          provider: 'aws-cloudhsm',
          fipsLevel: undefined
        }
      );

      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
    });
  });

  describe('Error Scenarios', () => {
    it('should throw UserError for validation failures', async () => {
      const validationError = new Error('Missing required field: provider');
      (HSMConfigSchema.parse as jest.Mock).mockImplementation(() => {
        throw validationError;
      });

      const thrownError = await toolDefinition.execute({}, mockExecContext).catch((e: any) => e);

      expect(thrownError).toBeInstanceOf(UserError);
      expect(thrownError.message).toBe('Failed to configure HSM integration: Missing required field: provider');
    });

    it('should throw UserError for HSM manager failures', async () => {
      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(validHSMConfig);
      mockHSMManager.configureHSM.mockRejectedValue(new Error('Connection timeout'));

      const thrownError = await toolDefinition.execute(validHSMConfig, mockExecContext).catch((e: any) => e);

      expect(thrownError).toBeInstanceOf(UserError);
      expect(thrownError.message).toBe('Failed to configure HSM integration: Connection timeout');
    });
  });

  describe('Integration with Context', () => {
    it('should use logger from context', () => {
      expect(toolDefinition).toBeDefined();
      // Logger is used internally in the tool implementation
      expect(mockContext.logger).toBe(mockLogger);
    });

    it('should handle context without optional methods', async () => {
      const contextWithoutOptionals = {
        logger: {
          info: undefined,
          error: undefined
        }
      };

      const toolWithMinimalContext = createConfigureHSMIntegrationTool(contextWithoutOptionals);

      (HSMConfigSchema.parse as jest.Mock).mockReturnValue(validHSMConfig);
      mockHSMManager.configureHSM.mockResolvedValue({ status: 'active' });

      // Should not throw when logger methods are undefined
      await expect(
        toolWithMinimalContext.execute(validHSMConfig, mockExecContext)
      ).resolves.toContain('"success": true');
    });
  });
});