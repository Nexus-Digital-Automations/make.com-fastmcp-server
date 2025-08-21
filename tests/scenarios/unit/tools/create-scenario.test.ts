/**
 * Unit tests for create-scenario tool
 * Tests parameter validation, successful creation, and error handling
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { createScenarioTool } from '../../../../src/tools/scenarios/tools/create-scenario.js';
import { createToolContext, ApiResponseBuilder } from '../../helpers/mock-factories.js';
import { AssertionHelpers, ErrorTestUtils } from '../../helpers/test-utils.js';
import { mockScenarios, validUUIDs, invalidData } from '../../fixtures/scenario-data.js';

describe('Create Scenario Tool', () => {
  let toolContext: ReturnType<typeof createToolContext>;
  let mockApiClient: any;
  let mockLogger: any;

  beforeEach(() => {
    toolContext = createToolContext();
    mockApiClient = toolContext.apiClient;
    mockLogger = toolContext.logger;
  });

  describe('Parameter Validation', () => {
    it('should validate required scenario name', async () => {
      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({})).rejects.toThrow('name');
      expect(mockLogger.error).toHaveBeenCalled();
    });

    it('should validate empty scenario name', async () => {
      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute(invalidData.emptyStrings)).rejects.toThrow();
      expect(mockLogger.error).toHaveBeenCalled();
    });

    it('should validate teamId format when provided', async () => {
      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: 'Test Scenario',
        teamId: invalidData.invalidUUIDs.teamId
      })).rejects.toThrow();
    });

    it('should validate folderId format when provided', async () => {
      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: 'Test Scenario',
        teamId: validUUIDs.teamId,
        folderId: 'invalid-folder-uuid'
      })).rejects.toThrow();
    });

    it('should validate blueprint structure when provided', async () => {
      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: 'Test Scenario',
        teamId: validUUIDs.teamId,
        blueprint: 'invalid-blueprint'
      })).rejects.toThrow();
    });
  });

  describe('Successful Creation', () => {
    it('should create scenario with minimal required parameters', async () => {
      const expectedResponse = {
        id: 'new-scenario-123',
        name: 'Test Scenario',
        teamId: validUUIDs.teamId
      };

      mockApiClient.post.mockResolvedValue(
        ApiResponseBuilder.success(expectedResponse)
      );

      const tool = createScenarioTool(toolContext);
      const result = await tool.execute({
        name: 'Test Scenario',
        teamId: validUUIDs.teamId
      });

      AssertionHelpers.expectSuccessfulResult(result);
      AssertionHelpers.expectApiCall(mockApiClient.post, 'POST', '/scenarios', {
        name: 'Test Scenario',
        teamId: validUUIDs.teamId
      });
      AssertionHelpers.expectLogCall(mockLogger, 'info', 'created scenario');
    });

    it('should create scenario with all optional parameters', async () => {
      const fullScenarioData = {
        name: 'Complete Test Scenario',
        teamId: validUUIDs.teamId,
        folderId: validUUIDs.folderId,
        blueprint: {
          modules: [{ id: 1, app: 'webhook', type: 'trigger' }],
          connections: []
        }
      };

      const expectedResponse = {
        id: 'new-scenario-456',
        ...fullScenarioData
      };

      mockApiClient.post.mockResolvedValue(
        ApiResponseBuilder.success(expectedResponse)
      );

      const tool = createScenarioTool(toolContext);
      const result = await tool.execute(fullScenarioData);

      AssertionHelpers.expectSuccessfulResult(result);
      expect(result).toContain(expectedResponse.id);
      AssertionHelpers.expectApiCall(mockApiClient.post, 'POST', '/scenarios', fullScenarioData);
    });

    it('should handle scenario creation with scheduling options', async () => {
      const scenarioWithScheduling = {
        name: 'Scheduled Scenario',
        teamId: validUUIDs.teamId,
        scheduling: {
          type: 'interval',
          interval: 15,
          timezone: 'UTC'
        }
      };

      mockApiClient.post.mockResolvedValue(
        ApiResponseBuilder.success({ 
          id: 'scheduled-scenario-789',
          ...scenarioWithScheduling
        })
      );

      const tool = createScenarioTool(toolContext);
      const result = await tool.execute(scenarioWithScheduling);

      AssertionHelpers.expectSuccessfulResult(result);
      expect(result).toContain('scheduling');
    });
  });

  describe('Error Handling', () => {
    it('should handle team not found error', async () => {
      mockApiClient.post.mockRejectedValue(
        ApiResponseBuilder.error('Team not found', 'TEAM_NOT_FOUND', 404)
      );

      const tool = createScenarioTool(toolContext);
      
      await ErrorTestUtils.expectThrowsWithMessage(
        () => tool.execute({
          name: 'Test Scenario',
          teamId: 'non-existent-team'
        }),
        'Team not found'
      );

      AssertionHelpers.expectLogCall(mockLogger, 'error', 'failed to create scenario');
    });

    it('should handle insufficient permissions error', async () => {
      mockApiClient.post.mockRejectedValue(
        ApiResponseBuilder.unauthorized('Insufficient permissions')
      );

      const tool = createScenarioTool(toolContext);
      
      await ErrorTestUtils.expectThrowsWithMessage(
        () => tool.execute({
          name: 'Test Scenario',
          teamId: validUUIDs.teamId
        }),
        'Insufficient permissions'
      );
    });

    it('should handle rate limiting error', async () => {
      mockApiClient.post.mockRejectedValue(
        ApiResponseBuilder.rateLimit()
      );

      const tool = createScenarioTool(toolContext);
      
      await ErrorTestUtils.expectThrowsWithMessage(
        () => tool.execute({
          name: 'Test Scenario',
          teamId: validUUIDs.teamId
        }),
        'rate limit'
      );
    });

    it('should handle network timeout error', async () => {
      mockApiClient.post.mockRejectedValue(new Error('Network timeout'));

      const tool = createScenarioTool(toolContext);
      
      await ErrorTestUtils.expectThrowsWithMessage(
        () => tool.execute({
          name: 'Test Scenario',
          teamId: validUUIDs.teamId
        }),
        'Network timeout'
      );
    });

    it('should handle malformed response data', async () => {
      mockApiClient.post.mockResolvedValue({
        data: null // Malformed response
      });

      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: 'Test Scenario',
        teamId: validUUIDs.teamId
      })).rejects.toThrow();

      AssertionHelpers.expectLogCall(mockLogger, 'error');
    });
  });

  describe('Input Sanitization and Security', () => {
    it('should handle special characters in scenario name safely', async () => {
      const specialCharName = "Test <script>alert('xss')</script> Scenario";
      
      mockApiClient.post.mockResolvedValue(
        ApiResponseBuilder.success({
          id: 'scenario-special-123',
          name: specialCharName,
          teamId: validUUIDs.teamId
        })
      );

      const tool = createScenarioTool(toolContext);
      const result = await tool.execute({
        name: specialCharName,
        teamId: validUUIDs.teamId
      });

      AssertionHelpers.expectSuccessfulResult(result);
      // Ensure no script execution or XSS vulnerabilities
      expect(result).not.toContain('<script>');
    });

    it('should handle very long scenario names', async () => {
      const longName = 'A'.repeat(1000);
      
      // Should be validated and rejected for being too long
      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: longName,
        teamId: validUUIDs.teamId
      })).rejects.toThrow();
    });

    it('should handle SQL injection attempts safely', async () => {
      const maliciousName = "'; DROP TABLE scenarios; --";
      
      mockApiClient.post.mockResolvedValue(
        ApiResponseBuilder.success({
          id: 'scenario-safe-456',
          name: maliciousName,
          teamId: validUUIDs.teamId
        })
      );

      const tool = createScenarioTool(toolContext);
      const result = await tool.execute({
        name: maliciousName,
        teamId: validUUIDs.teamId
      });

      AssertionHelpers.expectSuccessfulResult(result);
      // Ensure no SQL injection indicators in logs
      expect(mockLogger.error).not.toHaveBeenCalledWith(
        expect.stringContaining('DROP TABLE')
      );
    });
  });

  describe('Blueprint Validation', () => {
    it('should validate blueprint module structure', async () => {
      const invalidBlueprint = {
        modules: [
          { /* missing required properties */ }
        ],
        connections: []
      };

      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: 'Test Scenario',
        teamId: validUUIDs.teamId,
        blueprint: invalidBlueprint
      })).rejects.toThrow('blueprint');
    });

    it('should validate blueprint connection references', async () => {
      const invalidBlueprint = {
        modules: [
          { id: 1, app: 'webhook', type: 'trigger' }
        ],
        connections: [
          { source: 1, target: 999 } // Invalid target reference
        ]
      };

      const tool = createScenarioTool(toolContext);
      
      await expect(tool.execute({
        name: 'Test Scenario',
        teamId: validUUIDs.teamId,
        blueprint: invalidBlueprint
      })).rejects.toThrow();
    });
  });
});