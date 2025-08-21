/**
 * Unit tests for scenario schemas
 * Tests Zod schema validation for various scenario operations
 */

import { describe, it, expect } from '@jest/globals';
import { 
  CreateScenarioSchema, 
  UpdateScenarioSchema,
  DeleteScenarioSchema,
  GetScenarioSchema
} from '../../../../src/tools/scenarios/schemas/scenario-schemas.js';
import { SchemaTestUtils } from '../../helpers/test-utils.js';
import { validUUIDs, invalidData, mockBlueprints } from '../../fixtures/scenario-data.js';

describe('Scenario Schemas', () => {
  describe('CreateScenarioSchema', () => {
    const validCreateData = {
      name: 'Test Scenario',
      teamId: validUUIDs.teamId
    };

    it('should validate required fields only', () => {
      expect(() => CreateScenarioSchema.parse(validCreateData)).not.toThrow();
    });

    it('should validate with all optional fields', () => {
      const fullData = {
        ...validCreateData,
        folderId: validUUIDs.folderId,
        blueprint: mockBlueprints.validSimple,
        scheduling: {
          type: 'interval',
          interval: 15,
          timezone: 'UTC'
        }
      };

      expect(() => CreateScenarioSchema.parse(fullData)).not.toThrow();
    });

    it('should reject invalid data types', () => {
      const testCases = SchemaTestUtils.generateSchemaTestCases(validCreateData);
      
      // Add scenario-specific invalid cases
      testCases.invalid.push(
        { ...validCreateData, name: 123 },
        { ...validCreateData, teamId: 'invalid-uuid' },
        { ...validCreateData, folderId: 'invalid-uuid' },
        { ...validCreateData, blueprint: 'not-an-object' },
        { ...validCreateData, scheduling: 'not-an-object' }
      );

      SchemaTestUtils.testSchemaValidation(CreateScenarioSchema, testCases);
    });

    it('should validate name length constraints', () => {
      // Empty name
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        name: ''
      })).toThrow();

      // Very long name
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        name: 'A'.repeat(1000)
      })).toThrow();

      // Reasonable length name
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        name: 'A'.repeat(100)
      })).not.toThrow();
    });

    it('should validate UUID formats', () => {
      // Invalid teamId UUID
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        teamId: 'not-a-uuid'
      })).toThrow();

      // Invalid folderId UUID
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        folderId: 'not-a-uuid'
      })).toThrow();

      // Valid UUIDs
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        teamId: validUUIDs.teamId,
        folderId: validUUIDs.folderId
      })).not.toThrow();
    });

    it('should validate blueprint structure', () => {
      // Valid blueprint
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        blueprint: mockBlueprints.validSimple
      })).not.toThrow();

      // Invalid blueprint structure
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        blueprint: { invalidProperty: 'test' }
      })).toThrow();
    });

    it('should validate scheduling configuration', () => {
      // Valid scheduling
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        scheduling: {
          type: 'interval',
          interval: 15
        }
      })).not.toThrow();

      // Invalid scheduling type
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        scheduling: {
          type: 'invalid-type',
          interval: 15
        }
      })).toThrow();

      // Invalid interval value
      expect(() => CreateScenarioSchema.parse({
        ...validCreateData,
        scheduling: {
          type: 'interval',
          interval: -1
        }
      })).toThrow();
    });
  });

  describe('UpdateScenarioSchema', () => {
    const validUpdateData = {
      scenarioId: validUUIDs.scenarioId,
      name: 'Updated Scenario Name'
    };

    it('should validate required scenarioId', () => {
      expect(() => UpdateScenarioSchema.parse(validUpdateData)).not.toThrow();
      
      // Missing scenarioId
      expect(() => UpdateScenarioSchema.parse({
        name: 'Updated Name'
      })).toThrow();
    });

    it('should validate optional update fields', () => {
      const fullUpdateData = {
        scenarioId: validUUIDs.scenarioId,
        name: 'Updated Name',
        folderId: validUUIDs.folderId,
        isActive: true,
        blueprint: mockBlueprints.validSimple,
        scheduling: {
          type: 'cron',
          cron: '0 0 * * *'
        }
      };

      expect(() => UpdateScenarioSchema.parse(fullUpdateData)).not.toThrow();
    });

    it('should allow partial updates', () => {
      // Only name
      expect(() => UpdateScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        name: 'New Name Only'
      })).not.toThrow();

      // Only status
      expect(() => UpdateScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        isActive: false
      })).not.toThrow();

      // Only folder
      expect(() => UpdateScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        folderId: validUUIDs.folderId
      })).not.toThrow();
    });

    it('should validate boolean fields', () => {
      // Valid boolean
      expect(() => UpdateScenarioSchema.parse({
        ...validUpdateData,
        isActive: true
      })).not.toThrow();

      // Invalid boolean
      expect(() => UpdateScenarioSchema.parse({
        ...validUpdateData,
        isActive: 'true' // String instead of boolean
      })).toThrow();
    });
  });

  describe('DeleteScenarioSchema', () => {
    it('should validate required scenarioId', () => {
      const validDeleteData = {
        scenarioId: validUUIDs.scenarioId
      };

      expect(() => DeleteScenarioSchema.parse(validDeleteData)).not.toThrow();
    });

    it('should reject missing scenarioId', () => {
      expect(() => DeleteScenarioSchema.parse({})).toThrow();
    });

    it('should validate optional force delete flag', () => {
      const validDeleteWithForce = {
        scenarioId: validUUIDs.scenarioId,
        force: true
      };

      expect(() => DeleteScenarioSchema.parse(validDeleteWithForce)).not.toThrow();
    });

    it('should reject invalid force flag type', () => {
      expect(() => DeleteScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        force: 'true' // Should be boolean
      })).toThrow();
    });
  });

  describe('GetScenarioSchema', () => {
    it('should validate required scenarioId', () => {
      const validGetData = {
        scenarioId: validUUIDs.scenarioId
      };

      expect(() => GetScenarioSchema.parse(validGetData)).not.toThrow();
    });

    it('should validate optional include fields', () => {
      const validGetWithIncludes = {
        scenarioId: validUUIDs.scenarioId,
        includeBlueprint: true,
        includeExecutions: false,
        includeStatistics: true
      };

      expect(() => GetScenarioSchema.parse(validGetWithIncludes)).not.toThrow();
    });

    it('should reject invalid include field types', () => {
      expect(() => GetScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        includeBlueprint: 'yes' // Should be boolean
      })).toThrow();
    });

    it('should handle execution limit validation', () => {
      // Valid limit
      expect(() => GetScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        executionLimit: 50
      })).not.toThrow();

      // Negative limit
      expect(() => GetScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        executionLimit: -1
      })).toThrow();

      // Too high limit
      expect(() => GetScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        executionLimit: 10000
      })).toThrow();
    });
  });

  describe('Cross-Schema Consistency', () => {
    it('should maintain consistent UUID validation across schemas', () => {
      const invalidUUID = 'not-a-uuid';
      
      // All schemas should reject invalid UUIDs consistently
      expect(() => CreateScenarioSchema.parse({
        name: 'Test',
        teamId: invalidUUID
      })).toThrow();

      expect(() => UpdateScenarioSchema.parse({
        scenarioId: invalidUUID,
        name: 'Test'
      })).toThrow();

      expect(() => DeleteScenarioSchema.parse({
        scenarioId: invalidUUID
      })).toThrow();

      expect(() => GetScenarioSchema.parse({
        scenarioId: invalidUUID
      })).toThrow();
    });

    it('should maintain consistent blueprint validation', () => {
      const invalidBlueprint = { invalidProperty: 'test' };
      
      // Create and Update schemas should validate blueprints consistently
      expect(() => CreateScenarioSchema.parse({
        name: 'Test',
        teamId: validUUIDs.teamId,
        blueprint: invalidBlueprint
      })).toThrow();

      expect(() => UpdateScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        blueprint: invalidBlueprint
      })).toThrow();
    });
  });

  describe('Edge Cases and Security', () => {
    it('should handle null and undefined values appropriately', () => {
      // Null values in required fields
      expect(() => CreateScenarioSchema.parse({
        name: null,
        teamId: validUUIDs.teamId
      })).toThrow();

      // Undefined values in optional fields should be allowed
      expect(() => CreateScenarioSchema.parse({
        name: 'Test',
        teamId: validUUIDs.teamId,
        folderId: undefined
      })).not.toThrow();
    });

    it('should reject potentially malicious input', () => {
      const maliciousInputs = [
        '<script>alert("xss")</script>',
        '${process.env.SECRET}',
        '../../etc/passwd',
        '\u0000\u0001\u0002'
      ];

      maliciousInputs.forEach(maliciousInput => {
        // Should still validate (schemas don't block content, just format)
        // but shouldn't cause parsing errors
        expect(() => CreateScenarioSchema.parse({
          name: maliciousInput,
          teamId: validUUIDs.teamId
        })).not.toThrow();
      });
    });

    it('should handle extreme values', () => {
      // Very large numbers
      expect(() => GetScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        executionLimit: Number.MAX_SAFE_INTEGER
      })).toThrow();

      // Negative numbers where not allowed
      expect(() => GetScenarioSchema.parse({
        scenarioId: validUUIDs.scenarioId,
        executionLimit: -100
      })).toThrow();
    });
  });
});