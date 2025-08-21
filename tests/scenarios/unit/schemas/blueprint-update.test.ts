/**
 * @fileoverview Unit Tests for Blueprint Update Schemas
 * 
 * Tests all Zod validation schemas used for blueprint and scenario modification operations.
 * Ensures robust input validation and proper error handling.
 */

import { z } from 'zod';
import {
  CreateScenarioSchema,
  UpdateScenarioSchema,
  DeleteScenarioSchema,
  CloneScenarioSchema,
  ValidateBlueprintSchema,
  ExtractBlueprintConnectionsSchema,
  OptimizeBlueprintSchema,
  type CreateScenario,
  type UpdateScenario,
  type DeleteScenario,
  type CloneScenario,
  type ValidateBlueprint,
  type ExtractBlueprintConnections,
  type OptimizeBlueprint
} from '../../../../src/tools/scenarios/schemas/blueprint-update.js';

describe('Blueprint Update Schemas', () => {
  describe('CreateScenarioSchema', () => {
    test('should accept valid minimal scenario creation data', () => {
      const validData = { name: 'Test Scenario' };
      const result = CreateScenarioSchema.parse(validData);
      expect(result.name).toBe('Test Scenario');
    });

    test('should accept complete scenario creation data', () => {
      const completeData: CreateScenario = {
        name: 'Complete Test Scenario',
        teamId: 'team_123',
        folderId: 'folder_456',
        blueprint: { modules: [], connections: [] },
        scheduling: {
          type: 'interval',
          interval: 30
        }
      };

      const result = CreateScenarioSchema.parse(completeData);
      expect(result).toEqual(completeData);
    });

    test('should apply default scheduling type', () => {
      const dataWithScheduling = {
        name: 'Test Scenario',
        scheduling: {}
      };

      const result = CreateScenarioSchema.parse(dataWithScheduling);
      expect(result.scheduling?.type).toBe('immediately');
    });

    test('should validate scheduling configurations', () => {
      // Valid interval scheduling
      const intervalData = {
        name: 'Test',
        scheduling: { type: 'interval' as const, interval: 60 }
      };
      expect(() => CreateScenarioSchema.parse(intervalData)).not.toThrow();

      // Valid cron scheduling
      const cronData = {
        name: 'Test',
        scheduling: { type: 'cron' as const, cron: '0 9 * * 1' }
      };
      expect(() => CreateScenarioSchema.parse(cronData)).not.toThrow();

      // Valid immediately scheduling
      const immediateData = {
        name: 'Test',
        scheduling: { type: 'immediately' as const }
      };
      expect(() => CreateScenarioSchema.parse(immediateData)).not.toThrow();
    });

    test('should reject invalid data', () => {
      const invalidCases = [
        {}, // Missing name
        { name: '' }, // Empty name
        { name: 'a'.repeat(101) }, // Name too long
        { name: 'Test', scheduling: { type: 'invalid' } }, // Invalid scheduling type
        { name: 'Test', scheduling: { type: 'interval', interval: -1 } }, // Invalid interval
        { name: 'Test', unknownField: 'value' } // Unknown field
      ];

      invalidCases.forEach(invalidData => {
        expect(() => CreateScenarioSchema.parse(invalidData)).toThrow();
      });
    });

    test('should handle complex blueprint data', () => {
      const complexBlueprint = {
        name: 'Complex Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 5,
            maxErrors: 3,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: [
          {
            id: 1,
            module: 'webhook',
            version: 1,
            parameters: {
              port: 8080,
              path: '/webhook'
            }
          }
        ]
      };

      const dataWithComplexBlueprint = {
        name: 'Test Scenario',
        blueprint: complexBlueprint
      };

      const result = CreateScenarioSchema.parse(dataWithComplexBlueprint);
      expect(result.blueprint).toEqual(complexBlueprint);
    });
  });

  describe('UpdateScenarioSchema', () => {
    test('should require scenarioId', () => {
      expect(() => UpdateScenarioSchema.parse({})).toThrow();
      expect(() => UpdateScenarioSchema.parse({ name: 'Test' })).toThrow();
    });

    test('should accept valid update data', () => {
      const validUpdates = [
        { scenarioId: 'scn_123', name: 'Updated Name' },
        { scenarioId: 'scn_123', active: true },
        { scenarioId: 'scn_123', active: false },
        { scenarioId: 'scn_123', blueprint: { modules: [] } },
        {
          scenarioId: 'scn_123',
          scheduling: {
            type: 'cron' as const,
            cron: '0 */6 * * *'
          }
        },
        {
          scenarioId: 'scn_123',
          name: 'Complete Update',
          active: true,
          blueprint: { modules: [], connections: [] },
          scheduling: {
            type: 'interval' as const,
            interval: 120
          }
        }
      ];

      validUpdates.forEach(updateData => {
        const result = UpdateScenarioSchema.parse(updateData);
        expect(result.scenarioId).toBe('scn_123');
      });
    });

    test('should reject invalid update data', () => {
      const invalidCases = [
        { scenarioId: '' }, // Empty scenarioId
        { scenarioId: 'scn_123', name: '' }, // Empty name
        { scenarioId: 'scn_123', name: 'a'.repeat(101) }, // Name too long
        { scenarioId: 'scn_123', unknownField: 'value' } // Unknown field
      ];

      invalidCases.forEach(invalidData => {
        expect(() => UpdateScenarioSchema.parse(invalidData)).toThrow();
      });
    });

    test('should validate scheduling in updates', () => {
      const validSchedulingUpdates = [
        {
          scenarioId: 'scn_123',
          scheduling: { type: 'immediately' as const }
        },
        {
          scenarioId: 'scn_123',
          scheduling: { type: 'interval' as const, interval: 45 }
        },
        {
          scenarioId: 'scn_123',
          scheduling: { type: 'cron' as const, cron: '0 0 * * 0' }
        }
      ];

      validSchedulingUpdates.forEach(updateData => {
        expect(() => UpdateScenarioSchema.parse(updateData)).not.toThrow();
      });

      // Invalid scheduling
      const invalidSchedulingUpdate = {
        scenarioId: 'scn_123',
        scheduling: { type: 'invalid' }
      };
      expect(() => UpdateScenarioSchema.parse(invalidSchedulingUpdate)).toThrow();
    });
  });

  describe('DeleteScenarioSchema', () => {
    test('should accept valid delete data', () => {
      const validCases = [
        { scenarioId: 'scn_123' },
        { scenarioId: 'scn_123', force: false },
        { scenarioId: 'scn_123', force: true }
      ];

      validCases.forEach(deleteData => {
        const result = DeleteScenarioSchema.parse(deleteData);
        expect(result.scenarioId).toBe('scn_123');
      });
    });

    test('should apply default force value', () => {
      const result = DeleteScenarioSchema.parse({ scenarioId: 'scn_123' });
      expect(result.force).toBe(false);
    });

    test('should reject invalid delete data', () => {
      const invalidCases = [
        {}, // Missing scenarioId
        { scenarioId: '' }, // Empty scenarioId
        { scenarioId: 'scn_123', unknownField: 'value' } // Unknown field
      ];

      invalidCases.forEach(invalidData => {
        expect(() => DeleteScenarioSchema.parse(invalidData)).toThrow();
      });
    });
  });

  describe('CloneScenarioSchema', () => {
    test('should require both scenarioId and name', () => {
      expect(() => CloneScenarioSchema.parse({})).toThrow();
      expect(() => CloneScenarioSchema.parse({ scenarioId: 'scn_123' })).toThrow();
      expect(() => CloneScenarioSchema.parse({ name: 'Cloned' })).toThrow();
    });

    test('should accept valid clone data', () => {
      const validCloneData: CloneScenario = {
        scenarioId: 'scn_source',
        name: 'Cloned Scenario',
        teamId: 'team_456',
        folderId: 'folder_789',
        active: true
      };

      const result = CloneScenarioSchema.parse(validCloneData);
      expect(result).toEqual(validCloneData);
    });

    test('should apply default active value', () => {
      const minimalCloneData = {
        scenarioId: 'scn_123',
        name: 'Cloned Scenario'
      };

      const result = CloneScenarioSchema.parse(minimalCloneData);
      expect(result.active).toBe(false);
    });

    test('should validate name length', () => {
      const longNameData = {
        scenarioId: 'scn_123',
        name: 'a'.repeat(101)
      };

      expect(() => CloneScenarioSchema.parse(longNameData)).toThrow();
    });

    test('should reject invalid clone data', () => {
      const invalidCases = [
        { scenarioId: '', name: 'Test' }, // Empty scenarioId
        { scenarioId: 'scn_123', name: '' }, // Empty name
        { scenarioId: 'scn_123', name: 'Test', unknownField: 'value' } // Unknown field
      ];

      invalidCases.forEach(invalidData => {
        expect(() => CloneScenarioSchema.parse(invalidData)).toThrow();
      });
    });
  });

  describe('ValidateBlueprintSchema', () => {
    test('should accept valid blueprint validation data', () => {
      const validData: ValidateBlueprint = {
        blueprint: { modules: [], connections: [] },
        strict: true,
        includeSecurityChecks: false
      };

      const result = ValidateBlueprintSchema.parse(validData);
      expect(result).toEqual(validData);
    });

    test('should apply default values', () => {
      const minimalData = { blueprint: { modules: [] } };
      const result = ValidateBlueprintSchema.parse(minimalData);
      
      expect(result.strict).toBe(false);
      expect(result.includeSecurityChecks).toBe(true);
    });

    test('should accept any blueprint structure', () => {
      const complexBlueprint = {
        name: 'Complex Blueprint',
        metadata: { version: 1 },
        flow: [
          { id: 1, module: 'webhook', version: 1 }
        ],
        customField: 'custom value'
      };

      const data = { blueprint: complexBlueprint };
      const result = ValidateBlueprintSchema.parse(data);
      expect(result.blueprint).toEqual(complexBlueprint);
    });
  });

  describe('ExtractBlueprintConnectionsSchema', () => {
    test('should accept valid connection extraction data', () => {
      const validData: ExtractBlueprintConnections = {
        blueprint: { modules: [] },
        includeOptional: true,
        groupByModule: false
      };

      const result = ExtractBlueprintConnectionsSchema.parse(validData);
      expect(result).toEqual(validData);
    });

    test('should apply default values', () => {
      const minimalData = { blueprint: { modules: [] } };
      const result = ExtractBlueprintConnectionsSchema.parse(minimalData);
      
      expect(result.includeOptional).toBe(false);
      expect(result.groupByModule).toBe(true);
    });

    test('should handle complex blueprint structures', () => {
      const complexBlueprint = {
        flow: [
          {
            id: 1,
            module: 'http:request',
            version: 1,
            connection: 1,
            parameters: { url: 'https://api.example.com' }
          },
          {
            id: 2,
            module: 'database:mysql',
            version: 1,
            connection: 2,
            parameters: { query: 'SELECT * FROM users' }
          }
        ]
      };

      const data = { blueprint: complexBlueprint };
      const result = ExtractBlueprintConnectionsSchema.parse(data);
      expect(result.blueprint).toEqual(complexBlueprint);
    });
  });

  describe('OptimizeBlueprintSchema', () => {
    test('should accept valid optimization data', () => {
      const validData: OptimizeBlueprint = {
        blueprint: { modules: [] },
        optimizationType: 'security',
        includeImplementationSteps: false
      };

      const result = OptimizeBlueprintSchema.parse(validData);
      expect(result).toEqual(validData);
    });

    test('should apply default values', () => {
      const minimalData = { blueprint: { modules: [] } };
      const result = OptimizeBlueprintSchema.parse(minimalData);
      
      expect(result.optimizationType).toBe('performance');
      expect(result.includeImplementationSteps).toBe(true);
    });

    test('should validate optimization types', () => {
      const validTypes: Array<'performance' | 'cost' | 'security' | 'all'> = [
        'performance', 'cost', 'security', 'all'
      ];

      validTypes.forEach(type => {
        const data = { blueprint: {}, optimizationType: type };
        expect(() => OptimizeBlueprintSchema.parse(data)).not.toThrow();
      });

      const invalidData = { blueprint: {}, optimizationType: 'invalid' };
      expect(() => OptimizeBlueprintSchema.parse(invalidData)).toThrow();
    });

    test('should handle large blueprint optimization requests', () => {
      const largeBlueprint = {
        flow: Array.from({ length: 100 }, (_, i) => ({
          id: i + 1,
          module: `module_${i}`,
          version: 1,
          parameters: { config: `value_${i}` }
        }))
      };

      const data = {
        blueprint: largeBlueprint,
        optimizationType: 'all' as const,
        includeImplementationSteps: true
      };

      const result = OptimizeBlueprintSchema.parse(data);
      expect(result.blueprint.flow).toHaveLength(100);
    });
  });

  describe('Schema Type Integration', () => {
    test('should export proper TypeScript types', () => {
      // Test that the inferred types match expected interfaces
      const createData: CreateScenario = {
        name: 'Type Test Scenario',
        teamId: 'team_123',
        scheduling: {
          type: 'interval',
          interval: 30
        }
      };

      const updateData: UpdateScenario = {
        scenarioId: 'scn_123',
        name: 'Updated Scenario',
        active: true
      };

      const deleteData: DeleteScenario = {
        scenarioId: 'scn_123',
        force: true
      };

      const cloneData: CloneScenario = {
        scenarioId: 'scn_source',
        name: 'Cloned Scenario',
        active: false
      };

      // These should compile without errors
      expect(createData.name).toBe('Type Test Scenario');
      expect(updateData.scenarioId).toBe('scn_123');
      expect(deleteData.force).toBe(true);
      expect(cloneData.active).toBe(false);
    });

    test('should handle schema composition and inheritance', () => {
      // Test that schemas properly compose and share common structures
      const schedulingConfig = {
        type: 'cron' as const,
        cron: '0 0 * * 0'
      };

      // Should work in create scenario
      const createData = {
        name: 'Test Scenario',
        scheduling: schedulingConfig
      };
      expect(() => CreateScenarioSchema.parse(createData)).not.toThrow();

      // Should work in update scenario
      const updateData = {
        scenarioId: 'scn_123',
        scheduling: schedulingConfig
      };
      expect(() => UpdateScenarioSchema.parse(updateData)).not.toThrow();
    });

    test('should provide consistent error messages', () => {
      try {
        CreateScenarioSchema.parse({ name: '' });
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error).toBeInstanceOf(z.ZodError);
        const zodError = error as z.ZodError;
        expect(zodError.errors[0].message).toContain('String must contain at least 1 character');
      }

      try {
        UpdateScenarioSchema.parse({ scenarioId: '' });
        fail('Should have thrown validation error');
      } catch (error) {
        expect(error).toBeInstanceOf(z.ZodError);
        const zodError = error as z.ZodError;
        expect(zodError.errors[0].message).toContain('String must contain at least 1 character');
      }
    });
  });

  describe('Edge Cases and Boundary Values', () => {
    test('should handle boundary values for string lengths', () => {
      // Test minimum valid name
      const minName = { name: 'a' };
      expect(() => CreateScenarioSchema.parse(minName)).not.toThrow();

      // Test maximum valid name
      const maxName = { name: 'a'.repeat(100) };
      expect(() => CreateScenarioSchema.parse(maxName)).not.toThrow();

      // Test over-limit name
      const overLimitName = { name: 'a'.repeat(101) };
      expect(() => CreateScenarioSchema.parse(overLimitName)).toThrow();
    });

    test('should handle interval boundary values', () => {
      // Valid minimum interval
      const minInterval = {
        name: 'Test',
        scheduling: { type: 'interval' as const, interval: 1 }
      };
      expect(() => CreateScenarioSchema.parse(minInterval)).not.toThrow();

      // Invalid zero interval
      const zeroInterval = {
        name: 'Test',
        scheduling: { type: 'interval' as const, interval: 0 }
      };
      expect(() => CreateScenarioSchema.parse(zeroInterval)).toThrow();

      // Invalid negative interval
      const negativeInterval = {
        name: 'Test',
        scheduling: { type: 'interval' as const, interval: -1 }
      };
      expect(() => CreateScenarioSchema.parse(negativeInterval)).toThrow();
    });

    test('should handle special character scenarios', () => {
      const specialCharNames = [
        'Scenario with spaces',
        'Scenario-with-hyphens',
        'Scenario_with_underscores',
        'Scenario (with parentheses)',
        'Scenario [with brackets]',
        'Scenario {with braces}',
        'Scenario with émojis 🚀',
        'Scenario with unicode: 测试'
      ];

      specialCharNames.forEach(name => {
        const data = { name };
        expect(() => CreateScenarioSchema.parse(data)).not.toThrow();
      });
    });

    test('should handle null and undefined values appropriately', () => {
      // Should reject null names
      expect(() => CreateScenarioSchema.parse({ name: null })).toThrow();
      
      // Should reject undefined names
      expect(() => CreateScenarioSchema.parse({ name: undefined })).toThrow();

      // Should handle optional fields being undefined
      const dataWithOptionalUndefined = {
        name: 'Test',
        teamId: undefined, // Optional field
        blueprint: undefined // Optional field
      };
      const result = CreateScenarioSchema.parse(dataWithOptionalUndefined);
      expect(result.teamId).toBeUndefined();
      expect(result.blueprint).toBeUndefined();
    });
  });
});