/**
 * @fileoverview Unit Tests for Blueprint Analysis Utilities
 * 
 * Tests the comprehensive blueprint validation, structure analysis,
 * and connection extraction utilities used in the refactored scenarios module.
 */

import {
  validateBlueprintStructure,
  extractBlueprintConnections,
  ValidateBlueprintSchema,
  ExtractBlueprintConnectionsSchema,
  type Blueprint,
  type BlueprintModule
} from '../../../../src/tools/scenarios/utils/blueprint-analysis.js';

describe('Blueprint Analysis Utilities', () => {
  describe('validateBlueprintStructure', () => {
    test('should validate a complete valid blueprint', () => {
      const validBlueprint: Blueprint = {
        name: 'Valid Test Blueprint',
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
            parameters: { port: 8080 },
            metadata: { description: 'Webhook trigger' }
          },
          {
            id: 2,
            module: 'http',
            version: 1,
            connection: 1,
            parameters: { url: 'https://api.example.com' },
            metadata: { description: 'HTTP request' }
          }
        ]
      };

      const result = validateBlueprintStructure(validBlueprint, true);

      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toHaveLength(0);
      expect(result.securityIssues).toHaveLength(0);
    });

    test('should detect missing required properties', () => {
      const invalidBlueprints = [
        // Missing name
        {
          metadata: { version: 1 },
          flow: []
        },
        // Missing flow
        {
          name: 'Test',
          metadata: { version: 1 }
        },
        // Missing metadata
        {
          name: 'Test',
          flow: []
        }
      ];

      invalidBlueprints.forEach(blueprint => {
        const result = validateBlueprintStructure(blueprint);
        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
    });

    test('should validate metadata structure', () => {
      const blueprintWithInvalidMetadata = {
        name: 'Test Blueprint',
        metadata: {
          // Missing version
          scenario: {
            roundtrips: 5
          }
        },
        flow: []
      };

      const result = validateBlueprintStructure(blueprintWithInvalidMetadata);
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Blueprint metadata must include version number');
    });

    test('should validate scenario configuration', () => {
      const blueprintWithInvalidScenario = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: -1,  // Invalid
            maxErrors: -5,   // Invalid
            autoCommit: 'true', // Invalid type
            sequential: 'false' // Invalid type
          }
        },
        flow: []
      };

      const result = validateBlueprintStructure(blueprintWithInvalidScenario);
      
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings).toContain('Scenario roundtrips should be a positive number');
      expect(result.warnings).toContain('Scenario maxErrors should be a non-negative number');
      expect(result.warnings).toContain('Scenario autoCommit should be a boolean value');
      expect(result.warnings).toContain('Scenario sequential should be a boolean value');
    });

    test('should validate flow modules', () => {
      const blueprintWithInvalidModules = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false }
        },
        flow: [
          // Invalid module - missing required properties
          {
            id: 'invalid',  // Should be number
            // Missing module property
            version: 'invalid' // Should be number
          },
          // Valid module
          {
            id: 2,
            module: 'http',
            version: 1
          }
        ]
      };

      const result = validateBlueprintStructure(blueprintWithInvalidModules);
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Module at index 0 must have a positive numeric id');
      expect(result.errors).toContain('Module at index 0 must have a module type string');
      expect(result.errors).toContain('Module at index 0 must have a positive version number');
    });

    test('should detect duplicate module IDs', () => {
      const blueprintWithDuplicateIds = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false }
        },
        flow: [
          { id: 1, module: 'webhook', version: 1 },
          { id: 1, module: 'http', version: 1 },  // Duplicate ID
          { id: 2, module: 'email', version: 1 },
          { id: 2, module: 'slack', version: 1 }  // Another duplicate
        ]
      };

      const result = validateBlueprintStructure(blueprintWithDuplicateIds);
      
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Duplicate module IDs found: 1, 2');
    });

    test('should detect security issues', () => {
      const blueprintWithSecurityIssues = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 1,
            autoCommit: true,
            sequential: false,
            confidential: false  // Security concern
          }
        },
        flow: [
          {
            id: 1,
            module: 'http',
            version: 1,
            parameters: {
              url: 'https://user:password@api.example.com/data',  // Credentials in URL
              apikey: 'secret123'  // Potential hardcoded secret
            }
          }
        ]
      };

      const result = validateBlueprintStructure(blueprintWithSecurityIssues, false);
      
      expect(result.securityIssues.length).toBeGreaterThan(0);
      
      // Check for credentials in URL
      const credentialsIssue = result.securityIssues.find(issue => 
        issue.type === 'credentials_in_url'
      );
      expect(credentialsIssue).toBeDefined();
      expect(credentialsIssue?.severity).toBe('critical');

      // Check for potential hardcoded secrets
      const secretIssue = result.securityIssues.find(issue => 
        issue.type === 'potential_hardcoded_secret'
      );
      expect(secretIssue).toBeDefined();
      expect(secretIssue?.severity).toBe('high');

      // Check for non-confidential scenario warning
      const confidentialIssue = result.securityIssues.find(issue => 
        issue.type === 'non_confidential_scenario'
      );
      expect(confidentialIssue).toBeDefined();
      expect(confidentialIssue?.severity).toBe('low');
    });

    test('should provide warnings in strict mode', () => {
      const blueprintForStrictMode = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false }
        },
        flow: [
          {
            id: 1,
            module: 'webhook',
            version: 1
            // Missing metadata (warning in strict mode)
          },
          {
            id: 2,
            module: 'http',
            version: 1,
            connection: 'invalid'  // Invalid connection reference
          }
        ]
      };

      const result = validateBlueprintStructure(blueprintForStrictMode, true);
      
      expect(result.warnings).toContain('Module 1 is missing metadata (recommended for better performance)');
      expect(result.warnings).toContain('Module 2 has invalid connection reference');
    });

    test('should detect sequential ID gaps', () => {
      const blueprintWithIdGaps = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false }
        },
        flow: [
          { id: 1, module: 'webhook', version: 1 },
          { id: 5, module: 'http', version: 1 },    // Gap from 1 to 5
          { id: 10, module: 'email', version: 1 }   // Gap from 5 to 10
        ]
      };

      const result = validateBlueprintStructure(blueprintWithIdGaps);
      
      expect(result.warnings).toContain('Non-sequential module IDs detected (gap between 1 and 5)');
    });

    test('should handle invalid input types', () => {
      const invalidInputs = [
        null,
        undefined,
        'string',
        123,
        [],
        true
      ];

      invalidInputs.forEach(input => {
        const result = validateBlueprintStructure(input);
        expect(result.isValid).toBe(false);
        expect(result.errors).toContain('Blueprint must be a valid JSON object');
      });
    });

    test('should handle validation errors gracefully', () => {
      const problematicBlueprint = {
        name: 'Test Blueprint',
        metadata: {
          version: 1,
          scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false }
        },
        flow: [
          {
            // Object that might cause issues during validation
            id: { toString: () => { throw new Error('toString error'); } },
            module: 'test',
            version: 1
          }
        ]
      };

      const result = validateBlueprintStructure(problematicBlueprint);
      
      // Should handle errors gracefully
      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('extractBlueprintConnections', () => {
    test('should extract connections from a valid blueprint', () => {
      const blueprintWithConnections: Blueprint = {
        name: 'Connection Test Blueprint',
        flow: [
          {
            id: 1,
            module: 'webhook',
            version: 1
            // No connection needed for webhook
          },
          {
            id: 2,
            module: 'http:request',
            version: 1,
            connection: 1
          },
          {
            id: 3,
            module: 'database:mysql',
            version: 1,
            connection: 2
          },
          {
            id: 4,
            module: 'builtin:BasicRouter',
            version: 1
            // No connection needed for builtin router
          },
          {
            id: 5,
            module: 'email:send',
            version: 1,
            connection: 3
          }
        ]
      };

      const result = extractBlueprintConnections(blueprintWithConnections, false);

      expect(result.requiredConnections).toHaveLength(3);
      expect(result.connectionSummary.totalModules).toBe(5);
      expect(result.connectionSummary.modulesRequiringConnections).toBe(3);
      expect(result.connectionSummary.uniqueServices).toContain('http');
      expect(result.connectionSummary.uniqueServices).toContain('database');
      expect(result.connectionSummary.uniqueServices).toContain('email');

      // Check dependency map
      expect(result.dependencyMap.http).toEqual([2]);
      expect(result.dependencyMap.database).toEqual([3]);
      expect(result.dependencyMap.email).toEqual([5]);
    });

    test('should include optional connections when requested', () => {
      const blueprintWithOptionalConnections: Blueprint = {
        name: 'Optional Connection Test',
        flow: [
          {
            id: 1,
            module: 'builtin:Iterator',
            version: 1,
            connection: 1  // Optional connection for builtin module
          },
          {
            id: 2,
            module: 'http:request',
            version: 1,
            connection: 2  // Required connection
          }
        ]
      };

      // Without optional connections
      const resultWithoutOptional = extractBlueprintConnections(blueprintWithOptionalConnections, false);
      expect(resultWithoutOptional.requiredConnections).toHaveLength(1);
      expect(resultWithoutOptional.requiredConnections[0].moduleId).toBe(2);

      // With optional connections
      const resultWithOptional = extractBlueprintConnections(blueprintWithOptionalConnections, true);
      expect(resultWithOptional.requiredConnections).toHaveLength(2);
      
      const iteratorConnection = resultWithOptional.requiredConnections.find(conn => conn.moduleId === 1);
      expect(iteratorConnection).toBeDefined();
      expect(iteratorConnection?.required).toBe(false);

      const httpConnection = resultWithOptional.requiredConnections.find(conn => conn.moduleId === 2);
      expect(httpConnection).toBeDefined();
      expect(httpConnection?.required).toBe(true);
    });

    test('should handle blueprints with no connections', () => {
      const blueprintWithoutConnections: Blueprint = {
        name: 'No Connection Blueprint',
        flow: [
          { id: 1, module: 'builtin:BasicRouter', version: 1 },
          { id: 2, module: 'builtin:Delay', version: 1 },
          { id: 3, module: 'builtin:JSONTransformer', version: 1 }
        ]
      };

      const result = extractBlueprintConnections(blueprintWithoutConnections);

      expect(result.requiredConnections).toHaveLength(0);
      expect(result.connectionSummary.totalModules).toBe(3);
      expect(result.connectionSummary.modulesRequiringConnections).toBe(0);
      expect(result.connectionSummary.uniqueServices).toHaveLength(0);
      expect(Object.keys(result.dependencyMap)).toHaveLength(0);
    });

    test('should identify service types correctly', () => {
      const blueprintWithVariousServices: Blueprint = {
        name: 'Service Type Test',
        flow: [
          { id: 1, module: 'http:get', version: 1, connection: 1 },
          { id: 2, module: 'http:post', version: 1, connection: 2 },
          { id: 3, module: 'database:postgresql', version: 1, connection: 3 },
          { id: 4, module: 'email:send', version: 1, connection: 4 },
          { id: 5, module: 'slack:message', version: 1, connection: 5 },
          { id: 6, module: 'unknown_service', version: 1, connection: 6 } // No colon separator
        ]
      };

      const result = extractBlueprintConnections(blueprintWithVariousServices);

      expect(result.connectionSummary.uniqueServices).toContain('http');
      expect(result.connectionSummary.uniqueServices).toContain('database');
      expect(result.connectionSummary.uniqueServices).toContain('email');
      expect(result.connectionSummary.uniqueServices).toContain('slack');
      expect(result.connectionSummary.uniqueServices).toContain('unknown');

      // HTTP service should have multiple modules
      expect(result.dependencyMap.http).toEqual([1, 2]);
    });

    test('should group connections by module when requested', () => {
      const blueprintForGrouping: Blueprint = {
        name: 'Grouping Test',
        flow: [
          { id: 1, module: 'http:get', version: 1, connection: 1 },
          { id: 2, module: 'http:post', version: 1, connection: 2 },
          { id: 3, module: 'database:query', version: 1, connection: 3 }
        ]
      };

      const result = extractBlueprintConnections(blueprintForGrouping, false);

      expect(result.dependencyMap.http).toEqual([1, 2]);
      expect(result.dependencyMap.database).toEqual([3]);
    });

    test('should handle invalid blueprint structures', () => {
      const invalidBlueprints = [
        null,
        undefined,
        {},  // Missing flow
        { flow: null },  // Invalid flow
        { flow: 'invalid' }  // Non-array flow
      ];

      invalidBlueprints.forEach(blueprint => {
        expect(() => extractBlueprintConnections(blueprint)).toThrow();
      });
    });

    test('should skip invalid modules gracefully', () => {
      const blueprintWithInvalidModules: Blueprint = {
        name: 'Invalid Modules Test',
        flow: [
          null,  // Invalid module
          { id: 'invalid', module: 'test', version: 1 },  // Invalid ID type
          { module: 'test', version: 1 },  // Missing ID
          { id: 2, module: 'http:request', version: 1, connection: 1 }  // Valid module
        ]
      };

      const result = extractBlueprintConnections(blueprintWithInvalidModules);

      // Should only process the valid module
      expect(result.requiredConnections).toHaveLength(1);
      expect(result.requiredConnections[0].moduleId).toBe(2);
    });

    test('should handle complex connection scenarios', () => {
      const complexBlueprint: Blueprint = {
        name: 'Complex Connection Test',
        flow: [
          // Webhook (no connection needed)
          { id: 1, module: 'webhook', version: 1 },
          
          // Multiple HTTP modules with different connections
          { id: 2, module: 'http:get', version: 1, connection: 1 },
          { id: 3, module: 'http:post', version: 1, connection: 2 },
          { id: 4, module: 'http:put', version: 1, connection: 1 }, // Reuse connection 1
          
          // Database modules
          { id: 5, module: 'database:mysql', version: 1, connection: 3 },
          { id: 6, module: 'database:postgresql', version: 1, connection: 4 },
          
          // Builtin modules (some with optional connections)
          { id: 7, module: 'builtin:Iterator', version: 1 },
          { id: 8, module: 'builtin:JSONTransformer', version: 1, connection: 5 },
          
          // Email module
          { id: 9, module: 'email:send', version: 1, connection: 6 }
        ]
      };

      const result = extractBlueprintConnections(complexBlueprint, true);

      expect(result.connectionSummary.totalModules).toBe(9);
      expect(result.requiredConnections.length).toBeGreaterThan(4);
      
      // Check that HTTP modules are grouped together
      expect(result.dependencyMap.http).toEqual([2, 3, 4]);
      
      // Check that database modules are separate by specific type
      expect(result.connectionSummary.uniqueServices).toContain('database');
      
      // Verify builtin modules are handled correctly
      const builtinConnection = result.requiredConnections.find(conn => 
        conn.moduleType === 'builtin:JSONTransformer'
      );
      expect(builtinConnection?.required).toBe(false); // Optional for builtin
    });
  });

  describe('Schema Validation', () => {
    test('ValidateBlueprintSchema should work correctly', () => {
      const validData = {
        blueprint: { modules: [] },
        strict: true,
        includeSecurityChecks: false
      };

      const result = ValidateBlueprintSchema.parse(validData);
      expect(result).toEqual(validData);

      // Test defaults
      const minimalData = { blueprint: {} };
      const resultWithDefaults = ValidateBlueprintSchema.parse(minimalData);
      expect(resultWithDefaults.strict).toBe(false);
      expect(resultWithDefaults.includeSecurityChecks).toBe(true);
    });

    test('ExtractBlueprintConnectionsSchema should work correctly', () => {
      const validData = {
        blueprint: { flow: [] },
        includeOptional: true,
        groupByModule: false
      };

      const result = ExtractBlueprintConnectionsSchema.parse(validData);
      expect(result).toEqual(validData);

      // Test defaults
      const minimalData = { blueprint: {} };
      const resultWithDefaults = ExtractBlueprintConnectionsSchema.parse(minimalData);
      expect(resultWithDefaults.includeOptional).toBe(false);
      expect(resultWithDefaults.groupByModule).toBe(true);
    });
  });

  describe('Integration and Edge Cases', () => {
    test('should handle large blueprints efficiently', () => {
      const largeBlueprint: Blueprint = {
        name: 'Large Blueprint Test',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 5,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: Array.from({ length: 1000 }, (_, i) => ({
          id: i + 1,
          module: i % 2 === 0 ? 'http:request' : 'builtin:Iterator',
          version: 1,
          connection: i % 2 === 0 ? Math.floor(i / 10) + 1 : undefined,
          parameters: { config: `value_${i}` }
        }))
      };

      const startTime = Date.now();
      const validationResult = validateBlueprintStructure(largeBlueprint, true);
      const validationTime = Date.now() - startTime;

      expect(validationTime).toBeLessThan(1000); // Should complete within 1 second
      expect(validationResult.isValid).toBe(true);

      const connectionStartTime = Date.now();
      const connectionResult = extractBlueprintConnections(largeBlueprint, true);
      const connectionTime = Date.now() - connectionStartTime;

      expect(connectionTime).toBeLessThan(1000); // Should complete within 1 second
      expect(connectionResult.connectionSummary.totalModules).toBe(1000);
    });

    test('should maintain consistency between validation and extraction', () => {
      const testBlueprint: Blueprint = {
        name: 'Consistency Test',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 3,
            maxErrors: 2,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: [
          { id: 1, module: 'webhook', version: 1 },
          { id: 2, module: 'http:request', version: 1, connection: 1 },
          { id: 3, module: 'database:query', version: 1, connection: 2 }
        ]
      };

      const validationResult = validateBlueprintStructure(testBlueprint);
      const connectionResult = extractBlueprintConnections(testBlueprint);

      // If validation passes, connection extraction should also work
      expect(validationResult.isValid).toBe(true);
      expect(() => extractBlueprintConnections(testBlueprint)).not.toThrow();
      
      // Module count should be consistent
      expect(connectionResult.connectionSummary.totalModules).toBe(testBlueprint.flow!.length);
    });

    test('should handle Unicode and special characters', () => {
      const unicodeBlueprint: Blueprint = {
        name: 'Unicode Test 测试 🚀',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 1,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: [
          {
            id: 1,
            module: 'http:request',
            version: 1,
            connection: 1,
            parameters: {
              url: 'https://api.测试.com/data',
              headers: {
                'Content-Type': 'application/json; charset=utf-8',
                'Description': 'API call with émojis 🔥'
              }
            },
            metadata: {
              description: 'Unicode test module with 特殊字符'
            }
          }
        ]
      };

      const validationResult = validateBlueprintStructure(unicodeBlueprint);
      const connectionResult = extractBlueprintConnections(unicodeBlueprint);

      expect(validationResult.isValid).toBe(true);
      expect(connectionResult.requiredConnections).toHaveLength(1);
    });
  });
});