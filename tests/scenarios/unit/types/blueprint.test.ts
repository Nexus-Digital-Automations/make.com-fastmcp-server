/**
 * @fileoverview Unit Tests for Blueprint Types
 * 
 * Tests the blueprint type definitions and interfaces used in the refactored scenarios module.
 * Validates TypeScript type correctness and interface compliance.
 */

import { 
  BlueprintModule, 
  Blueprint, 
  OptimizationRecommendation 
} from '../../../../src/tools/scenarios/types/blueprint.js';

describe('Blueprint Types', () => {
  describe('BlueprintModule Interface', () => {
    test('should accept valid BlueprintModule objects', () => {
      const validModule: BlueprintModule = {
        id: 1,
        module: 'webhook',
        version: 1
      };

      expect(validModule.id).toBe(1);
      expect(validModule.module).toBe('webhook');
      expect(validModule.version).toBe(1);
    });

    test('should accept BlueprintModule with optional properties', () => {
      const moduleWithOptionals: BlueprintModule = {
        id: 2,
        module: 'http',
        version: 1,
        parameters: { url: 'https://api.example.com' },
        connection: 1,
        metadata: { description: 'HTTP request module' }
      };

      expect(moduleWithOptionals.parameters).toEqual({ url: 'https://api.example.com' });
      expect(moduleWithOptionals.connection).toBe(1);
      expect(moduleWithOptionals.metadata).toEqual({ description: 'HTTP request module' });
    });

    test('should handle complex parameter objects', () => {
      const complexModule: BlueprintModule = {
        id: 3,
        module: 'database:mysql',
        version: 2,
        parameters: {
          connection: {
            host: 'localhost',
            port: 3306,
            database: 'testdb'
          },
          query: 'SELECT * FROM users WHERE active = ?',
          bindings: [true],
          options: {
            timeout: 30000,
            retry: 3
          }
        },
        connection: 2,
        metadata: {
          category: 'database',
          tags: ['mysql', 'select'],
          createdAt: '2024-01-15T10:00:00Z'
        }
      };

      expect(complexModule.parameters).toBeDefined();
      expect(complexModule.parameters!.connection).toEqual({
        host: 'localhost',
        port: 3306,
        database: 'testdb'
      });
      expect(complexModule.metadata!.tags).toEqual(['mysql', 'select']);
    });
  });

  describe('Blueprint Interface', () => {
    test('should accept minimal valid Blueprint', () => {
      const minimalBlueprint: Blueprint = {
        name: 'Simple Blueprint'
      };

      expect(minimalBlueprint.name).toBe('Simple Blueprint');
    });

    test('should accept complete Blueprint with all properties', () => {
      const completeBlueprint: Blueprint = {
        name: 'Complete Blueprint',
        metadata: {
          version: 2,
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
            parameters: { port: 8080 }
          },
          {
            id: 2,
            module: 'http',
            version: 1,
            connection: 1,
            parameters: { url: 'https://api.example.com' }
          }
        ],
        customProperty: 'custom value',
        anotherProperty: { nested: 'object' }
      };

      expect(completeBlueprint.name).toBe('Complete Blueprint');
      expect(completeBlueprint.metadata!.version).toBe(2);
      expect(completeBlueprint.metadata!.scenario!.roundtrips).toBe(5);
      expect(completeBlueprint.flow).toHaveLength(2);
      expect(completeBlueprint.customProperty).toBe('custom value');
      expect(completeBlueprint.anotherProperty).toEqual({ nested: 'object' });
    });

    test('should handle blueprint with optional metadata properties', () => {
      const partialMetadataBlueprint: Blueprint = {
        name: 'Partial Metadata Blueprint',
        metadata: {
          version: 1
          // scenario property is optional
        },
        flow: []
      };

      expect(partialMetadataBlueprint.metadata!.version).toBe(1);
      expect(partialMetadataBlueprint.metadata!.scenario).toBeUndefined();
    });

    test('should handle blueprint with partial scenario metadata', () => {
      const partialScenarioBlueprint: Blueprint = {
        name: 'Partial Scenario Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 3,
            autoCommit: false
            // Other scenario properties are optional
          }
        },
        flow: []
      };

      expect(partialScenarioBlueprint.metadata!.scenario!.roundtrips).toBe(3);
      expect(partialScenarioBlueprint.metadata!.scenario!.autoCommit).toBe(false);
      expect(partialScenarioBlueprint.metadata!.scenario!.maxErrors).toBeUndefined();
    });

    test('should handle blueprint with empty flow', () => {
      const emptyFlowBlueprint: Blueprint = {
        name: 'Empty Flow Blueprint',
        flow: []
      };

      expect(emptyFlowBlueprint.flow).toEqual([]);
    });

    test('should handle blueprint with complex flow modules', () => {
      const complexFlowBlueprint: Blueprint = {
        name: 'Complex Flow Blueprint',
        flow: [
          {
            id: 1,
            module: 'builtin:Webhook',
            version: 1,
            parameters: {
              port: 8080,
              path: '/webhook',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer token'
              }
            }
          },
          {
            id: 2,
            module: 'http:Request',
            version: 2,
            connection: 1,
            parameters: {
              url: 'https://api.external.com/data',
              method: 'GET',
              headers: {},
              timeout: 30000
            },
            metadata: {
              description: 'Fetch external data',
              category: 'api'
            }
          },
          {
            id: 3,
            module: 'builtin:JSONTransformer',
            version: 1,
            parameters: {
              mapping: {
                'id': '$.data.id',
                'name': '$.data.attributes.name',
                'email': '$.data.attributes.email'
              }
            }
          }
        ]
      };

      expect(complexFlowBlueprint.flow).toHaveLength(3);
      expect(complexFlowBlueprint.flow![0].parameters!.port).toBe(8080);
      expect(complexFlowBlueprint.flow![1].connection).toBe(1);
      expect(complexFlowBlueprint.flow![2].parameters!.mapping).toBeDefined();
    });

    test('should handle blueprint with arbitrary additional properties', () => {
      const extendedBlueprint: Blueprint = {
        name: 'Extended Blueprint',
        customField: 'custom value',
        nestedObject: {
          property1: 'value1',
          property2: 42,
          property3: ['array', 'values']
        },
        arrayField: [1, 2, 3, 4, 5],
        booleanField: true,
        nullField: null
      };

      expect(extendedBlueprint.customField).toBe('custom value');
      expect(extendedBlueprint.nestedObject).toEqual({
        property1: 'value1',
        property2: 42,
        property3: ['array', 'values']
      });
      expect(extendedBlueprint.arrayField).toEqual([1, 2, 3, 4, 5]);
      expect(extendedBlueprint.booleanField).toBe(true);
      expect(extendedBlueprint.nullField).toBe(null);
    });
  });

  describe('OptimizationRecommendation Interface', () => {
    test('should accept minimal OptimizationRecommendation', () => {
      const minimalRecommendation: OptimizationRecommendation = {
        category: 'performance',
        priority: 'high',
        title: 'Optimize API Calls',
        description: 'Reduce the number of API calls by batching requests'
      };

      expect(minimalRecommendation.category).toBe('performance');
      expect(minimalRecommendation.priority).toBe('high');
      expect(minimalRecommendation.title).toBe('Optimize API Calls');
      expect(minimalRecommendation.description).toBe('Reduce the number of API calls by batching requests');
    });

    test('should accept complete OptimizationRecommendation with all properties', () => {
      const completeRecommendation: OptimizationRecommendation = {
        category: 'security',
        priority: 'medium',
        title: 'Implement Input Validation',
        description: 'Add comprehensive input validation to prevent security vulnerabilities',
        estimatedImpact: '30% reduction in security risks',
        implementationSteps: [
          'Identify all input points in the scenario',
          'Define validation rules for each input type',
          'Implement validation modules',
          'Test validation with various inputs',
          'Monitor validation effectiveness'
        ]
      };

      expect(completeRecommendation.category).toBe('security');
      expect(completeRecommendation.priority).toBe('medium');
      expect(completeRecommendation.estimatedImpact).toBe('30% reduction in security risks');
      expect(completeRecommendation.implementationSteps).toHaveLength(5);
      expect(completeRecommendation.implementationSteps![0]).toBe('Identify all input points in the scenario');
    });

    test('should accept different priority levels', () => {
      const priorities: ('high' | 'medium' | 'low')[] = ['high', 'medium', 'low'];
      
      priorities.forEach(priority => {
        const recommendation: OptimizationRecommendation = {
          category: 'test',
          priority: priority,
          title: `${priority} Priority Recommendation`,
          description: `This is a ${priority} priority recommendation`
        };

        expect(recommendation.priority).toBe(priority);
      });
    });

    test('should handle recommendation with empty implementation steps', () => {
      const recommendationWithEmptySteps: OptimizationRecommendation = {
        category: 'cost',
        priority: 'low',
        title: 'Cost Optimization',
        description: 'General cost optimization recommendation',
        implementationSteps: []
      };

      expect(recommendationWithEmptySteps.implementationSteps).toEqual([]);
    });

    test('should handle complex implementation steps', () => {
      const complexRecommendation: OptimizationRecommendation = {
        category: 'performance',
        priority: 'high',
        title: 'Database Query Optimization',
        description: 'Optimize database queries for better performance',
        estimatedImpact: 'Up to 50% faster execution time',
        implementationSteps: [
          'Analyze current query patterns and identify bottlenecks',
          'Index frequently queried columns (user_id, created_at, status)',
          'Implement query result caching with 15-minute TTL',
          'Consider database connection pooling for high-traffic scenarios',
          'Monitor query performance using built-in analytics',
          'Set up alerts for queries exceeding 2-second execution time',
          'Document optimized query patterns for team reference'
        ]
      };

      expect(complexRecommendation.implementationSteps).toHaveLength(7);
      expect(complexRecommendation.implementationSteps![1]).toContain('Index frequently queried columns');
      expect(complexRecommendation.estimatedImpact).toContain('50%');
    });
  });

  describe('Type Compatibility', () => {
    test('should handle nested Blueprint in BlueprintModule parameters', () => {
      // Test case where a module's parameters might contain a nested blueprint
      const moduleWithNestedBlueprint: BlueprintModule = {
        id: 1,
        module: 'scenario:executor',
        version: 1,
        parameters: {
          nestedScenario: {
            name: 'Nested Scenario',
            metadata: {
              version: 1,
              scenario: {
                roundtrips: 2,
                autoCommit: true
              }
            },
            flow: [
              {
                id: 1,
                module: 'http',
                version: 1
              }
            ]
          } as Blueprint
        }
      };

      expect(moduleWithNestedBlueprint.parameters!.nestedScenario).toBeDefined();
      const nestedBlueprint = moduleWithNestedBlueprint.parameters!.nestedScenario as Blueprint;
      expect(nestedBlueprint.name).toBe('Nested Scenario');
      expect(nestedBlueprint.flow).toHaveLength(1);
    });

    test('should handle array of OptimizationRecommendations', () => {
      const recommendations: OptimizationRecommendation[] = [
        {
          category: 'performance',
          priority: 'high',
          title: 'First Recommendation',
          description: 'First description'
        },
        {
          category: 'security',
          priority: 'medium',
          title: 'Second Recommendation',
          description: 'Second description',
          estimatedImpact: '20% improvement'
        },
        {
          category: 'cost',
          priority: 'low',
          title: 'Third Recommendation',
          description: 'Third description',
          implementationSteps: ['Step 1', 'Step 2']
        }
      ];

      expect(recommendations).toHaveLength(3);
      expect(recommendations[0].priority).toBe('high');
      expect(recommendations[1].estimatedImpact).toBe('20% improvement');
      expect(recommendations[2].implementationSteps).toEqual(['Step 1', 'Step 2']);
    });

    test('should handle Blueprint with mixed data types', () => {
      const mixedBlueprint: Blueprint = {
        name: 'Mixed Data Types Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 0,
            autoCommit: false,
            sequential: true,
            confidential: false,
            dlq: false
          }
        },
        flow: [
          {
            id: 1,
            module: 'data:processor',
            version: 1,
            parameters: {
              stringValue: 'text',
              numberValue: 42,
              booleanValue: true,
              arrayValue: [1, 'two', true, null],
              objectValue: {
                nested: {
                  deep: 'value'
                }
              },
              nullValue: null,
              undefinedValue: undefined
            }
          }
        ],
        customProperties: {
          tags: ['test', 'mixed', 'types'],
          config: {
            enabled: true,
            settings: {
              timeout: 30,
              retries: 3
            }
          }
        }
      };

      expect(mixedBlueprint.flow![0].parameters!.stringValue).toBe('text');
      expect(mixedBlueprint.flow![0].parameters!.numberValue).toBe(42);
      expect(mixedBlueprint.flow![0].parameters!.booleanValue).toBe(true);
      expect(mixedBlueprint.flow![0].parameters!.arrayValue).toEqual([1, 'two', true, null]);
      expect(mixedBlueprint.flow![0].parameters!.nullValue).toBe(null);
      expect(mixedBlueprint.customProperties).toBeDefined();
    });
  });
});