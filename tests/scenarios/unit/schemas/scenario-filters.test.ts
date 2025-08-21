/**
 * @fileoverview Unit Tests for Scenario Filter Schemas
 * 
 * Tests all Zod validation schemas used for scenario filtering, querying,
 * and diagnostic operations in the refactored scenarios module.
 */

import { z } from 'zod';
import {
  ScenarioFiltersSchema,
  ScenarioDetailSchema,
  RunScenarioSchema,
  TroubleshootScenarioSchema,
  GenerateTroubleshootingReportSchema,
  type ScenarioFilters,
  type ScenarioDetail,
  type RunScenario,
  type TroubleshootScenario,
  type GenerateTroubleshootingReport
} from '../../../../src/tools/scenarios/schemas/scenario-filters.js';

describe('Scenario Filter Schemas', () => {
  describe('ScenarioFiltersSchema', () => {
    test('should accept empty filters with defaults', () => {
      const result = ScenarioFiltersSchema.parse({});
      
      expect(result.limit).toBe(10);
      expect(result.offset).toBe(0);
      expect(result.teamId).toBeUndefined();
      expect(result.folderId).toBeUndefined();
      expect(result.search).toBeUndefined();
      expect(result.active).toBeUndefined();
    });

    test('should accept all filter parameters', () => {
      const filters: ScenarioFilters = {
        teamId: 'team_123',
        folderId: 'folder_456',
        limit: 25,
        offset: 50,
        search: 'test scenario',
        active: true
      };

      const result = ScenarioFiltersSchema.parse(filters);
      expect(result).toEqual(filters);
    });

    test('should validate limit boundaries', () => {
      // Valid limits
      expect(() => ScenarioFiltersSchema.parse({ limit: 1 })).not.toThrow();
      expect(() => ScenarioFiltersSchema.parse({ limit: 50 })).not.toThrow();
      expect(() => ScenarioFiltersSchema.parse({ limit: 100 })).not.toThrow();

      // Invalid limits
      expect(() => ScenarioFiltersSchema.parse({ limit: 0 })).toThrow();
      expect(() => ScenarioFiltersSchema.parse({ limit: -1 })).toThrow();
      expect(() => ScenarioFiltersSchema.parse({ limit: 101 })).toThrow();
    });

    test('should validate offset boundaries', () => {
      // Valid offsets
      expect(() => ScenarioFiltersSchema.parse({ offset: 0 })).not.toThrow();
      expect(() => ScenarioFiltersSchema.parse({ offset: 100 })).not.toThrow();
      expect(() => ScenarioFiltersSchema.parse({ offset: 1000 })).not.toThrow();

      // Invalid offsets
      expect(() => ScenarioFiltersSchema.parse({ offset: -1 })).toThrow();
    });

    test('should handle boolean active filter', () => {
      // Valid boolean values
      expect(() => ScenarioFiltersSchema.parse({ active: true })).not.toThrow();
      expect(() => ScenarioFiltersSchema.parse({ active: false })).not.toThrow();

      // Invalid values should be rejected
      expect(() => ScenarioFiltersSchema.parse({ active: 'true' })).toThrow();
      expect(() => ScenarioFiltersSchema.parse({ active: 1 })).toThrow();
    });

    test('should reject unknown fields', () => {
      expect(() => ScenarioFiltersSchema.parse({ unknownField: 'value' })).toThrow();
    });

    test('should handle complex search terms', () => {
      const complexSearchTerms = [
        'simple search',
        'search with "quotes"',
        'search with [brackets]',
        'search with (parentheses)',
        'search with émojis 🔍',
        'unicode search: 测试搜索',
        'multi\nline\nsearch',
        'search with special chars: !@#$%^&*()',
        'very long search term that goes on and on and on and should still be valid'
      ];

      complexSearchTerms.forEach(searchTerm => {
        expect(() => ScenarioFiltersSchema.parse({ search: searchTerm })).not.toThrow();
      });
    });
  });

  describe('ScenarioDetailSchema', () => {
    test('should require scenarioId', () => {
      expect(() => ScenarioDetailSchema.parse({})).toThrow();
    });

    test('should accept valid scenario detail request', () => {
      const validDetail: ScenarioDetail = {
        scenarioId: 'scn_123',
        includeBlueprint: true,
        includeExecutions: true
      };

      const result = ScenarioDetailSchema.parse(validDetail);
      expect(result).toEqual(validDetail);
    });

    test('should apply default values', () => {
      const minimalDetail = { scenarioId: 'scn_123' };
      const result = ScenarioDetailSchema.parse(minimalDetail);
      
      expect(result.scenarioId).toBe('scn_123');
      expect(result.includeBlueprint).toBe(false);
      expect(result.includeExecutions).toBe(false);
    });

    test('should validate scenarioId', () => {
      expect(() => ScenarioDetailSchema.parse({ scenarioId: '' })).toThrow();
      expect(() => ScenarioDetailSchema.parse({ scenarioId: 'valid_id' })).not.toThrow();
    });

    test('should validate boolean flags', () => {
      const validBooleanCombinations = [
        { scenarioId: 'scn_123', includeBlueprint: true },
        { scenarioId: 'scn_123', includeBlueprint: false },
        { scenarioId: 'scn_123', includeExecutions: true },
        { scenarioId: 'scn_123', includeExecutions: false },
        { scenarioId: 'scn_123', includeBlueprint: true, includeExecutions: true },
        { scenarioId: 'scn_123', includeBlueprint: false, includeExecutions: false }
      ];

      validBooleanCombinations.forEach(data => {
        expect(() => ScenarioDetailSchema.parse(data)).not.toThrow();
      });
    });

    test('should reject unknown fields', () => {
      expect(() => ScenarioDetailSchema.parse({ 
        scenarioId: 'scn_123',
        unknownField: 'value'
      })).toThrow();
    });
  });

  describe('RunScenarioSchema', () => {
    test('should require scenarioId', () => {
      expect(() => RunScenarioSchema.parse({})).toThrow();
    });

    test('should accept valid run scenario request', () => {
      const validRun: RunScenario = {
        scenarioId: 'scn_123',
        wait: false,
        timeout: 120
      };

      const result = RunScenarioSchema.parse(validRun);
      expect(result).toEqual(validRun);
    });

    test('should apply default values', () => {
      const minimalRun = { scenarioId: 'scn_123' };
      const result = RunScenarioSchema.parse(minimalRun);
      
      expect(result.scenarioId).toBe('scn_123');
      expect(result.wait).toBe(true);
      expect(result.timeout).toBe(60);
    });

    test('should validate timeout boundaries', () => {
      // Valid timeouts
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeout: 1 
      })).not.toThrow();
      
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeout: 150 
      })).not.toThrow();
      
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeout: 300 
      })).not.toThrow();

      // Invalid timeouts
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeout: 0 
      })).toThrow();
      
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeout: -1 
      })).toThrow();
      
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeout: 301 
      })).toThrow();
    });

    test('should validate wait parameter', () => {
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        wait: true 
      })).not.toThrow();
      
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        wait: false 
      })).not.toThrow();

      // Invalid wait values
      expect(() => RunScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        wait: 'true' 
      })).toThrow();
    });
  });

  describe('TroubleshootScenarioSchema', () => {
    test('should require scenarioId', () => {
      expect(() => TroubleshootScenarioSchema.parse({})).toThrow();
    });

    test('should accept valid troubleshoot request', () => {
      const validTroubleshoot: TroubleshootScenario = {
        scenarioId: 'scn_123',
        diagnosticTypes: ['health', 'performance', 'connections'],
        includeRecommendations: false,
        includePerformanceHistory: false,
        severityFilter: 'error',
        autoFix: true,
        timeRange: { hours: 48 }
      };

      const result = TroubleshootScenarioSchema.parse(validTroubleshoot);
      expect(result).toEqual(validTroubleshoot);
    });

    test('should apply default values', () => {
      const minimalTroubleshoot = { scenarioId: 'scn_123' };
      const result = TroubleshootScenarioSchema.parse(minimalTroubleshoot);
      
      expect(result.scenarioId).toBe('scn_123');
      expect(result.diagnosticTypes).toEqual(['all']);
      expect(result.includeRecommendations).toBe(true);
      expect(result.includePerformanceHistory).toBe(true);
      expect(result.autoFix).toBe(false);
    });

    test('should validate diagnostic types', () => {
      const validDiagnosticTypes = [
        ['health'],
        ['performance'],
        ['connections'],
        ['errors'],
        ['security'],
        ['all'],
        ['health', 'performance'],
        ['health', 'performance', 'connections', 'errors', 'security'],
        ['all']
      ];

      validDiagnosticTypes.forEach(types => {
        expect(() => TroubleshootScenarioSchema.parse({ 
          scenarioId: 'scn_123', 
          diagnosticTypes: types 
        })).not.toThrow();
      });

      // Invalid diagnostic type
      expect(() => TroubleshootScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        diagnosticTypes: ['invalid'] 
      })).toThrow();
    });

    test('should validate severity filter', () => {
      const validSeverityLevels = ['info', 'warning', 'error', 'critical'];

      validSeverityLevels.forEach(severity => {
        expect(() => TroubleshootScenarioSchema.parse({ 
          scenarioId: 'scn_123', 
          severityFilter: severity 
        })).not.toThrow();
      });

      // Invalid severity
      expect(() => TroubleshootScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        severityFilter: 'invalid' 
      })).toThrow();
    });

    test('should validate time range', () => {
      const validTimeRanges = [
        { hours: 1 },
        { hours: 24 },
        { hours: 168 }, // 1 week
        { hours: 720 }  // 30 days
      ];

      validTimeRanges.forEach(timeRange => {
        expect(() => TroubleshootScenarioSchema.parse({ 
          scenarioId: 'scn_123', 
          timeRange 
        })).not.toThrow();
      });

      // Invalid time ranges
      expect(() => TroubleshootScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeRange: { hours: 0 } 
      })).toThrow();
      
      expect(() => TroubleshootScenarioSchema.parse({ 
        scenarioId: 'scn_123', 
        timeRange: { hours: 721 } 
      })).toThrow();
    });

    test('should handle complex troubleshooting configurations', () => {
      const complexConfig = {
        scenarioId: 'scn_complex',
        diagnosticTypes: ['health', 'performance', 'security'],
        includeRecommendations: true,
        includePerformanceHistory: true,
        severityFilter: 'warning',
        autoFix: false,
        timeRange: { hours: 72 }
      };

      const result = TroubleshootScenarioSchema.parse(complexConfig);
      expect(result.diagnosticTypes).toEqual(['health', 'performance', 'security']);
      expect(result.timeRange?.hours).toBe(72);
    });
  });

  describe('GenerateTroubleshootingReportSchema', () => {
    test('should accept empty configuration with defaults', () => {
      const result = GenerateTroubleshootingReportSchema.parse({});
      
      expect(result.scenarioIds).toBeUndefined();
      expect(result.reportOptions?.includeExecutiveSummary).toBe(true);
      expect(result.analysisFilters?.timeRangeHours).toBe(24);
      expect(result.comparisonBaseline?.compareToHistorical).toBe(true);
    });

    test('should accept complete report configuration', () => {
      const completeConfig: GenerateTroubleshootingReport = {
        scenarioIds: ['scn_1', 'scn_2', 'scn_3'],
        reportOptions: {
          includeExecutiveSummary: true,
          includeDetailedAnalysis: true,
          includeActionPlan: true,
          includePerformanceMetrics: true,
          includeSecurityAssessment: true,
          includeCostAnalysis: true,
          includeRecommendationTimeline: true,
          formatType: 'markdown'
        },
        analysisFilters: {
          timeRangeHours: 168,
          severityThreshold: 'warning',
          includeInactiveScenarios: true,
          maxScenariosToAnalyze: 50,
          prioritizeByUsage: false
        },
        comparisonBaseline: {
          compareToHistorical: true,
          baselineTimeRangeHours: 336,
          includeBenchmarks: true
        }
      };

      const result = GenerateTroubleshootingReportSchema.parse(completeConfig);
      expect(result).toEqual(completeConfig);
    });

    test('should validate scenario IDs array', () => {
      const validScenarioArrays = [
        ['scn_1'],
        ['scn_1', 'scn_2'],
        ['scn_1', 'scn_2', 'scn_3', 'scn_4', 'scn_5']
      ];

      validScenarioArrays.forEach(scenarioIds => {
        expect(() => GenerateTroubleshootingReportSchema.parse({ scenarioIds })).not.toThrow();
      });

      // Invalid scenario ID (empty string)
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        scenarioIds: ['scn_1', ''] 
      })).toThrow();
    });

    test('should validate report format types', () => {
      const validFormats = ['json', 'markdown', 'pdf-ready'];

      validFormats.forEach(formatType => {
        expect(() => GenerateTroubleshootingReportSchema.parse({ 
          reportOptions: { formatType } 
        })).not.toThrow();
      });

      // Invalid format
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        reportOptions: { formatType: 'xml' } 
      })).toThrow();
    });

    test('should validate analysis filter ranges', () => {
      const validAnalysisFilters = [
        { timeRangeHours: 1 },
        { timeRangeHours: 24 },
        { timeRangeHours: 720 },
        { maxScenariosToAnalyze: 1 },
        { maxScenariosToAnalyze: 50 },
        { maxScenariosToAnalyze: 100 }
      ];

      validAnalysisFilters.forEach(filters => {
        expect(() => GenerateTroubleshootingReportSchema.parse({ 
          analysisFilters: filters 
        })).not.toThrow();
      });

      // Invalid ranges
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        analysisFilters: { timeRangeHours: 0 } 
      })).toThrow();
      
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        analysisFilters: { timeRangeHours: 721 } 
      })).toThrow();
      
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        analysisFilters: { maxScenariosToAnalyze: 0 } 
      })).toThrow();
      
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        analysisFilters: { maxScenariosToAnalyze: 101 } 
      })).toThrow();
    });

    test('should validate baseline comparison settings', () => {
      const validBaselineSettings = [
        { baselineTimeRangeHours: 24 },
        { baselineTimeRangeHours: 168 }, // 1 week
        { baselineTimeRangeHours: 720 }, // 30 days
        { baselineTimeRangeHours: 2160 } // 90 days
      ];

      validBaselineSettings.forEach(settings => {
        expect(() => GenerateTroubleshootingReportSchema.parse({ 
          comparisonBaseline: settings 
        })).not.toThrow();
      });

      // Invalid baseline ranges
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        comparisonBaseline: { baselineTimeRangeHours: 23 } 
      })).toThrow();
      
      expect(() => GenerateTroubleshootingReportSchema.parse({ 
        comparisonBaseline: { baselineTimeRangeHours: 2161 } 
      })).toThrow();
    });

    test('should apply nested default values correctly', () => {
      const partialConfig = {
        reportOptions: {
          includeExecutiveSummary: false
          // Other options should get defaults
        },
        analysisFilters: {
          timeRangeHours: 48
          // Other filters should get defaults
        }
      };

      const result = GenerateTroubleshootingReportSchema.parse(partialConfig);
      
      // Explicitly set values
      expect(result.reportOptions?.includeExecutiveSummary).toBe(false);
      expect(result.analysisFilters?.timeRangeHours).toBe(48);
      
      // Default values
      expect(result.reportOptions?.includeDetailedAnalysis).toBe(true);
      expect(result.reportOptions?.formatType).toBe('json');
      expect(result.analysisFilters?.severityThreshold).toBe('info');
      expect(result.analysisFilters?.maxScenariosToAnalyze).toBe(25);
    });
  });

  describe('Type Exports and Integration', () => {
    test('should export correct TypeScript types', () => {
      // Test type inference and compilation
      const filters: ScenarioFilters = {
        teamId: 'team_123',
        limit: 50,
        active: true
      };

      const detail: ScenarioDetail = {
        scenarioId: 'scn_123',
        includeBlueprint: true
      };

      const run: RunScenario = {
        scenarioId: 'scn_123',
        wait: false,
        timeout: 120
      };

      const troubleshoot: TroubleshootScenario = {
        scenarioId: 'scn_123',
        diagnosticTypes: ['health', 'performance']
      };

      const report: GenerateTroubleshootingReport = {
        scenarioIds: ['scn_1', 'scn_2']
      };

      // These should compile without errors
      expect(filters.teamId).toBe('team_123');
      expect(detail.scenarioId).toBe('scn_123');
      expect(run.wait).toBe(false);
      expect(troubleshoot.diagnosticTypes).toEqual(['health', 'performance']);
      expect(report.scenarioIds).toEqual(['scn_1', 'scn_2']);
    });

    test('should handle schema validation errors consistently', () => {
      const invalidSchemas = [
        { schema: ScenarioFiltersSchema, data: { limit: -1 } },
        { schema: ScenarioDetailSchema, data: { scenarioId: '' } },
        { schema: RunScenarioSchema, data: { scenarioId: '', timeout: 0 } },
        { schema: TroubleshootScenarioSchema, data: { scenarioId: '', diagnosticTypes: ['invalid'] } },
        { schema: GenerateTroubleshootingReportSchema, data: { analysisFilters: { timeRangeHours: 0 } } }
      ];

      invalidSchemas.forEach(({ schema, data }) => {
        try {
          schema.parse(data);
          fail(`Should have thrown validation error for ${schema}`);
        } catch (error) {
          expect(error).toBeInstanceOf(z.ZodError);
        }
      });
    });
  });
});