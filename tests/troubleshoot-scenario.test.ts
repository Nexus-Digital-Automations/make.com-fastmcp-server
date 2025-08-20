/**
 * @fileoverview Tests for troubleshoot-scenario tool implementation
 * 
 * Basic validation tests for the diagnostic engine and troubleshooting tool
 * to ensure proper functionality and integration.
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 */

import DiagnosticEngine from '../lib/diagnostic-engine.js';
import { defaultDiagnosticRules } from '../lib/diagnostic-rules.js';
import { MakeBlueprint, DiagnosticOptions } from '../types/diagnostics.js';

// Mock API client for testing
const mockApiClient = {
  get: async (url: string) => {
    if (url.includes('/scenarios/')) {
      return {
        success: true,
        data: {
          id: 'test-scenario',
          name: 'Test Scenario',
          active: true
        }
      };
    }
    if (url.includes('/executions')) {
      return {
        success: true,
        data: [
          {
            duration: 5000,
            status: 'success',
            createdAt: new Date().toISOString()
          }
        ]
      };
    }
    if (url.includes('/connections/')) {
      return {
        success: true,
        data: {
          verified: true,
          status: 'verified',
          accountName: 'test@example.com'
        }
      };
    }
    return { success: false, error: { message: 'Not found' } };
  },
  post: async () => ({ success: true, data: {} }),
  patch: async () => ({ success: true, data: {} }),
  delete: async () => ({ success: true, data: {} })
};

// Mock blueprint for testing
const mockBlueprint: MakeBlueprint = {
  name: 'Test Scenario',
  flow: [
    {
      id: 1,
      module: 'webhook:customWebHook',
      version: 1,
      parameters: {
        hook: 'test-hook'
      }
    },
    {
      id: 2,
      module: 'json:ParseJSON',
      version: 1,
      parameters: {
        json: '{{1.body}}'
      }
    }
  ],
  metadata: {
    version: 1,
    scenario: {
      roundtrips: 1,
      maxErrors: 3,
      autoCommit: true,
      sequential: false,
      confidential: false,
      dlq: false,
      freshVariables: false
    }
  }
};

/**
 * Test diagnostic engine initialization
 */
export function testDiagnosticEngineInitialization(): boolean {
  try {
    const engine = new DiagnosticEngine();
    
    // Register default rules
    defaultDiagnosticRules.forEach(rule => {
      engine.registerRule(rule);
    });
    
    return true;
  } catch (error) {
    console.error('Diagnostic engine initialization failed:', error);
    return false;
  }
}

/**
 * Test basic diagnostic execution
 */
export async function testBasicDiagnostics(): Promise<boolean> {
  try {
    const engine = new DiagnosticEngine();
    
    // Register default rules
    defaultDiagnosticRules.forEach(rule => {
      engine.registerRule(rule);
    });
    
    const options: DiagnosticOptions = {
      diagnosticTypes: ['health', 'performance'],
      timeRangeHours: 24,
      includePerformanceMetrics: true,
      includeSecurityChecks: false,
      timeoutMs: 10000
    };
    
    const report = await engine.runDiagnostics(
      'test-scenario',
      { name: 'Test Scenario', active: true },
      mockBlueprint,
      mockApiClient as any,
      options
    );
    
    // Validate report structure
    if (!report.scenarioId || !report.scenarioName || !report.overallHealth) {
      console.error('Invalid report structure');
      return false;
    }
    
    if (!Array.isArray(report.diagnostics)) {
      console.error('Diagnostics should be an array');
      return false;
    }
    
    if (typeof report.summary.totalIssues !== 'number') {
      console.error('Summary should include total issues count');
      return false;
    }
    
    console.log('Basic diagnostics test passed:', {
      overallHealth: report.overallHealth,
      totalIssues: report.summary.totalIssues,
      executionTime: report.executionTime
    });
    
    return true;
  } catch (error) {
    console.error('Basic diagnostics test failed:', error);
    return false;
  }
}

/**
 * Test security assessment rule
 */
export async function testSecurityAssessment(): Promise<boolean> {
  try {
    const engine = new DiagnosticEngine();
    
    // Register security rule
    const securityRule = defaultDiagnosticRules.find(r => r.id === 'security-assessment');
    if (!securityRule) {
      console.error('Security assessment rule not found');
      return false;
    }
    
    engine.registerRule(securityRule);
    
    // Test with blueprint containing potential security issues
    const unsafeBlueprintStr = JSON.stringify({
      ...mockBlueprint,
      flow: [
        ...mockBlueprint.flow,
        {
          id: 3,
          module: 'http:ActionSendData',
          version: 1,
          parameters: {
            url: 'https://api.example.com/data',
            api_key: 'hardcoded-secret-key-12345'
          }
        }
      ]
    });
    
    const unsafeBlueprint = JSON.parse(unsafeBlueprintStr) as MakeBlueprint;
    
    const options: DiagnosticOptions = {
      diagnosticTypes: ['security'],
      timeRangeHours: 24,
      includePerformanceMetrics: false,
      includeSecurityChecks: true,
      timeoutMs: 10000
    };
    
    const report = await engine.runDiagnostics(
      'test-scenario',
      { name: 'Test Scenario', active: true },
      unsafeBlueprint,
      mockApiClient as any,
      options
    );
    
    // Should detect security issues
    const securityIssues = report.diagnostics.filter(d => d.category === 'security');
    if (securityIssues.length === 0) {
      console.error('Security assessment should detect hardcoded secrets');
      return false;
    }
    
    console.log('Security assessment test passed:', {
      securityIssuesFound: securityIssues.length,
      overallHealth: report.overallHealth
    });
    
    return true;
  } catch (error) {
    console.error('Security assessment test failed:', error);
    return false;
  }
}

/**
 * Run all tests
 */
export async function runAllTests(): Promise<void> {
  console.log('Starting troubleshoot-scenario tests...\n');
  
  const tests = [
    { name: 'Diagnostic Engine Initialization', test: testDiagnosticEngineInitialization },
    { name: 'Basic Diagnostics', test: testBasicDiagnostics },
    { name: 'Security Assessment', test: testSecurityAssessment }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const { name, test } of tests) {
    console.log(`Running test: ${name}`);
    try {
      const result = typeof test === 'function' ? await test() : test();
      if (result) {
        console.log(`✅ ${name} - PASSED\n`);
        passed++;
      } else {
        console.log(`❌ ${name} - FAILED\n`);
        failed++;
      }
    } catch (error) {
      console.log(`❌ ${name} - ERROR: ${error}\n`);
      failed++;
    }
  }
  
  console.log(`\nTest Results: ${passed} passed, ${failed} failed`);
  
  if (failed === 0) {
    console.log('🎉 All tests passed! Troubleshoot-scenario implementation is working correctly.');
  } else {
    console.log('⚠️  Some tests failed. Please review the implementation.');
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAllTests().catch(console.error);
}