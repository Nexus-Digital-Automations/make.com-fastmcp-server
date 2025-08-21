const { jest, describe, it, expect, beforeEach, afterEach } = require('@jest/globals');

// Mock the imports to use the compiled version
const createMockServer = () => ({
  server: { addTool: jest.fn() },
  mockTool: jest.fn()
});

const findTool = (mockTool, name) => {
  const calls = mockTool.mock.calls;
  for (const call of calls) {
    if (call[0].name === name) {
      return call[0];
    }
  }
  return null;
};

class MockMakeApiClient {
  constructor() {
    this.responses = new Map();
    this.failures = new Map();
  }
  
  mockResponse(method, path, response) {
    this.responses.set(`${method}:${path}`, response);
  }
  
  mockFailure(method, path, error) {
    this.failures.set(`${method}:${path}`, error);
  }
  
  async get(path) {
    const key = `GET:${path}`;
    if (this.failures.has(key)) {
      throw this.failures.get(key);
    }
    return this.responses.get(key) || { success: false };
  }
  
  async post(path) {
    const key = `POST:${path}`;
    if (this.failures.has(key)) {
      throw this.failures.get(key);
    }
    return this.responses.get(key) || { success: false };
  }
}

async function runTest() {
  try {
    // Import the compiled JS version
    const { addBudgetControlTools } = await import('./dist/tools/budget-control.js');
    
    // Setup
    const serverSetup = createMockServer();
    const mockServer = serverSetup.server;
    const mockTool = serverSetup.mockTool;
    const mockApiClient = new MockMakeApiClient();

    // Mock the API response for cost control 
    const costControlData = {
      budgetId: 'budget_001',
      analysis: {
        totalScenarios: 25,
        highCostScenarios: 5,
        averageCost: 45.60,
        topCostScenarios: [
          {
            scenarioId: 2001,
            name: 'Data Processing Pipeline',
            dailyCost: 150.30,
            monthlyProjection: 4509,
            riskLevel: 'high'
          }
        ]
      },
      recommendations: [
        'Consider optimizing data processing batch sizes',
        'Review webhook timeout configurations',
        'Implement cost-aware scheduling'
      ],
      appliedActions: []
    };

    mockApiClient.mockResponse('POST', '/budget/budget_001/control', {
      success: true,
      data: costControlData
    });

    // Register tools
    addBudgetControlTools(mockServer, mockApiClient);

    // Find and execute the tool
    const tool = findTool(mockTool, 'control-high-cost-scenarios');
    console.log('Found tool:', tool ? tool.name : 'NOT FOUND');
    
    if (tool) {
      const result = await tool.execute({
        budgetId: 'budget_001',
        action: 'analyze',
        reason: 'Budget threshold analysis'
      }, { 
        log: { info: () => {}, warn: () => {}, error: () => {} }, 
        reportProgress: () => {} 
      });

      console.log('=== RAW TOOL RESULT ===');
      console.log(result);
      
      console.log('\n=== PARSED RESULT ===');
      const parsedResult = JSON.parse(result);
      console.log(JSON.stringify(parsedResult, null, 2));

      console.log('\n=== ANALYSIS PROPERTY ===');
      console.log('parsedResult.analysis:', parsedResult.analysis);

      console.log('\n=== RECOMMENDATIONS PROPERTY ===');
      console.log('parsedResult.recommendations:', parsedResult.recommendations);

      console.log('\n=== CONTROL ACTIONS PROPERTY ===');
      console.log('parsedResult.controlActions:', parsedResult.controlActions);

      // Test expectations
      console.log('\n=== TEST RESULTS ===');
      console.log('analysis defined:', parsedResult.analysis !== undefined);
      console.log('recommendations defined:', parsedResult.recommendations !== undefined);
      console.log('controlActions defined:', parsedResult.controlActions !== undefined);
    }
  } catch (error) {
    console.error('Test failed:', error.message);
    console.error('Stack:', error.stack);
  }
}

runTest();