// Debug test for the exact failing generate-cost-projection test

const createMockServer = () => ({
  server: { addTool: (tool) => mockTool.mock.calls.push([tool]) },
  mockTool: mockTool
});

const mockTool = {
  mock: {
    calls: []
  }
};

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
    
    // Setup exactly like failing test
    const serverSetup = createMockServer();
    const mockServer = serverSetup.server;
    const mockApiClient = new MockMakeApiClient();

    // Mock the exact same API response as failing test (which doesn't get used)
    const projectionData = {
      budgetId: 'budget_001',
      tenantId: 'tenant_123',
      projectionPeriod: {
        startDate: '2024-01-15',
        endDate: '2024-01-31',
        daysTotal: 17,
        daysRemaining: 16
      },
      currentSpend: 2500,
      projectedSpend: {
        conservative: 4200,
        expected: 4800,
        optimistic: 5400
      },
      confidence: {
        level: 85,
        factors: ['historical_data', 'seasonal_trends'],
        uncertainties: ['market_volatility']
      }
    };

    mockApiClient.mockResponse('POST', '/budget/budget_001/projections', {
      success: true,
      data: projectionData
    });

    // Register tools
    addBudgetControlTools(mockServer, mockApiClient);

    // Find and execute with EXACT same parameters as failing test
    const tool = findTool(mockTool, 'generate-cost-projection');
    console.log('Found tool:', tool ? tool.name : 'NOT FOUND');
    
    if (tool) {
      const result = await tool.execute({
        budgetId: 'budget_001',
        projectionDays: 30,
        includeSeasonality: true,
        confidenceLevel: 0.85
      }, { 
        log: { info: () => {}, warn: () => {}, error: () => {} }, 
        reportProgress: () => {} 
      });

      console.log('=== RAW TOOL RESULT ===');
      console.log(result);
      
      console.log('\\n=== PARSED RESULT ===');
      const parsedResult = JSON.parse(result);
      console.log(JSON.stringify(parsedResult, null, 2));

      console.log('\\n=== PROJECTION PROPERTY ===');
      console.log('parsedResult.projection:', parsedResult.projection ? 'DEFINED' : 'UNDEFINED');
      if (parsedResult.projection) {
        console.log('projectedSpend:', parsedResult.projection.projectedSpend ? 'DEFINED' : 'UNDEFINED');
      }

      console.log('\\n=== ANALYSIS PROPERTY ===');
      console.log('parsedResult.analysis:', parsedResult.analysis ? 'DEFINED' : 'UNDEFINED');
      if (parsedResult.analysis) {
        console.log('analysis keys:', Object.keys(parsedResult.analysis));
      }

      // Test expectations from failing test
      console.log('\\n=== FAILING TEST EXPECTATIONS ===');
      console.log('result defined:', result !== undefined);
      console.log('projection defined:', parsedResult.projection !== undefined);
      console.log('projection.projectedSpend defined:', parsedResult.projection?.projectedSpend !== undefined);
      console.log('analysis defined:', parsedResult.analysis !== undefined); // This is failing
    }
  } catch (error) {
    console.error('Test failed:', error.message);
    console.error('Stack:', error.stack);
  }
}

runTest();