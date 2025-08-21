import { addBudgetControlTools } from './dist/tools/budget-control.js';
import { createMockServer, findTool } from './tests/utils/test-helpers.js';
import { MockMakeApiClient } from './tests/mocks/make-api-client.mock.js';

console.log('Starting budget tool debug test...');

try {
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
      log: { info: () => {}, error: () => {} }, 
      reportProgress: () => {} 
    });

    console.log('=== TOOL RESULT ===');
    console.log(result);
    console.log('\n=== PARSED RESULT ===');
    const parsedResult = JSON.parse(result);
    console.log(JSON.stringify(parsedResult, null, 2));

    console.log('\n=== ANALYSIS PROPERTY ===');
    console.log('parsedResult.analysis:', parsedResult.analysis);

    console.log('\n=== TOP LEVEL PROPERTIES ===');
    console.log('Keys:', Object.keys(parsedResult));

    console.log('\n=== CONTROL ACTIONS ===');
    console.log('parsedResult.controlActions:', parsedResult.controlActions);

    console.log('\n=== RECOMMENDATION PROPERTY ===');
    console.log('parsedResult.recommendations:', parsedResult.recommendations);
  }
} catch (error) {
  console.error('Debug test failed:', error.message);
  console.error('Stack:', error.stack);
}