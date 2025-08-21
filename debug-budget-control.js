#!/usr/bin/env node

import pkg from '@jest/globals';
const { jest } = pkg;

// Mock the test environment
const mockApiClient = {
  post: jest.fn(),
  get: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
  mockResponse: function(method, path, response) {
    this[method.toLowerCase()].mockResolvedValue(response);
  },
  mockFailure: function(method, path, error) {
    this[method.toLowerCase()].mockRejectedValue(error);
  }
};

const mockServer = {
  addTool: jest.fn(),
};

try {
  // Mock scenario list API response
  mockApiClient.mockResponse('GET', '/scenarios?costAnalysis=true&budgetId=budget_001', {
    success: true,
    data: {
      scenarios: [
        {
          id: 2001,
          name: 'Data Processing Pipeline',
          status: 'active',
          costMetrics: {
            dailyCost: 150.30,
            monthlyProjection: 4509
          }
        }
      ]
    }
  });

  // Import and register tools
  const { addBudgetControlTools } = await import('./src/tools/budget-control.js');
  addBudgetControlTools(mockServer, mockApiClient);

  // Find the control tool
  const tools = mockServer.addTool.mock.calls;
  const controlTool = tools.find(call => call[0].name === 'control-high-cost-scenarios');
  
  if (!controlTool) {
    console.error('Could not find control-high-cost-scenarios tool');
    process.exit(1);
  }

  // Execute the tool with 'analyze' action
  const result = await controlTool[0].execute({
    budgetId: 'budget_001',
    action: 'analyze',
    reason: 'Budget threshold analysis'
  }, {
    log: {
      info: console.log,
      warn: console.warn,
      error: console.error,
      debug: console.debug
    },
    reportProgress: (progress) => console.log('Progress:', progress)
  });

  console.log('\n=== ACTUAL TOOL RESULT ===');
  console.log(result);
  
  console.log('\n=== PARSED RESULT ===');
  const parsed = JSON.parse(result);
  console.log(JSON.stringify(parsed, null, 2));
  
  console.log('\n=== ANALYSIS PROPERTY CHECK ===');
  console.log('parsed.analysis exists:', parsed.analysis !== undefined);
  console.log('parsed.analysis:', parsed.analysis);

} catch (error) {
  console.error('Error:', error);
  process.exit(1);
}