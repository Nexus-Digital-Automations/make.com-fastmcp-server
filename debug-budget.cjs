#!/usr/bin/env node

// Simple mock functions to simulate the test environment
const mockApiClient = {
  post: () => Promise.resolve(),
  get: () => Promise.resolve({
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
  }),
  put: () => Promise.resolve(),
  delete: () => Promise.resolve(),
};

let registeredTools = [];
const mockServer = {
  addTool: (tool) => {
    registeredTools.push(tool);
  },
};

async function debugBudgetControl() {
  try {
    console.log('Loading budget control tools...');
    
    // Import the module using dynamic import
    const budgetModule = await import('./src/tools/budget-control.js');
    const { addBudgetControlTools } = budgetModule;
    
    // Register tools
    addBudgetControlTools(mockServer, mockApiClient);
    
    console.log(`Registered ${registeredTools.length} tools`);
    
    // Find the control tool
    const controlTool = registeredTools.find(tool => tool.name === 'control-high-cost-scenarios');
    
    if (!controlTool) {
      console.error('Could not find control-high-cost-scenarios tool');
      console.log('Available tools:', registeredTools.map(t => t.name));
      return;
    }

    console.log('Found control-high-cost-scenarios tool');

    // Execute the tool with 'analyze' action
    const result = await controlTool.execute({
      budgetId: 'budget_001',
      action: 'analyze',
      reason: 'Budget threshold analysis'
    }, {
      log: {
        info: (...args) => console.log('INFO:', ...args),
        warn: (...args) => console.warn('WARN:', ...args),
        error: (...args) => console.error('ERROR:', ...args),
        debug: (...args) => console.debug('DEBUG:', ...args)
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
    console.log('parsed.analysis type:', typeof parsed.analysis);
    if (parsed.analysis) {
      console.log('analysis keys:', Object.keys(parsed.analysis));
    }

  } catch (error) {
    console.error('Error:', error);
    console.error('Stack:', error.stack);
  }
}

debugBudgetControl();