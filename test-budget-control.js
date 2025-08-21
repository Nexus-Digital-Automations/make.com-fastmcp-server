async function testTool() {
  try {
    // Import the budget control module from compiled JS
    const { default: addBudgetControlTools } = await import('./dist/tools/budget-control.js');
    
    // Create a mock server similar to the test
    const registeredTools = new Map();
    const mockServer = {
      addTool: (tool) => {
        registeredTools.set(tool.name, tool);
      }
    };
    
    // Create a mock API client
    const mockApiClient = {
      get: () => Promise.resolve({ data: {} }),
      post: () => Promise.resolve({ data: {} }),
    };
    
    // Register the tools
    addBudgetControlTools(mockServer, mockApiClient);
    
    // Get the control-high-cost-scenarios tool
    const tool = registeredTools.get('control-high-cost-scenarios');
    console.log('Tool found:', tool ? 'yes' : 'no');
    console.log('Tool name:', tool?.name);
    console.log('Tool execute function:', typeof tool?.execute);
    
    if (tool) {
      // Create mock context
      const mockContext = {
        log: {
          info: (...args) => console.log('LOG INFO:', ...args),
          error: (...args) => console.log('LOG ERROR:', ...args),
          warn: (...args) => console.log('LOG WARN:', ...args),
          debug: (...args) => console.log('LOG DEBUG:', ...args),
        },
        reportProgress: (progress) => console.log('PROGRESS:', progress),
        session: { authenticated: true },
      };
      
      console.log('About to execute tool...');
      const result = await tool.execute({
        budgetId: 'budget_001',
        action: 'analyze',
        reason: 'Budget threshold analysis'
      }, mockContext);
      
      console.log('Tool execution completed');
      console.log('Result type:', typeof result);
      console.log('Result is defined:', result !== undefined);
      console.log('Result is null:', result === null);
      if (result) {
        console.log('Result preview:', result.substring(0, 200));
        try {
          const parsed = JSON.parse(result);
          console.log('Parsed successfully');
          console.log('Has analysis:', parsed.analysis ? 'yes' : 'no');
          console.log('Has recommendations:', parsed.recommendations ? 'yes' : 'no');
          console.log('Has controlActions:', parsed.controlActions ? 'yes' : 'no');
        } catch (e) {
          console.log('JSON parse error:', e.message);
        }
      } else {
        console.log('Result is undefined/null!');
      }
    }
  } catch (error) {
    console.error('Test error:', error.message);
    console.error(error.stack);
  }
}

testTool();