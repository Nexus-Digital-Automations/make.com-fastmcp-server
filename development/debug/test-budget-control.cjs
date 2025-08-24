const { createMockServer, findTool, executeTool } = require('./tests/utils/test-helpers.js');
const { MockMakeApiClient } = require('./tests/mocks/make-api-client.mock.js');
const { addBudgetControlTools } = require('./src/tools/budget-control.js');

async function testTool() {
  try {
    const { server, mockTool } = createMockServer();
    const mockApiClient = new MockMakeApiClient();
    
    addBudgetControlTools(server, mockApiClient);
    const tool = findTool(mockTool, 'control-high-cost-scenarios');
    
    console.log('Tool found:', !!tool, tool?.name);
    
    if (tool) {
      const result = await executeTool(tool, {
        budgetId: 'budget_001',
        action: 'analyze',
        reason: 'Test'
      });
      
      console.log('Success! Result type:', typeof result);
      console.log('Result defined:', result !== undefined);
      if (result) {
        console.log('Result length:', result.length);
        console.log('First 100 chars:', result.substring(0, 100));
        
        try {
          const parsed = JSON.parse(result);
          console.log('Parsed keys:', Object.keys(parsed));
          console.log('Has analysis:', !!parsed.analysis);
        } catch (parseError) {
          console.log('JSON parse failed:', parseError.message);
        }
      }
    }
  } catch (error) {
    console.log('Error:', error.message);
    console.log('Stack:', error.stack);
  }
}

testTool();