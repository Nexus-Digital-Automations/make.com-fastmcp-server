const { addBudgetControlTools } = require('./src/tools/budget-control.js');
const { createMockServer, findTool, executeTool } = require('./tests/utils/test-helpers.js');
const { MockMakeApiClient } = require('./tests/mocks/make-api-client.mock.js');

async function testBudgetControl() {
  try {
    const { server, mockTool } = createMockServer();
    const mockApiClient = new MockMakeApiClient();
    
    addBudgetControlTools(server, mockApiClient);
    const tool = findTool(mockTool, 'control-high-cost-scenarios');
    
    console.log('Tool found:', !!tool);
    
    if (tool) {
      const result = await executeTool(tool, {
        budgetId: 'budget_001',
        action: 'analyze',
        reason: 'Budget threshold analysis'
      });
      
      console.log('Result type:', typeof result);
      console.log('Result length:', result?.length);
      console.log('First 500 chars:', result?.substring(0, 500));
      
      const parsed = JSON.parse(result);
      console.log('Parsed keys:', Object.keys(parsed));
      console.log('Has analysis:', !!parsed.analysis);
      console.log('Analysis keys:', parsed.analysis ? Object.keys(parsed.analysis) : 'N/A');
    }
  } catch (error) {
    console.error('Error:', error);
  }
}

testBudgetControl();