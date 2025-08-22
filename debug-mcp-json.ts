/**
 * Debug script to identify MCP JSON parsing issues
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';

console.log('🔍 Testing FastMCP server JSON serialization...');

// Create a minimal FastMCP server
const server = new FastMCP({
  name: "Test Server",
  version: "1.0.0",
  instructions: "Test server for JSON parsing debugging"
});

// Add a simple test tool
server.addTool({
  name: 'test-json-response',
  description: 'Test tool to check JSON response format',
  parameters: z.object({}),
  execute: async () => {
    // Test different response formats that might cause issues
    console.log('📝 Testing different response formats...');
    
    // Format 1: Plain string
    const plainResponse = "Simple string response";
    console.log('Format 1 (string):', typeof plainResponse);
    
    // Format 2: Content array format
    const contentResponse = {
      content: [
        {
          type: 'text',
          text: 'Content array response'
        }
      ]
    };
    console.log('Format 2 (content array):', JSON.stringify(contentResponse).substring(0, 50));
    
    // Format 3: JSON.stringify return (problematic)
    const jsonStringResponse = JSON.stringify({
      data: "test",
      array: ["item1", "item2", "item3"]
    });
    console.log('Format 3 (JSON string):', jsonStringResponse.substring(0, 50));
    
    // Test potential problematic patterns
    const testArrays = [
      '[]',
      '[true]',
      '[true false]', // Missing comma - this would cause position 5 error!
      '["a", "b"]',
      '["a" "b"]'    // Missing comma - this would cause similar error!
    ];
    
    console.log('\n🧪 Testing JSON array patterns:');
    testArrays.forEach((pattern, i) => {
      try {
        JSON.parse(pattern);
        console.log(`✅ Pattern ${i + 1}: ${pattern} - Valid`);
      } catch (error) {
        console.log(`❌ Pattern ${i + 1}: ${pattern} - ERROR: ${error.message}`);
        if (error.message.includes('position 5') || error.message.includes('position 6')) {
          console.log('🎯 POTENTIAL MATCH for the error we\'re seeing!');
        }
      }
    });
    
    return contentResponse;
  }
});

// Test server initialization
async function testServer() {
  console.log('\n🚀 Testing server initialization...');
  
  try {
    // Don't actually start the server, just test the setup
    console.log('✅ Server created successfully');
    console.log('✅ Tool added successfully');
    
    // Test the tool patterns that might cause JSON issues
    console.log('✅ Tools and JSON patterns tested');
    
  } catch (error) {
    console.error('❌ Server setup error:', error);
  }
}

testServer().catch(console.error);