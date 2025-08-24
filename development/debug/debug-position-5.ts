/**
 * Debug script to find what causes JSON parsing error at position 5
 */

// Test various patterns that could cause "position 5" error
const problematicPatterns = [
  // Basic arrays
  "[]",
  "[a]", // Invalid - no quotes
  '["a"]',
  '["a" "b"]', // Missing comma - position 5 error!
  '["ab" "c"]', // Missing comma - position 6 error
  "[true false]", // Missing comma - position 6 error

  // Objects
  "{}",
  '{"a"}', // Invalid
  '{"a":}', // Invalid
  '{"a":"b"}',
  '{"a":"b" "c":"d"}', // Missing comma

  // Content arrays (our format)
  '{"content": []}',
  '{"content": [{"type": "text"}]}',
  '{"content": [{"type": "text", "text": ""}]}',
  '{"content": [{"type": "text" "text": ""}]}', // Missing comma!
];

console.log("🔍 Testing patterns for JSON parsing errors at position 5...\n");

problematicPatterns.forEach((pattern, i) => {
  try {
    JSON.parse(pattern);
    console.log(`✅ Pattern ${i + 1}: ${pattern}`);
  } catch (error) {
    const position = error.message.match(/position (\d+)/)?.[1];
    console.log(`❌ Pattern ${i + 1}: ${pattern}`);
    console.log(`   Error: ${error.message}`);
    if (position === "5") {
      console.log("🎯 EXACT MATCH: This causes position 5 error!");
    }
    console.log("");
  }
});

// Test our actual response format patterns
console.log("\n🧪 Testing actual response format patterns:\n");

const responsePatterns = [
  // Correct format
  JSON.stringify({
    content: [{ type: "text", text: "test" }],
  }),

  // Potential problematic format if string concatenation goes wrong
  '{"content": [{"type": "text" "text": "test"}]}',

  // Tool response format
  JSON.stringify({
    success: true,
    data: ["item1", "item2"],
  }),
];

responsePatterns.forEach((pattern, i) => {
  try {
    JSON.parse(pattern);
    console.log(`✅ Response ${i + 1}: Valid JSON`);
  } catch (error) {
    console.log(`❌ Response ${i + 1}: ${error.message}`);
    if (error.message.includes("position 5")) {
      console.log("🎯 FOUND THE ISSUE!");
    }
  }
});

// Test if our tools might be creating this pattern
console.log("\n🔧 Testing tool response construction:\n");

function testToolResponse(data: any, message?: string) {
  try {
    // Simulate our response formatter
    const response = {
      success: true,
      ...(message && { message }),
      ...(typeof data === "object" && data !== null ? data : { data }),
    };

    const formatted = {
      content: [
        {
          type: "text",
          text: JSON.stringify(response, null, 2),
        },
      ],
    };

    const serialized = JSON.stringify(formatted);
    JSON.parse(serialized); // Test if it's valid
    console.log("✅ Tool response format: Valid");
  } catch (error) {
    console.log(`❌ Tool response error: ${error.message}`);
  }
}

testToolResponse({ test: "data" }, "Test message");
