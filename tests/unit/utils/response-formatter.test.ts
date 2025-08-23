/**
 * Comprehensive Unit Tests for Response Formatter Utilities
 * 
 * Tests response formatting functionality for FastMCP tools,
 * ensuring consistent response formats and preventing JSON parsing errors.
 * Focuses on coverage improvement for utils/response-formatter.ts.
 */

import { describe, it, expect } from '@jest/globals';
import {
  formatToolResponse,
  formatSuccessResponse,
  formatErrorResponse,
  convertLegacyJsonResponse,
  validateToolResponse,
  type ToolResponse
} from '../../../src/utils/response-formatter.js';

describe('Response Formatter Utilities', () => {

  describe('formatToolResponse()', () => {
    it('should format string data correctly', () => {
      const data = 'Simple string response';
      const result = formatToolResponse(data);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: 'Simple string response'
          }
        ]
      });
    });

    it('should format object data as JSON string', () => {
      const data = { message: 'Success', count: 42 };
      const result = formatToolResponse(data);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: JSON.stringify(data, null, 2)
          }
        ]
      });
      
      // Verify it's properly formatted JSON
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual(data);
    });

    it('should format array data as JSON string', () => {
      const data = [1, 2, 'three', { key: 'value' }];
      const result = formatToolResponse(data);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: JSON.stringify(data, null, 2)
          }
        ]
      });
    });

    it('should handle null data', () => {
      const result = formatToolResponse(null);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: 'null'
          }
        ]
      });
    });

    it('should handle undefined data', () => {
      const result = formatToolResponse(undefined);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: undefined
          }
        ]
      });
    });

    it('should handle boolean data', () => {
      const resultTrue = formatToolResponse(true);
      const resultFalse = formatToolResponse(false);
      
      expect(resultTrue.content[0].text).toBe('true');
      expect(resultFalse.content[0].text).toBe('false');
    });

    it('should handle number data', () => {
      const resultNumber = formatToolResponse(42);
      const resultFloat = formatToolResponse(3.14159);
      
      expect(resultNumber.content[0].text).toBe('42');
      expect(resultFloat.content[0].text).toBe('3.14159');
    });

    it('should handle empty string', () => {
      const result = formatToolResponse('');
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: ''
          }
        ]
      });
    });

    it('should handle complex nested object', () => {
      const data = {
        users: [
          { id: 1, name: 'Alice', active: true },
          { id: 2, name: 'Bob', active: false }
        ],
        metadata: {
          total: 2,
          page: 1,
          filters: null
        }
      };
      
      const result = formatToolResponse(data);
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual(data);
    });
  });

  describe('formatSuccessResponse()', () => {
    it('should format success response with data object', () => {
      const data = { id: 123, name: 'Test Item' };
      const result = formatSuccessResponse(data);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true,
        id: 123,
        name: 'Test Item'
      });
    });

    it('should format success response with message', () => {
      const data = { count: 5 };
      const message = 'Operation completed successfully';
      const result = formatSuccessResponse(data, message);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true,
        message: 'Operation completed successfully',
        count: 5
      });
    });

    it('should handle primitive data types', () => {
      const result = formatSuccessResponse('simple string');
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true,
        data: 'simple string'
      });
    });

    it('should handle number data', () => {
      const result = formatSuccessResponse(42);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true,
        data: 42
      });
    });

    it('should handle null data', () => {
      const result = formatSuccessResponse(null);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true,
        data: null
      });
    });

    it('should handle success response without message', () => {
      const data = { items: [], total: 0 };
      const result = formatSuccessResponse(data);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true,
        items: [],
        total: 0
      });
      expect(parsedText).not.toHaveProperty('message');
    });

    it('should handle empty object data', () => {
      const result = formatSuccessResponse({});
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toMatchObject({
        success: true
      });
    });

    it('should preserve all object properties', () => {
      const data = {
        result: 'completed',
        timestamp: '2023-01-01T00:00:00Z',
        metadata: { version: '1.0' }
      };
      const result = formatSuccessResponse(data, 'Task finished');
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: true,
        message: 'Task finished',
        result: 'completed',
        timestamp: '2023-01-01T00:00:00Z',
        metadata: { version: '1.0' }
      });
    });
  });

  describe('formatErrorResponse()', () => {
    it('should format error response with string error', () => {
      const error = 'Something went wrong';
      const result = formatErrorResponse(error);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: 'Something went wrong'
      });
    });

    it('should format error response with Error object', () => {
      const error = new Error('Database connection failed');
      const result = formatErrorResponse(error);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: 'Database connection failed'
      });
    });

    it('should format error response with error code', () => {
      const error = 'Validation failed';
      const code = 'VALIDATION_ERROR';
      const result = formatErrorResponse(error, code);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: 'Validation failed',
        code: 'VALIDATION_ERROR'
      });
    });

    it('should format error response with Error object and code', () => {
      const error = new Error('Network timeout');
      const code = 'TIMEOUT';
      const result = formatErrorResponse(error, code);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: 'Network timeout',
        code: 'TIMEOUT'
      });
    });

    it('should handle empty string error', () => {
      const result = formatErrorResponse('');
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: ''
      });
    });

    it('should handle Error with no message', () => {
      const error = new Error();
      const result = formatErrorResponse(error);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: ''
      });
    });

    it('should handle custom Error types', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }
      
      const error = new CustomError('Custom error occurred');
      const result = formatErrorResponse(error, 'CUSTOM_ERROR');
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        success: false,
        error: 'Custom error occurred',
        code: 'CUSTOM_ERROR'
      });
    });
  });

  describe('convertLegacyJsonResponse()', () => {
    it('should convert valid JSON string to tool response', () => {
      const jsonString = JSON.stringify({ status: 'success', data: [1, 2, 3] });
      const result = convertLegacyJsonResponse(jsonString);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        status: 'success',
        data: [1, 2, 3]
      });
    });

    it('should handle invalid JSON as plain text', () => {
      const invalidJson = '{ status: "success", data: [1, 2, 3] }'; // Missing quotes
      const result = convertLegacyJsonResponse(invalidJson);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: invalidJson
          }
        ]
      });
    });

    it('should handle plain text string', () => {
      const plainText = 'This is not JSON';
      const result = convertLegacyJsonResponse(plainText);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: plainText
          }
        ]
      });
    });

    it('should handle empty string', () => {
      const result = convertLegacyJsonResponse('');
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: ''
          }
        ]
      });
    });

    it('should handle JSON with null values', () => {
      const jsonString = JSON.stringify({ value: null, active: false });
      const result = convertLegacyJsonResponse(jsonString);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual({
        value: null,
        active: false
      });
    });

    it('should handle complex nested JSON', () => {
      const complexData = {
        users: [
          { id: 1, profile: { name: 'Alice', settings: { theme: 'dark' } } },
          { id: 2, profile: { name: 'Bob', settings: { theme: 'light' } } }
        ],
        metadata: {
          total: 2,
          filters: { active: true }
        }
      };
      
      const jsonString = JSON.stringify(complexData);
      const result = convertLegacyJsonResponse(jsonString);
      
      const parsedText = JSON.parse(result.content[0].text);
      expect(parsedText).toEqual(complexData);
    });

    it('should handle malformed JSON gracefully', () => {
      const malformedJson = '{"key": "value"'; // Missing closing brace
      const result = convertLegacyJsonResponse(malformedJson);
      
      expect(result).toEqual({
        content: [
          {
            type: 'text',
            text: malformedJson
          }
        ]
      });
    });
  });

  describe('validateToolResponse()', () => {
    it('should validate correct tool response format', () => {
      const validResponse: ToolResponse = {
        content: [
          {
            type: 'text',
            text: 'Valid response'
          }
        ]
      };
      
      expect(validateToolResponse(validResponse)).toBe(true);
    });

    it('should validate tool response with multiple content items', () => {
      const validResponse: ToolResponse = {
        content: [
          {
            type: 'text',
            text: 'First item'
          },
          {
            type: 'text',
            text: 'Second item'
          }
        ]
      };
      
      expect(validateToolResponse(validResponse)).toBe(true);
    });

    it('should validate plain string as valid response', () => {
      expect(validateToolResponse('Simple string')).toBe(true);
      expect(validateToolResponse('')).toBe(true);
    });

    it('should reject response with invalid content structure', () => {
      const invalidResponse = {
        content: [
          {
            type: 'image', // Wrong type
            text: 'Some text'
          }
        ]
      };
      
      expect(validateToolResponse(invalidResponse)).toBe(false);
    });

    it('should reject response without content property', () => {
      const invalidResponse = {
        data: 'Some data'
      };
      
      expect(validateToolResponse(invalidResponse)).toBe(false);
    });

    it('should reject response with non-array content', () => {
      const invalidResponse = {
        content: 'Not an array'
      };
      
      expect(validateToolResponse(invalidResponse)).toBe(false);
    });

    it('should reject response with invalid content items', () => {
      const invalidResponse = {
        content: [
          {
            type: 'text'
            // Missing text property
          }
        ]
      };
      
      expect(validateToolResponse(invalidResponse)).toBe(false);
    });

    it('should reject response with non-string text', () => {
      const invalidResponse = {
        content: [
          {
            type: 'text',
            text: 123 // Should be string
          }
        ]
      };
      
      expect(validateToolResponse(invalidResponse)).toBe(false);
    });

    it('should reject null response', () => {
      expect(validateToolResponse(null)).toBe(false);
    });

    it('should reject undefined response', () => {
      expect(validateToolResponse(undefined)).toBe(false);
    });

    it('should reject number response', () => {
      expect(validateToolResponse(42)).toBe(false);
    });

    it('should reject boolean response', () => {
      expect(validateToolResponse(true)).toBe(false);
      expect(validateToolResponse(false)).toBe(false);
    });

    it('should handle empty content array', () => {
      const emptyResponse = {
        content: []
      };
      
      expect(validateToolResponse(emptyResponse)).toBe(true);
    });

    it('should reject mixed content types', () => {
      const invalidResponse = {
        content: [
          {
            type: 'text',
            text: 'Valid item'
          },
          {
            type: 'text',
            text: 123 // Invalid text type
          }
        ]
      };
      
      expect(validateToolResponse(invalidResponse)).toBe(false);
    });
  });

  describe('Interface Validation', () => {
    it('should validate ToolResponse interface structure', () => {
      const response: ToolResponse = {
        content: [
          {
            type: 'text',
            text: 'Test content'
          }
        ]
      };
      
      expect(typeof response.content).toBe('object');
      expect(Array.isArray(response.content)).toBe(true);
      expect(response.content[0].type).toBe('text');
      expect(typeof response.content[0].text).toBe('string');
    });

    it('should handle multiple content items in interface', () => {
      const response: ToolResponse = {
        content: [
          { type: 'text', text: 'First' },
          { type: 'text', text: 'Second' },
          { type: 'text', text: 'Third' }
        ]
      };
      
      expect(response.content).toHaveLength(3);
      response.content.forEach(item => {
        expect(item.type).toBe('text');
        expect(typeof item.text).toBe('string');
      });
    });
  });

  describe('Integration Tests', () => {
    it('should work with real-world success scenario', () => {
      const userData = {
        id: 'user_123',
        email: 'test@example.com',
        profile: {
          firstName: 'John',
          lastName: 'Doe',
          preferences: {
            theme: 'dark',
            notifications: true
          }
        },
        createdAt: '2023-01-01T00:00:00Z'
      };
      
      const response = formatSuccessResponse(userData, 'User retrieved successfully');
      const isValid = validateToolResponse(response);
      
      expect(isValid).toBe(true);
      
      const parsedText = JSON.parse(response.content[0].text);
      expect(parsedText.success).toBe(true);
      expect(parsedText.message).toBe('User retrieved successfully');
      expect(parsedText.id).toBe('user_123');
    });

    it('should work with real-world error scenario', () => {
      const error = new Error('Database connection timeout');
      const response = formatErrorResponse(error, 'DB_TIMEOUT');
      const isValid = validateToolResponse(response);
      
      expect(isValid).toBe(true);
      
      const parsedText = JSON.parse(response.content[0].text);
      expect(parsedText.success).toBe(false);
      expect(parsedText.error).toBe('Database connection timeout');
      expect(parsedText.code).toBe('DB_TIMEOUT');
    });

    it('should handle migration from legacy JSON response', () => {
      const legacyResponse = JSON.stringify({
        status: 'ok',
        results: [
          { id: 1, name: 'Item 1' },
          { id: 2, name: 'Item 2' }
        ],
        pagination: { page: 1, total: 2 }
      });
      
      const convertedResponse = convertLegacyJsonResponse(legacyResponse);
      const isValid = validateToolResponse(convertedResponse);
      
      expect(isValid).toBe(true);
      
      const parsedText = JSON.parse(convertedResponse.content[0].text);
      expect(parsedText.status).toBe('ok');
      expect(parsedText.results).toHaveLength(2);
      expect(parsedText.pagination.total).toBe(2);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle circular references in objects', () => {
      const circularData: any = { name: 'test' };
      circularData.self = circularData;
      
      // JSON.stringify should throw on circular reference
      expect(() => {
        formatToolResponse(circularData);
      }).toThrow();
    });

    it('should handle very large objects', () => {
      const largeObject = {
        data: new Array(1000).fill(0).map((_, i) => ({
          id: i,
          name: `Item ${i}`,
          description: 'A'.repeat(100)
        }))
      };
      
      const response = formatToolResponse(largeObject);
      expect(validateToolResponse(response)).toBe(true);
      
      const parsedText = JSON.parse(response.content[0].text);
      expect(parsedText.data).toHaveLength(1000);
    });

    it('should handle special characters and unicode', () => {
      const specialData = {
        emoji: '🚀🔥💻',
        unicode: 'こんにちは世界',
        special: 'Line 1\nLine 2\tTabbed\r\nWindows newline',
        quotes: 'He said "Hello" and she replied \'Hi\''
      };
      
      const response = formatSuccessResponse(specialData);
      const parsedText = JSON.parse(response.content[0].text);
      
      expect(parsedText.emoji).toBe('🚀🔥💻');
      expect(parsedText.unicode).toBe('こんにちは世界');
      expect(parsedText.special).toBe('Line 1\nLine 2\tTabbed\r\nWindows newline');
    });

    it('should handle Date objects in data', () => {
      const date = new Date('2023-01-01T00:00:00Z');
      const dataWithDate = {
        timestamp: date,
        message: 'Date test'
      };
      
      const response = formatToolResponse(dataWithDate);
      const parsedText = JSON.parse(response.content[0].text);
      
      expect(parsedText.timestamp).toBe('2023-01-01T00:00:00.000Z');
    });
  });
});