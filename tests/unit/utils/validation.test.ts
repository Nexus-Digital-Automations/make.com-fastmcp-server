/**
 * Comprehensive unit tests for validation.ts module
 * Ensures 100% test coverage for input validation functionality
 */

import { z } from 'zod';
import {
  idSchema,
  nameSchema,
  emailSchema,
  urlSchema,
  teamIdSchema,
  organizationIdSchema,
  paginationSchema,
  dateRangeSchema,
  scenarioCreateSchema,
  scenarioUpdateSchema,
  connectionCreateSchema,
  connectionUpdateSchema,
  templateCreateSchema,
  templateUpdateSchema,
  userCreateSchema,
  userUpdateSchema,
  webhookCreateSchema,
  webhookUpdateSchema,
  variableCreateSchema,
  variableUpdateSchema,
  validateId,
  validatePagination,
  validateDateRange,
  sanitizeString,
  isValidEmail,
  isValidUrl,
  validateSchema,
} from '../../../src/utils/validation.js';

describe('Validation System - Comprehensive Test Suite', () => {
  describe('Basic Schema Validation', () => {
    describe('idSchema', () => {
      it('should accept positive integers', () => {
        expect(idSchema.parse(1)).toBe(1);
        expect(idSchema.parse(123)).toBe(123);
        expect(idSchema.parse(999999)).toBe(999999);
      });

      it('should reject non-positive numbers', () => {
        expect(() => idSchema.parse(0)).toThrow();
        expect(() => idSchema.parse(-1)).toThrow();
        expect(() => idSchema.parse(-123)).toThrow();
      });

      it('should reject non-integers', () => {
        expect(() => idSchema.parse(1.5)).toThrow();
        expect(() => idSchema.parse(3.14)).toThrow();
      });

      it('should reject non-numbers', () => {
        expect(() => idSchema.parse('123')).toThrow();
        expect(() => idSchema.parse(null)).toThrow();
        expect(() => idSchema.parse(undefined)).toThrow();
        expect(() => idSchema.parse({})).toThrow();
      });
    });

    describe('nameSchema', () => {
      it('should accept valid names', () => {
        expect(nameSchema.parse('Test Name')).toBe('Test Name');
        expect(nameSchema.parse('A')).toBe('A');
        expect(nameSchema.parse('x'.repeat(255))).toBe('x'.repeat(255));
      });

      it('should reject empty strings', () => {
        expect(() => nameSchema.parse('')).toThrow();
      });

      it('should reject names that are too long', () => {
        expect(() => nameSchema.parse('x'.repeat(256))).toThrow();
      });

      it('should reject non-strings', () => {
        expect(() => nameSchema.parse(123)).toThrow();
        expect(() => nameSchema.parse(null)).toThrow();
        expect(() => nameSchema.parse(undefined)).toThrow();
      });
    });

    describe('emailSchema', () => {
      it('should accept valid emails', () => {
        const validEmails = [
          'test@example.com',
          'user.name@domain.co.uk',
          'admin+tag@company.org',
          'test123@test-domain.com',
        ];

        validEmails.forEach(email => {
          expect(emailSchema.parse(email)).toBe(email);
        });
      });

      it('should reject invalid emails', () => {
        const invalidEmails = [
          'invalid-email',
          '@domain.com',
          'user@',
          'user@domain',
          'user..name@domain.com',
          '',
        ];

        invalidEmails.forEach(email => {
          expect(() => emailSchema.parse(email)).toThrow();
        });
      });
    });

    describe('urlSchema', () => {
      it('should accept valid URLs', () => {
        const validUrls = [
          'https://example.com',
          'http://test.domain.co.uk',
          'https://api.service.com/v1/endpoint',
          'http://localhost:3000/path',
        ];

        validUrls.forEach(url => {
          expect(urlSchema.parse(url)).toBe(url);
        });
      });

      it('should reject invalid URLs', () => {
        const invalidUrls = [
          'invalid-url',
          'ftp://example.com',
          'example.com',
          '',
          'http://',
          'https://',
        ];

        invalidUrls.forEach(url => {
          expect(() => urlSchema.parse(url)).toThrow();
        });
      });
    });

    describe('teamIdSchema and organizationIdSchema', () => {
      it('should accept positive integers and undefined', () => {
        expect(teamIdSchema.parse(1)).toBe(1);
        expect(teamIdSchema.parse(undefined)).toBe(undefined);
        expect(organizationIdSchema.parse(123)).toBe(123);
        expect(organizationIdSchema.parse(undefined)).toBe(undefined);
      });

      it('should reject invalid values', () => {
        expect(() => teamIdSchema.parse(0)).toThrow();
        expect(() => teamIdSchema.parse(-1)).toThrow();
        expect(() => teamIdSchema.parse('123')).toThrow();
      });
    });
  });

  describe('Complex Schema Validation', () => {
    describe('paginationSchema', () => {
      it('should accept valid pagination parameters', () => {
        const result = paginationSchema.parse({
          page: 2,
          limit: 50,
          sortBy: 'name',
          sortOrder: 'desc',
        });

        expect(result).toEqual({
          page: 2,
          limit: 50,
          sortBy: 'name',
          sortOrder: 'desc',
        });
      });

      it('should apply default values', () => {
        const result = paginationSchema.parse({});
        expect(result).toEqual({
          page: 1,
          limit: 20,
          sortOrder: 'asc',
        });
      });

      it('should reject invalid page numbers', () => {
        expect(() => paginationSchema.parse({ page: 0 })).toThrow();
        expect(() => paginationSchema.parse({ page: -1 })).toThrow();
      });

      it('should reject invalid limit values', () => {
        expect(() => paginationSchema.parse({ limit: 0 })).toThrow();
        expect(() => paginationSchema.parse({ limit: 101 })).toThrow();
        expect(() => paginationSchema.parse({ limit: -1 })).toThrow();
      });

      it('should reject invalid sort orders', () => {
        expect(() => paginationSchema.parse({ sortOrder: 'invalid' })).toThrow();
      });
    });

    describe('dateRangeSchema', () => {
      it('should accept valid date ranges', () => {
        const result = dateRangeSchema.parse({
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
        });

        expect(result).toEqual({
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
        });
      });

      it('should accept empty date range', () => {
        const result = dateRangeSchema.parse({});
        expect(result).toEqual({});
      });

      it('should accept partial date range', () => {
        const result1 = dateRangeSchema.parse({ startDate: '2024-01-01T00:00:00Z' });
        expect(result1.startDate).toBe('2024-01-01T00:00:00Z');
        expect(result1.endDate).toBeUndefined();

        const result2 = dateRangeSchema.parse({ endDate: '2024-01-31T23:59:59Z' });
        expect(result2.endDate).toBe('2024-01-31T23:59:59Z');
        expect(result2.startDate).toBeUndefined();
      });

      it('should reject invalid date formats', () => {
        expect(() => dateRangeSchema.parse({ startDate: '2024-01-01' })).toThrow();
        expect(() => dateRangeSchema.parse({ endDate: 'invalid-date' })).toThrow();
      });
    });

    describe('scenarioCreateSchema', () => {
      it('should accept valid scenario creation data', () => {
        const validData = {
          name: 'Test Scenario',
          teamId: 123,
          folderId: 456,
          blueprint: { flow: [] },
          scheduling: {
            type: 'indefinitely' as const,
            interval: 900,
          },
          isActive: true,
        };

        const result = scenarioCreateSchema.parse(validData);
        expect(result).toEqual(validData);
      });

      it('should apply default isActive value', () => {
        const data = {
          name: 'Test Scenario',
          teamId: 123,
          blueprint: { flow: [] },
          scheduling: { type: 'immediate' as const },
        };

        const result = scenarioCreateSchema.parse(data);
        expect(result.isActive).toBe(true);
      });

      it('should reject missing required fields', () => {
        expect(() => scenarioCreateSchema.parse({})).toThrow();
        expect(() => scenarioCreateSchema.parse({ name: 'Test' })).toThrow();
        expect(() => scenarioCreateSchema.parse({ teamId: 123 })).toThrow();
      });

      it('should reject invalid scheduling types', () => {
        const data = {
          name: 'Test',
          teamId: 123,
          blueprint: {},
          scheduling: { type: 'invalid' },
        };

        expect(() => scenarioCreateSchema.parse(data)).toThrow();
      });
    });

    describe('scenarioUpdateSchema', () => {
      it('should accept partial update data', () => {
        const result = scenarioUpdateSchema.parse({ name: 'Updated Name' });
        expect(result).toEqual({ name: 'Updated Name' });
      });

      it('should accept empty update data', () => {
        const result = scenarioUpdateSchema.parse({});
        expect(result).toEqual({});
      });
    });

    describe('connectionCreateSchema', () => {
      it('should accept valid connection data', () => {
        const validData = {
          name: 'Test Connection',
          accountName: 'test@example.com',
          service: 'gmail',
          metadata: { scopes: ['read', 'write'] },
        };

        const result = connectionCreateSchema.parse(validData);
        expect(result).toEqual(validData);
      });

      it('should reject missing required fields', () => {
        expect(() => connectionCreateSchema.parse({})).toThrow();
        expect(() => connectionCreateSchema.parse({ name: 'Test' })).toThrow();
      });
    });

    describe('templateCreateSchema', () => {
      it('should accept valid template data with defaults', () => {
        const data = {
          name: 'Test Template',
          blueprint: { flow: [] },
        };

        const result = templateCreateSchema.parse(data);
        expect(result.tags).toEqual([]);
        expect(result.isPublic).toBe(false);
      });

      it('should accept complete template data', () => {
        const data = {
          name: 'Test Template',
          description: 'A test template',
          category: 'automation',
          blueprint: { flow: [] },
          tags: ['test', 'automation'],
          isPublic: true,
        };

        const result = templateCreateSchema.parse(data);
        expect(result).toEqual(data);
      });
    });

    describe('userCreateSchema', () => {
      it('should accept valid user data', () => {
        const data = {
          name: 'John Doe',
          email: 'john@example.com',
          role: 'member' as const,
          teamId: 123,
        };

        const result = userCreateSchema.parse(data);
        expect(result.permissions).toEqual([]);
      });

      it('should reject invalid roles', () => {
        const data = {
          name: 'John Doe',
          email: 'john@example.com',
          role: 'invalid',
          teamId: 123,
        };

        expect(() => userCreateSchema.parse(data)).toThrow();
      });
    });

    describe('webhookCreateSchema', () => {
      it('should accept valid webhook data with defaults', () => {
        const data = {
          name: 'Test Webhook',
          url: 'https://example.com/webhook',
        };

        const result = webhookCreateSchema.parse(data);
        expect(result.method).toBe('POST');
        expect(result.isActive).toBe(true);
      });

      it('should accept custom method and headers', () => {
        const data = {
          name: 'Test Webhook',
          url: 'https://example.com/webhook',
          method: 'PUT' as const,
          headers: { 'X-API-Key': 'secret' },
        };

        const result = webhookCreateSchema.parse(data);
        expect(result.method).toBe('PUT');
        expect(result.headers).toEqual({ 'X-API-Key': 'secret' });
      });
    });

    describe('variableCreateSchema', () => {
      it('should accept valid variable data', () => {
        const data = {
          name: 'API_KEY',
          value: 'secret-key',
          type: 'string' as const,
          scope: 'global' as const,
        };

        const result = variableCreateSchema.parse(data);
        expect(result.isEncrypted).toBe(false);
      });

      it('should reject invalid variable names', () => {
        const invalidNames = ['123invalid', 'invalid-name', 'invalid name', ''];
        
        invalidNames.forEach(name => {
          expect(() => variableCreateSchema.parse({
            name,
            value: 'test',
            type: 'string',
            scope: 'global',
          })).toThrow();
        });
      });

      it('should accept valid variable names', () => {
        const validNames = ['API_KEY', 'apiKey', 'api_key_123', '_private'];
        
        validNames.forEach(name => {
          expect(() => variableCreateSchema.parse({
            name,
            value: 'test',
            type: 'string',
            scope: 'global',
          })).not.toThrow();
        });
      });
    });
  });

  describe('Validation Helper Functions', () => {
    describe('validateId', () => {
      it('should return valid ID', () => {
        expect(validateId(123)).toBe(123);
        expect(validateId(1)).toBe(1);
      });

      it('should throw error for invalid ID', () => {
        expect(() => validateId(0)).toThrow('Invalid ID:');
        expect(() => validateId(-1)).toThrow('Invalid ID:');
        expect(() => validateId('123')).toThrow('Invalid ID:');
        expect(() => validateId(null)).toThrow('Invalid ID:');
      });
    });

    describe('validatePagination', () => {
      it('should return valid pagination with defaults', () => {
        const result = validatePagination({});
        expect(result).toEqual({
          page: 1,
          limit: 20,
          sortOrder: 'asc',
        });
      });

      it('should return custom pagination values', () => {
        const params = { page: 3, limit: 50, sortBy: 'name', sortOrder: 'desc' };
        const result = validatePagination(params);
        expect(result).toEqual(params);
      });

      it('should throw error for invalid pagination', () => {
        expect(() => validatePagination({ page: 0 })).toThrow('Invalid pagination parameters:');
        expect(() => validatePagination({ limit: 101 })).toThrow('Invalid pagination parameters:');
      });
    });

    describe('validateDateRange', () => {
      it('should return valid date range', () => {
        const dateRange = {
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
        };
        
        const result = validateDateRange(dateRange);
        expect(result).toEqual(dateRange);
      });

      it('should return empty object for no dates', () => {
        const result = validateDateRange({});
        expect(result).toEqual({});
      });

      it('should throw error for invalid date format', () => {
        expect(() => validateDateRange({ startDate: 'invalid-date' })).toThrow('Invalid date range:');
      });

      it('should throw error when start date is after end date', () => {
        const invalidRange = {
          startDate: '2024-02-01T00:00:00Z',
          endDate: '2024-01-01T00:00:00Z',
        };

        expect(() => validateDateRange(invalidRange)).toThrow('Start date must be before end date');
      });

      it('should throw error when start date equals end date', () => {
        const invalidRange = {
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-01T00:00:00Z',
        };

        expect(() => validateDateRange(invalidRange)).toThrow('Start date must be before end date');
      });

      it('should accept only start date', () => {
        const result = validateDateRange({ startDate: '2024-01-01T00:00:00Z' });
        expect(result.startDate).toBe('2024-01-01T00:00:00Z');
        expect(result.endDate).toBeUndefined();
      });

      it('should accept only end date', () => {
        const result = validateDateRange({ endDate: '2024-01-31T23:59:59Z' });
        expect(result.endDate).toBe('2024-01-31T23:59:59Z');
        expect(result.startDate).toBeUndefined();
      });
    });

    describe('sanitizeString', () => {
      it('should remove dangerous characters', () => {
        expect(sanitizeString('  <script>alert("xss")</script>  ')).toBe('scriptalert(xss)/script');
        expect(sanitizeString('Test & "quoted" \'string\'')).toBe('Test  quoted string');
        expect(sanitizeString('Normal string')).toBe('Normal string');
      });

      it('should trim whitespace', () => {
        expect(sanitizeString('  test  ')).toBe('test');
        expect(sanitizeString('\t\ntest\r\n')).toBe('test');
      });

      it('should handle empty strings', () => {
        expect(sanitizeString('')).toBe('');
        expect(sanitizeString('   ')).toBe('');
      });
    });

    describe('isValidEmail', () => {
      it('should return true for valid emails', () => {
        expect(isValidEmail('test@example.com')).toBe(true);
        expect(isValidEmail('user.name@domain.co.uk')).toBe(true);
      });

      it('should return false for invalid emails', () => {
        expect(isValidEmail('invalid-email')).toBe(false);
        expect(isValidEmail('@domain.com')).toBe(false);
        expect(isValidEmail('')).toBe(false);
      });
    });

    describe('isValidUrl', () => {
      it('should return true for valid URLs', () => {
        expect(isValidUrl('https://example.com')).toBe(true);
        expect(isValidUrl('http://localhost:3000')).toBe(true);
      });

      it('should return false for invalid URLs', () => {
        expect(isValidUrl('invalid-url')).toBe(false);
        expect(isValidUrl('ftp://example.com')).toBe(false);
        expect(isValidUrl('')).toBe(false);
      });
    });

    describe('validateSchema', () => {
      it('should return validated data for valid input', () => {
        const schema = z.object({
          name: z.string(),
          age: z.number(),
        });

        const data = { name: 'John', age: 30 };
        const result = validateSchema(schema, data);
        expect(result).toEqual(data);
      });

      it('should throw error for invalid input', () => {
        const schema = z.object({
          name: z.string(),
          age: z.number(),
        });

        const invalidData = { name: 'John', age: 'thirty' };
        expect(() => validateSchema(schema, invalidData)).toThrow('Validation failed:');
      });

      it('should work with complex schemas', () => {
        const result = validateSchema(scenarioCreateSchema, {
          name: 'Test Scenario',
          teamId: 123,
          blueprint: { flow: [] },
          scheduling: { type: 'immediate' },
        });

        expect(result.name).toBe('Test Scenario');
        expect(result.isActive).toBe(true); // Default value
      });
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle null and undefined values appropriately', () => {
      expect(() => nameSchema.parse(null)).toThrow();
      expect(() => nameSchema.parse(undefined)).toThrow();
      expect(teamIdSchema.parse(undefined)).toBe(undefined);
    });

    it('should handle extremely long strings', () => {
      const longString = 'x'.repeat(1000);
      expect(() => nameSchema.parse(longString)).toThrow();
    });

    it('should handle various number types', () => {
      expect(idSchema.parse(1)).toBe(1);
      expect(() => idSchema.parse(1.1)).toThrow();
      expect(() => idSchema.parse(Infinity)).toThrow();
      expect(() => idSchema.parse(-Infinity)).toThrow();
      expect(() => idSchema.parse(NaN)).toThrow();
    });

    it('should handle boundary values for pagination', () => {
      expect(paginationSchema.parse({ page: 1, limit: 1 })).toMatchObject({ page: 1, limit: 1 });
      expect(paginationSchema.parse({ page: 999999, limit: 100 })).toMatchObject({ page: 999999, limit: 100 });
      expect(() => paginationSchema.parse({ page: 0 })).toThrow();
      expect(() => paginationSchema.parse({ limit: 0 })).toThrow();
    });

    it('should handle complex nested objects', () => {
      const complexBlueprint = {
        flow: [
          { id: 1, app: 'webhook', config: { url: 'https://example.com' } },
          { id: 2, app: 'email', config: { template: 'welcome' } },
        ],
        settings: { timeout: 30000, retries: 3 },
      };

      const result = scenarioCreateSchema.parse({
        name: 'Complex Scenario',
        teamId: 123,
        blueprint: complexBlueprint,
        scheduling: { type: 'indefinitely', interval: 900 },
      });

      expect(result.blueprint).toEqual(complexBlueprint);
    });
  });
});