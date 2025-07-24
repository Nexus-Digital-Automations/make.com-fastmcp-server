/**
 * Basic setup test to verify test infrastructure is working
 */

import { jest, describe, it, expect } from '@jest/globals';

describe('Test Infrastructure Setup', () => {
  it('should have Jest configured correctly', () => {
    expect(typeof describe).toBe('function');
    expect(typeof it).toBe('function');
    expect(typeof expect).toBe('function');
  });

  it('should have global test utilities available', () => {
    expect(globalThis.testUtils).toBeDefined();
    expect(typeof globalThis.testUtils.generateId).toBe('function');
    expect(typeof globalThis.testUtils.createMockUser).toBe('function');
    expect(typeof globalThis.testUtils.delay).toBe('function');
  });

  it('should be able to generate test data', () => {
    const id = globalThis.testUtils.generateId();
    expect(typeof id).toBe('number');
    expect(id).toBeGreaterThan(0);
    
    const user = globalThis.testUtils.createMockUser();
    expect(user).toHaveProperty('id');
    expect(user).toHaveProperty('name');
    expect(user).toHaveProperty('email');
  });

  it('should have mocks configured', () => {
    expect(jest.fn).toBeDefined();
    expect(jest.mock).toBeDefined();
    expect(jest.clearAllMocks).toBeDefined();
  });

  it('should support async operations', async () => {
    const start = Date.now();
    await globalThis.testUtils.delay(10);
    const duration = Date.now() - start;
    
    expect(duration).toBeGreaterThanOrEqual(10);
  });
});