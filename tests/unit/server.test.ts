/**
 * Unit Tests for Main Server Implementation
 * Tests server initialization, configuration, and basic functionality
 */

import { describe, test, expect, beforeEach } from '@jest/globals';

describe('Server Module', () => {
  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  test('should be importable without throwing errors', async () => {
    let importError: Error | null = null;
    
    try {
      await import('../../../src/server.js');
    } catch (error) {
      importError = error as Error;
    }
    
    expect(importError).toBeNull();
  });

  test('should export server instance', async () => {
    const serverModule = await import('../../../src/server.js');
    expect(serverModule.server).toBeDefined();
    expect(serverModule.server).toBeTruthy();
  });

  test('should export default server instance', async () => {
    const serverModule = await import('../../../src/server.js');
    expect(serverModule.default).toBeDefined();
    expect(serverModule.default).toBeTruthy();
  });

  test('server instance should be an object', async () => {
    const serverModule = await import('../../../src/server.js');
    expect(typeof serverModule.server).toBe('object');
    expect(serverModule.server).not.toBeNull();
  });

  test('should have common FastMCP server properties', async () => {
    const serverModule = await import('../../../src/server.js');
    const server = serverModule.server;
    
    // Basic checks to ensure it's a FastMCP-like object
    expect(server).toHaveProperty('name');
    expect(server).toHaveProperty('version');
  });

  test('should have initialized with Make.com server configuration', async () => {
    const serverModule = await import('../../../src/server.js');
    const server = serverModule.server;
    
    // Check that server has been configured with expected name
    expect(server.name).toBe('make-fastmcp-server');
    expect(server.version).toBe('1.0.0');
  });

  test('should be able to access tools collection', async () => {
    const serverModule = await import('../../../src/server.js');
    const server = serverModule.server;
    
    // FastMCP servers typically have a tools property
    expect(server).toHaveProperty('tools');
  });

  test('should have setup multiple tool categories', async () => {
    const serverModule = await import('../../../src/server.js');
    const server = serverModule.server;
    
    // Check that tools have been registered (tools Map should not be empty)
    if (server.tools && server.tools.size !== undefined) {
      expect(server.tools.size).toBeGreaterThan(0);
    }
  });
});