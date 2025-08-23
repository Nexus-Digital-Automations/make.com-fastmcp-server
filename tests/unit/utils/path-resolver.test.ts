/**
 * Comprehensive Unit Tests for Path Resolver Utility
 * 
 * Tests path resolution functionality for project root detection,
 * logs directory resolution, and environment-specific path handling.
 * Focuses on coverage improvement for utils/path-resolver.ts.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as path from 'path';
import * as fs from 'fs';
import { getProjectRoot, getLogsDirectory } from '../../../src/utils/path-resolver.js';

describe('Path Resolver Utility', () => {
  const originalEnv = process.env.NODE_ENV;
  const originalJestWorker = process.env.JEST_WORKER_ID;
  const originalCwd = process.cwd();

  beforeEach(() => {
    // Reset environment to known state
    process.env.NODE_ENV = 'test';
    process.env.JEST_WORKER_ID = '1';
  });

  afterEach(() => {
    // Restore original environment
    process.env.NODE_ENV = originalEnv;
    process.env.JEST_WORKER_ID = originalJestWorker;
    // Note: We don't restore cwd() as Jest manages this
  });

  describe('getProjectRoot()', () => {
    it('should return current directory in test environment', () => {
      process.env.NODE_ENV = 'test';
      process.env.JEST_WORKER_ID = '1';
      
      const result = getProjectRoot();
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(result).toBe(process.cwd());
    });

    it('should return current directory when JEST_WORKER_ID is set', () => {
      delete process.env.NODE_ENV;
      process.env.JEST_WORKER_ID = '2';
      
      const result = getProjectRoot();
      expect(result).toBe(process.cwd());
    });

    it('should handle production-like environment path resolution', () => {
      delete process.env.NODE_ENV;
      delete process.env.JEST_WORKER_ID;
      
      const result = getProjectRoot();
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    it('should return absolute path', () => {
      const result = getProjectRoot();
      expect(path.isAbsolute(result)).toBe(true);
    });

    it('should return existing directory', () => {
      const result = getProjectRoot();
      expect(fs.existsSync(result)).toBe(true);
    });
  });

  describe('getLogsDirectory()', () => {
    it('should return logs directory path', () => {
      const result = getLogsDirectory();
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    it('should return absolute path for logs directory', () => {
      const result = getLogsDirectory();
      expect(path.isAbsolute(result)).toBe(true);
    });

    it('should include logs in the path', () => {
      const result = getLogsDirectory();
      expect(result).toContain('logs');
    });

    it('should be based on project root', () => {
      const projectRoot = getProjectRoot();
      const logsDir = getLogsDirectory();
      expect(logsDir.startsWith(projectRoot)).toBe(true);
    });
  });

  describe('Path Resolution Logic', () => {
    it('should handle different operating system path separators', () => {
      const result = getProjectRoot();
      // Should work on both Windows and Unix-like systems
      expect(result).toMatch(/^[A-Z]:|^\//);
    });

    it('should be consistent across multiple calls', () => {
      const result1 = getProjectRoot();
      const result2 = getProjectRoot();
      expect(result1).toBe(result2);
    });

    it('should handle various environment configurations', () => {
      // Test with no environment variables
      delete process.env.NODE_ENV;
      delete process.env.JEST_WORKER_ID;
      
      const result1 = getProjectRoot();
      
      // Test with test environment
      process.env.NODE_ENV = 'test';
      const result2 = getProjectRoot();
      
      // Test with Jest worker
      delete process.env.NODE_ENV;
      process.env.JEST_WORKER_ID = '1';
      const result3 = getProjectRoot();
      
      expect(typeof result1).toBe('string');
      expect(typeof result2).toBe('string');
      expect(typeof result3).toBe('string');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle missing environment variables gracefully', () => {
      delete process.env.NODE_ENV;
      delete process.env.JEST_WORKER_ID;
      
      expect(() => getProjectRoot()).not.toThrow();
    });

    it('should handle empty environment variables', () => {
      process.env.NODE_ENV = '';
      process.env.JEST_WORKER_ID = '';
      
      expect(() => getProjectRoot()).not.toThrow();
      const result = getProjectRoot();
      expect(typeof result).toBe('string');
    });

    it('should return valid path even in edge cases', () => {
      process.env.NODE_ENV = 'unknown_environment';
      
      const result = getProjectRoot();
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
      expect(path.isAbsolute(result)).toBe(true);
    });
  });

  describe('Integration Tests', () => {
    it('should resolve paths that work with Node.js path module', () => {
      const projectRoot = getProjectRoot();
      const logsDir = getLogsDirectory();
      
      // These should work with path operations
      expect(() => path.join(projectRoot, 'test')).not.toThrow();
      expect(() => path.resolve(logsDir, 'app.log')).not.toThrow();
      expect(() => path.dirname(projectRoot)).not.toThrow();
    });

    it('should resolve paths that work with fs module', () => {
      const projectRoot = getProjectRoot();
      
      // Basic fs operations should work
      expect(() => fs.existsSync(projectRoot)).not.toThrow();
      expect(() => fs.statSync(projectRoot)).not.toThrow();
    });
  });
});