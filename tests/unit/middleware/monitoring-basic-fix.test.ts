/**
 * @fileoverview Basic test to verify monitoring middleware initialization fix
 * Tests that the monitoring middleware can be created without throwing errors
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

describe('MonitoringMiddleware - Basic Initialization Fix', () => {
  // Clear modules before each test to ensure fresh imports
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should be able to import and instantiate MonitoringMiddleware without errors', async () => {
    // This test specifically verifies that our fallback logger handling works
    let importError: Error | null = null;
    let instantiationError: Error | null = null;
    let MonitoringMiddleware: any;

    try {
      // Try to import the middleware
      const middlewareModule = await import('../../../src/middleware/monitoring.js');
      MonitoringMiddleware = middlewareModule.MonitoringMiddleware;
      console.log('Import successful');
    } catch (error) {
      importError = error as Error;
      console.error('Import failed:', error);
    }

    // Import should succeed (our logger fallback should handle missing dependencies)
    expect(importError).toBeNull();
    expect(MonitoringMiddleware).toBeDefined();

    if (MonitoringMiddleware) {
      try {
        // Try to instantiate the middleware
        const instance = new MonitoringMiddleware();
        console.log('Instantiation successful');
        
        // Verify basic functionality exists
        expect(typeof instance.initializeServerMonitoring).toBe('function');
        expect(typeof instance.wrapToolExecution).toBe('function');
        expect(typeof instance.getMonitoringStats).toBe('function');
        expect(typeof instance.shutdown).toBe('function');
        
      } catch (error) {
        instantiationError = error as Error;
        console.error('Instantiation failed:', error);
      }
    }

    // Instantiation should succeed with our fallback handling
    expect(instantiationError).toBeNull();
  });

  it('should handle singleton pattern without initialization errors', async () => {
    let getInstanceError: Error | null = null;
    let instance: any;

    try {
      const { getMonitoringInstance } = await import('../../../src/middleware/monitoring.js');
      instance = getMonitoringInstance();
      console.log('Singleton instantiation successful');
    } catch (error) {
      getInstanceError = error as Error;
      console.error('Singleton instantiation failed:', error);
    }

    expect(getInstanceError).toBeNull();
    expect(instance).toBeDefined();
  });

  it('should have working fallback logger in test environment', async () => {
    const { MonitoringMiddleware } = await import('../../../src/middleware/monitoring.js');
    const instance = new MonitoringMiddleware();

    // Should not throw when calling logger methods
    expect(() => {
      // Access the monitoring stats which internally uses the logger
      const stats = instance.getMonitoringStats();
      expect(stats).toBeDefined();
    }).not.toThrow();
  });

  it('should handle metrics singleton initialization gracefully', async () => {
    // This test verifies our MetricsCollector fallback works
    const { MetricsCollector } = await import('../../../src/lib/metrics.js');
    
    let metricsError: Error | null = null;
    let metricsInstance: any;

    try {
      metricsInstance = MetricsCollector.getInstance();
      console.log('MetricsCollector singleton created successfully');
    } catch (error) {
      metricsError = error as Error;
      console.error('MetricsCollector failed:', error);
    }

    expect(metricsError).toBeNull();
    expect(metricsInstance).toBeDefined();
  });

  it('should reset monitoring instance for test isolation', async () => {
    const { getMonitoringInstance, resetMonitoringInstance } = await import('../../../src/middleware/monitoring.js');
    
    // Get first instance
    const instance1 = getMonitoringInstance();
    
    // Reset should not throw
    expect(() => {
      resetMonitoringInstance();
    }).not.toThrow();
    
    // Get second instance should work
    const instance2 = getMonitoringInstance();
    expect(instance2).toBeDefined();
  });
});