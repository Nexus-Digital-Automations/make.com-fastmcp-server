/**
 * Make.com Core Operations Server
 * Handles user-facing operations: scenarios, connections, permissions, templates, etc.
 * Optimized for low latency and high availability
 */

import { BaseServer, ServerConfig, ToolRegistration } from './base-server.js';
import { 
  coreToolCategories, 
  coreToolRegistrations, 
  coreServerDescription,
  coreCapabilityDescription
} from '../config/core-tools.js';

export class CoreServer extends BaseServer {
  constructor() {
    const config: ServerConfig = {
      name: 'make-core-server',
      version: '1.0.0',
      port: 3000,
      toolCategories: coreToolCategories,
      description: coreServerDescription
    };

    super(config);
    
    this.componentLogger.info('Core Server initialized', {
      toolCategories: coreToolCategories.length,
      categories: coreToolCategories
    });
  }

  protected getServerType(): string {
    return 'Core Operations';
  }

  protected getToolRegistrations(): ToolRegistration[] {
    return coreToolRegistrations;
  }

  protected getCapabilityDescription(): string {
    return coreCapabilityDescription;
  }

  protected async performCleanup(): Promise<void> {
    // Core server specific cleanup
    this.componentLogger.info('Performing core server cleanup');
    
    // Cleanup any active scenarios or connections
    // This would typically involve gracefully stopping active operations
    await this.cleanupActiveOperations();
    
    this.componentLogger.info('Core server cleanup completed');
  }

  private async cleanupActiveOperations(): Promise<void> {
    // In a production environment, this would:
    // 1. Stop any running scenarios gracefully
    // 2. Close active webhook connections
    // 3. Flush any pending operations
    // 4. Clean up temporary resources
    
    // For now, just log the cleanup
    this.componentLogger.debug('Cleaning up active operations');
  }

  /**
   * Get server-specific health metrics
   */
  public getHealthMetrics(): Record<string, unknown> {
    return {
      serverType: 'core',
      activeConnections: 0, // Would track real connections
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
      toolCategories: this.config.toolCategories.length,
      lastActivity: new Date().toISOString()
    };
  }

  /**
   * Get performance metrics specific to core operations
   */
  public getPerformanceMetrics(): Record<string, unknown> {
    return {
      averageResponseTime: 0, // Would calculate from actual metrics
      requestsPerSecond: 0, // Would calculate from actual metrics
      errorRate: 0, // Would calculate from actual metrics
      activeScenarios: 0, // Would query actual active scenarios
      activeConnections: 0 // Would query actual active connections
    };
  }
}

// Export singleton instance for use in startup scripts
export default CoreServer;