import { BaseServer, ToolRegistration } from "./base-server.js";
import {
  essentialToolCategories,
  essentialToolRegistrations,
  essentialServerDescription,
  essentialCapabilityDescription,
} from "../config/essential-tools.js";

export class EssentialServer extends BaseServer {
  constructor() {
    const config = {
      name: "make-essential-server",
      version: "1.0.0",
      port: 3000,
      toolCategories: essentialToolCategories,
      description: essentialServerDescription,
    };

    super(config);

    this.componentLogger.info("Essential Server initialized", {
      toolCategories: essentialToolCategories.length,
      categories: essentialToolCategories,
    });
  }

  getServerType(): string {
    return "Essential Operations";
  }

  getToolRegistrations(): ToolRegistration[] {
    return essentialToolRegistrations;
  }

  getCapabilityDescription(): string {
    return essentialCapabilityDescription;
  }

  async performCleanup(): Promise<void> {
    this.componentLogger.info("Performing essential server cleanup");
    await this.cleanupActiveOperations();
    this.componentLogger.info("Essential server cleanup completed");
  }

  private async cleanupActiveOperations(): Promise<void> {
    this.componentLogger.debug("Cleaning up active essential operations");
    // Add specific cleanup logic for essential operations
  }

  getHealthMetrics(): Record<string, unknown> {
    return {
      serverType: "essential",
      activeConnections: 0,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
      toolCategories: this.config.toolCategories.length,
      lastActivity: new Date().toISOString(),
    };
  }

  getPerformanceMetrics(): Record<string, number> {
    return {
      averageResponseTime: 0,
      requestsPerSecond: 0,
      errorRate: 0,
      activeScenarios: 0,
      activeConnections: 0,
    };
  }
}

export default EssentialServer;
