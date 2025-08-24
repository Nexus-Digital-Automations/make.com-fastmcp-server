import { BaseServer, ToolRegistration } from "./base-server.js";
import {
  governanceToolCategories,
  governanceToolRegistrations,
  governanceServerDescription,
  governanceCapabilityDescription,
} from "../config/governance-tools.js";

export class GovernanceServer extends BaseServer {
  constructor() {
    const config = {
      name: "make-governance-server",
      version: "1.0.0",
      port: 3002,
      toolCategories: governanceToolCategories,
      description: governanceServerDescription,
    };

    super(config);

    this.componentLogger.info("Governance Server initialized", {
      toolCategories: governanceToolCategories.length,
      categories: governanceToolCategories,
    });
  }

  getServerType(): string {
    return "Analytics & Governance";
  }

  getToolRegistrations(): ToolRegistration[] {
    return governanceToolRegistrations;
  }

  getCapabilityDescription(): string {
    return governanceCapabilityDescription;
  }

  async performCleanup(): Promise<void> {
    this.componentLogger.info("Performing governance server cleanup");
    await this.cleanupActiveOperations();
    this.componentLogger.info("Governance server cleanup completed");
  }

  private async cleanupActiveOperations(): Promise<void> {
    this.componentLogger.debug("Cleaning up active governance operations");
    // Add specific cleanup logic for governance operations
  }

  getHealthMetrics(): Record<string, unknown> {
    return {
      serverType: "governance",
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
      activeMonitoring: 0,
      activePolicies: 0,
    };
  }
}

export default GovernanceServer;
