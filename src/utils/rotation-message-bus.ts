/**
 * Message Bus coordination system for the 5-agent credential rotation architecture
 * Handles inter-agent communication, message routing, and coordination workflows
 */

import { EventEmitter } from "events";
import * as crypto from "crypto";
import logger from "../lib/logger.js";
import type {
  AgentMessage,
  AgentResponse,
  AgentStatus,
  RotationAgentBase,
} from "./rotation-agent-base.js";

// Interface extensions for type safety
interface AgentWithMetadata extends RotationAgentBase {
  agentId: string;
  role: string;
  getStatus(): AgentStatus;
}

interface MessageData {
  type: string;
  payload: Record<string, unknown>;
  timestamp: Date;
}

interface _MessageHandler<T = MessageData> {
  (message: T): Promise<void> | void;
}

interface _WorkflowStepResult {
  result: Record<string, unknown>;
  success: boolean;
  error?: string;
}

/**
 * Message routing configuration
 */
export interface MessageRoute {
  fromAgent: string;
  toAgent: string;
  messageType: string;
  priority: "low" | "normal" | "high" | "critical";
  timeoutMs?: number;
  retryAttempts?: number;
}

/**
 * Workflow definition for complex operations
 */
export interface WorkflowDefinition {
  workflowId: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  timeout: number;
  onFailure: "abort" | "continue" | "retry";
  maxRetries?: number;
}

export interface WorkflowStep {
  stepId: string;
  agentRole: string;
  messageType: string;
  payload: Record<string, unknown>;
  dependencies?: string[]; // stepIds that must complete first
  timeout: number;
  onFailure: "abort" | "continue" | "retry";
  retryAttempts?: number;
}

/**
 * Workflow execution state
 */
export interface WorkflowExecution {
  workflowId: string;
  executionId: string;
  definition: WorkflowDefinition;
  status: "pending" | "running" | "completed" | "failed" | "aborted";
  startTime: Date;
  endTime?: Date;
  completedSteps: string[];
  failedSteps: { stepId: string; error: string; timestamp: Date }[];
  results: Map<string, Record<string, unknown>>;
}

/**
 * Message Bus coordination system
 */
export class RotationMessageBus extends EventEmitter {
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly agents: Map<string, RotationAgentBase> = new Map();
  private readonly agentsByRole: Map<string, RotationAgentBase> = new Map();

  // Message handling
  private readonly messageQueue: Map<string, AgentMessage[]> = new Map();
  private readonly pendingMessages: Map<
    string,
    {
      resolve: (value: Record<string, unknown>) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
    }
  > = new Map();

  // Workflow management
  private readonly workflows: Map<string, WorkflowDefinition> = new Map();
  private readonly activeExecutions: Map<string, WorkflowExecution> = new Map();

  // Performance tracking
  private messageCount = 0;
  private totalMessageLatency = 0;
  private failedMessageCount = 0;

  constructor() {
    super();

    this.componentLogger = logger.child({
      component: "RotationMessageBus",
    });

    this.setupDefaultWorkflows();

    this.componentLogger.info("Message Bus initialized");
  }

  /**
   * Register an agent with the message bus
   */
  public registerAgent(agent: RotationAgentBase): void {
    const agentId = (agent as AgentWithMetadata).agentId;
    const role = (agent as AgentWithMetadata).role;

    if (this.agents.has(agentId)) {
      throw new Error(`Agent ${agentId} already registered`);
    }

    this.agents.set(agentId, agent);
    this.agentsByRole.set(role, agent);
    this.messageQueue.set(agentId, []);

    // Setup agent event handlers
    agent.on("send_message", (message: AgentMessage) => {
      this.routeMessage(message);
    });

    agent.on("send_response", (response: AgentResponse) => {
      this.handleResponse(response);
    });

    agent.on("agent_ready", () => {
      this.componentLogger.info("Agent registered and ready", {
        agentId,
        role,
      });
    });

    this.componentLogger.info("Agent registered with message bus", {
      agentId,
      role,
    });
  }

  /**
   * Unregister an agent
   */
  public unregisterAgent(agentId: string): void {
    const agent = this.agents.get(agentId);
    if (!agent) {
      return;
    }

    const role = (agent as AgentWithMetadata).role;

    this.agents.delete(agentId);
    this.agentsByRole.delete(role);
    this.messageQueue.delete(agentId);

    agent.removeAllListeners();

    this.componentLogger.info("Agent unregistered from message bus", {
      agentId,
      role,
    });
  }

  /**
   * Send a message between agents
   */
  public async sendMessage(
    fromAgent: string,
    toAgent: string,
    messageType: string,
    payload: Record<string, unknown>,
    timeoutMs = 30000,
  ): Promise<Record<string, unknown>> {
    const messageId = crypto.randomUUID();
    const message: AgentMessage = {
      messageId,
      timestamp: new Date(),
      fromAgent,
      toAgent,
      type: messageType,
      payload,
      correlationId: crypto.randomUUID(),
    };

    return new Promise((resolve, reject) => {
      // Set up timeout
      const timeout = setTimeout(() => {
        this.pendingMessages.delete(messageId);
        this.failedMessageCount++;
        reject(new Error(`Message timeout: ${messageId} after ${timeoutMs}ms`));
      }, timeoutMs);

      this.pendingMessages.set(messageId, { resolve, reject, timeout });

      // Route the message
      this.routeMessage(message);
    });
  }

  /**
   * Route a message to the appropriate agent
   */
  private routeMessage(message: AgentMessage): void {
    const startTime = Date.now();

    try {
      // Find target agent
      let targetAgent: RotationAgentBase | undefined;

      // Try direct agent ID first
      targetAgent = this.agents.get(message.toAgent);

      // If not found, try by role
      if (!targetAgent) {
        targetAgent = this.agentsByRole.get(message.toAgent);
      }

      if (!targetAgent) {
        throw new Error(`Target agent not found: ${message.toAgent}`);
      }

      // Queue message for processing
      const queue = this.messageQueue.get(message.toAgent) || [];
      queue.push(message);
      this.messageQueue.set(message.toAgent, queue);

      // Deliver message to agent
      setImmediate(() => {
        targetAgent.emit("message_received", message);
      });

      this.messageCount++;
      const latency = Date.now() - startTime;
      this.totalMessageLatency += latency;

      this.componentLogger.debug("Message routed successfully", {
        messageId: message.messageId,
        fromAgent: message.fromAgent,
        toAgent: message.toAgent,
        type: message.type,
        latencyMs: latency,
      });
    } catch (error) {
      this.failedMessageCount++;
      this.componentLogger.error("Failed to route message", {
        messageId: message.messageId,
        error: error instanceof Error ? error.message : "Unknown error",
      });

      // Send error response if this was a request
      const errorResponse: AgentResponse = {
        messageId: crypto.randomUUID(),
        replyTo: message.messageId,
        timestamp: new Date(),
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };

      this.handleResponse(errorResponse);
    }
  }

  /**
   * Handle agent responses
   */
  private handleResponse(response: AgentResponse): void {
    const pending = this.pendingMessages.get(response.replyTo);

    if (pending) {
      clearTimeout(pending.timeout);
      this.pendingMessages.delete(response.replyTo);

      if (response.success) {
        pending.resolve(response.data || {});
      } else {
        pending.reject(new Error(response.error || "Unknown error"));
      }

      this.componentLogger.debug("Response handled", {
        messageId: response.messageId,
        replyTo: response.replyTo,
        success: response.success,
      });
    }
  }

  /**
   * Register a workflow definition
   */
  public registerWorkflow(workflow: WorkflowDefinition): void {
    this.workflows.set(workflow.workflowId, workflow);

    this.componentLogger.info("Workflow registered", {
      workflowId: workflow.workflowId,
      name: workflow.name,
      steps: workflow.steps.length,
    });
  }

  /**
   * Execute a workflow
   * Complexity reduced via Extract Method pattern
   */
  public async executeWorkflow(
    workflowId: string,
    initialPayload: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const workflow = this.validateWorkflow(workflowId);
    const execution = this.initializeWorkflowExecution(workflowId, workflow);
    
    return this.runWorkflowExecution(execution, initialPayload);
  }

  /**
   * Extract Method: Validate workflow exists
   * Complexity: ≤3
   */
  private validateWorkflow(workflowId: string): WorkflowDefinition {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }
    return workflow;
  }

  /**
   * Extract Method: Initialize workflow execution
   * Complexity: ≤5
   */
  private initializeWorkflowExecution(
    workflowId: string,
    workflow: WorkflowDefinition
  ): WorkflowExecution {
    const executionId = crypto.randomUUID();
    const execution: WorkflowExecution = {
      workflowId,
      executionId,
      definition: workflow,
      status: "pending",
      startTime: new Date(),
      completedSteps: [],
      failedSteps: [],
      results: new Map(),
    };

    this.activeExecutions.set(executionId, execution);
    
    this.componentLogger.info("Starting workflow execution", {
      workflowId,
      executionId,
      steps: workflow.steps.length,
    });
    
    return execution;
  }

  /**
   * Extract Method: Run workflow execution with error handling
   * Complexity: ≤8
   */
  private async runWorkflowExecution(
    execution: WorkflowExecution,
    initialPayload: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    try {
      execution.status = "running";

      // Execute workflow steps
      const results = await this.executeWorkflowSteps(
        execution,
        initialPayload,
      );

      execution.status = "completed";
      execution.endTime = new Date();

      this.componentLogger.info("Workflow execution completed", {
        workflowId: execution.workflowId,
        executionId: execution.executionId,
        durationMs: execution.endTime.getTime() - execution.startTime.getTime(),
        completedSteps: execution.completedSteps.length,
        failedSteps: execution.failedSteps.length,
      });

      return results;
    } catch (error) {
      this.handleWorkflowExecutionError(execution, error);
      throw error;
    } finally {
      this.scheduleWorkflowCleanup(execution.executionId);
    }
  }

  /**
   * Extract Method: Handle workflow execution errors
   * Complexity: ≤4
   */
  private handleWorkflowExecutionError(
    execution: WorkflowExecution,
    error: unknown
  ): void {
    execution.status = "failed";
    execution.endTime = new Date();

    this.componentLogger.error("Workflow execution failed", {
      workflowId: execution.workflowId,
      executionId: execution.executionId,
      error: error instanceof Error ? error.message : "Unknown error",
      completedSteps: execution.completedSteps.length,
      failedSteps: execution.failedSteps.length,
    });
  }

  /**
   * Extract Method: Schedule workflow cleanup
   * Complexity: ≤2
   */
  private scheduleWorkflowCleanup(executionId: string): void {
    setTimeout(() => {
      this.activeExecutions.delete(executionId);
    }, 300000); // 5 minutes
  }

  /**
   * Execute workflow steps with dependency management
   */
  private async executeWorkflowSteps(
    execution: WorkflowExecution,
    initialPayload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { definition } = execution;
    const stepResults = new Map<string, Record<string, unknown>>();
    const pendingSteps = new Set(definition.steps.map((step) => step.stepId));
    const completedSteps = new Set<string>();

    // Add initial payload to results
    stepResults.set("initial", initialPayload);

    while (pendingSteps.size > 0) {
      const readySteps = definition.steps.filter((step) => {
        if (!pendingSteps.has(step.stepId)) {
          return false;
        }

        // Check if all dependencies are completed
        if (step.dependencies) {
          return step.dependencies.every((depId) => completedSteps.has(depId));
        }

        return true;
      });

      if (readySteps.length === 0) {
        throw new Error("Workflow deadlock detected - no steps can proceed");
      }

      // Execute ready steps in parallel
      const stepPromises = readySteps.map(async (step) => {
        try {
          // Prepare step payload with results from dependencies
          const stepPayload = { ...step.payload };
          if (step.dependencies) {
            for (const depId of step.dependencies) {
              const depResult = stepResults.get(depId);
              if (depResult) {
                stepPayload[`${depId}_result`] = depResult;
              }
            }
          }

          // Find target agent for this step
          const targetAgent = this.agentsByRole.get(step.agentRole);
          if (!targetAgent) {
            throw new Error(`Agent not found for role: ${step.agentRole}`);
          }

          const agentId = (targetAgent as AgentWithMetadata).agentId;

          // Execute step
          const result = await this.sendMessage(
            "message-bus",
            agentId,
            step.messageType,
            stepPayload,
            step.timeout,
          );

          stepResults.set(step.stepId, result);
          execution.completedSteps.push(step.stepId);
          completedSteps.add(step.stepId);
          pendingSteps.delete(step.stepId);

          this.componentLogger.debug("Workflow step completed", {
            executionId: execution.executionId,
            stepId: step.stepId,
            agentRole: step.agentRole,
          });

          return { stepId: step.stepId, success: true, result };
        } catch (error) {
          const errorInfo = {
            stepId: step.stepId,
            error: error instanceof Error ? error.message : "Unknown error",
            timestamp: new Date(),
          };

          execution.failedSteps.push(errorInfo);
          pendingSteps.delete(step.stepId);

          this.componentLogger.error("Workflow step failed", {
            executionId: execution.executionId,
            stepId: step.stepId,
            error: errorInfo.error,
          });

          if (step.onFailure === "abort" || definition.onFailure === "abort") {
            throw new Error(
              `Workflow aborted due to failed step: ${step.stepId}`,
            );
          }

          return {
            stepId: step.stepId,
            success: false,
            error: errorInfo.error,
          };
        }
      });

      await Promise.all(stepPromises);
    }

    // Compile final results
    const finalResults: Record<string, unknown> = {};
    for (const [stepId, result] of stepResults) {
      if (stepId !== "initial") {
        finalResults[stepId] = result;
      }
    }

    return finalResults;
  }

  /**
   * Get message bus statistics
   */
  public getStatistics(): Record<string, unknown> {
    const avgLatency =
      this.messageCount > 0 ? this.totalMessageLatency / this.messageCount : 0;

    return {
      registeredAgents: this.agents.size,
      totalMessages: this.messageCount,
      failedMessages: this.failedMessageCount,
      successRate:
        this.messageCount > 0
          ? (this.messageCount - this.failedMessageCount) / this.messageCount
          : 0,
      avgMessageLatencyMs: Math.round(avgLatency),
      pendingMessages: this.pendingMessages.size,
      registeredWorkflows: this.workflows.size,
      activeWorkflowExecutions: this.activeExecutions.size,
      queueSizes: Array.from(this.messageQueue.entries()).reduce(
        (acc, [agentId, queue]) => {
          acc[agentId] = queue.length;
          return acc;
        },
        {} as Record<string, number>,
      ),
    };
  }

  /**
   * Get all agent statuses
   */
  public getAgentStatuses(): Record<string, AgentStatus> {
    const statuses: Record<string, AgentStatus> = {};

    for (const [agentId, agent] of this.agents) {
      try {
        statuses[agentId] = (agent as AgentWithMetadata).getStatus();
      } catch (error) {
        this.componentLogger.error("Failed to get agent status", {
          agentId,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }

    return statuses;
  }

  /**
   * Setup default workflows for common operations
   */
  private setupDefaultWorkflows(): void {
    // Complete credential rotation workflow
    const credentialRotationWorkflow: WorkflowDefinition = {
      workflowId: "complete_credential_rotation",
      name: "Complete Credential Rotation",
      description:
        "Full credential rotation with validation, encryption, monitoring, and external service updates",
      timeout: 300000, // 5 minutes
      onFailure: "abort",
      maxRetries: 3,
      steps: [
        {
          stepId: "pre_rotation_validation",
          agentRole: "validation",
          messageType: "validate_pre_rotation",
          payload: {},
          timeout: 30000,
          onFailure: "abort",
        },
        {
          stepId: "generate_new_credential",
          agentRole: "encryption",
          messageType: "generate_credential",
          payload: {},
          dependencies: ["pre_rotation_validation"],
          timeout: 15000,
          onFailure: "abort",
        },
        {
          stepId: "rotate_credential",
          agentRole: "rotation",
          messageType: "perform_rotation",
          payload: {},
          dependencies: ["generate_new_credential"],
          timeout: 60000,
          onFailure: "abort",
        },
        {
          stepId: "update_external_services",
          agentRole: "integration",
          messageType: "update_external_services",
          payload: {},
          dependencies: ["rotate_credential"],
          timeout: 120000,
          onFailure: "continue",
        },
        {
          stepId: "post_rotation_validation",
          agentRole: "validation",
          messageType: "validate_post_rotation",
          payload: {},
          dependencies: ["update_external_services"],
          timeout: 30000,
          onFailure: "continue",
        },
        {
          stepId: "log_security_event",
          agentRole: "security",
          messageType: "log_rotation_event",
          payload: {},
          dependencies: ["post_rotation_validation"],
          timeout: 10000,
          onFailure: "continue",
        },
      ],
    };

    this.registerWorkflow(credentialRotationWorkflow);

    // Emergency rotation workflow
    const emergencyRotationWorkflow: WorkflowDefinition = {
      workflowId: "emergency_credential_rotation",
      name: "Emergency Credential Rotation",
      description: "Fast-track rotation for security incidents",
      timeout: 60000, // 1 minute
      onFailure: "continue",
      maxRetries: 1,
      steps: [
        {
          stepId: "emergency_generate_credential",
          agentRole: "encryption",
          messageType: "generate_credential",
          payload: { priority: "emergency" },
          timeout: 5000,
          onFailure: "abort",
        },
        {
          stepId: "emergency_rotate_credential",
          agentRole: "rotation",
          messageType: "perform_emergency_rotation",
          payload: {},
          dependencies: ["emergency_generate_credential"],
          timeout: 15000,
          onFailure: "abort",
        },
        {
          stepId: "emergency_security_alert",
          agentRole: "security",
          messageType: "send_security_alert",
          payload: { level: "critical" },
          dependencies: ["emergency_rotate_credential"],
          timeout: 5000,
          onFailure: "continue",
        },
      ],
    };

    this.registerWorkflow(emergencyRotationWorkflow);
  }

  /**
   * Shutdown message bus
   */
  public async shutdown(): Promise<void> {
    this.componentLogger.info("Shutting down message bus");

    // Cancel all pending messages
    for (const [_messageId, pending] of this.pendingMessages) {
      clearTimeout(pending.timeout);
      pending.reject(new Error("Message bus shutting down"));
    }
    this.pendingMessages.clear();

    // Clear message queues
    this.messageQueue.clear();

    // Remove all listeners
    this.removeAllListeners();

    this.componentLogger.info("Message bus shutdown completed");
  }
}

export default RotationMessageBus;
