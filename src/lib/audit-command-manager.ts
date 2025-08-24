/**
 * Audit Compliance Command Pattern Implementation
 * Reduces complexity from 13-23 to 4-6 per method through command abstraction
 */

import MakeApiClient from './make-api-client.js';
import logger from './logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Common interfaces for all audit commands
export interface CommandInput {
  [key: string]: unknown;
}

export interface CommandContext {
  apiClient: MakeApiClient;
  logger?: typeof logger;
}

export interface CommandResult {
  success: boolean;
  data?: unknown;
  message: string;
  error?: string;
  [key: string]: unknown; // FastMCP compatibility
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

// Core Command Interface
export interface AuditCommand {
  execute(input: CommandInput, context: CommandContext): Promise<CommandResult>;
  validate(input: CommandInput): ValidationResult;
  buildParams(input: CommandInput): Record<string, unknown>;
  formatOutput(data: unknown, metadata?: Record<string, unknown>): unknown;
}

// Command Manager - Central coordination (complexity: 3)
export class ComplianceCommandManager {
  private readonly commands: Map<string, AuditCommand> = new Map();
  
  constructor(private readonly apiClient: MakeApiClient) {
    this.initializeCommands();
  }
  
  private initializeCommands(): void {
    this.commands.set('search-audit-events', new SearchAuditEventsCommand());
    this.commands.set('generate-compliance-report', new GenerateComplianceReportCommand());
    this.commands.set('log-audit-event', new LogAuditEventCommand());
    this.commands.set('export-audit-logs', new ExportAuditLogsCommand());
    this.commands.set('validate-compliance', new ValidateComplianceCommand());
    this.commands.set('generate-risk-assessment', new GenerateRiskAssessmentCommand());
    this.commands.set('audit-maintenance', new AuditMaintenanceCommand());
    this.commands.set('bulk-audit-operations', new BulkAuditOperationsCommand());
  }
  
  async executeCommand(commandType: string, input: CommandInput): Promise<CommandResult> {
    const command = this.getCommand(commandType);
    const validationResult = command.validate(input);
    
    if (!validationResult.isValid) {
      throw new Error(`Validation failed: ${validationResult.errors.join(', ')}`);
    }
    
    return command.execute(input, { apiClient: this.apiClient, logger });
  }
  
  private getCommand(type: string): AuditCommand {
    const command = this.commands.get(type);
    if (!command) {
      throw new Error(`No command found for type: ${type}`);
    }
    return command;
  }
}

// Base Command Class - Common functionality (complexity: 4)
abstract class BaseAuditCommand implements AuditCommand {
  abstract validate(input: CommandInput): ValidationResult;
  abstract buildParams(input: CommandInput): Record<string, unknown>;
  abstract formatOutput(data: unknown, metadata?: Record<string, unknown>): unknown;
  
  async execute(input: CommandInput, context: CommandContext): Promise<CommandResult> {
    const { apiClient, logger } = context;
    
    try {
      logger?.info(`Executing ${this.constructor.name}`, input);
      
      const params = this.buildParams(input);
      const endpoint = this.getEndpoint(input);
      const response = await this.makeApiCall(apiClient, endpoint, params, input);
      
      if (!response.success && response.error) {
        throw new Error(`API request failed: ${response.error.message || 'Unknown error'}`);
      }
      
      const formattedData = this.formatOutput(response.data, response.metadata);
      
      logger?.info(`Successfully completed ${this.constructor.name}`);
      return {
        success: true,
        data: formattedData,
        message: this.getSuccessMessage()
      };
      
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger?.error(`Error in ${this.constructor.name}`, { error: errorMessage });
      throw new Error(`${this.constructor.name} failed: ${errorMessage}`);
    }
  }
  
  protected abstract getEndpoint(input: CommandInput): string;
  protected abstract getSuccessMessage(): string;
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>, _input: CommandInput): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    // Default GET request, can be overridden for POST/PUT operations
    return apiClient.get(endpoint, { params });
  }
}

// Search Audit Events Command (complexity: 4)
export class SearchAuditEventsCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (input.startDate && input.endDate) {
      const startDate = new Date(input.startDate as string);
      const endDate = new Date(input.endDate as string);
      if (endDate < startDate) {
        errors.push('End date must be after start date');
      }
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    const params: Record<string, unknown> = {};
    
    if (input.level) {params.level = input.level;}
    if (input.category) {params.category = input.category;}
    if (input.action) {params.action = input.action;}
    if (input.startDate) {params.startDate = input.startDate;}
    if (input.endDate) {params.endDate = input.endDate;}
    if (input.userId) {params.userId = input.userId;}
    if (input.riskLevel) {params.riskLevel = input.riskLevel;}
    if (input.limit) {params.limit = input.limit;}
    if (input.offset) {params.offset = input.offset;}
    
    return params;
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/audit/events` : 
      '/audit/events';
  }
  
  formatOutput(data: unknown, metadata?: Record<string, unknown>, input?: CommandInput): unknown {
    const eventArray = Array.isArray(data) ? data : [];
    return formatSuccessResponse({
      events: eventArray,
      summary: this.generateEventAnalysis(eventArray, input || {}),
      metadata: metadata || {}
    }, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Audit events searched successfully";
  }
  
  private generateEventAnalysis(events: unknown[], input: CommandInput): Record<string, unknown> {
    return {
      totalEvents: events.length,
      searchCriteria: this.buildParams(input),
      riskDistribution: this.analyzeRiskDistribution(events),
      categoryBreakdown: this.analyzeCategoryBreakdown(events)
    };
  }
  
  private analyzeRiskDistribution(events: unknown[]): Record<string, number> {
    const distribution: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    events.forEach((event: unknown) => {
      const eventObj = event as { riskLevel?: string };
      if (eventObj?.riskLevel && Object.prototype.hasOwnProperty.call(distribution, eventObj.riskLevel)) {
        distribution[eventObj.riskLevel]++;
      }
    });
    return distribution;
  }
  
  private analyzeCategoryBreakdown(events: unknown[]): Record<string, number> {
    const breakdown: Record<string, number> = {};
    events.forEach((event: unknown) => {
      const eventObj = event as { category?: string };
      if (eventObj?.category) {
        breakdown[eventObj.category] = (breakdown[eventObj.category] || 0) + 1;
      }
    });
    return breakdown;
  }
}

// Generate Compliance Report Command (complexity: 5)
export class GenerateComplianceReportCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (input.period) {
      const period = input.period as { startDate?: string; endDate?: string };
      if (period.startDate && period.endDate) {
        const startDate = new Date(period.startDate);
        const endDate = new Date(period.endDate);
        if (endDate < startDate) {
          errors.push('Report end date must be after start date');
        }
      }
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    const params: Record<string, unknown> = {};
    
    if (input.title) {params.title = input.title;}
    if (input.framework) {params.framework = input.framework;}
    if (input.reportType) {params.reportType = input.reportType;}
    if (input.period) {params.period = input.period;}
    if (input.scope) {params.scope = input.scope;}
    if (input.format) {params.format = input.format;}
    if (input.includeRecommendations) {params.includeRecommendations = input.includeRecommendations;}
    if (input.detailLevel) {params.detailLevel = input.detailLevel;}
    
    // Legacy support
    if (input.startDate && !params.period) {
      params.period = { startDate: input.startDate, endDate: input.endDate };
    }
    
    return params;
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/compliance/reports` : 
      '/compliance/reports';
  }
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    return apiClient.post(endpoint, params);
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Compliance report generated successfully";
  }
}

// Log Audit Event Command (complexity: 4)
export class LogAuditEventCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (!input.action || typeof input.action !== 'string' || input.action.trim().length === 0) {
      errors.push('Action is required and cannot be empty');
    }
    
    if (!input.level || !['info', 'warn', 'error', 'critical'].includes(input.level as string)) {
      errors.push('Valid level is required (info, warn, error, critical)');
    }
    
    if (!input.category || !['authentication', 'authorization', 'data_access', 'configuration', 'security', 'system'].includes(input.category as string)) {
      errors.push('Valid category is required');
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    return {
      level: input.level,
      category: input.category,
      action: input.action,
      resource: input.resource,
      userId: input.userId,
      userAgent: input.userAgent,
      ipAddress: input.ipAddress,
      sessionId: input.sessionId,
      requestId: input.requestId,
      success: input.success,
      details: input.details || {},
      riskLevel: input.riskLevel,
      actorId: input.actorId,
      actorName: input.actorName,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      outcome: input.outcome,
      timestamp: new Date().toISOString()
    };
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/audit/events` : 
      '/audit/events';
  }
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    return apiClient.post(endpoint, params);
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Audit event logged successfully";
  }
}

// Export Audit Logs Command (complexity: 3)
export class ExportAuditLogsCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (!input.startDate || !input.endDate) {
      errors.push('Start date and end date are required for export');
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    return {
      startDate: input.startDate,
      endDate: input.endDate,
      format: input.format || 'json',
      includeDetails: input.includeDetails !== false,
      filterCriteria: input.filterCriteria || {}
    };
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/audit/export` : 
      '/audit/export';
  }
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    return apiClient.post(endpoint, params);
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Audit logs exported successfully";
  }
}

// Validate Compliance Command (complexity: 4)
export class ValidateComplianceCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (!input.framework) {
      errors.push('Compliance framework is required');
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    return {
      framework: input.framework,
      scope: input.scope,
      validationCriteria: input.validationCriteria || {},
      includeRecommendations: input.includeRecommendations !== false
    };
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/compliance/validate` : 
      '/compliance/validate';
  }
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    return apiClient.post(endpoint, params);
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Compliance validation completed successfully";
  }
}

// Generate Risk Assessment Command (complexity: 4)
export class GenerateRiskAssessmentCommand extends BaseAuditCommand {
  validate(): ValidationResult {
    return { isValid: true, errors: [] };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    return {
      assessmentType: input.assessmentType || 'comprehensive',
      timeframe: input.timeframe || '30d',
      includeMetrics: input.includeMetrics !== false,
      riskThresholds: input.riskThresholds || {}
    };
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/risk/assessment` : 
      '/risk/assessment';
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Risk assessment generated successfully";
  }
}

// Audit Maintenance Command (complexity: 3)
export class AuditMaintenanceCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (input.retentionDays && (input.retentionDays as number) < 1) {
      errors.push('Retention days must be greater than 0');
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    return {
      retentionDays: input.retentionDays || 90,
      operation: input.operation || 'cleanup'
    };
  }
  
  protected getEndpoint(): string {
    return '/audit/maintenance';
  }
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    return apiClient.post(endpoint, params);
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Audit maintenance completed successfully";
  }
}

// Bulk Audit Operations Command (complexity: 5)
export class BulkAuditOperationsCommand extends BaseAuditCommand {
  validate(input: CommandInput): ValidationResult {
    const errors: string[] = [];
    
    if (!input.operations || !Array.isArray(input.operations)) {
      errors.push('Operations array is required');
    }
    
    return { isValid: errors.length === 0, errors };
  }
  
  buildParams(input: CommandInput): Record<string, unknown> {
    return {
      operations: input.operations,
      batchSize: input.batchSize || 50,
      concurrency: input.concurrency || 5
    };
  }
  
  protected getEndpoint(input: CommandInput): string {
    return input.organizationId ? 
      `/organizations/${input.organizationId}/audit/bulk` : 
      '/audit/bulk';
  }
  
  protected makeApiCall(apiClient: MakeApiClient, endpoint: string, params: Record<string, unknown>): Promise<{ success: boolean; data: unknown; metadata?: Record<string, unknown>; error?: { message: string } }> {
    return apiClient.post(endpoint, params);
  }
  
  formatOutput(data: unknown): unknown {
    return formatSuccessResponse(data, this.getSuccessMessage());
  }
  
  protected getSuccessMessage(): string {
    return "Bulk audit operations completed successfully";
  }
}