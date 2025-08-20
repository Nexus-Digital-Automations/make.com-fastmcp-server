# Make.com Budget Control Tools - Technical Implementation Research Report

**Research Task ID:** task_1755671347157_yjei7i70l  
**Date:** 2025-08-20  
**Researcher:** Claude Code AI Assistant  
**Focus:** FastMCP Integration Patterns, Database Design, Background Processing, Performance Optimization

## Executive Summary

This comprehensive research provides detailed technical implementation guidance for integrating advanced Make.com budget control tools within the existing FastMCP server architecture. The analysis covers five critical technical areas: FastMCP integration patterns, database design for multi-tenant budgets, background processing architectures, Make.com API integration strategies, and performance optimization patterns.

## 1. FastMCP Integration Patterns for Budget Management

### 1.1 Tool Registration Patterns

**Current FastMCP Tool Structure Analysis:**
Based on the existing implementation in `/src/server.ts` and `/src/tools/billing.ts`, the server follows a modular tool registration pattern:

```typescript
// Existing pattern from src/server.ts (lines 426-472)
private addAdvancedTools(): void {
  addScenarioTools(this.server, this.apiClient);
  addConnectionTools(this.server, this.apiClient);
  addBillingTools(this.server, this.apiClient);
  // ... other tools
}
```

**Recommended Budget Tool Integration Pattern:**
```typescript
// src/tools/budget-control.ts
export function addBudgetControlTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'BudgetControlTools' });
  
  // Budget Configuration Tool
  server.addTool({
    name: 'set-budget',
    description: 'Configure budget limits with multi-tenant support and alert thresholds',
    parameters: BudgetConfigurationSchema,
    annotations: {
      title: 'Budget Configuration',
      category: 'cost-management',
      requiresAuth: true,
      rateLimit: { maxRequests: 10, windowMs: 3600000 }, // 10 requests per hour
    },
    execute: async (args, { log, session, reportProgress }) => {
      const correlationId = extractCorrelationId({ session });
      const tenantId = extractTenantId({ session });
      
      return await budgetManager.createBudget({
        ...args,
        tenantId,
        correlationId
      });
    }
  });

  // Cost Alert Configuration Tool
  server.addTool({
    name: 'create-cost-alert',
    description: 'Create intelligent cost alerts with ML-powered threshold monitoring',
    parameters: CostAlertConfigurationSchema,
    annotations: {
      title: 'Cost Alert Setup',
      category: 'monitoring',
      openWorldHint: true,
    },
    execute: async (args, context) => {
      return await alertManager.createAlert(args, context);
    }
  });

  // Cost Projection Tool  
  server.addTool({
    name: 'get-cost-projection',
    description: 'Get ML-powered cost projections with confidence intervals',
    parameters: CostProjectionRequestSchema,
    annotations: {
      title: 'Cost Forecasting',
      category: 'analytics',
      readOnlyHint: true,
    },
    execute: async (args, context) => {
      return await projectionEngine.generateProjection(args, context);
    }
  });

  // Automated Scenario Control Tool
  server.addTool({
    name: 'pause-high-cost-scenarios',
    description: 'Automatically pause scenarios exceeding cost thresholds with graduated response',
    parameters: ScenarioControlSchema,
    annotations: {
      title: 'Automated Cost Control',
      category: 'automation',
      dangerousHint: true, // Indicates this can pause running scenarios
    },
    execute: async (args, context) => {
      return await scenarioController.pauseHighCostScenarios(args, context);
    }
  });
}
```

### 1.2 Schema Validation Approaches

**Leveraging Existing Zod Patterns:**
The codebase extensively uses Zod for validation (seen in `src/tools/billing.ts` lines 216-278). Budget tools should follow the same pattern:

```typescript
// Enhanced validation schema with multi-tenant support
const BudgetConfigurationSchema = z.object({
  // Tenant and Organization Context
  tenantId: z.string().min(1).optional().describe('Tenant identifier for multi-tenant isolation'),
  organizationId: z.number().min(1).optional().describe('Make.com organization ID'),
  
  // Budget Definition
  budgetLimits: z.object({
    monthly: z.number().min(0).describe('Monthly budget limit in USD'),
    daily: z.number().min(0).optional().describe('Daily budget limit in USD'),
    perScenario: z.number().min(0).optional().describe('Per-scenario budget limit'),
    credits: z.number().min(0).optional().describe('Credits-based budget (Make.com 2025 billing model)'),
  }),
  
  // Time Period Configuration
  budgetPeriod: z.object({
    type: z.enum(['monthly', 'weekly', 'daily', 'custom']),
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    timezone: z.string().default('UTC').describe('Timezone for budget period calculations'),
  }),
  
  // Alert Configuration
  alertThresholds: z.array(z.object({
    percentage: z.number().min(0).max(200).describe('Threshold percentage (0-200%)'),
    type: z.enum(['actual', 'forecasted', 'trend']).describe('Alert trigger type'),
    severity: z.enum(['info', 'warning', 'critical', 'emergency']),
    channels: z.array(z.enum(['email', 'webhook', 'slack', 'sms'])),
    cooldownMinutes: z.number().min(5).max(1440).default(60).describe('Minimum time between alerts'),
  })),
  
  // Automated Actions
  automatedActions: z.array(z.object({
    trigger: z.enum(['threshold_50', 'threshold_75', 'threshold_90', 'threshold_100']),
    action: z.enum(['notify', 'throttle', 'pause_non_critical', 'pause_all', 'custom']),
    parameters: z.record(z.unknown()).optional(),
    requiresApproval: z.boolean().default(false),
  })),
  
  // Scope and Filtering  
  scope: z.object({
    scenarioIds: z.array(z.number()).optional().describe('Specific scenarios to monitor'),
    scenarioTags: z.array(z.string()).optional().describe('Scenarios with specific tags'),
    teamIds: z.array(z.number()).optional().describe('Teams to include in budget'),
    excludeScenarios: z.array(z.number()).optional().describe('Scenarios to exclude'),
  }).optional(),
  
  // Metadata
  name: z.string().min(1).max(100).describe('Budget configuration name'),
  description: z.string().max(500).optional().describe('Budget description'),
  isActive: z.boolean().default(true).describe('Whether budget monitoring is active'),
  tags: z.record(z.string()).optional().describe('Budget metadata tags'),
}).strict();
```

### 1.3 Error Handling Patterns

**Extending Existing Error System:**
The server uses a comprehensive error system (from `src/utils/errors.ts`). Budget tools should extend this:

```typescript
// src/utils/budget-errors.ts
export class BudgetError extends MakeServerError {
  constructor(
    message: string,
    code: string,
    statusCode: number,
    tenantId?: string,
    budgetId?: string,
    additionalContext?: Record<string, unknown>
  ) {
    super(message, code, statusCode, true, additionalContext, {
      component: 'BudgetManager',
      tenantId,
      budgetId,
    });
  }
}

export class BudgetThresholdExceededError extends BudgetError {
  constructor(
    tenantId: string,
    budgetId: string,
    currentSpend: number,
    threshold: number,
    thresholdType: 'actual' | 'forecasted'
  ) {
    super(
      `Budget threshold exceeded: ${currentSpend} > ${threshold} (${thresholdType})`,
      'BUDGET_THRESHOLD_EXCEEDED',
      429, // Too Many Requests - appropriate for budget limits
      tenantId,
      budgetId,
      {
        currentSpend,
        threshold,
        thresholdType,
        exceedancePercentage: ((currentSpend - threshold) / threshold) * 100,
      }
    );
  }
}

export class InsufficientBudgetError extends BudgetError {
  constructor(
    tenantId: string,
    requestedAmount: number,
    availableBudget: number,
    operation: string
  ) {
    super(
      `Insufficient budget for operation: ${operation} requires ${requestedAmount}, only ${availableBudget} available`,
      'INSUFFICIENT_BUDGET',
      402, // Payment Required
      tenantId,
      undefined,
      {
        requestedAmount,
        availableBudget,
        shortfall: requestedAmount - availableBudget,
        operation,
      }
    );
  }
}
```

### 1.4 Progress Reporting for Long-Running Operations

**Following Existing Progress Patterns:**
Budget operations (especially cost projection) should use the progress reporting pattern seen in existing tools:

```typescript
// From src/tools/billing.ts example (lines 330-355)
execute: async (input, { log, reportProgress }) => {
  reportProgress({ progress: 0, total: 100 });
  
  // Phase 1: Data Collection (0-40%)
  reportProgress({ progress: 10, total: 100 });
  const historicalData = await this.gatherHistoricalData(tenantId);
  
  reportProgress({ progress: 25, total: 100 });
  const currentUsage = await this.getCurrentUsage(tenantId);
  
  reportProgress({ progress: 40, total: 100 });
  
  // Phase 2: Analysis (40-70%)
  reportProgress({ progress: 50, total: 100 });
  const seasonalPatterns = await this.analyzeSeasonality(historicalData);
  
  reportProgress({ progress: 65, total: 100 });
  const trendAnalysis = await this.analyzeTrends(historicalData);
  
  reportProgress({ progress: 70, total: 100 });
  
  // Phase 3: Projection (70-90%)
  reportProgress({ progress: 80, total: 100 });
  const projection = await this.generateProjection(seasonalPatterns, trendAnalysis);
  
  reportProgress({ progress: 90, total: 100 });
  
  // Phase 4: Confidence Calculation (90-100%)
  const confidence = await this.calculateConfidence(projection);
  
  reportProgress({ progress: 100, total: 100 });
  
  return projectionResult;
}
```

## 2. Database Design for Multi-Tenant Budget Management

### 2.1 Multi-Tenant Data Partitioning Strategy

**Recommended Database Schema:**
Based on the existing configuration patterns and multi-tenant requirements:

```sql
-- Core budget configuration table with tenant isolation
CREATE TABLE budget_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    organization_id INTEGER, -- Make.com organization ID
    name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Budget limits (stored in cents to avoid floating point issues)
    monthly_limit_cents INTEGER NOT NULL DEFAULT 0,
    daily_limit_cents INTEGER DEFAULT 0,
    per_scenario_limit_cents INTEGER DEFAULT 0,
    credits_limit INTEGER DEFAULT 0, -- Make.com credits system
    
    -- Time configuration
    budget_period_type VARCHAR(20) NOT NULL DEFAULT 'monthly',
    period_start_date TIMESTAMPTZ,
    period_end_date TIMESTAMPTZ,
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    
    -- State management
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255),
    
    -- Metadata
    tags JSONB DEFAULT '{}',
    
    -- Multi-tenant isolation constraints
    CONSTRAINT budget_tenant_name_unique UNIQUE (tenant_id, name),
    INDEX idx_budget_configurations_tenant_id (tenant_id),
    INDEX idx_budget_configurations_org_id (organization_id),
    INDEX idx_budget_configurations_active (is_active) WHERE is_active = true,
    
    -- Row Level Security (if using PostgreSQL)
    -- ENABLE ROW LEVEL SECURITY;
);

-- Alert threshold configurations
CREATE TABLE budget_alert_thresholds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID NOT NULL REFERENCES budget_configurations(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL, -- Denormalized for performance
    
    percentage INTEGER NOT NULL CHECK (percentage >= 0 AND percentage <= 200),
    threshold_type VARCHAR(20) NOT NULL DEFAULT 'actual', -- actual, forecasted, trend
    severity VARCHAR(20) NOT NULL DEFAULT 'warning', -- info, warning, critical, emergency
    
    -- Notification configuration
    notification_channels JSONB NOT NULL DEFAULT '[]', -- email, webhook, slack, sms
    cooldown_minutes INTEGER NOT NULL DEFAULT 60,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- Alert state
    last_triggered_at TIMESTAMPTZ,
    trigger_count INTEGER NOT NULL DEFAULT 0,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    INDEX idx_alert_thresholds_budget_id (budget_id),
    INDEX idx_alert_thresholds_tenant_id (tenant_id),
    INDEX idx_alert_thresholds_enabled (is_enabled) WHERE is_enabled = true
);

-- Automated action configurations
CREATE TABLE budget_automated_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID NOT NULL REFERENCES budget_configurations(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL,
    
    trigger_condition VARCHAR(50) NOT NULL, -- threshold_50, threshold_75, etc.
    action_type VARCHAR(50) NOT NULL, -- notify, throttle, pause_non_critical, pause_all
    action_parameters JSONB DEFAULT '{}',
    
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- Execution tracking
    last_executed_at TIMESTAMPTZ,
    execution_count INTEGER NOT NULL DEFAULT 0,
    last_execution_result JSONB,
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    INDEX idx_automated_actions_budget_id (budget_id),
    INDEX idx_automated_actions_tenant_id (tenant_id)
);

-- Budget scope and filtering configuration
CREATE TABLE budget_scope_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    budget_id UUID NOT NULL REFERENCES budget_configurations(id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL,
    
    -- Inclusion filters
    scenario_ids INTEGER[], -- Specific scenarios to monitor
    scenario_tags TEXT[], -- Scenarios with specific tags
    team_ids INTEGER[], -- Teams to include
    
    -- Exclusion filters
    excluded_scenario_ids INTEGER[],
    excluded_tags TEXT[],
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE (budget_id), -- One scope per budget
    INDEX idx_budget_scope_tenant_id (tenant_id),
    INDEX idx_budget_scope_scenario_ids USING GIN (scenario_ids),
    INDEX idx_budget_scope_tags USING GIN (scenario_tags)
);
```

### 2.2 Time-Series Data for Cost Tracking

**Cost Tracking Tables:**
```sql
-- Time-series cost tracking with optimized partitioning
CREATE TABLE cost_tracking_data (
    id BIGSERIAL,
    tenant_id VARCHAR(255) NOT NULL,
    organization_id INTEGER NOT NULL,
    
    -- Time dimensions
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_date DATE NOT NULL, -- Partitioning key
    period_hour INTEGER NOT NULL CHECK (period_hour >= 0 AND period_hour <= 23),
    
    -- Cost dimensions
    scenario_id INTEGER,
    scenario_name VARCHAR(255),
    team_id INTEGER,
    operation_type VARCHAR(100), -- webhook, schedule, manual, etc.
    
    -- Metrics (in cents and credits)
    operations_count INTEGER NOT NULL DEFAULT 0,
    data_transfer_mb INTEGER NOT NULL DEFAULT 0,
    credits_consumed INTEGER NOT NULL DEFAULT 0,
    cost_cents INTEGER NOT NULL DEFAULT 0,
    
    -- Metadata
    tags JSONB DEFAULT '{}',
    raw_usage_data JSONB, -- Store original Make.com API response
    
    PRIMARY KEY (id, period_date), -- Composite primary key for partitioning
    INDEX idx_cost_tracking_tenant_period (tenant_id, period_date),
    INDEX idx_cost_tracking_scenario (scenario_id, period_date),
    INDEX idx_cost_tracking_recorded_at (recorded_at)
) PARTITION BY RANGE (period_date);

-- Create monthly partitions automatically
CREATE OR REPLACE FUNCTION create_monthly_cost_partitions()
RETURNS void AS $$
DECLARE
    start_date DATE;
    end_date DATE;
    table_name TEXT;
BEGIN
    FOR i IN 0..12 LOOP -- Create partitions for current and next 12 months
        start_date := date_trunc('month', CURRENT_DATE) + (i || ' months')::interval;
        end_date := start_date + '1 month'::interval;
        table_name := 'cost_tracking_data_' || to_char(start_date, 'YYYY_MM');
        
        EXECUTE format('
            CREATE TABLE IF NOT EXISTS %I 
            PARTITION OF cost_tracking_data 
            FOR VALUES FROM (%L) TO (%L)',
            table_name, start_date, end_date
        );
        
        EXECUTE format('
            CREATE INDEX IF NOT EXISTS %I 
            ON %I (tenant_id, recorded_at)',
            table_name || '_tenant_time_idx', table_name
        );
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Cost aggregation materialized views for performance
CREATE MATERIALIZED VIEW daily_cost_aggregates AS
SELECT 
    tenant_id,
    organization_id,
    period_date,
    scenario_id,
    team_id,
    SUM(operations_count) as daily_operations,
    SUM(data_transfer_mb) as daily_data_transfer_mb,
    SUM(credits_consumed) as daily_credits,
    SUM(cost_cents) as daily_cost_cents,
    COUNT(*) as hourly_records
FROM cost_tracking_data
GROUP BY tenant_id, organization_id, period_date, scenario_id, team_id;

CREATE UNIQUE INDEX ON daily_cost_aggregates (tenant_id, period_date, scenario_id, team_id);
CREATE INDEX ON daily_cost_aggregates (tenant_id, period_date);

-- Refresh materialized views automatically
CREATE OR REPLACE FUNCTION refresh_cost_aggregates()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY daily_cost_aggregates;
END;
$$ LANGUAGE plpgsql;
```

### 2.3 Audit Log Table Structures

**Comprehensive Audit Logging:**
```sql
-- Budget audit events table
CREATE TABLE budget_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255),
    correlation_id VARCHAR(255),
    
    -- Event details
    event_type VARCHAR(50) NOT NULL, -- budget_created, threshold_exceeded, action_executed, etc.
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Subject references
    budget_id UUID,
    alert_id UUID,
    scenario_id INTEGER,
    
    -- Event data
    event_details JSONB NOT NULL DEFAULT '{}',
    previous_state JSONB,
    new_state JSONB,
    
    -- Context information
    source VARCHAR(50) NOT NULL DEFAULT 'api', -- api, automated, scheduled
    ip_address INET,
    user_agent TEXT,
    
    -- Impact tracking
    affected_scenarios INTEGER[],
    estimated_cost_impact_cents INTEGER,
    
    INDEX idx_budget_audit_tenant_time (tenant_id, event_timestamp),
    INDEX idx_budget_audit_event_type (event_type),
    INDEX idx_budget_audit_budget_id (budget_id),
    INDEX idx_budget_audit_correlation (correlation_id)
) PARTITION BY RANGE (event_timestamp);

-- Create audit log partitions (daily partitions for performance)
CREATE OR REPLACE FUNCTION create_daily_audit_partitions()
RETURNS void AS $$
DECLARE
    start_date DATE;
    end_date DATE;
    table_name TEXT;
BEGIN
    FOR i IN -30..60 LOOP -- 30 days historical, 60 days future
        start_date := CURRENT_DATE + (i || ' days')::interval;
        end_date := start_date + '1 day'::interval;
        table_name := 'budget_audit_events_' || to_char(start_date, 'YYYY_MM_DD');
        
        EXECUTE format('
            CREATE TABLE IF NOT EXISTS %I 
            PARTITION OF budget_audit_events 
            FOR VALUES FROM (%L) TO (%L)',
            table_name, start_date, end_date
        );
    END LOOP;
END;
$$ LANGUAGE plpgsql;
```

## 3. Background Processing Architecture

### 3.1 Cost Monitoring Job Scheduling

**Microservice Architecture with Distributed Processing:**
```typescript
// src/services/cost-monitoring-service.ts
export class CostMonitoringService {
  private scheduledJobs = new Map<string, NodeJS.Timeout>();
  private isShuttingDown = false;
  
  constructor(
    private readonly budgetRepository: BudgetRepository,
    private readonly costTracker: CostTracker,
    private readonly alertManager: AlertManager,
    private readonly auditLogger: AuditLogger
  ) {}
  
  public async startMonitoring(): Promise<void> {
    // High-frequency monitoring for critical thresholds (every 5 minutes)
    this.scheduleJob('critical-monitoring', 5 * 60 * 1000, 
      () => this.monitorCriticalThresholds()
    );
    
    // Standard monitoring for warning thresholds (every 15 minutes)
    this.scheduleJob('standard-monitoring', 15 * 60 * 1000,
      () => this.monitorStandardThresholds()
    );
    
    // Daily budget reset and rollover processing (at midnight UTC)
    this.scheduleJob('daily-processing', this.getMillisecondsUntilMidnight(),
      () => this.processDailyBudgetOperations()
    );
    
    // Hourly cost aggregation and projection updates
    this.scheduleJob('hourly-aggregation', 60 * 60 * 1000,
      () => this.updateCostAggregations()
    );
    
    // Weekly trend analysis and optimization recommendations
    this.scheduleJob('weekly-analysis', 7 * 24 * 60 * 60 * 1000,
      () => this.generateWeeklyAnalytics()
    );
  }
  
  private async monitorCriticalThresholds(): Promise<void> {
    const componentLogger = logger.child({ 
      component: 'CostMonitoring',
      operation: 'critical-threshold-check'
    });
    
    try {
      const criticalBudgets = await this.budgetRepository.getBudgetsWithCriticalAlerts();
      
      for (const budget of criticalBudgets) {
        const currentStatus = await this.calculateBudgetStatus(budget);
        const criticalThresholds = budget.alertThresholds.filter(
          t => t.severity === 'critical' || t.severity === 'emergency'
        );
        
        for (const threshold of criticalThresholds) {
          if (this.isThresholdExceeded(currentStatus, threshold)) {
            await this.handleThresholdExceeded(budget, threshold, currentStatus);
          }
        }
      }
      
      componentLogger.info('Critical threshold monitoring completed', {
        budgetsChecked: criticalBudgets.length
      });
      
    } catch (error) {
      componentLogger.error('Critical threshold monitoring failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Alert administrators about monitoring system failure
      await this.alertManager.sendSystemAlert({
        severity: 'emergency',
        message: 'Cost monitoring system failure detected',
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
  
  private async calculateBudgetStatus(budget: BudgetConfiguration): Promise<BudgetStatus> {
    const tenantId = budget.tenantId;
    const periodStart = this.getBudgetPeriodStart(budget);
    const periodEnd = this.getBudgetPeriodEnd(budget);
    
    // Get current spend from time-series data
    const currentSpend = await this.costTracker.getCurrentSpend({
      tenantId,
      organizationId: budget.organizationId,
      startDate: periodStart,
      endDate: new Date(),
      scenarioFilters: budget.scope?.scenarioIds,
      teamFilters: budget.scope?.teamIds
    });
    
    // Get projected spend using ML models
    const projectedSpend = await this.costProjector.projectSpend({
      tenantId,
      organizationId: budget.organizationId,
      historicalPeriod: 30, // days
      projectionPeriod: this.getDaysUntilPeriodEnd(budget),
      currentSpend
    });
    
    const budgetLimit = this.getBudgetLimitForPeriod(budget);
    
    return {
      budgetId: budget.id,
      tenantId,
      currentSpend,
      projectedSpend: projectedSpend.amount,
      budgetLimit,
      percentUsed: (currentSpend / budgetLimit) * 100,
      percentProjected: (projectedSpend.amount / budgetLimit) * 100,
      remainingBudget: budgetLimit - currentSpend,
      daysRemaining: this.getDaysUntilPeriodEnd(budget),
      confidence: projectedSpend.confidence,
      lastUpdated: new Date(),
      trends: {
        dailyAverage: currentSpend / this.getDaysInCurrentPeriod(budget),
        weeklyTrend: await this.calculateWeeklyTrend(tenantId, budget),
        seasonalFactors: projectedSpend.seasonalFactors
      }
    };
  }
}
```

### 3.2 Alert Evaluation Algorithms

**Intelligent Alert Processing:**
```typescript
// src/services/alert-manager.ts
export class AlertManager {
  private alertCooldowns = new Map<string, Date>();
  
  constructor(
    private readonly notificationService: NotificationService,
    private readonly auditLogger: AuditLogger
  ) {}
  
  public async evaluateAlerts(
    budget: BudgetConfiguration,
    currentStatus: BudgetStatus
  ): Promise<AlertEvaluationResult[]> {
    const results: AlertEvaluationResult[] = [];
    
    for (const threshold of budget.alertThresholds) {
      const evaluation = await this.evaluateThreshold(
        budget,
        threshold,
        currentStatus
      );
      
      if (evaluation.shouldTrigger) {
        // Check cooldown period to prevent alert spam
        const cooldownKey = `${budget.id}-${threshold.percentage}-${threshold.type}`;
        const lastAlertTime = this.alertCooldowns.get(cooldownKey);
        const cooldownExpired = !lastAlertTime || 
          (Date.now() - lastAlertTime.getTime()) > (threshold.cooldownMinutes * 60 * 1000);
        
        if (cooldownExpired) {
          await this.triggerAlert(budget, threshold, currentStatus, evaluation);
          this.alertCooldowns.set(cooldownKey, new Date());
          
          results.push({
            threshold,
            triggered: true,
            reason: evaluation.reason,
            severity: threshold.severity,
            channels: threshold.channels
          });
        } else {
          results.push({
            threshold,
            triggered: false,
            reason: 'Cooldown period active',
            severity: threshold.severity,
            suppressedUntil: new Date(lastAlertTime.getTime() + threshold.cooldownMinutes * 60 * 1000)
          });
        }
      }
    }
    
    return results;
  }
  
  private async evaluateThreshold(
    budget: BudgetConfiguration,
    threshold: AlertThreshold,
    status: BudgetStatus
  ): Promise<ThresholdEvaluation> {
    switch (threshold.type) {
      case 'actual':
        return this.evaluateActualSpendThreshold(threshold, status);
        
      case 'forecasted':
        return this.evaluateForecastedThreshold(threshold, status);
        
      case 'trend':
        return this.evaluateTrendThreshold(threshold, status, budget);
        
      default:
        throw new Error(`Unknown threshold type: ${threshold.type}`);
    }
  }
  
  private async evaluateForecastedThreshold(
    threshold: AlertThreshold,
    status: BudgetStatus
  ): Promise<ThresholdEvaluation> {
    const projectedPercent = status.percentProjected;
    const shouldTrigger = projectedPercent >= threshold.percentage;
    
    return {
      shouldTrigger,
      currentValue: projectedPercent,
      thresholdValue: threshold.percentage,
      reason: shouldTrigger 
        ? `Projected spend (${projectedPercent.toFixed(1)}%) exceeds threshold (${threshold.percentage}%)`
        : `Projected spend (${projectedPercent.toFixed(1)}%) within threshold`,
      confidence: status.confidence,
      additionalContext: {
        projectedAmount: status.projectedSpend,
        daysRemaining: status.daysRemaining,
        currentTrend: status.trends.weeklyTrend
      }
    };
  }
  
  private async evaluateTrendThreshold(
    threshold: AlertThreshold,
    status: BudgetStatus,
    budget: BudgetConfiguration
  ): Promise<ThresholdEvaluation> {
    // Trend-based alerts look for rapid spending increases
    const trendMultiplier = 1.5; // Alert if trend indicates 150% of threshold will be exceeded
    const adjustedThreshold = threshold.percentage / trendMultiplier;
    
    // Calculate spending velocity
    const dailyAverage = status.trends.dailyAverage;
    const recentTrend = status.trends.weeklyTrend;
    const velocityIncrease = recentTrend / dailyAverage;
    
    // Project end-of-period spending based on current velocity
    const daysRemaining = status.daysRemaining;
    const projectedAdditionalSpend = dailyAverage * velocityIncrease * daysRemaining;
    const totalProjectedPercent = ((status.currentSpend + projectedAdditionalSpend) / status.budgetLimit) * 100;
    
    const shouldTrigger = totalProjectedPercent >= adjustedThreshold;
    
    return {
      shouldTrigger,
      currentValue: totalProjectedPercent,
      thresholdValue: adjustedThreshold,
      reason: shouldTrigger
        ? `Trend analysis indicates ${totalProjectedPercent.toFixed(1)}% budget usage by period end (velocity: ${velocityIncrease.toFixed(2)}x)`
        : `Spending trend within acceptable bounds`,
      confidence: Math.max(0.6, status.confidence * 0.8), // Lower confidence for trend predictions
      additionalContext: {
        velocityIncrease,
        dailyAverage,
        recentTrend,
        projectedAdditionalSpend
      }
    };
  }
}
```

### 3.3 Batch Processing for Usage Aggregation

**High-Performance Data Aggregation:**
```typescript
// src/services/usage-aggregation-service.ts
export class UsageAggregationService {
  constructor(
    private readonly makeApiClient: MakeApiClient,
    private readonly costTracker: CostTracker,
    private readonly redisClient: Redis
  ) {}
  
  public async performBatchAggregation(): Promise<AggregationResult> {
    const batchSize = 100; // Process 100 tenants at a time
    const tenants = await this.getTenantsBatch(batchSize);
    
    const results = await Promise.allSettled(
      tenants.map(tenant => this.aggregateTenantUsage(tenant))
    );
    
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    return {
      totalProcessed: tenants.length,
      successful,
      failed,
      errors: results
        .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
        .map(r => r.reason)
    };
  }
  
  private async aggregateTenantUsage(tenant: TenantInfo): Promise<void> {
    const componentLogger = logger.child({
      component: 'UsageAggregation',
      tenantId: tenant.id
    });
    
    try {
      // Get usage data from Make.com API with rate limiting
      const usageData = await this.makeApiClient.get(
        `/organizations/${tenant.organizationId}/usage`,
        {
          params: {
            period: 'last_24_hours',
            breakdown: ['scenario', 'team', 'operation_type']
          }
        }
      );
      
      if (!usageData.success) {
        throw new Error(`Failed to fetch usage data: ${usageData.error?.message}`);
      }
      
      // Transform Make.com data to internal format
      const costRecords = this.transformUsageData(
        tenant.id,
        tenant.organizationId,
        usageData.data
      );
      
      // Batch insert cost records
      await this.costTracker.batchInsertCostRecords(costRecords);
      
      // Update cached aggregations in Redis
      await this.updateCachedAggregations(tenant.id, costRecords);
      
      // Update real-time budget status
      await this.updateBudgetStatuses(tenant.id);
      
      componentLogger.info('Usage aggregation completed', {
        recordsProcessed: costRecords.length,
        totalCost: costRecords.reduce((sum, r) => sum + r.costCents, 0)
      });
      
    } catch (error) {
      componentLogger.error('Usage aggregation failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }
  
  private transformUsageData(
    tenantId: string,
    organizationId: number,
    makeUsageData: any
  ): CostRecord[] {
    const records: CostRecord[] = [];
    const currentHour = new Date();
    currentHour.setMinutes(0, 0, 0);
    
    // Transform scenario-level usage data
    if (makeUsageData.scenarios) {
      for (const scenarioUsage of makeUsageData.scenarios) {
        const costRecord: CostRecord = {
          tenantId,
          organizationId,
          recordedAt: new Date(),
          periodDate: currentHour.toISOString().split('T')[0],
          periodHour: currentHour.getHours(),
          scenarioId: scenarioUsage.id,
          scenarioName: scenarioUsage.name,
          teamId: scenarioUsage.teamId,
          operationType: 'mixed',
          operationsCount: scenarioUsage.operations || 0,
          dataTransferMb: scenarioUsage.dataTransfer || 0,
          creditsConsumed: scenarioUsage.credits || 0,
          costCents: this.calculateCostInCents(scenarioUsage),
          tags: {
            scenarioType: scenarioUsage.type,
            isActive: scenarioUsage.isActive
          },
          rawUsageData: scenarioUsage
        };
        
        records.push(costRecord);
      }
    }
    
    return records;
  }
  
  private calculateCostInCents(scenarioUsage: any): number {
    // Make.com's new credits system (2025)
    const creditsConsumed = scenarioUsage.credits || 0;
    const costPerCredit = 0.1; // $0.001 per credit (example rate)
    
    // Convert to cents to avoid floating point precision issues
    return Math.round(creditsConsumed * costPerCredit * 100);
  }
  
  private async updateCachedAggregations(
    tenantId: string,
    costRecords: CostRecord[]
  ): Promise<void> {
    const pipeline = this.redisClient.pipeline();
    
    // Cache daily aggregations
    const dailyTotal = costRecords.reduce((sum, r) => sum + r.costCents, 0);
    const cacheKey = `daily_cost:${tenantId}:${new Date().toISOString().split('T')[0]}`;
    
    pipeline.incrby(cacheKey, dailyTotal);
    pipeline.expire(cacheKey, 86400 * 7); // Keep for 7 days
    
    // Cache hourly aggregations for real-time monitoring
    const currentHour = new Date().getHours();
    const hourlyKey = `hourly_cost:${tenantId}:${currentHour}`;
    
    pipeline.set(hourlyKey, dailyTotal, 'EX', 3600); // 1 hour expiry
    
    await pipeline.exec();
  }
}
```

### 3.4 Real-Time Threshold Checking

**Event-Driven Threshold Monitoring:**
```typescript
// src/services/real-time-monitor.ts
export class RealTimeThresholdMonitor {
  private eventEmitter = new EventEmitter();
  private websocketServer?: WebSocket.Server;
  
  constructor(
    private readonly budgetRepository: BudgetRepository,
    private readonly alertManager: AlertManager
  ) {
    this.setupEventHandlers();
  }
  
  private setupEventHandlers(): void {
    // Listen for cost updates
    this.eventEmitter.on('cost-update', async (costUpdate: CostUpdate) => {
      await this.checkThresholdsForCostUpdate(costUpdate);
    });
    
    // Listen for budget configuration changes
    this.eventEmitter.on('budget-updated', async (budgetId: string) => {
      await this.refreshBudgetMonitoring(budgetId);
    });
  }
  
  public async checkThresholdsForCostUpdate(costUpdate: CostUpdate): Promise<void> {
    const affectedBudgets = await this.budgetRepository.getBudgetsAffectedByCost(
      costUpdate.tenantId,
      costUpdate.scenarioId,
      costUpdate.teamId
    );
    
    for (const budget of affectedBudgets) {
      const currentStatus = await this.calculateCurrentStatus(budget);
      
      // Check if any thresholds are newly exceeded
      const exceededThresholds = budget.alertThresholds.filter(threshold => 
        this.isThresholdNewlyExceeded(threshold, currentStatus, budget.lastCheckedStatus)
      );
      
      if (exceededThresholds.length > 0) {
        // Trigger alerts for exceeded thresholds
        for (const threshold of exceededThresholds) {
          await this.alertManager.triggerImmediateAlert(budget, threshold, currentStatus);
        }
        
        // Update last checked status
        await this.budgetRepository.updateLastCheckedStatus(budget.id, currentStatus);
        
        // Broadcast to connected clients
        this.broadcastThresholdAlert({
          budgetId: budget.id,
          tenantId: budget.tenantId,
          thresholds: exceededThresholds,
          currentStatus
        });
      }
    }
  }
  
  private isThresholdNewlyExceeded(
    threshold: AlertThreshold,
    currentStatus: BudgetStatus,
    lastStatus?: BudgetStatus
  ): boolean {
    const currentValue = this.getThresholdValue(threshold, currentStatus);
    const previousValue = lastStatus ? this.getThresholdValue(threshold, lastStatus) : 0;
    
    // Threshold is newly exceeded if:
    // 1. Current value exceeds threshold
    // 2. Previous value was below threshold (or no previous status)
    return currentValue >= threshold.percentage && 
           previousValue < threshold.percentage;
  }
  
  public setupWebSocketServer(server: http.Server): void {
    this.websocketServer = new WebSocket.Server({ server });
    
    this.websocketServer.on('connection', (ws: WebSocket, request: http.IncomingMessage) => {
      const tenantId = this.extractTenantFromRequest(request);
      if (!tenantId) {
        ws.close(4001, 'Unauthorized: Missing tenant ID');
        return;
      }
      
      ws.on('message', (message: string) => {
        try {
          const data = JSON.parse(message);
          this.handleWebSocketMessage(ws, tenantId, data);
        } catch (error) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Invalid message format'
          }));
        }
      });
      
      // Send current budget status on connection
      this.sendCurrentBudgetStatus(ws, tenantId);
    });
  }
  
  private broadcastThresholdAlert(alert: ThresholdAlert): void {
    if (!this.websocketServer) return;
    
    const message = JSON.stringify({
      type: 'threshold-alert',
      data: alert,
      timestamp: new Date().toISOString()
    });
    
    this.websocketServer.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        // Only send to clients belonging to the same tenant
        const clientTenantId = (client as any).tenantId;
        if (clientTenantId === alert.tenantId) {
          client.send(message);
        }
      }
    });
  }
}
```

## 4. Make.com API Integration Strategies

### 4.1 Polling Strategies for Usage Data

**Intelligent Polling with Rate Limit Management:**
```typescript
// src/services/make-api-polling-service.ts
export class MakeApiPollingService {
  private pollingIntervals = new Map<string, NodeJS.Timeout>();
  private rateLimiter: Bottleneck;
  
  constructor(
    private readonly makeApiClient: MakeApiClient,
    private readonly tenantManager: TenantManager
  ) {
    // Initialize rate limiter based on Make.com API limits
    // Teams plan: 240 requests/minute, Pro: 120, Basic: 60
    this.rateLimiter = new Bottleneck({
      reservoir: 200, // Conservative limit
      reservoirRefreshAmount: 200,
      reservoirRefreshInterval: 60 * 1000, // 1 minute
      maxConcurrent: 10,
      minTime: 300 // 300ms between requests
    });
  }
  
  public async startPollingForTenant(
    tenantId: string,
    organizationId: number,
    pollingConfig: PollingConfiguration
  ): Promise<void> {
    const existingInterval = this.pollingIntervals.get(tenantId);
    if (existingInterval) {
      clearInterval(existingInterval);
    }
    
    const interval = setInterval(async () => {
      try {
        await this.rateLimiter.schedule(() => 
          this.pollTenantUsageData(tenantId, organizationId, pollingConfig)
        );
      } catch (error) {
        logger.error('Polling failed for tenant', {
          tenantId,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }, pollingConfig.intervalMs);
    
    this.pollingIntervals.set(tenantId, interval);
  }
  
  private async pollTenantUsageData(
    tenantId: string,
    organizationId: number,
    config: PollingConfiguration
  ): Promise<void> {
    const componentLogger = logger.child({
      component: 'MakeApiPolling',
      tenantId,
      organizationId
    });
    
    try {
      // Adaptive polling - check if critical thresholds are active
      const criticalBudgets = await this.budgetRepository.getCriticalBudgetsForTenant(tenantId);
      const pollFrequency = criticalBudgets.length > 0 ? 'high' : 'standard';
      
      // Batch multiple API calls for efficiency
      const [usageData, consumptionData, scenarioData] = await Promise.all([
        this.fetchUsageData(organizationId),
        this.fetchConsumptionData(organizationId),
        this.fetchActiveScenarios(organizationId)
      ]);
      
      // Process and store the collected data
      await this.processUsageData(tenantId, organizationId, {
        usage: usageData,
        consumption: consumptionData,
        scenarios: scenarioData,
        pollFrequency,
        timestamp: new Date()
      });
      
      componentLogger.info('Usage data polling completed', {
        pollFrequency,
        scenariosActive: scenarioData?.length || 0,
        totalOperations: usageData?.totalOperations || 0
      });
      
    } catch (error) {
      componentLogger.error('Usage data polling failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Implement exponential backoff for failed requests
      await this.handlePollingFailure(tenantId, error);
    }
  }
  
  private async fetchUsageData(organizationId: number): Promise<UsageData | null> {
    try {
      const response = await this.makeApiClient.get(
        `/organizations/${organizationId}/usage`,
        {
          params: {
            period: 'current_day',
            breakdown: ['scenario', 'app', 'team'],
            include_credits: true
          },
          timeout: 10000 // 10 second timeout
        }
      );
      
      return response.success ? response.data : null;
    } catch (error) {
      if (error.response?.status === 429) {
        // Rate limit hit - back off more aggressively
        throw new RateLimitExceededError('Make.com API rate limit exceeded');
      }
      throw error;
    }
  }
  
  private async handlePollingFailure(tenantId: string, error: unknown): Promise<void> {
    const failureCount = await this.getFailureCount(tenantId);
    const backoffMs = Math.min(300000, 5000 * Math.pow(2, failureCount)); // Max 5 minutes
    
    setTimeout(() => {
      // Retry with exponential backoff
      this.retryPolling(tenantId);
    }, backoffMs);
    
    await this.incrementFailureCount(tenantId);
    
    if (failureCount >= 5) {
      // Alert administrators after 5 consecutive failures
      await this.alertManager.sendSystemAlert({
        severity: 'critical',
        tenantId,
        message: `Polling failures for tenant ${tenantId}`,
        failureCount,
        lastError: error instanceof Error ? error.message : String(error)
      });
    }
  }
}
```

### 4.2 Rate Limiting and Retry Logic

**Advanced Rate Limiting Strategy:**
```typescript
// src/lib/advanced-rate-limiter.ts
export class AdvancedRateLimiter {
  private limiters = new Map<string, Bottleneck>();
  private tenantPriorities = new Map<string, number>();
  
  constructor() {
    // Default global rate limiter
    this.limiters.set('global', new Bottleneck({
      reservoir: 180, // Global limit: 180 requests/minute  
      reservoirRefreshAmount: 180,
      reservoirRefreshInterval: 60 * 1000,
      maxConcurrent: 8
    }));
  }
  
  public async scheduleRequest<T>(
    operation: () => Promise<T>,
    context: {
      tenantId: string;
      priority: 'low' | 'normal' | 'high' | 'critical';
      operation: string;
    }
  ): Promise<T> {
    const limiter = this.getLimiterForTenant(context.tenantId, context.priority);
    
    return limiter.schedule({
      priority: this.getPriorityValue(context.priority),
      id: `${context.tenantId}-${context.operation}-${Date.now()}`
    }, async () => {
      try {
        const result = await operation();
        this.recordSuccessfulRequest(context.tenantId);
        return result;
      } catch (error) {
        await this.handleRequestError(error, context);
        throw error;
      }
    });
  }
  
  private getLimiterForTenant(tenantId: string, priority: string): Bottleneck {
    const limiterKey = `tenant-${tenantId}`;
    
    if (!this.limiters.has(limiterKey)) {
      // Create tenant-specific limiter with adaptive limits
      const tenantLimiter = new Bottleneck({
        reservoir: this.getTenantReservoir(tenantId, priority),
        reservoirRefreshAmount: this.getTenantReservoir(tenantId, priority),
        reservoirRefreshInterval: 60 * 1000,
        maxConcurrent: priority === 'critical' ? 3 : 2,
        minTime: priority === 'critical' ? 200 : 400
      });
      
      this.limiters.set(limiterKey, tenantLimiter);
    }
    
    return this.limiters.get(limiterKey)!;
  }
  
  private async handleRequestError(error: unknown, context: any): Promise<void> {
    if (axios.isAxiosError(error) && error.response?.status === 429) {
      // Rate limit exceeded - implement adaptive backoff
      const retryAfter = error.response.headers['retry-after'];
      const backoffMs = retryAfter ? parseInt(retryAfter) * 1000 : 30000;
      
      // Temporarily reduce rate limits for this tenant
      await this.reduceRateLimits(context.tenantId, backoffMs);
      
      throw new RateLimitExceededError(
        `Rate limit exceeded for tenant ${context.tenantId}`,
        backoffMs
      );
    }
  }
  
  private async reduceRateLimits(tenantId: string, backoffMs: number): Promise<void> {
    const limiterKey = `tenant-${tenantId}`;
    const limiter = this.limiters.get(limiterKey);
    
    if (limiter) {
      // Reduce reservoir by 50% and increase min time between requests
      await limiter.updateSettings({
        reservoir: Math.floor(limiter.reservoir / 2),
        reservoirRefreshAmount: Math.floor(limiter.reservoirRefreshAmount / 2),
        minTime: (limiter.minTime || 300) * 2
      });
      
      // Reset to normal limits after backoff period
      setTimeout(async () => {
        await this.resetRateLimits(tenantId);
      }, backoffMs);
    }
  }
}
```

### 4.3 Error Handling for API Failures

**Comprehensive Error Recovery:**
```typescript
// src/utils/api-error-handler.ts
export class ApiErrorHandler {
  private retryQueue = new Map<string, RetryOperation[]>();
  private circuitBreakers = new Map<string, CircuitBreaker>();
  
  public async handleApiError(
    error: unknown,
    context: ApiOperationContext,
    retryConfig?: RetryConfiguration
  ): Promise<ErrorHandlingResult> {
    const errorInfo = this.analyzeError(error);
    const circuitBreaker = this.getCircuitBreaker(context.tenantId);
    
    // Check if circuit breaker is open
    if (circuitBreaker.state === 'open') {
      throw new ServiceUnavailableError(
        `Service temporarily unavailable for tenant ${context.tenantId}`,
        circuitBreaker.nextAttemptTime
      );
    }
    
    // Determine error handling strategy
    switch (errorInfo.category) {
      case 'rate_limit':
        return await this.handleRateLimitError(error as RateLimitError, context);
        
      case 'authentication':
        return await this.handleAuthError(error as AuthError, context);
        
      case 'network':
        return await this.handleNetworkError(error as NetworkError, context, retryConfig);
        
      case 'server_error':
        return await this.handleServerError(error as ServerError, context, retryConfig);
        
      case 'client_error':
        return await this.handleClientError(error as ClientError, context);
        
      default:
        return await this.handleUnknownError(error, context);
    }
  }
  
  private async handleRateLimitError(
    error: RateLimitError,
    context: ApiOperationContext
  ): Promise<ErrorHandlingResult> {
    const retryAfter = error.retryAfter || 60000; // Default 60 seconds
    const queueKey = `${context.tenantId}-rate-limit`;
    
    // Add operation to retry queue
    const retryOperation: RetryOperation = {
      id: context.operationId,
      operation: context.operation,
      context,
      scheduledTime: new Date(Date.now() + retryAfter),
      attempts: (context.attempts || 0) + 1,
      maxAttempts: 3
    };
    
    if (!this.retryQueue.has(queueKey)) {
      this.retryQueue.set(queueKey, []);
    }
    this.retryQueue.get(queueKey)!.push(retryOperation);
    
    // Schedule retry execution
    setTimeout(() => {
      this.executeRetryQueue(queueKey);
    }, retryAfter);
    
    return {
      status: 'queued_for_retry',
      retryAfter,
      message: `Operation queued for retry after rate limit (${retryAfter}ms)`
    };
  }
  
  private async handleNetworkError(
    error: NetworkError,
    context: ApiOperationContext,
    retryConfig?: RetryConfiguration
  ): Promise<ErrorHandlingResult> {
    const maxRetries = retryConfig?.maxRetries || 3;
    const currentAttempt = context.attempts || 0;
    
    if (currentAttempt >= maxRetries) {
      // Record circuit breaker failure
      this.getCircuitBreaker(context.tenantId).recordFailure();
      
      throw new MaxRetriesExceededError(
        `Network operation failed after ${maxRetries} attempts`,
        error
      );
    }
    
    // Calculate exponential backoff with jitter
    const baseDelay = retryConfig?.baseDelay || 1000;
    const jitter = Math.random() * 1000;
    const delay = Math.min(
      baseDelay * Math.pow(2, currentAttempt) + jitter,
      30000 // Max 30 seconds
    );
    
    // Schedule retry
    setTimeout(async () => {
      try {
        await context.operation({
          ...context,
          attempts: currentAttempt + 1
        });
        
        // Record success for circuit breaker
        this.getCircuitBreaker(context.tenantId).recordSuccess();
        
      } catch (retryError) {
        await this.handleApiError(retryError, {
          ...context,
          attempts: currentAttempt + 1
        }, retryConfig);
      }
    }, delay);
    
    return {
      status: 'scheduled_for_retry',
      retryDelay: delay,
      attempt: currentAttempt + 1,
      maxAttempts: maxRetries
    };
  }
  
  private getCircuitBreaker(tenantId: string): CircuitBreaker {
    if (!this.circuitBreakers.has(tenantId)) {
      this.circuitBreakers.set(tenantId, new CircuitBreaker({
        failureThreshold: 5,
        recoveryTimeout: 60000, // 1 minute
        monitoringPeriod: 300000 // 5 minutes
      }));
    }
    
    return this.circuitBreakers.get(tenantId)!;
  }
}

class CircuitBreaker {
  public state: 'closed' | 'open' | 'half-open' = 'closed';
  public failureCount = 0;
  public lastFailureTime?: Date;
  public nextAttemptTime?: Date;
  
  constructor(private config: CircuitBreakerConfig) {}
  
  public recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = new Date();
    
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = 'open';
      this.nextAttemptTime = new Date(Date.now() + this.config.recoveryTimeout);
    }
  }
  
  public recordSuccess(): void {
    this.failureCount = 0;
    this.state = 'closed';
    this.nextAttemptTime = undefined;
  }
  
  public canAttempt(): boolean {
    if (this.state === 'closed') return true;
    if (this.state === 'open') {
      if (this.nextAttemptTime && Date.now() >= this.nextAttemptTime.getTime()) {
        this.state = 'half-open';
        return true;
      }
      return false;
    }
    return true; // half-open state
  }
}
```

### 4.4 Data Caching and Invalidation

**Multi-Layer Caching Strategy:**
```typescript
// src/services/cache-manager.ts
export class CacheManager {
  private memoryCache = new Map<string, CacheEntry>();
  private redisClient: Redis;
  
  constructor() {
    this.redisClient = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3
    });
  }
  
  public async getCachedData<T>(
    key: string,
    fetchFunction: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<T> {
    const cacheKey = this.buildCacheKey(key, options.namespace);
    
    // L1 Cache: Memory (fastest)
    const memoryResult = this.getFromMemoryCache<T>(cacheKey);
    if (memoryResult.found) {
      return memoryResult.data!;
    }
    
    // L2 Cache: Redis (fast)
    const redisResult = await this.getFromRedisCache<T>(cacheKey);
    if (redisResult.found) {
      // Store in memory cache for next time
      this.setMemoryCache(cacheKey, redisResult.data!, options.memoryTtl || 300);
      return redisResult.data!;
    }
    
    // L3: Fetch from source (slow)
    const freshData = await fetchFunction();
    
    // Store in both caches
    await this.setCaches(cacheKey, freshData, options);
    
    return freshData;
  }
  
  public async invalidateCache(pattern: string): Promise<void> {
    // Invalidate memory cache
    for (const key of this.memoryCache.keys()) {
      if (this.matchPattern(key, pattern)) {
        this.memoryCache.delete(key);
      }
    }
    
    // Invalidate Redis cache
    const keys = await this.redisClient.keys(pattern);
    if (keys.length > 0) {
      await this.redisClient.del(...keys);
    }
  }
  
  // Specific cache methods for budget operations
  public async cacheBudgetStatus(
    tenantId: string,
    budgetId: string,
    status: BudgetStatus
  ): Promise<void> {
    const key = `budget_status:${tenantId}:${budgetId}`;
    await this.setCaches(key, status, {
      redisTtl: 300, // 5 minutes
      memoryTtl: 60  // 1 minute
    });
  }
  
  public async getCachedBudgetStatus(
    tenantId: string,
    budgetId: string
  ): Promise<BudgetStatus | null> {
    const key = `budget_status:${tenantId}:${budgetId}`;
    const result = await this.getCachedData(key, async () => {
      throw new Error('No fetch function for cached budget status');
    });
    
    return result || null;
  }
  
  public async cacheUsageData(
    tenantId: string,
    organizationId: number,
    usageData: UsageData
  ): Promise<void> {
    const key = `usage_data:${tenantId}:${organizationId}`;
    await this.setCaches(key, usageData, {
      redisTtl: 900, // 15 minutes
      memoryTtl: 300 // 5 minutes
    });
  }
  
  public async invalidateTenantCache(tenantId: string): Promise<void> {
    await this.invalidateCache(`*${tenantId}*`);
  }
  
  // Smart cache warming for budget-related data
  public async warmBudgetCaches(tenantId: string): Promise<void> {
    const budgets = await this.budgetRepository.getBudgetsByTenant(tenantId);
    
    // Warm budget status caches
    const statusPromises = budgets.map(async budget => {
      const status = await this.calculateBudgetStatus(budget);
      await this.cacheBudgetStatus(tenantId, budget.id, status);
    });
    
    await Promise.all(statusPromises);
    
    // Pre-warm usage data cache
    const usageData = await this.makeApiClient.getUsageData(tenantId);
    if (usageData) {
      await this.cacheUsageData(tenantId, usageData.organizationId, usageData);
    }
  }
}
```

## 5. Performance Optimization Strategies

### 5.1 Caching Strategies for Budget Data

**Hierarchical Caching Architecture:**
```typescript
// src/services/performance-optimizer.ts
export class PerformanceOptimizer {
  private queryOptimizer: QueryOptimizer;
  private cacheWarmer: CacheWarmer;
  private connectionPool: ConnectionPool;
  
  constructor() {
    this.queryOptimizer = new QueryOptimizer();
    this.cacheWarmer = new CacheWarmer();
    this.connectionPool = new ConnectionPool({
      min: 5,
      max: 50,
      acquireTimeoutMillis: 30000
    });
  }
  
  public async optimizeBudgetQueries(tenantId: string): Promise<QueryOptimization> {
    const optimization: QueryOptimization = {
      cacheHitRate: 0,
      queryExecutionTime: 0,
      optimizationsApplied: []
    };
    
    // Analyze query patterns
    const queryPatterns = await this.analyzeQueryPatterns(tenantId);
    
    // Pre-compute expensive aggregations
    if (queryPatterns.frequentAggregations.length > 0) {
      await this.preComputeAggregations(tenantId, queryPatterns.frequentAggregations);
      optimization.optimizationsApplied.push('pre-computed-aggregations');
    }
    
    // Optimize cache warming based on access patterns
    const accessPattern = queryPatterns.accessPattern;
    if (accessPattern.type === 'predictable') {
      await this.scheduleIntelligentCacheWarming(tenantId, accessPattern);
      optimization.optimizationsApplied.push('intelligent-cache-warming');
    }
    
    // Set up read replicas for heavy read workloads
    if (queryPatterns.readWriteRatio > 10) {
      await this.enableReadReplicas(tenantId);
      optimization.optimizationsApplied.push('read-replicas');
    }
    
    return optimization;
  }
  
  private async preComputeAggregations(
    tenantId: string,
    aggregations: AggregationPattern[]
  ): Promise<void> {
    for (const aggregation of aggregations) {
      const cacheKey = `pre_computed:${tenantId}:${aggregation.type}`;
      
      // Use background job to compute expensive aggregations
      await this.scheduleBackgroundComputation({
        type: 'aggregation',
        tenantId,
        aggregation,
        cacheKey,
        ttl: aggregation.recommendedTtl
      });
    }
  }
}
```

### 5.2 Query Optimization for Time-Series Data

**Advanced Query Optimization:**
```sql
-- Optimized budget status query with time-series aggregation
WITH tenant_cost_summary AS (
  SELECT 
    tenant_id,
    period_date,
    SUM(cost_cents) as daily_cost_cents,
    SUM(operations_count) as daily_operations,
    SUM(credits_consumed) as daily_credits
  FROM cost_tracking_data
  WHERE tenant_id = $1 
    AND period_date >= $2 
    AND period_date <= $3
  GROUP BY tenant_id, period_date
),
budget_periods AS (
  SELECT 
    bc.id as budget_id,
    bc.tenant_id,
    bc.monthly_limit_cents,
    bc.daily_limit_cents,
    -- Calculate budget period boundaries
    CASE 
      WHEN bc.budget_period_type = 'monthly' THEN 
        date_trunc('month', CURRENT_DATE)::date
      WHEN bc.budget_period_type = 'weekly' THEN 
        date_trunc('week', CURRENT_DATE)::date
      ELSE bc.period_start_date::date
    END as period_start,
    CASE 
      WHEN bc.budget_period_type = 'monthly' THEN 
        (date_trunc('month', CURRENT_DATE) + interval '1 month' - interval '1 day')::date
      WHEN bc.budget_period_type = 'weekly' THEN 
        (date_trunc('week', CURRENT_DATE) + interval '1 week' - interval '1 day')::date
      ELSE bc.period_end_date::date
    END as period_end
  FROM budget_configurations bc
  WHERE bc.tenant_id = $1 AND bc.is_active = true
),
current_spending AS (
  SELECT 
    bp.budget_id,
    bp.tenant_id,
    bp.monthly_limit_cents,
    bp.daily_limit_cents,
    bp.period_start,
    bp.period_end,
    COALESCE(SUM(tcs.daily_cost_cents), 0) as current_spend_cents,
    COALESCE(SUM(tcs.daily_operations), 0) as total_operations,
    COALESCE(SUM(tcs.daily_credits), 0) as total_credits,
    COUNT(tcs.period_date) as days_with_activity
  FROM budget_periods bp
  LEFT JOIN tenant_cost_summary tcs ON (
    bp.tenant_id = tcs.tenant_id 
    AND tcs.period_date >= bp.period_start 
    AND tcs.period_date <= bp.period_end
  )
  GROUP BY bp.budget_id, bp.tenant_id, bp.monthly_limit_cents, 
           bp.daily_limit_cents, bp.period_start, bp.period_end
),
trend_analysis AS (
  SELECT 
    cs.budget_id,
    cs.current_spend_cents,
    cs.monthly_limit_cents,
    -- Calculate percentage used
    ROUND((cs.current_spend_cents::decimal / NULLIF(cs.monthly_limit_cents, 0)) * 100, 2) as percent_used,
    -- Calculate daily average
    ROUND(cs.current_spend_cents::decimal / NULLIF(cs.days_with_activity, 0), 2) as daily_average_cents,
    -- Calculate remaining days in period
    (cs.period_end - CURRENT_DATE) as days_remaining,
    -- Simple linear projection
    CASE 
      WHEN cs.days_with_activity > 0 AND (cs.period_end - CURRENT_DATE) > 0 THEN
        ROUND(
          cs.current_spend_cents + 
          (cs.current_spend_cents::decimal / cs.days_with_activity) * (cs.period_end - CURRENT_DATE),
          2
        )
      ELSE cs.current_spend_cents
    END as projected_spend_cents
  FROM current_spending cs
)
SELECT 
  ta.budget_id,
  bc.name as budget_name,
  ta.current_spend_cents,
  ta.monthly_limit_cents,
  ta.percent_used,
  ta.daily_average_cents,
  ta.days_remaining,
  ta.projected_spend_cents,
  ROUND((ta.projected_spend_cents / NULLIF(ta.monthly_limit_cents, 0)) * 100, 2) as projected_percent,
  -- Risk assessment
  CASE 
    WHEN ta.projected_spend_cents > ta.monthly_limit_cents * 1.2 THEN 'high'
    WHEN ta.projected_spend_cents > ta.monthly_limit_cents * 1.0 THEN 'medium'
    WHEN ta.projected_spend_cents > ta.monthly_limit_cents * 0.8 THEN 'low'
    ELSE 'minimal'
  END as risk_level,
  -- Get threshold alerts that may be triggered
  ARRAY_AGG(
    CASE 
      WHEN bat.percentage <= ta.percent_used OR 
           bat.percentage <= (ta.projected_spend_cents / NULLIF(ta.monthly_limit_cents, 0)) * 100
      THEN jsonb_build_object(
        'threshold_id', bat.id,
        'percentage', bat.percentage,
        'severity', bat.severity,
        'type', bat.threshold_type
      )
      ELSE NULL
    END
  ) FILTER (WHERE bat.id IS NOT NULL) as triggered_thresholds
FROM trend_analysis ta
JOIN budget_configurations bc ON ta.budget_id = bc.id
LEFT JOIN budget_alert_thresholds bat ON (
  ta.budget_id = bat.budget_id 
  AND bat.is_enabled = true
)
GROUP BY ta.budget_id, bc.name, ta.current_spend_cents, ta.monthly_limit_cents,
         ta.percent_used, ta.daily_average_cents, ta.days_remaining, 
         ta.projected_spend_cents
ORDER BY ta.percent_used DESC;
```

### 5.3 Load Balancing for Budget Services

**Microservice Load Balancing Architecture:**
```typescript
// src/services/load-balancer.ts
export class BudgetServiceLoadBalancer {
  private serviceInstances = new Map<string, ServiceInstance[]>();
  private healthChecker: ServiceHealthChecker;
  
  constructor() {
    this.healthChecker = new ServiceHealthChecker();
    this.startHealthChecking();
  }
  
  public async routeRequest(
    operation: BudgetOperation,
    context: RequestContext
  ): Promise<any> {
    const serviceType = this.determineServiceType(operation);
    const availableInstances = this.getHealthyInstances(serviceType);
    
    if (availableInstances.length === 0) {
      throw new ServiceUnavailableError(`No healthy ${serviceType} instances available`);
    }
    
    // Load balancing strategies
    const instance = this.selectInstance(availableInstances, {
      strategy: 'weighted_least_connections',
      context
    });
    
    try {
      const result = await this.executeOperation(instance, operation, context);
      this.recordSuccessMetrics(instance, operation);
      return result;
      
    } catch (error) {
      this.recordFailureMetrics(instance, operation, error);
      
      // Retry with different instance if available
      const retryInstances = availableInstances.filter(i => i.id !== instance.id);
      if (retryInstances.length > 0 && this.shouldRetry(error)) {
        const retryInstance = this.selectInstance(retryInstances, { 
          strategy: 'random',
          context 
        });
        return this.executeOperation(retryInstance, operation, context);
      }
      
      throw error;
    }
  }
  
  private determineServiceType(operation: BudgetOperation): ServiceType {
    switch (operation.type) {
      case 'budget_status_check':
      case 'cost_projection':
        return 'read_service';
        
      case 'budget_create':
      case 'budget_update':
      case 'threshold_update':
        return 'write_service';
        
      case 'alert_evaluation':
      case 'threshold_monitoring':
        return 'monitoring_service';
        
      case 'scenario_control':
        return 'automation_service';
        
      default:
        return 'general_service';
    }
  }
  
  private selectInstance(
    instances: ServiceInstance[],
    options: LoadBalancingOptions
  ): ServiceInstance {
    switch (options.strategy) {
      case 'weighted_least_connections':
        return this.selectByWeightedConnections(instances);
        
      case 'resource_aware':
        return this.selectByResourceUsage(instances);
        
      case 'tenant_affinity':
        return this.selectByTenantAffinity(instances, options.context.tenantId);
        
      case 'random':
      default:
        return instances[Math.floor(Math.random() * instances.length)];
    }
  }
  
  private selectByWeightedConnections(instances: ServiceInstance[]): ServiceInstance {
    // Select instance with lowest weighted connection count
    let selectedInstance = instances[0];
    let lowestScore = Number.MAX_VALUE;
    
    for (const instance of instances) {
      // Score = (active_connections / max_connections) * (1 / weight)
      const connectionRatio = instance.activeConnections / instance.maxConnections;
      const score = connectionRatio * (1 / instance.weight);
      
      if (score < lowestScore) {
        lowestScore = score;
        selectedInstance = instance;
      }
    }
    
    return selectedInstance;
  }
  
  private selectByResourceUsage(instances: ServiceInstance[]): ServiceInstance {
    // Select instance with best resource availability
    return instances.reduce((best, current) => {
      const bestScore = this.calculateResourceScore(best);
      const currentScore = this.calculateResourceScore(current);
      return currentScore > bestScore ? current : best;
    });
  }
  
  private calculateResourceScore(instance: ServiceInstance): number {
    const cpuScore = (100 - instance.metrics.cpuUsage) / 100;
    const memoryScore = (100 - instance.metrics.memoryUsage) / 100;
    const responseTimeScore = Math.max(0, (1000 - instance.metrics.avgResponseTime) / 1000);
    
    return (cpuScore * 0.4) + (memoryScore * 0.3) + (responseTimeScore * 0.3);
  }
}
```

### 5.4 Monitoring and Alerting Infrastructure

**Comprehensive Monitoring System:**
```typescript
// src/services/monitoring-service.ts
export class BudgetMonitoringService {
  private metricsCollector: PrometheusMetrics;
  private distributedTracer: JaegerTracer;
  private alertingSystem: AlertingSystem;
  
  constructor() {
    this.metricsCollector = new PrometheusMetrics();
    this.distributedTracer = new JaegerTracer();
    this.alertingSystem = new AlertingSystem();
    this.setupMetrics();
  }
  
  private setupMetrics(): void {
    // Budget operation metrics
    this.metricsCollector.createHistogram({
      name: 'budget_operation_duration_seconds',
      help: 'Duration of budget operations',
      labelNames: ['operation', 'tenant_id', 'status'],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30]
    });
    
    this.metricsCollector.createCounter({
      name: 'budget_threshold_alerts_total',
      help: 'Total number of budget threshold alerts triggered',
      labelNames: ['tenant_id', 'budget_id', 'threshold_type', 'severity']
    });
    
    this.metricsCollector.createGauge({
      name: 'active_budget_configurations',
      help: 'Number of active budget configurations per tenant',
      labelNames: ['tenant_id']
    });
    
    this.metricsCollector.createHistogram({
      name: 'cost_projection_accuracy',
      help: 'Accuracy of cost projections vs actual spend',
      labelNames: ['tenant_id', 'projection_period'],
      buckets: [0.70, 0.80, 0.85, 0.90, 0.95, 0.98, 1.0]
    });
    
    // API integration metrics
    this.metricsCollector.createCounter({
      name: 'make_api_requests_total',
      help: 'Total Make.com API requests',
      labelNames: ['endpoint', 'method', 'status_code', 'tenant_id']
    });
    
    this.metricsCollector.createHistogram({
      name: 'make_api_request_duration_seconds',
      help: 'Duration of Make.com API requests',
      labelNames: ['endpoint', 'method'],
      buckets: [0.1, 0.3, 0.5, 1, 2, 5, 10]
    });
  }
  
  public recordBudgetOperation(
    operation: string,
    tenantId: string,
    duration: number,
    status: 'success' | 'error'
  ): void {
    this.metricsCollector.getHistogram('budget_operation_duration_seconds')
      .labels({ operation, tenant_id: tenantId, status })
      .observe(duration / 1000);
  }
  
  public recordThresholdAlert(
    tenantId: string,
    budgetId: string,
    thresholdType: string,
    severity: string
  ): void {
    this.metricsCollector.getCounter('budget_threshold_alerts_total')
      .labels({
        tenant_id: tenantId,
        budget_id: budgetId,
        threshold_type: thresholdType,
        severity
      })
      .inc();
  }
  
  public async createMonitoringDashboard(): Promise<DashboardConfig> {
    return {
      dashboard: {
        id: 'budget-control-monitoring',
        title: 'Make.com Budget Control Monitoring',
        tags: ['budget', 'costs', 'monitoring'],
        panels: [
          {
            title: 'Budget Status Overview',
            type: 'stat',
            targets: [
              {
                expr: 'sum by (tenant_id) (active_budget_configurations)',
                legendFormat: 'Active Budgets - {{ tenant_id }}'
              }
            ]
          },
          {
            title: 'Threshold Alert Rate',
            type: 'graph',
            targets: [
              {
                expr: 'rate(budget_threshold_alerts_total[5m])',
                legendFormat: 'Alerts/sec - {{ severity }}'
              }
            ]
          },
          {
            title: 'Cost Projection Accuracy',
            type: 'heatmap',
            targets: [
              {
                expr: 'cost_projection_accuracy',
                legendFormat: 'Accuracy Distribution'
              }
            ]
          },
          {
            title: 'Make.com API Performance',
            type: 'graph',
            targets: [
              {
                expr: 'histogram_quantile(0.95, rate(make_api_request_duration_seconds_bucket[5m]))',
                legendFormat: '95th percentile - {{ endpoint }}'
              }
            ]
          }
        ]
      }
    };
  }
  
  public setupDistributedTracing(): void {
    // Trace budget operations across services
    this.distributedTracer.instrument({
      serviceName: 'budget-control-service',
      spans: [
        'budget.create',
        'budget.update', 
        'budget.status.check',
        'cost.projection.generate',
        'alert.evaluate',
        'scenario.pause',
        'make.api.call'
      ]
    });
  }
}
```

## 6. Implementation Timeline and Priorities

### 6.1 Phase 1: Core Budget Management (Weeks 1-2)
1. **Database Schema Setup**
2. **Basic FastMCP Tool Integration** 
3. **Budget Configuration API**
4. **Simple Cost Tracking**

### 6.2 Phase 2: Alert System (Weeks 3-4)
1. **Alert Configuration Tools**
2. **Threshold Monitoring Service**
3. **Notification Integration**
4. **Basic Polling System**

### 6.3 Phase 3: Cost Projection (Weeks 5-6)
1. **Historical Data Analysis**
2. **ML-Powered Forecasting**
3. **Confidence Interval Calculation**
4. **Projection API Integration**

### 6.4 Phase 4: Automated Controls (Weeks 7-8)
1. **Scenario Control Integration**
2. **Automated Pause/Resume Logic**
3. **Circuit Breaker Implementation**
4. **Audit Logging System**

### 6.5 Phase 5: Performance & Scale (Weeks 9-10)
1. **Caching Layer Implementation**
2. **Load Balancing Setup**
3. **Monitoring & Alerting**
4. **Performance Optimization**

## Conclusion

This technical implementation research provides a comprehensive blueprint for integrating advanced budget control tools into the existing Make.com FastMCP server architecture. The approach leverages existing patterns while introducing sophisticated multi-tenant budget management, real-time monitoring, ML-powered cost projection, and automated scenario control capabilities.

The recommended architecture prioritizes security, scalability, and maintainability while providing flexible configuration options for diverse customer requirements. The phased implementation approach ensures reliable delivery of core functionality before advancing to sophisticated features.

**Key Success Factors:**
- Leverage existing FastMCP patterns and error handling
- Implement multi-tenant data isolation from day one
- Use ML-powered cost projection for accuracy
- Provide comprehensive audit trails
- Scale services using proven load balancing patterns
- Monitor system health with detailed metrics

This implementation will significantly enhance the Make.com FastMCP server's value proposition by providing enterprise-grade cost management capabilities that rival major cloud providers.