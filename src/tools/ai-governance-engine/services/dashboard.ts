/**
 * Dashboard Service for AI Governance Engine
 * Handles dashboard generation and real-time data management
 * Generated on 2025-08-22T09:58:23.000Z
 */

import { MakeApiClient } from '../../../lib/make-api-client.js';
import logger from '../../../lib/logger.js';
import type { GovernanceContext } from '../types/context.js';
import type {
  DashboardConfig,
  DashboardWidget,
  RealTimeData,
  Forecast,
  ForecastPoint,
  AlertConfiguration,
  SystemHealth
} from '../types/index.js';
import type { GovernanceDashboardRequest } from '../schemas/index.js';

interface DashboardTemplate {
  type: 'executive' | 'operational' | 'technical' | 'comprehensive';
  defaultWidgets: DashboardWidget[];
  layout: string;
  refreshInterval: number;
  targetAudience: string[];
}

interface WidgetData {
  widgetId: string;
  type: string;
  data: Record<string, unknown>;
  lastUpdated: string;
  status: 'active' | 'error' | 'loading';
}

interface RealTimeMetrics {
  timestamp: string;
  complianceScore: number;
  riskScore: number;
  activeIncidents: number;
  systemHealth: 'healthy' | 'degraded' | 'critical';
  throughput: number;
  responseTime: number;
}

interface DashboardCustomization {
  layout?: string;
  widgets?: string[];
  theme?: string;
  colors?: {
    primary?: string;
    secondary?: string;
    success?: string;
    warning?: string;
    error?: string;
  };
  displayOptions?: {
    showLegend?: boolean;
    showTooltips?: boolean;
    animateTransitions?: boolean;
  };
}

export class DashboardService {
  private readonly componentLogger = logger.child({ component: 'DashboardService' });
  private readonly dashboardTemplates: Map<string, DashboardTemplate> = new Map();
  private readonly activeDashboards: Map<string, DashboardConfig> = new Map();
  private readonly widgetDataCache: Map<string, WidgetData> = new Map();
  private realTimeDataStream: RealTimeMetrics[] = [];
  private readonly forecastCache: Map<string, Forecast> = new Map();

  constructor(
    private readonly context: GovernanceContext,
    private readonly apiClient: MakeApiClient
  ) {
    this.initializeDashboardTemplates();
    this.startRealTimeDataCollection();
  }

  /**
   * Generates a comprehensive governance dashboard based on _request parameters
   */
  async generateDashboard(_request: GovernanceDashboardRequest): Promise<{
    success: boolean;
    message?: string;
    data?: {
      dashboardConfig: DashboardConfig;
      widgetData: WidgetData[];
      realTimeMetrics: RealTimeData;
      alertConfig: AlertConfiguration[];
      systemStatus: SystemHealth;
    };
    errors?: string[];
  }> {
    try {
      this.componentLogger.info('Generating governance dashboard', {
        dashboardType: _request.dashboardType,
        metricsLevel: _request.metricsLevel,
        includeRealTime: _request.includeRealTime
      });

      const startTime = Date.now();

      // Get or create dashboard configuration
      const dashboardConfig = await this.createDashboardConfig(_request);

      // Generate widget data
      const widgetData = await this.generateWidgetData(dashboardConfig, _request);

      // Get real-time metrics if _requested
      const realTimeMetrics = _request.includeRealTime ? 
        await this.getRealTimeMetrics(_request) : this.getStaticMetrics();

      // Configure alerts
      const alertConfig = await this.generateAlertConfiguration(_request);

      // Get system health status
      const systemStatus = await this.getSystemHealth();

      // Cache the dashboard
      const dashboardId = `dashboard_${_request.dashboardType}_${Date.now()}`;
      this.activeDashboards.set(dashboardId, dashboardConfig);

      const processingTime = Date.now() - startTime;
      this.componentLogger.info('Dashboard generated successfully', {
        dashboardType: _request.dashboardType,
        widgetCount: widgetData.length,
        processingTime
      });

      return {
        success: true,
        message: `${_request.dashboardType} dashboard generated with ${widgetData.length} widgets`,
        data: {
          dashboardConfig,
          widgetData,
          realTimeMetrics,
          alertConfig,
          systemStatus
        }
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.componentLogger.error('Dashboard generation failed', { error: errorMessage });
      return {
        success: false,
        errors: [errorMessage]
      };
    }
  }

  /**
   * Updates real-time dashboard data
   */
  async updateRealTimeData(dashboardId: string): Promise<{
    success: boolean;
    data?: RealTimeData;
    errors?: string[];
  }> {
    try {
      const dashboardConfig = this.activeDashboards.get(dashboardId);
      if (!dashboardConfig) {
        throw new Error(`Dashboard not found: ${dashboardId}`);
      }

      // Collect latest real-time data
      const realTimeData = await this.collectRealTimeData();

      // Update widget data cache
      for (const widget of dashboardConfig.widgets) {
        if (this.isRealTimeWidget(widget)) {
          await this.updateWidgetData(widget, realTimeData);
        }
      }

      this.componentLogger.debug('Real-time data updated', { dashboardId });

      return {
        success: true,
        data: realTimeData
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.componentLogger.error('Real-time data update failed', { error: errorMessage });
      return {
        success: false,
        errors: [errorMessage]
      };
    }
  }

  /**
   * Generates forecasting data for dashboard widgets
   */
  async generateForecasts(metrics: string[], timeframe: string): Promise<{
    success: boolean;
    data?: Forecast[];
    errors?: string[];
  }> {
    try {
      this.componentLogger.info('Generating dashboard forecasts', { metrics, timeframe });

      const forecasts: Forecast[] = [];

      for (const metric of metrics) {
        const cacheKey = `forecast_${metric}_${timeframe}`;
        
        // Check cache first
        if (this.forecastCache.has(cacheKey)) {
          forecasts.push(this.forecastCache.get(cacheKey));
          continue;
        }

        // Generate new forecast
        const forecast = await this.generateMetricForecast(metric, timeframe);
        forecasts.push(forecast);

        // Cache the forecast
        this.forecastCache.set(cacheKey, forecast);
      }

      return {
        success: true,
        data: forecasts
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.componentLogger.error('Forecast generation failed', { error: errorMessage });
      return {
        success: false,
        errors: [errorMessage]
      };
    }
  }

  /**
   * Customizes dashboard layout and widgets
   */
  async customizeDashboard(
    dashboardId: string,
    customization: {
      layout?: string;
      widgets?: string[];
      theme?: string;
      filters?: Record<string, string | number | boolean | string[]>;
    }
  ): Promise<{
    success: boolean;
    data?: DashboardConfig;
    errors?: string[];
  }> {
    try {
      this.componentLogger.info('Customizing dashboard', { dashboardId, customization });

      const dashboardConfig = this.activeDashboards.get(dashboardId);
      if (!dashboardConfig) {
        throw new Error(`Dashboard not found: ${dashboardId}`);
      }

      // Apply customizations
      const updatedConfig = await this.applyCustomizations(dashboardConfig, customization);

      // Update cache
      this.activeDashboards.set(dashboardId, updatedConfig);

      // Regenerate affected widget data
      if (customization.widgets) {
        await this.regenerateWidgetData(updatedConfig);
      }

      return {
        success: true,
        data: updatedConfig
      };

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.componentLogger.error('Dashboard customization failed', { error: errorMessage });
      return {
        success: false,
        errors: [errorMessage]
      };
    }
  }

  // Private helper methods

  private initializeDashboardTemplates(): void {
    const templates: DashboardTemplate[] = [
      {
        type: 'executive',
        defaultWidgets: [
          {
            id: 'exec_compliance_summary',
            type: 'metric',
            title: 'Compliance Score',
            position: { x: 0, y: 0 },
            size: { width: 4, height: 2 },
            config: { metric: 'complianceScore', format: 'percentage', threshold: 80 },
            dataSource: 'compliance_metrics',
            refreshRate: 300 // 5 minutes
          },
          {
            id: 'exec_risk_overview',
            type: 'chart',
            title: 'Risk Trend',
            position: { x: 4, y: 0 },
            size: { width: 8, height: 4 },
            config: { chartType: 'line', timeframe: '30d' },
            dataSource: 'risk_metrics',
            refreshRate: 300
          },
          {
            id: 'exec_alerts',
            type: 'alert',
            title: 'Critical Alerts',
            position: { x: 0, y: 2 },
            size: { width: 4, height: 2 },
            config: { severity: ['critical', 'high'], limit: 5 },
            dataSource: 'alert_system',
            refreshRate: 60
          }
        ],
        layout: 'grid',
        refreshInterval: 300,
        targetAudience: ['executives', 'board_members', 'senior_management']
      },
      {
        type: 'operational',
        defaultWidgets: [
          {
            id: 'ops_incident_queue',
            type: 'table',
            title: 'Active Incidents',
            position: { x: 0, y: 0 },
            size: { width: 6, height: 4 },
            config: { columns: ['id', 'severity', 'status', 'assignee'], sortBy: 'severity' },
            dataSource: 'incident_management',
            refreshRate: 120
          },
          {
            id: 'ops_automation_status',
            type: 'metric',
            title: 'Automation Coverage',
            position: { x: 6, y: 0 },
            size: { width: 3, height: 2 },
            config: { metric: 'automationCoverage', format: 'percentage' },
            dataSource: 'automation_metrics',
            refreshRate: 300
          },
          {
            id: 'ops_response_time',
            type: 'chart',
            title: 'Response Time Trend',
            position: { x: 6, y: 2 },
            size: { width: 6, height: 2 },
            config: { chartType: 'area', timeframe: '24h' },
            dataSource: 'performance_metrics',
            refreshRate: 180
          }
        ],
        layout: 'operational',
        refreshInterval: 120,
        targetAudience: ['operations_team', 'incident_managers', 'devops']
      },
      {
        type: 'technical',
        defaultWidgets: [
          {
            id: 'tech_system_health',
            type: 'metric',
            title: 'System Health',
            position: { x: 0, y: 0 },
            size: { width: 3, height: 2 },
            config: { metric: 'systemHealth', format: 'status' },
            dataSource: 'system_monitoring',
            refreshRate: 60
          },
          {
            id: 'tech_api_performance',
            type: 'chart',
            title: 'API Performance',
            position: { x: 3, y: 0 },
            size: { width: 6, height: 3 },
            config: { chartType: 'bar', metrics: ['latency', 'throughput', 'errors'] },
            dataSource: 'api_metrics',
            refreshRate: 60
          },
          {
            id: 'tech_security_events',
            type: 'table',
            title: 'Security Events',
            position: { x: 0, y: 2 },
            size: { width: 9, height: 3 },
            config: { columns: ['timestamp', 'event_type', 'source', 'risk_level'], limit: 20 },
            dataSource: 'security_logs',
            refreshRate: 30
          }
        ],
        layout: 'technical',
        refreshInterval: 60,
        targetAudience: ['engineers', 'security_team', 'system_administrators']
      },
      {
        type: 'comprehensive',
        defaultWidgets: [
          // Combines elements from all other dashboard types
          {
            id: 'comp_overview',
            type: 'metric',
            title: 'Governance Overview',
            position: { x: 0, y: 0 },
            size: { width: 12, height: 2 },
            config: { 
              metrics: ['complianceScore', 'riskScore', 'incidentCount', 'automationCoverage'],
              layout: 'horizontal'
            },
            dataSource: 'governance_summary',
            refreshRate: 180
          }
        ],
        layout: 'comprehensive',
        refreshInterval: 180,
        targetAudience: ['all_stakeholders']
      }
    ];

    templates.forEach(template => {
      this.dashboardTemplates.set(template.type, template);
    });

    this.componentLogger.info('Initialized dashboard templates', { count: templates.length });
  }

  private startRealTimeDataCollection(): void {
    // Simulate real-time data collection
    setInterval(() => {
      const metrics: RealTimeMetrics = {
        timestamp: new Date().toISOString(),
        complianceScore: 80 + (Math.random() * 15), // 80-95
        riskScore: 20 + (Math.random() * 30), // 20-50
        activeIncidents: Math.floor(Math.random() * 10), // 0-10
        systemHealth: Math.random() > 0.9 ? 'degraded' : 'healthy',
        throughput: 1000 + (Math.random() * 500), // 1000-1500 _requests/sec
        responseTime: 100 + (Math.random() * 200) // 100-300ms
      };

      this.realTimeDataStream.push(metrics);

      // Keep only last 1000 data points
      if (this.realTimeDataStream.length > 1000) {
        this.realTimeDataStream = this.realTimeDataStream.slice(-1000);
      }
    }, 30000); // Update every 30 seconds

    this.componentLogger.info('Started real-time data collection');
  }

  private async createDashboardConfig(_request: GovernanceDashboardRequest): Promise<DashboardConfig> {
    const template = this.dashboardTemplates.get(_request.dashboardType);
    if (!template) {
      throw new Error(`Unknown dashboard type: ${_request.dashboardType}`);
    }

    const config: DashboardConfig = {
      userId: _request.organizationId || 'default',
      layout: template.layout,
      widgets: [...template.defaultWidgets], // Deep copy
      refreshInterval: _request.refreshInterval,
      alertSettings: this.getDefaultAlertSettings(_request.dashboardType)
    };

    // Customize based on metrics level
    if (_request.metricsLevel === 'summary') {
      config.widgets = config.widgets.filter(w => w.type === 'metric');
    } else if (_request.metricsLevel === 'granular') {
      config.widgets.push(...this.getGranularWidgets());
    }

    return config;
  }

  private async generateWidgetData(config: DashboardConfig, _request: GovernanceDashboardRequest): Promise<WidgetData[]> {
    const widgetData: WidgetData[] = [];

    for (const widget of config.widgets) {
      try {
        const data = await this.generateDataForWidget(widget, _request);
        
        widgetData.push({
          widgetId: widget.id,
          type: widget.type,
          data,
          lastUpdated: new Date().toISOString(),
          status: 'active'
        });

        // Cache the widget data
        this.widgetDataCache.set(widget.id, widgetData[widgetData.length - 1]);

      } catch (error) {
        this.componentLogger.error('Widget data generation failed', { 
          widgetId: widget.id, 
          error: error instanceof Error ? error.message : String(error)
        });

        widgetData.push({
          widgetId: widget.id,
          type: widget.type,
          data: { error: 'Failed to load data' },
          lastUpdated: new Date().toISOString(),
          status: 'error'
        });
      }
    }

    return widgetData;
  }

  private async generateDataForWidget(widget: DashboardWidget, __request: GovernanceDashboardRequest): Promise<Record<string, unknown>> {
    switch (widget.type) {
      case 'metric':
        return this.generateMetricData(widget);
      case 'chart':
        return this.generateChartData(widget, __request);
      case 'table':
        return this.generateTableData(widget);
      case 'alert':
        return this.generateAlertData(widget);
      default:
        throw new Error(`Unknown widget type: ${widget.type}`);
    }
  }

  private generateMetricData(widget: DashboardWidget): Record<string, unknown> {
    const metrics: Record<string, Record<string, unknown>> = {
      complianceScore: {
        value: 85 + (Math.random() * 10),
        unit: '%',
        trend: Math.random() > 0.5 ? 'up' : 'down',
        change: Math.random() * 5
      },
      riskScore: {
        value: 25 + (Math.random() * 20),
        unit: 'points',
        trend: Math.random() > 0.5 ? 'down' : 'up',
        change: Math.random() * 3
      },
      automationCoverage: {
        value: 70 + (Math.random() * 25),
        unit: '%',
        trend: 'up',
        change: Math.random() * 2
      },
      systemHealth: {
        value: 'healthy',
        components: {
          api: 'healthy',
          database: 'healthy',
          monitoring: 'degraded'
        }
      }
    };

    const metricName = widget.config.metric as string;
    return metrics[metricName] || { value: 'N/A', unit: '', trend: 'stable', change: 0 };
  }

  private generateChartData(widget: DashboardWidget, __request: GovernanceDashboardRequest): Record<string, unknown> {
    const dataPoints = 20;
    const data = [];

    for (let i = 0; i < dataPoints; i++) {
      data.push({
        timestamp: new Date(Date.now() - (dataPoints - i) * 60000).toISOString(),
        value: Math.random() * 100,
        category: `Category ${Math.floor(Math.random() * 3) + 1}`
      });
    }

    return {
      chartType: widget.config.chartType || 'line',
      data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { type: 'time' },
          y: { beginAtZero: true }
        }
      }
    };
  }

  private generateTableData(widget: DashboardWidget): Record<string, unknown> {
    const rowCount = (widget.config.limit as number) || 10;
    const rows = [];

    for (let i = 0; i < rowCount; i++) {
      rows.push({
        id: `item_${i + 1}`,
        severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
        status: ['open', 'in_progress', 'resolved'][Math.floor(Math.random() * 3)],
        assignee: `User ${Math.floor(Math.random() * 10) + 1}`,
        timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString()
      });
    }

    return {
      columns: widget.config.columns || ['id', 'status', 'timestamp'],
      rows,
      sortBy: widget.config.sortBy || 'timestamp',
      sortOrder: 'desc'
    };
  }

  private generateAlertData(widget: DashboardWidget): Record<string, unknown> {
    const alertCount = (widget.config.limit as number) || 5;
    const alerts = [];

    for (let i = 0; i < alertCount; i++) {
      alerts.push({
        id: `alert_${i + 1}`,
        title: `Alert ${i + 1}`,
        message: `Sample alert message ${i + 1}`,
        severity: ['info', 'warning', 'critical'][Math.floor(Math.random() * 3)],
        timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
        status: 'active'
      });
    }

    return {
      alerts,
      totalCount: alertCount,
      unacknowledged: Math.floor((alertCount) * 0.6)
    };
  }

  private async getRealTimeMetrics(_request: GovernanceDashboardRequest): Promise<RealTimeData> {
    const latestMetrics = this.realTimeDataStream[this.realTimeDataStream.length - 1];
    
    if (!latestMetrics) {
      // Fallback to generated data
      return this.getStaticMetrics();
    }

    const alerts = [
      'High risk score detected',
      'Compliance violation in progress',
      'System performance degraded'
    ].filter(() => Math.random() > 0.7); // Randomly include alerts

    const forecasts = _request.includeForecasting ? 
      await this.generateQuickForecasts() : [];

    return {
      timestamp: latestMetrics.timestamp,
      metrics: {
        complianceScore: latestMetrics.complianceScore,
        riskScore: latestMetrics.riskScore,
        policyViolations: latestMetrics.activeIncidents,
        automatedRemediations: Math.floor(Math.random() * 10),
        avgResponseTime: latestMetrics.responseTime,
        predictionAccuracy: 85 + (Math.random() * 10)
      },
      alerts,
      forecasts
    };
  }

  private getStaticMetrics(): RealTimeData {
    return {
      timestamp: new Date().toISOString(),
      metrics: {
        complianceScore: 85 + (Math.random() * 10),
        riskScore: 25 + (Math.random() * 20),
        policyViolations: Math.floor(Math.random() * 5),
        automatedRemediations: Math.floor(Math.random() * 10),
        avgResponseTime: 200 + (Math.random() * 100),
        predictionAccuracy: 85 + (Math.random() * 10)
      },
      alerts: [],
      forecasts: []
    };
  }

  private async generateAlertConfiguration(_request: GovernanceDashboardRequest): Promise<AlertConfiguration[]> {
    return [
      {
        metric: 'complianceScore',
        thresholds: { warning: 80, critical: 70 },
        enabled: true,
        recipients: ['governance_team@company.com']
      },
      {
        metric: 'riskScore',
        thresholds: { warning: 70, critical: 90 },
        enabled: true,
        recipients: ['security_team@company.com']
      }
    ];
  }

  private async getSystemHealth(): Promise<SystemHealth> {
    return {
      status: Math.random() > 0.9 ? 'degraded' : 'healthy',
      components: [
        {
          name: 'API Gateway',
          status: 'healthy',
          responseTime: 50 + (Math.random() * 50),
          errorRate: Math.random() * 2,
          lastCheck: new Date().toISOString()
        },
        {
          name: 'Database',
          status: Math.random() > 0.95 ? 'degraded' : 'healthy',
          responseTime: 20 + (Math.random() * 30),
          errorRate: Math.random() * 1,
          lastCheck: new Date().toISOString()
        }
      ],
      lastCheck: new Date().toISOString()
    };
  }

  private async collectRealTimeData(): Promise<RealTimeData> {
    // Return the latest real-time data
    return this.getRealTimeMetrics({ includeRealTime: true } as GovernanceDashboardRequest);
  }

  private isRealTimeWidget(widget: DashboardWidget): boolean {
    return widget.refreshRate <= 60; // Widgets that update every minute or less
  }

  private async updateWidgetData(widget: DashboardWidget, _realTimeData: RealTimeData): Promise<void> {
    const data = await this.generateDataForWidget(widget, { includeRealTime: true } as GovernanceDashboardRequest);
    
    this.widgetDataCache.set(widget.id, {
      widgetId: widget.id,
      type: widget.type,
      data,
      lastUpdated: new Date().toISOString(),
      status: 'active'
    });
  }

  private async generateMetricForecast(metric: string, _timeframe: string): Promise<Forecast> {
    const dataPoints = 10;
    const predictions: ForecastPoint[] = [];

    for (let i = 0; i < dataPoints; i++) {
      const timestamp = new Date(Date.now() + i * 3600000).toISOString(); // Hourly predictions
      const value = 50 + (Math.random() * 50);
      
      predictions.push({
        timestamp,
        value,
        upperBound: value + 10,
        lowerBound: value - 10
      });
    }

    return {
      metric,
      predictions,
      confidence: 0.8 + (Math.random() * 0.15)
    };
  }

  private async applyCustomizations(
    config: DashboardConfig,
    customization: DashboardCustomization
  ): Promise<DashboardConfig> {
    const updatedConfig = { ...config };

    if (customization.layout) {
      updatedConfig.layout = customization.layout;
    }

    if (customization.widgets) {
      // Filter widgets based on customization
      updatedConfig.widgets = config.widgets.filter(w => 
        customization.widgets.includes(w.id)
      );
    }

    if (customization.theme) {
      // Theme would be applied on the frontend
      updatedConfig.alertSettings = {
        ...updatedConfig.alertSettings,
        theme: customization.theme
      };
    }

    return updatedConfig;
  }

  private async regenerateWidgetData(config: DashboardConfig): Promise<void> {
    for (const widget of config.widgets) {
      const data = await this.generateDataForWidget(widget, {} as GovernanceDashboardRequest);
      
      this.widgetDataCache.set(widget.id, {
        widgetId: widget.id,
        type: widget.type,
        data,
        lastUpdated: new Date().toISOString(),
        status: 'active'
      });
    }
  }

  private getDefaultAlertSettings(dashboardType: string): Record<string, unknown> {
    const settings: Record<string, unknown> = {
      executive: {
        severityLevels: ['critical'],
        notifications: ['email'],
        frequency: 'immediate'
      },
      operational: {
        severityLevels: ['critical', 'high'],
        notifications: ['email', 'slack'],
        frequency: 'real-time'
      },
      technical: {
        severityLevels: ['critical', 'high', 'medium'],
        notifications: ['email', 'slack', 'webhook'],
        frequency: 'real-time'
      },
      comprehensive: {
        severityLevels: ['critical', 'high'],
        notifications: ['email'],
        frequency: 'hourly'
      }
    };

    return (settings[dashboardType] as Record<string, unknown>) || (settings.comprehensive as Record<string, unknown>);
  }

  private getGranularWidgets(): DashboardWidget[] {
    return [
      {
        id: 'granular_api_metrics',
        type: 'chart',
        title: 'API Performance Details',
        position: { x: 0, y: 6 },
        size: { width: 6, height: 3 },
        config: { chartType: 'line', granularity: 'minute' },
        dataSource: 'api_detailed_metrics',
        refreshRate: 60
      }
    ];
  }

  private async generateQuickForecasts(): Promise<Forecast[]> {
    return [
      {
        metric: 'complianceScore',
        predictions: [
          {
            timestamp: new Date(Date.now() + 3600000).toISOString(),
            value: 87,
            upperBound: 92,
            lowerBound: 82
          }
        ],
        confidence: 0.85
      }
    ];
  }

  /**
   * Get active dashboard statistics
   */
  getDashboardStats(): {
    activeDashboards: number;
    cachedWidgets: number;
    realTimeDataPoints: number;
  } {
    return {
      activeDashboards: this.activeDashboards.size,
      cachedWidgets: this.widgetDataCache.size,
      realTimeDataPoints: this.realTimeDataStream.length
    };
  }

  /**
   * Clear dashboard caches - useful for testing
   */
  clearCaches(): void {
    this.widgetDataCache.clear();
    this.forecastCache.clear();
    this.realTimeDataStream = [];
    this.componentLogger.info('Dashboard caches cleared');
  }
}