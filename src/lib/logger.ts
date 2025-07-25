/**
 * Structured logging utility for Make.com FastMCP Server
 * Provides consistent logging across the application with correlation ID tracking
 */

import configManager from './config.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: Record<string, unknown>;
  component?: string;
  operation?: string;
  sessionId?: string;
  userId?: string;
  correlationId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  requestId?: string;
  duration?: number;
  metadata?: Record<string, unknown>;
}

export interface LogContext {
  component?: string;
  operation?: string;
  sessionId?: string;
  userId?: string;
  correlationId?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  requestId?: string;
  metadata?: Record<string, unknown>;
}

class Logger {
  private static instance: Logger;
  private logLevel: LogLevel;
  private logLevels: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
  };

  private constructor() {
    this.logLevel = configManager.getLogLevel() as LogLevel;
  }

  public static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  private shouldLog(level: LogLevel): boolean {
    return this.logLevels[level] >= this.logLevels[this.logLevel];
  }

  private formatLogEntry(entry: LogEntry): string {
    const { 
      timestamp, level, message, component, operation, sessionId, userId, 
      correlationId, traceId, spanId, requestId, duration, data, metadata 
    } = entry;
    
    let logLine = `[${timestamp}] ${level.toUpperCase()}`;
    
    if (correlationId) logLine += ` [corr:${correlationId}]`;
    if (traceId) logLine += ` [trace:${traceId}]`;
    if (spanId) logLine += ` [span:${spanId}]`;
    if (requestId) logLine += ` [req:${requestId}]`;
    if (component) logLine += ` [${component}]`;
    if (operation) logLine += ` [${operation}]`;
    if (sessionId) logLine += ` [session:${sessionId}]`;
    if (userId) logLine += ` [user:${userId}]`;
    if (duration !== undefined) logLine += ` [${duration.toFixed(3)}s]`;
    
    logLine += `: ${message}`;
    
    if (data && Object.keys(data).length > 0) {
      logLine += ` | Data: ${JSON.stringify(data)}`;
    }

    if (metadata && Object.keys(metadata).length > 0) {
      logLine += ` | Meta: ${JSON.stringify(metadata)}`;
    }
    
    return logLine;
  }

  private log(level: LogLevel, message: string, data?: Record<string, unknown>, context?: LogContext): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data,
      ...context,
    };

    const formattedLog = this.formatLogEntry(entry);

    switch (level) {
      case 'debug':
      case 'info':
        console.log(formattedLog);
        break;
      case 'warn':
        console.warn(formattedLog);
        break;
      case 'error':
        console.error(formattedLog);
        break;
    }
  }

  public debug(message: string, data?: Record<string, unknown>, context?: LogContext): void {
    this.log('debug', message, data, context);
  }

  public info(message: string, data?: Record<string, unknown>, context?: LogContext): void {
    this.log('info', message, data, context);
  }

  public warn(message: string, data?: Record<string, unknown>, context?: LogContext): void {
    this.log('warn', message, data, context);
  }

  public error(message: string, data?: Record<string, unknown>, context?: LogContext): void {
    this.log('error', message, data, context);
  }

  public child(context: LogContext): {
    debug: (message: string, data?: Record<string, unknown>) => void;
    info: (message: string, data?: Record<string, unknown>) => void;
    warn: (message: string, data?: Record<string, unknown>) => void;
    error: (message: string, data?: Record<string, unknown>) => void;
  } {
    return {
      debug: (message: string, data?: Record<string, unknown>) => this.debug(message, data, context),
      info: (message: string, data?: Record<string, unknown>) => this.info(message, data, context),
      warn: (message: string, data?: Record<string, unknown>) => this.warn(message, data, context),
      error: (message: string, data?: Record<string, unknown>) => this.error(message, data, context),
    };
  }

  // Correlation ID utilities
  public generateCorrelationId(): string {
    return `corr_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  public generateTraceId(): string {
    return `trace_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  public generateSpanId(): string {
    return `span_${Math.random().toString(36).substring(2, 15)}`;
  }

  public generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  // Enhanced logging with automatic correlation ID generation
  public logWithCorrelation(
    level: LogLevel, 
    message: string, 
    data?: Record<string, unknown>, 
    context: LogContext = {}
  ): string {
    const correlationId = context.correlationId || this.generateCorrelationId();
    const enhancedContext = {
      ...context,
      correlationId
    };
    
    this.log(level, message, data, enhancedContext);
    return correlationId;
  }

  // Performance logging utility
  public logDuration(
    level: LogLevel,
    operation: string,
    startTime: number,
    context?: LogContext
  ): void {
    const duration = (Date.now() - startTime) / 1000;
    this.log(level, `Operation completed: ${operation}`, { duration }, {
      ...context,
      duration,
      operation
    });
  }

  public setLogLevel(level: LogLevel): void {
    this.logLevel = level;
  }

  public getLogLevel(): LogLevel {
    return this.logLevel;
  }
}

export const logger = Logger.getInstance();
export default logger;