/**
 * Structured logging utility for Make.com FastMCP Server
 * Provides consistent logging across the application with correlation ID tracking
 */

import * as fs from 'fs';
import * as path from 'path';
import configManager from './config.js';
import { getLogsDirectory } from '../utils/path-resolver.js';

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
  duration?: number;
  metadata?: Record<string, unknown>;
  // Additional context fields for specialized logging
  circuitName?: string;
  bulkheadName?: string;
  [key: string]: unknown; // Index signature for extensibility
}

export class Logger {
  private static instance: Logger;
  private logLevel: LogLevel;
  private readonly logLevels: Record<LogLevel, number> = {
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

  private safeStringify(obj: unknown): string {
    try {
      return JSON.stringify(obj, (key, value) => {
        // Handle circular references by replacing them with a placeholder
        if (typeof value === 'object' && value !== null) {
          // Use a WeakSet to detect circular references
          if (this.circularRefs?.has(value)) {
            return '[Circular Reference]';
          }
          if (!this.circularRefs) {
            this.circularRefs = new WeakSet();
          }
          this.circularRefs.add(value);
        }
        return value;
      });
    } catch {
      return '[Object with circular references or unstringifiable content]';
    } finally {
      // Clear the circular reference tracker after each stringify operation
      this.circularRefs = undefined;
    }
  }

  private circularRefs?: WeakSet<object>;

  private formatLogEntry(entry: LogEntry): string {
    const { 
      timestamp, level, message, component, operation, sessionId, userId, 
      correlationId, traceId, spanId, requestId, duration, data, metadata 
    } = entry;
    
    let logLine = `[${timestamp}] ${level.toUpperCase()}`;
    
    if (correlationId) {logLine += ` [corr:${correlationId}]`;}
    if (traceId) {logLine += ` [trace:${traceId}]`;}
    if (spanId) {logLine += ` [span:${spanId}]`;}
    if (requestId) {logLine += ` [req:${requestId}]`;}
    if (component) {logLine += ` [${component}]`;}
    if (operation) {logLine += ` [${operation}]`;}
    if (sessionId) {logLine += ` [session:${sessionId}]`;}
    if (userId) {logLine += ` [user:${userId}]`;}
    if (duration !== undefined) {logLine += ` [${duration.toFixed(3)}s]`;}
    
    logLine += `: ${message}`;
    
    if (data && Object.keys(data).length > 0) {
      logLine += ` | Data: ${this.safeStringify(data)}`;
    }

    if (metadata && Object.keys(metadata).length > 0) {
      logLine += ` | Meta: ${this.safeStringify(metadata)}`;
    }
    
    return logLine;
  }

  private log(level: LogLevel, message: string, data?: Record<string, unknown>, context?: LogContext): void {
    if (!this.shouldLog(level)) {return;}

    const mergedContext = { ...this.defaultContext, ...context };

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data,
      ...mergedContext,
    };

    const formattedLog = this.formatLogEntry(entry);

    // For MCP servers, we must avoid writing to stdout as it corrupts the JSON-RPC protocol
    // All output should go to stderr or a log file
    
    try {
      // Write to log file instead of console
      // Use test-friendly path resolver
      const logDir = getLogsDirectory();
      
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
      
      const logFile = path.join(logDir, 'server.log');
      fs.appendFileSync(logFile, formattedLog + '\n');
      
      // Only write critical errors to stderr (not all errors) to minimize stdio pollution
      if (level === 'error') {
        process.stderr.write(formattedLog + '\n');
      }
    } catch (writeError) {
      // Fallback: only write to stderr if file writing fails
      // Suppress logger errors to avoid infinite loops and stdio pollution
      process.stderr.write(`[${new Date().toISOString()}] LOGGER_ERROR: ${writeError}\n`);
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

  public child(context: LogContext): Logger {
    // Create a new logger instance that inherits the context
    const childLogger = Object.create(this);
    childLogger.defaultContext = { ...this.defaultContext, ...context };
    return childLogger;
  }

  // Helper property to store default context
  private readonly defaultContext: LogContext = {};

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