/**
 * Structured logging utility for Make.com FastMCP Server
 * Provides consistent logging across the application
 */

import configManager from './config.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
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
    const { timestamp, level, message, component, operation, sessionId, userId, data } = entry;
    
    let logLine = `[${timestamp}] ${level.toUpperCase()}`;
    
    if (component) logLine += ` [${component}]`;
    if (operation) logLine += ` [${operation}]`;
    if (sessionId) logLine += ` [session:${sessionId}]`;
    if (userId) logLine += ` [user:${userId}]`;
    
    logLine += `: ${message}`;
    
    if (data && Object.keys(data).length > 0) {
      logLine += ` | Data: ${JSON.stringify(data)}`;
    }
    
    return logLine;
  }

  private log(level: LogLevel, message: string, data?: Record<string, unknown>, context?: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
    correlationId?: string;
    traceId?: string;
  }): void {
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

  public debug(message: string, data?: Record<string, unknown>, context?: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
    correlationId?: string;
    traceId?: string;
  }): void {
    this.log('debug', message, data, context);
  }

  public info(message: string, data?: Record<string, unknown>, context?: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
    correlationId?: string;
    traceId?: string;
  }): void {
    this.log('info', message, data, context);
  }

  public warn(message: string, data?: Record<string, unknown>, context?: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
    correlationId?: string;
    traceId?: string;
  }): void {
    this.log('warn', message, data, context);
  }

  public error(message: string, data?: Record<string, unknown>, context?: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
    correlationId?: string;
    traceId?: string;
  }): void {
    this.log('error', message, data, context);
  }

  public child(context: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
    correlationId?: string;
    traceId?: string;
  }): {
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

  public setLogLevel(level: LogLevel): void {
    this.logLevel = level;
  }

  public getLogLevel(): LogLevel {
    return this.logLevel;
  }
}

export const logger = Logger.getInstance();
export default logger;