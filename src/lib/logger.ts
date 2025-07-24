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
  data?: any;
  component?: string;
  operation?: string;
  sessionId?: string;
  userId?: string;
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

  private log(level: LogLevel, message: string, data?: any, context?: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
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

  public debug(message: string, data?: any, context?: any): void {
    this.log('debug', message, data, context);
  }

  public info(message: string, data?: any, context?: any): void {
    this.log('info', message, data, context);
  }

  public warn(message: string, data?: any, context?: any): void {
    this.log('warn', message, data, context);
  }

  public error(message: string, data?: any, context?: any): void {
    this.log('error', message, data, context);
  }

  public child(context: {
    component?: string;
    operation?: string;
    sessionId?: string;
    userId?: string;
  }): {
    debug: (message: string, data?: any) => void;
    info: (message: string, data?: any) => void;
    warn: (message: string, data?: any) => void;
    error: (message: string, data?: any) => void;
  } {
    return {
      debug: (message: string, data?: any) => this.debug(message, data, context),
      info: (message: string, data?: any) => this.info(message, data, context),
      warn: (message: string, data?: any) => this.warn(message, data, context),
      error: (message: string, data?: any) => this.error(message, data, context),
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