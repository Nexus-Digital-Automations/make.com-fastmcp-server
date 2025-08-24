/**
 * LLM Sampling Integration for FastMCP Server
 * Enables server to request completions from connected client's LLM
 */

import { z } from 'zod';
import * as crypto from 'crypto';
import logger from './logger.js';
// import { extractCorrelationId } from '../utils/error-response.js'; // Not used in current implementation

// Logger interface for type safety
interface ComponentLogger {
  info(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  debug(message: string, data?: Record<string, unknown>): void;
}

// LLM Sampling Message Schema
const SamplingMessageSchema = z.object({
  role: z.enum(['user', 'assistant', 'system']),
  content: z.union([
    z.string(),
    z.object({
      type: z.enum(['text', 'image', 'audio']),
      text: z.string().optional(),
      data: z.string().optional(),
      mimeType: z.string().optional(),
    }),
  ]),
});

// LLM Sampling Request Schema
const SamplingRequestSchema = z.object({
  messages: z.array(SamplingMessageSchema),
  systemPrompt: z.string().optional(),
  includeContext: z.enum(['none', 'thisServer', 'allServers']).default('thisServer'),
  maxTokens: z.number().min(1).max(8192).default(1000),
  temperature: z.number().min(0).max(2).default(0.7),
  topP: z.number().min(0).max(1).default(0.9),
  stopSequences: z.array(z.string()).max(4).default([]),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

type SamplingMessage = z.infer<typeof SamplingMessageSchema>;
type SamplingRequest = z.infer<typeof SamplingRequestSchema>;

// LLM Sampling Response Schema
const SamplingResponseSchema = z.object({
  model: z.string(),
  content: z.array(z.object({
    type: z.enum(['text']),
    text: z.string(),
  })),
  stopReason: z.enum(['end_turn', 'max_tokens', 'stop_sequence']).optional(),
  usage: z.object({
    inputTokens: z.number(),
    outputTokens: z.number(),
    totalTokens: z.number(),
  }).optional(),
});

type SamplingResponse = z.infer<typeof SamplingResponseSchema>;

interface LLMSamplingOptions {
  retryAttempts?: number;
  retryDelay?: number;
  timeout?: number;
  fallbackResponse?: string;
  enableCaching?: boolean;
  cacheKeyPrefix?: string;
}

export class LLMSamplingManager {
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly options: Required<LLMSamplingOptions>;
  private readonly responseCache = new Map<string, { response: SamplingResponse; expires: Date }>();

  constructor(options: LLMSamplingOptions = {}) {
    this.componentLogger = logger.child({ component: 'LLMSamplingManager' });
    
    this.options = {
      retryAttempts: options.retryAttempts ?? 3,
      retryDelay: options.retryDelay ?? 1000,
      timeout: options.timeout ?? 30000,
      fallbackResponse: options.fallbackResponse ?? 'Unable to generate response at this time.',
      enableCaching: options.enableCaching ?? true,
      cacheKeyPrefix: options.cacheKeyPrefix ?? 'llm_sampling',
    };

    this.componentLogger.info('LLM Sampling Manager initialized', {
      retryAttempts: this.options.retryAttempts,
      timeout: this.options.timeout,
      cachingEnabled: this.options.enableCaching,
    });

    // Start cache cleanup
    this.startCacheCleanup();
  }

  /**
   * Request LLM completion from connected client
   */
  async requestCompletion(
    session: { requestSampling: (request: SamplingRequest) => Promise<unknown> },
    request: Partial<SamplingRequest>,
    correlationId?: string
  ): Promise<SamplingResponse> {
    const requestId = correlationId || crypto.randomUUID();
    const componentLogger = this.componentLogger.child({
      operation: 'requestCompletion',
      correlationId: requestId,
    });

    try {
      const samplingRequest = SamplingRequestSchema.parse(request);
      this.logRequestStart(componentLogger, samplingRequest);

      // Check cache first
      const cached = this.checkCache(samplingRequest, componentLogger);
      if (cached) {
        return cached;
      }

      this.validateSession(session);
      
      const response = await this.executeWithRetry(
        () => session.requestSampling(samplingRequest),
        requestId
      );

      const validatedResponse = SamplingResponseSchema.parse(response);
      this.handleSuccessfulResponse(samplingRequest, validatedResponse, componentLogger);

      return validatedResponse;
    } catch (error) {
      return this.handleError(error, componentLogger);
    }
  }

  private logRequestStart(componentLogger: ComponentLogger, samplingRequest: SamplingRequest): void {
    componentLogger.info('Initiating LLM sampling request', {
      messageCount: samplingRequest.messages.length,
      maxTokens: samplingRequest.maxTokens,
      includeContext: samplingRequest.includeContext,
      temperature: samplingRequest.temperature,
    });
  }

  private checkCache(samplingRequest: SamplingRequest, componentLogger: ComponentLogger): SamplingResponse | null {
    if (!this.options.enableCaching) {
      return null;
    }

    const cacheKey = this.generateCacheKey(samplingRequest);
    const cached = this.getCachedResponse(cacheKey);
    
    if (cached) {
      componentLogger.debug('Returning cached LLM response');
      return cached;
    }
    
    return null;
  }

  private validateSession(session: { requestSampling: (request: SamplingRequest) => Promise<unknown> }): void {
    if (!session?.requestSampling) {
      throw new Error('Client session does not support LLM sampling');
    }
  }

  private handleSuccessfulResponse(
    samplingRequest: SamplingRequest, 
    validatedResponse: SamplingResponse, 
    componentLogger: ComponentLogger
  ): void {
    // Cache successful response
    if (this.options.enableCaching) {
      const cacheKey = this.generateCacheKey(samplingRequest);
      this.cacheResponse(cacheKey, validatedResponse);
    }

    componentLogger.info('LLM sampling completed successfully', {
      model: validatedResponse.model,
      contentLength: validatedResponse.content[0]?.text?.length || 0,
      stopReason: validatedResponse.stopReason,
      inputTokens: validatedResponse.usage?.inputTokens,
      outputTokens: validatedResponse.usage?.outputTokens,
    });
  }

  private handleError(error: unknown, componentLogger: ComponentLogger): SamplingResponse {
    componentLogger.error('LLM sampling failed', { error });
    
    return {
      model: 'fallback',
      content: [{ type: 'text', text: this.options.fallbackResponse }],
      stopReason: 'end_turn',
    };
  }

  /**
   * Request completion for text analysis
   */
  async analyzeText(
    session: { requestSampling: (request: SamplingRequest) => Promise<unknown> },
    text: string,
    analysisType: 'sentiment' | 'summary' | 'keywords' | 'classification',
    options: { language?: string; maxTokens?: number } = {},
    correlationId?: string
  ): Promise<string> {
    const systemPrompts = {
      sentiment: 'Analyze the sentiment of the provided text. Respond with only: positive, negative, or neutral.',
      summary: 'Provide a concise summary of the provided text in 2-3 sentences.',
      keywords: 'Extract the key topics and keywords from the provided text. Return as a comma-separated list.',
      classification: 'Classify the content type of the provided text. Examples: technical, business, personal, news, etc.',
    };

    const samplingRequest: SamplingRequest = {
      messages: [
        {
          role: 'user',
          content: text,
        },
      ],
      systemPrompt: systemPrompts[analysisType],
      maxTokens: options.maxTokens || 200,
      temperature: 0.3, // Lower temperature for more consistent analysis
      includeContext: 'none', // Don't include server context for analysis
      topP: 0.9,
      stopSequences: [],
      metadata: {},
    };

    const response = await this.requestCompletion(session, samplingRequest, correlationId);
    return response.content[0]?.text || this.options.fallbackResponse;
  }

  /**
   * Request completion for code generation
   */
  async generateCode(
    session: { requestSampling: (request: SamplingRequest) => Promise<unknown> },
    prompt: string,
    language: string,
    options: { style?: string; maxTokens?: number; includeComments?: boolean } = {},
    correlationId?: string
  ): Promise<string> {
    const systemPrompt = `Generate ${language} code based on the user's request. ${
      options.includeComments ? 'Include helpful comments.' : 'Provide clean code without comments.'
    } ${options.style ? `Follow ${options.style} coding style.` : ''}`;

    const samplingRequest: SamplingRequest = {
      messages: [
        {
          role: 'user',
          content: `Generate ${language} code for: ${prompt}`,
        },
      ],
      systemPrompt,
      maxTokens: options.maxTokens || 2000,
      temperature: 0.2, // Lower temperature for more predictable code
      includeContext: 'thisServer',
      topP: 0.9,
      stopSequences: [],
      metadata: {},
    };

    const response = await this.requestCompletion(session, samplingRequest, correlationId);
    return response.content[0]?.text || '// Code generation failed';
  }

  /**
   * Request completion for Make.com scenario optimization suggestions
   */
  async suggestScenarioOptimizations(
    session: { requestSampling: (request: SamplingRequest) => Promise<unknown> },
    scenarioDescription: string,
    currentModules: string[],
    correlationId?: string
  ): Promise<string> {
    const systemPrompt = `You are a Make.com automation expert. Analyze the provided scenario description and current modules to suggest optimizations for better performance, reliability, and maintainability. Focus on practical improvements.`;

    const modulesList = currentModules.length > 0 
      ? `\n\nCurrent modules: ${currentModules.join(', ')}`
      : '';

    const samplingRequest: SamplingRequest = {
      messages: [
        {
          role: 'user',
          content: `Scenario Description: ${scenarioDescription}${modulesList}\n\nPlease provide optimization suggestions for this Make.com scenario.`,
        },
      ],
      systemPrompt,
      maxTokens: 1500,
      temperature: 0.4,
      includeContext: 'thisServer',
      topP: 0.9,
      stopSequences: [],
      metadata: {},
    };

    const response = await this.requestCompletion(session, samplingRequest, correlationId);
    return response.content[0]?.text || 'Unable to generate optimization suggestions at this time.';
  }

  /**
   * Request completion for error analysis and debugging suggestions
   */
  async analyzeError(
    session: { requestSampling: (request: SamplingRequest) => Promise<unknown> },
    errorMessage: string,
    context: Record<string, unknown>,
    correlationId?: string
  ): Promise<string> {
    const systemPrompt = `You are a debugging expert for Make.com scenarios. Analyze the provided error message and context to provide clear, actionable debugging steps and potential solutions.`;

    const contextInfo = Object.keys(context).length > 0
      ? `\n\nContext: ${JSON.stringify(context, null, 2)}`
      : '';

    const samplingRequest: SamplingRequest = {
      messages: [
        {
          role: 'user',
          content: `Error: ${errorMessage}${contextInfo}\n\nPlease analyze this error and provide debugging guidance.`,
        },
      ],
      systemPrompt,
      maxTokens: 1000,
      temperature: 0.3,
      includeContext: 'thisServer',
      topP: 0.9,
      stopSequences: [],
      metadata: {},
    };

    const response = await this.requestCompletion(session, samplingRequest, correlationId);
    return response.content[0]?.text || 'Unable to analyze error at this time.';
  }

  /**
   * Execute request with retry logic
   */
  private async executeWithRetry<T>(
    operation: () => Promise<T>,
    correlationId: string
  ): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= this.options.retryAttempts; attempt++) {
      try {
        // Add timeout wrapper
        const timeoutPromise = new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error('LLM sampling timeout')), this.options.timeout);
        });

        const result = await Promise.race([operation(), timeoutPromise]);
        return result;
      } catch (error) {
        lastError = error as Error;
        
        this.componentLogger.warn('LLM sampling attempt failed', {
          attempt,
          maxAttempts: this.options.retryAttempts,
          error: lastError.message,
          correlationId,
        });

        if (attempt < this.options.retryAttempts) {
          await this.delay(this.options.retryDelay * attempt);
        }
      }
    }

    throw lastError || new Error('LLM sampling failed after all retry attempts');
  }

  /**
   * Generate cache key for request
   */
  private generateCacheKey(request: SamplingRequest): string {
    const key = {
      messages: request.messages,
      systemPrompt: request.systemPrompt,
      maxTokens: request.maxTokens,
      temperature: request.temperature,
      topP: request.topP,
    };
    
    const hash = crypto.createHash('sha256')
      .update(JSON.stringify(key))
      .digest('hex')
      .substring(0, 16);
    
    return `${this.options.cacheKeyPrefix}_${hash}`;
  }

  /**
   * Get cached response if available and not expired
   */
  private getCachedResponse(cacheKey: string): SamplingResponse | null {
    const cached = this.responseCache.get(cacheKey);
    if (cached && cached.expires > new Date()) {
      return cached.response;
    }
    
    if (cached) {
      this.responseCache.delete(cacheKey);
    }
    
    return null;
  }

  /**
   * Cache response with expiration
   */
  private cacheResponse(cacheKey: string, response: SamplingResponse): void {
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    this.responseCache.set(cacheKey, { response, expires });
  }

  /**
   * Start periodic cache cleanup
   */
  private startCacheCleanup(): void {
    setInterval(() => {
      const now = new Date();
      let cleaned = 0;

      for (const [key, cached] of this.responseCache.entries()) {
        if (cached.expires <= now) {
          this.responseCache.delete(key);
          cleaned++;
        }
      }

      if (cleaned > 0) {
        this.componentLogger.debug('Cleaned expired cache entries', { count: cleaned });
      }
    }, 5 * 60 * 1000); // Clean every 5 minutes
  }

  /**
   * Delay utility for retries
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get sampling statistics
   */
  getStatistics(): Record<string, unknown> {
    return {
      cacheSize: this.responseCache.size,
      configuration: this.options,
      uptime: process.uptime(),
    };
  }

  /**
   * Clear cache
   */
  clearCache(): void {
    const size = this.responseCache.size;
    this.responseCache.clear();
    this.componentLogger.info('Cache cleared', { entriesRemoved: size });
  }

  /**
   * Shutdown the sampling manager
   */
  async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down LLM Sampling Manager');
    this.clearCache();
    this.componentLogger.info('LLM Sampling Manager shutdown completed');
  }
}

export type { SamplingMessage, SamplingRequest, SamplingResponse };
export default LLMSamplingManager;