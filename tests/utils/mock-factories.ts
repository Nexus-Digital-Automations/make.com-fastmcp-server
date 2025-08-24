/**
 * Mock data factories for comprehensive testing
 * Based on research report recommendations
 */

export interface MockScenario {
  id: string;
  name: string;
  status: 'active' | 'inactive';
  created_at: string;
  blueprint?: unknown;
}

export interface MockConnection {
  id: string;
  app: string;
  name: string;
  status: 'verified' | 'error';
}

export interface MockUser {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user';
}

export class MockDataFactory {
  static createScenario(overrides: Partial<MockScenario> = {}): MockScenario {
    return {
      id: Math.random().toString(36).substr(2, 9),
      name: `Test Scenario ${Math.floor(Math.random() * 1000)}`,
      status: 'active',
      created_at: new Date().toISOString(),
      ...overrides
    };
  }

  static createConnection(overrides: Partial<MockConnection> = {}): MockConnection {
    return {
      id: Math.random().toString(36).substr(2, 9),
      app: 'test-app',
      name: `Test Connection ${Math.floor(Math.random() * 1000)}`,
      status: 'verified',
      ...overrides
    };
  }

  static createUser(overrides: Partial<MockUser> = {}): MockUser {
    return {
      id: Math.random().toString(36).substr(2, 9),
      name: `Test User ${Math.floor(Math.random() * 1000)}`,
      email: `test${Math.floor(Math.random() * 1000)}@example.com`,
      role: 'user',
      ...overrides
    };
  }

  static createApiErrorResponse(statusCode: number, message: string) {
    return {
      status: statusCode,
      data: {
        error: this.getErrorCodeForStatus(statusCode),
        message,
        timestamp: new Date().toISOString()
      }
    };
  }

  private static getErrorCodeForStatus(statusCode: number): string {
    const errorCodes: { [key: number]: string } = {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED', 
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      429: 'RATE_LIMIT_EXCEEDED',
      500: 'INTERNAL_SERVER_ERROR',
      502: 'BAD_GATEWAY',
      503: 'SERVICE_UNAVAILABLE',
      504: 'GATEWAY_TIMEOUT'
    };
    return errorCodes[statusCode] || 'UNKNOWN_ERROR';
  }
}

export class ErrorScenarioFactory {
  static createRateLimitError() {
    return {
      status: 429,
      headers: {
        'retry-after': '60'
      },
      data: {
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Rate limit exceeded. Try again in 60 seconds.'
      }
    };
  }

  static createAuthenticationError() {
    return {
      status: 401,
      data: {
        error: 'UNAUTHORIZED',
        message: 'Invalid API key or insufficient permissions.'
      }
    };
  }

  static createTimeoutError() {
    return {
      code: 'ECONNABORTED',
      message: 'Request timeout',
      config: { timeout: 30000 }
    };
  }

  static createNetworkError() {
    return {
      code: 'ENOTFOUND',
      message: 'Network error: Unable to connect to Make.com API',
      hostname: 'us1.make.com'
    };
  }

  static createServerError() {
    return {
      status: 500,
      data: {
        error: 'INTERNAL_SERVER_ERROR',
        message: 'An internal server error occurred. Please try again later.'
      }
    };
  }
}