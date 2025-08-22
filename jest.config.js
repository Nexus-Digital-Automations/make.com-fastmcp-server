export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  globals: {
    'ts-jest': {
      useESM: true,
      tsconfig: './jest.tsconfig.json'
    }
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: './jest.tsconfig.json'
    }],
  },
  transformIgnorePatterns: [
    'node_modules/(?!(fastmcp|@modelcontextprotocol|zod)/)',
  ],
  moduleNameMapper: {
    // Handle .js extensions in imports (resolve to TypeScript files)
    '^(\\.{1,2}/.*)\\.js$': '$1',
    // Mock fastmcp
    '^fastmcp$': '<rootDir>/tests/__mocks__/fastmcp.ts',
    // Mock logger
    '.*\\/logger\\.js$': '<rootDir>/tests/__mocks__/logger.ts',
    // Mock config manager
    '.*\\/config\\.js$': '<rootDir>/tests/__mocks__/config.ts',
    // Mock audit logger
    '.*\\/audit-logger\\.js$': '<rootDir>/tests/__mocks__/audit-logger.ts',
    // Mock axios
    '^axios$': '<rootDir>/tests/__mocks__/axios.ts',
    // Mock make-api-client
    '.*\\/make-api-client\\.js$': '<rootDir>/tests/__mocks__/make-api-client.js',
  },
  // Prevent auto-mocking of built-in Node.js modules and our core modules
  unmockedModulePathPatterns: [
    '<rootDir>/src/lib/diagnostic-rules.ts',
    '<rootDir>/src/types/',
    'node_modules',
    'util',
    'fs',
    'path',
    'os'
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  collectCoverageFrom: [
    'src/**/*.{ts,js}',
    '!src/**/*.d.ts',
    '!src/**/*.test.{ts,js}',
    '!src/**/__tests__/**',
    '!src/index.ts', // Entry point, covered by integration tests
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  coverageThreshold: {
    global: {
      branches: 20, // Lower initial threshold to allow gradual improvement
      functions: 20,
      lines: 20,
      statements: 20,
    },
    './src/lib/config.ts': { // Only enforce high coverage on tested files
      branches: 80,
      functions: 90,
      lines: 80,
      statements: 80,
    },
  },
  testMatch: [
    '<rootDir>/tests/**/*.test.{ts,js}',
    '<rootDir>/src/**/__tests__/**/*.{ts,js}',
  ],
  testPathIgnorePatterns: [
    '<rootDir>/node_modules/',
    '<rootDir>/dist/',
    '<rootDir>/coverage/',
  ],
  testTimeout: 30000,
  maxWorkers: 1, // Force single worker to avoid Jest worker issues
  verbose: false,
  collectCoverage: true,
  forceExit: true,
  clearMocks: true,
  restoreMocks: true,
  // Add error handling for worker exceptions
  errorOnDeprecated: false,
  detectOpenHandles: true,
  detectLeaks: false,
  // Disable auto-mocking to prevent class constructor issues
  automock: false,
  // Don't reset mocks between tests to avoid constructor issues
  resetMocks: false,
};