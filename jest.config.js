export default {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
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
    // Mock axios
    '^axios$': '<rootDir>/tests/__mocks__/axios.ts',
    // Mock make-api-client
    '.*\\/make-api-client\\.js$': '<rootDir>/tests/__mocks__/make-api-client.js',
  },
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
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    './src/lib/': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/utils/': {
      branches: 85,
      functions: 85,
      lines: 85,
      statements: 85,
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
  maxWorkers: '50%',
  verbose: false,
  collectCoverage: false, // Temporarily disabled due to test infrastructure issues
  forceExit: true,
  clearMocks: true,
  restoreMocks: true,
};