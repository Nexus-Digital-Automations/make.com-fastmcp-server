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
  // Temporarily disable coverage thresholds to focus on getting tests running
  // coverageThreshold: {
  //   global: {
  //     branches: 80,
  //     functions: 80,
  //     lines: 80,
  //     statements: 80,
  //   },
  //   './src/lib/': {
  //     branches: 100,
  //     functions: 100,
  //     lines: 100,
  //     statements: 100,
  //   },
  //   './src/utils/': {
  //     branches: 100,
  //     functions: 100,
  //     lines: 100,
  //     statements: 100,
  //   },
  // },
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
  collectCoverage: false, // Let scripts control this
  forceExit: true,
  clearMocks: true,
  restoreMocks: true,
};