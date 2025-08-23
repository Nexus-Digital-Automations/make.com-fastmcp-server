export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: "./jest.tsconfig.json",
      },
    ],
  },
  transformIgnorePatterns: [
    "node_modules/(?!(fastmcp|@modelcontextprotocol|zod)/)",
  ],
  moduleNameMapper: {
    // Handle .js extensions in imports (resolve to TypeScript files)
    "^(\\.{1,2}/.*)\\.js$": "$1",
    // Mock fastmcp
    "^fastmcp$": "<rootDir>/tests/__mocks__/fastmcp.ts",
    // Mock metrics - more specific patterns
    "^.*src/lib/metrics(\\.js)?$": "<rootDir>/tests/__mocks__/metrics.ts",
    ".*\\/metrics\\.js$": "<rootDir>/tests/__mocks__/metrics.ts",
    // Mock logger
    "^.*src/lib/logger(\\.js)?$": "<rootDir>/tests/__mocks__/logger.ts",
    ".*\\/logger\\.js$": "<rootDir>/tests/__mocks__/logger.ts",
    // Mock config manager
    ".*\\/config\\.js$": "<rootDir>/tests/__mocks__/config.ts",
    // Mock audit logger
    ".*\\/audit-logger\\.js$": "<rootDir>/tests/__mocks__/audit-logger.ts",
    // Mock axios
    "^axios$": "<rootDir>/tests/__mocks__/axios.ts",
    // Mock make-api-client - disabled for unit testing
    // '.*\\/make-api-client\\.js$': '<rootDir>/tests/__mocks__/make-api-client.js',
  },
  // Prevent auto-mocking of built-in Node.js modules and our core modules
  unmockedModulePathPatterns: [
    "<rootDir>/src/lib/diagnostic-rules.ts",
    "<rootDir>/src/types/",
    "node_modules",
    "util",
    "fs",
    "path",
    "os",
  ],
  setupFilesAfterEnv: ["<rootDir>/tests/setup.ts"],
  collectCoverageFrom: [
    "src/**/*.{ts,js}",
    "!src/**/*.d.ts",
    "!src/**/*.test.{ts,js}",
    "!src/**/__tests__/**",
    "!src/index.ts", // Entry point, covered by integration tests
  ],
  coverageDirectory: "coverage",
  coverageReporters: ["text", "lcov", "html", "json-summary"],
  coverageProvider: "v8",
  coverageThreshold: {
    global: {
      branches: 35, // Improved threshold for better quality
      functions: 35,
      lines: 35,
      statements: 35,
    },
    "./src/lib/config.ts": {
      // Only enforce high coverage on tested files
      branches: 80,
      functions: 90,
      lines: 80,
      statements: 80,
    },
  },
  testMatch: [
    "<rootDir>/tests/**/*.test.{ts,js}",
    "<rootDir>/src/**/__tests__/**/*.{ts,js}",
  ],
  testPathIgnorePatterns: [
    "<rootDir>/node_modules/",
    "<rootDir>/dist/",
    "<rootDir>/coverage/",
  ],
  testTimeout: 10000, // Reduced timeout for faster feedback
  maxWorkers: 1, // Use single worker to prevent resource conflicts
  verbose: false,
  collectCoverage: true, // Enable coverage collection for quality tracking
  forceExit: true,
  // Performance optimizations
  testEnvironmentOptions: {
    // Optimize jsdom performance
    pretendToBeVisual: false,
    url: "http://localhost",
  },
  // Cache test results for faster reruns
  cache: true,
  cacheDirectory: "<rootDir>/.jest-cache",
  // Improve test isolation and performance
  resetModules: false, // Don't reset modules between tests for better performance
  clearMocks: true,
  restoreMocks: true,
  // Add error handling for worker exceptions
  errorOnDeprecated: false,
  detectOpenHandles: false, // Disable to prevent timeout issues in tests
  detectLeaks: false,
  // Disable auto-mocking to prevent class constructor issues
  automock: false,
  // Don't reset mocks between tests to avoid constructor issues
  resetMocks: false,
  // Additional performance optimizations for server tests
  workerIdleMemoryLimit: "512MB", // Limit worker memory usage
  passWithNoTests: true, // Don't fail if no tests are found
};
