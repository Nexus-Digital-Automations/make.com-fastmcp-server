# Test Suite Documentation

This directory contains a comprehensive test suite for the Make.com FastMCP Server, designed to ensure reliability, performance, and maintainability through advanced testing strategies.

## 🧪 Test Structure

```
tests/
├── setup.ts                   # Global test setup and configuration
├── unit/                      # Unit tests for individual components
│   └── tools/                 # Tool-specific unit tests
│       ├── scenarios.test.ts  # Scenario management tools
│       ├── billing.test.ts    # Billing and payment tools
│       └── ...               # Other tool modules
├── integration/               # Integration tests for API client and services
│   └── api-client.test.ts    # Make.com API client integration
├── e2e/                      # End-to-end workflow tests
│   └── complete-workflows.test.ts  # Full user scenarios
├── mocks/                    # Mock implementations
│   └── make-api-client.mock.ts    # API client mock
├── fixtures/                 # Test data and sample objects
│   └── test-data.ts         # Comprehensive test fixtures
├── utils/                    # Test utilities and helpers
│   └── test-helpers.ts      # Reusable test functions
└── README.md                # This documentation
```

## 🚀 Running Tests

### Quick Start

```bash
# Run all tests with coverage
npm test

# Run specific test suites
npm run test:unit        # Unit tests only
npm run test:integration # Integration tests only
npm run test:e2e        # End-to-end tests only

# Development workflow
npm run test:watch      # Watch mode for active development
npm run test:validate   # Full validation (lint + typecheck + build + tests)
```

### Custom Test Execution

```bash
# Using the test runner script directly
node scripts/run-tests.js unit --watch --verbose
node scripts/run-tests.js integration --no-coverage
node scripts/run-tests.js e2e --max-workers=2
node scripts/run-tests.js validate  # Full project validation
```

## 📋 Test Categories

### Unit Tests (`tests/unit/`)

**Purpose**: Test individual functions, classes, and modules in isolation.

**Coverage Target**: 95%+ for tool modules, 90%+ for library modules

**Key Features**:
- Zod schema validation testing
- Input parameter validation
- Error handling scenarios
- Progress reporting verification
- Logging and audit trail testing
- Mock API client integration

**Example Test Structure**:
```typescript
describe('Scenario Management Tools', () => {
  describe('create-scenario tool', () => {
    it('should create scenario successfully with valid data', async () => {
      // Arrange
      mockApiClient.mockResponse('POST', '/scenarios', successResponse);
      
      // Act
      const result = await executeTool(tool, validInput);
      
      // Assert
      expect(result).toContain('success');
      expectProgressReported(mockProgress, expectedCalls);
    });
  });
});
```

### Integration Tests (`tests/integration/`)

**Purpose**: Test interactions between components and external services.

**Coverage Target**: 85%+ for API client and service integrations

**Key Features**:
- Rate limiting behavior verification
- Retry logic and circuit breaker testing
- Network condition simulation
- Connection pool management
- Performance characteristics validation
- Error handling across service boundaries

**Example Test Scenarios**:
- API client rate limiting and backoff
- Network timeout and recovery
- Concurrent request handling
- Circuit breaker pattern implementation
- Health check integration

### End-to-End Tests (`tests/e2e/`)

**Purpose**: Test complete user workflows from start to finish.

**Coverage Target**: Focus on critical user paths and business scenarios

**Key Features**:
- Complete workflow validation
- Cross-module integration testing
- Performance under load
- Failure recovery scenarios
- Data flow between modules

**Example Workflows**:
- Scenario lifecycle: create → configure → test → deploy → monitor
- User onboarding: invite → assign roles → configure permissions → verify access
- Template to production: browse → customize → create scenario → deploy
- Billing workflow: check account → review usage → analyze costs → update payment

## 🛠️ Test Infrastructure

### Mock API Client (`tests/mocks/make-api-client.mock.ts`)

Provides realistic Make.com API simulation with:
- Configurable responses and failures
- Network delay simulation
- Request/response logging
- Rate limiting simulation
- Circuit breaker testing

```typescript
// Basic usage
const mockClient = new MockMakeApiClient();
mockClient.mockResponse('GET', '/scenarios', successResponse);
mockClient.mockFailure('POST', '/scenarios', new Error('API Error'));
mockClient.mockDelay('GET', '/slow-endpoint', 5000);

// Verify API calls
const callLog = mockClient.getCallLog();
expect(callLog[0]).toMatchObject({
  method: 'GET',
  endpoint: '/scenarios'
});
```

### Test Fixtures (`tests/fixtures/test-data.ts`)

Comprehensive test data including:
- Sample users with different roles
- Complex scenario blueprints
- Connection configurations
- Billing and invoice data
- Analytics and metrics
- Error response patterns

```typescript
// Using fixtures
import { testScenarios, testUsers, generateTestData } from '../fixtures/test-data.js';

const scenario = testScenarios.active;
const user = generateTestData.user({ role: 'admin' });
```

### Test Helpers (`tests/utils/test-helpers.ts`)

Utility functions for:
- Mock server creation
- Tool execution with context
- Progress reporting verification
- Zod schema validation testing
- Performance measurement
- Network condition simulation

```typescript
// Common patterns
const { server, mockTool } = createMockServer();
const tool = findTool(mockTool, 'create-scenario');
const result = await executeTool(tool, input, { log: mockLog });
expectToolCall(mockLog, 'info', 'Successfully created');
```

## 📊 Coverage Requirements

### Global Thresholds
- **Branches**: 80%
- **Functions**: 85% 
- **Lines**: 85%
- **Statements**: 85%

### Tool Modules (`src/tools/`)
- **Branches**: 90%
- **Functions**: 95%
- **Lines**: 95%
- **Statements**: 95%

### Library Modules (`src/lib/`)
- **Branches**: 85%
- **Functions**: 90%
- **Lines**: 90%
- **Statements**: 90%

## 🔧 Advanced Testing Patterns

### Chaos Engineering

Fault injection testing to verify system resilience:

```typescript
const chaosMonkey = new ChaosMonkey({
  failureRate: 0.3,
  scenarios: ['latency', 'error', 'timeout']
});

const chaosService = await chaosMonkey.wrapService(apiClient);
// System should handle 30% failure rate gracefully
```

### Security Testing

Automated security validation:

```typescript
const sqlInjectionPayloads = ["' OR '1'='1", "'; DROP TABLE users; --"];
sqlInjectionPayloads.forEach(payload => {
  it(`should safely handle SQL injection: ${payload}`, async () => {
    const response = await executeTool(tool, { name: payload });
    expect(response).not.toContain('SQL');
  });
});
```

### Performance Testing

Load testing and performance validation:

```typescript
const stressTest = new StressTest({
  concurrent: 100,
  duration: 30000,
  rampUp: 5000
});

const results = await stressTest.run(async () => {
  await executeTool(tool, validInput);
});

expect(results.successRate).toBeGreaterThan(0.99);
expect(results.p95Latency).toBeLessThan(1000);
```

## 🎯 Best Practices

### Writing Effective Tests

1. **Arrange-Act-Assert Pattern**: Structure tests clearly
2. **Single Responsibility**: One test, one behavior
3. **Descriptive Names**: Tests should read like specifications
4. **Data Isolation**: Use fresh data for each test
5. **Mock External Dependencies**: Control the test environment

### Test Data Management

1. **Use Fixtures**: Consistent, realistic test data
2. **Generate Dynamic Data**: Avoid test interdependencies
3. **Clean State**: Reset mocks and data between tests
4. **Parameterized Tests**: Test multiple scenarios efficiently

### Error Testing

1. **Test Error Paths**: Verify error handling
2. **Boundary Conditions**: Test edge cases
3. **Input Validation**: Verify parameter checking
4. **Recovery Scenarios**: Test system resilience

## 🚨 Troubleshooting

### Common Issues

**Tests Timing Out**:
```bash
# Increase timeout in jest.config.js or specific tests
jest.setTimeout(60000);
```

**Module Import Errors**:
```bash
# Verify ESM configuration in jest.config.js
extensionsToTreatAsEsm: ['.ts']
```

**Coverage Too Low**:
```bash
# Run coverage report to identify gaps
npm run test:coverage
# Check coverage/lcov-report/index.html
```

**Flaky Tests**:
```bash
# Run flaky test detection
npm run test:unit -- --verbose --bail
```

### Debug Mode

```bash
# Run tests with debugging
node --inspect-brk=0.0.0.0:9229 node_modules/.bin/jest
```

## 📈 Continuous Integration

### Pre-commit Hooks

```bash
# Install husky and lint-staged for pre-commit validation
npm install --save-dev husky lint-staged
```

### Pipeline Integration

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: npm run test:validate
- name: Upload coverage
  uses: codecov/codecov-action@v1
```

## 🔄 Test Maintenance

### Regular Tasks

1. **Update Test Data**: Keep fixtures current with API changes
2. **Review Coverage**: Ensure new code has adequate tests
3. **Performance Monitoring**: Track test execution time
4. **Flaky Test Detection**: Identify and fix unreliable tests
5. **Mock Updates**: Keep mocks synchronized with real APIs

### Metrics to Monitor

- Test execution time trends
- Coverage percentage over time
- Flaky test frequency
- Test failure patterns
- Mock vs real API divergence

## 📚 Additional Resources

- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [Testing Best Practices](https://github.com/goldbergyoni/javascript-testing-best-practices)
- [FastMCP Testing Guide](https://docs.anthropic.com/en/docs/claude-code/testing)
- [TypeScript Testing Handbook](https://github.com/microsoft/TypeScript/wiki/Coding-guidelines#tests)

---

**Note**: This testing framework follows advanced testing methodologies including chaos engineering, security testing, and performance validation to ensure enterprise-grade reliability of the Make.com FastMCP Server.