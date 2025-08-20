# Browser Tests with Staged Loading Sequences

This directory contains browser-based end-to-end tests that implement proper loading sequences to prevent race conditions and system overload during testing.

## 🎯 User Requirements Addressed

The browser tests implement the specific requirements:

1. **"Workflows load first before clicking buttons"** - All tests wait for workflow elements to be fully loaded before any interactions
2. **"Performance dashboard loads after workflows"** - Staged approach ensures workflows are ready before dashboard navigation
3. **"Proper loading detection"** - Comprehensive loading state detection prevents premature interactions
4. **"System overload prevention"** - Stress detection and backoff mechanisms protect system stability

## 🏗️ Test Architecture

### Loading Sequence Helpers (`loading-sequence-helpers.ts`)

Provides comprehensive utilities for staged loading:

- **`waitForElementsToLoad()`** - Wait for basic page elements and loading indicators
- **`waitForWorkflowsLoaded()`** - Ensure workflows, scenarios, and connections are ready
- **`waitForDashboardReady()`** - Wait for dashboard, charts, and data visualization
- **`safeClick()`** - Click elements only when fully loaded and enabled
- **`safeNavigate()`** - Navigate between views with proper loading sequences
- **`detectSystemStress()`** - Monitor system health and loading performance
- **`waitWithBackoff()`** - Retry operations with intelligent backoff on stress

### Test Files

#### `staged-workflow.test.ts`
Comprehensive tests for each loading stage:
- Stage 1: Basic page load
- Stage 2: Workflows load first (user requirement)
- Stage 3: Dashboard loads after workflows (user requirement) 
- Stage 4: Full workflow with proper sequencing
- Stage 5: Error handling and recovery

#### `dashboard-workflow-sequence.test.ts`
Focused tests for the specific user requirements:
- Complete sequence: Workflows → Performance Dashboard → Interactions
- Stage recovery mechanisms for loading failures
- Performance monitoring under multiple transitions

## 🚀 Running Browser Tests

### Command Options

```bash
# Run all browser tests
npm run test:browser

# Run staging sequence tests
npm run test:browser:staging

# Run dashboard workflow sequence tests  
npm run test:browser:dashboard

# Run tests in debug mode (breakpoints, slow-mo)
npm run test:browser:debug

# Run tests with visible browser (headed mode)
npm run test:browser:headed

# View detailed test reports
npm run test:browser:report
```

### Direct Playwright Commands

```bash
# Run specific test file
npx playwright test tests/browser/staged-workflow.test.ts

# Run with specific browser
npx playwright test --project=chromium

# Run in debug mode with breakpoints
npx playwright test --debug

# Generate and view report
npx playwright test && npx playwright show-report
```

## ⚙️ Configuration

### Playwright Config (`playwright.config.ts`)

Optimized for staged loading tests:
- Extended timeouts (60s per test, 30s for assertions)
- Limited concurrent workers to prevent overload
- Screenshot/video capture on failures
- Trace collection for debugging
- Development server integration

### Loading Configuration

Tests use comprehensive loading configuration:

```typescript
const LOADING_CONFIG = {
  timeout: 60000,           // Extended timeout for complex pages
  debugLogging: true,       // Detailed logging for troubleshooting
  waitForCharts: true,      // Wait for data visualizations
  waitForData: true,        // Wait for data tables/lists
  waitForScenarios: true,   // Wait for workflow scenarios
  waitForConnections: true, // Wait for connection lists
  stagingDelay: 2000       // Delay between stages
};
```

## 📊 Test Execution Flow

### 1. Staged Loading Sequence

```
Basic Page Load → Workflows → Dashboard → Interactions
       ↓              ↓          ↓           ↓
  - DOM ready     - Scenarios  - Charts   - Safe clicks
  - Network idle  - Connections - Data    - Form inputs  
  - Loading gone  - Templates   - Metrics - Navigation
```

### 2. System Health Monitoring

- **Stress Detection**: Monitor error indicators and network timing
- **Backoff Strategy**: Implement delays when system shows stress
- **Recovery Mechanisms**: Graceful handling of loading failures
- **Performance Tracking**: Measure and validate loading times

### 3. Error Handling

- **Retry Logic**: Automatic retries for transient failures
- **Graceful Fallbacks**: Alternative approaches when primary methods fail
- **Screenshot Capture**: Visual debugging for test failures
- **Detailed Logging**: Comprehensive logs for troubleshooting

## 🔍 Debugging Browser Tests

### Debug Mode
```bash
npm run test:browser:debug
```
- Opens browser with DevTools
- Allows setting breakpoints in test code
- Step-through execution
- Manual inspection of page state

### Headed Mode
```bash
npm run test:browser:headed
```
- Visible browser window during test execution
- Watch real-time test interactions
- Observe loading sequences visually
- Identify timing issues

### Test Reports
```bash
npm run test:browser:report
```
- Detailed HTML report with screenshots
- Timeline of test execution
- Network activity logs
- Error traces and stack traces

## 🛠️ Troubleshooting

### Common Issues

#### Tests Timing Out
- **Issue**: Loading sequences take longer than expected
- **Solution**: Increase timeout in test configuration or verify application performance

#### Elements Not Found
- **Issue**: Page structure doesn't match expected selectors
- **Solution**: Update selectors in loading helpers or add fallback approaches

#### System Overload
- **Issue**: Tests run too fast and overwhelm the application
- **Solution**: Stress detection automatically handles this, but can adjust staging delays

#### Flaky Tests
- **Issue**: Tests pass/fail inconsistently
- **Solution**: Use staged loading helpers and stress detection for more reliable tests

### Debug Commands

```bash
# Run single test with full logging
npx playwright test tests/browser/staged-workflow.test.ts --headed --debug

# Generate trace file for analysis
npx playwright test --trace=on

# Run tests with specific timeout
npx playwright test --timeout=120000
```

## 📈 Performance Expectations

### Loading Time Targets

- **Basic Page Load**: < 10 seconds
- **Workflow Loading**: < 20 seconds
- **Dashboard Loading**: < 30 seconds
- **Complete Sequence**: < 60 seconds

### System Health Indicators

- **Network Idle**: < 5 seconds
- **Stress Recovery**: < 10 seconds
- **Error Rate**: < 5%
- **Retry Success**: > 95%

## 🔄 Continuous Integration

### CI Configuration

Browser tests are designed to run in CI environments:
- Headless mode by default
- Retry logic for transient failures
- Artifact collection (screenshots, videos, traces)
- Performance monitoring and reporting

### Environment Variables

```bash
# Skip web server startup (if already running)
SKIP_WEBSERVER=true

# Enable headed mode for debugging
HEADED=true

# Set base URL for testing
BASE_URL=http://localhost:3000

# Configure Playwright browsers path
PLAYWRIGHT_BROWSERS_PATH=/path/to/browsers
```

## 📝 Best Practices

### Writing New Tests

1. **Always use loading helpers** - Don't wait with arbitrary timeouts
2. **Implement staging** - Follow workflows → dashboard → interactions pattern
3. **Add stress detection** - Use `waitWithBackoff()` for critical operations
4. **Provide fallbacks** - Multiple approaches for finding elements
5. **Log extensively** - Enable debug logging for troubleshooting

### Test Maintenance

1. **Update selectors** - Keep element selectors synchronized with UI changes
2. **Monitor performance** - Track loading times and adjust expectations
3. **Review failures** - Analyze failed test reports to identify patterns
4. **Stress test regularly** - Verify system handles test load appropriately

---

**Note**: These browser tests specifically address the user's requirements for proper loading sequences, preventing system overload, and ensuring workflows load before dashboard interactions. The staging approach and stress detection mechanisms provide robust, reliable browser testing for the Make.com FastMCP server.