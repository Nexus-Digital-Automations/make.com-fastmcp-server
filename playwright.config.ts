import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for browser tests with staged loading sequences
 * 
 * This config supports the test restructuring for proper loading sequences:
 * 1. Workflows load first
 * 2. Dashboard loads after workflows
 * 3. Proper element detection before interactions
 */
export default defineConfig({
  testDir: './tests/browser',
  
  // Global timeout settings to prevent system overload
  timeout: 60 * 1000, // 60 seconds per test
  expect: {
    timeout: 30 * 1000, // 30 seconds for assertions
  },

  // Retry failed tests to handle transient issues
  retries: process.env.CI ? 2 : 1,
  
  // Limit concurrent workers to prevent overload
  workers: process.env.CI ? 2 : 1,

  // Reporter configuration
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['json', { outputFile: 'test-results/playwright-results.json' }],
    ['list']
  ],

  // Output directory for test artifacts
  outputDir: 'test-results/',

  // Global test settings
  use: {
    // Base URL for the application under test
    baseURL: process.env.BASE_URL || 'http://localhost:3000',
    
    // Browser settings optimized for testing
    headless: process.env.HEADED !== 'true',
    viewport: { width: 1280, height: 720 },
    
    // Network and timing settings to prevent overload
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',
    
    // Extended action timeout for loading sequences
    actionTimeout: 30 * 1000,
    navigationTimeout: 45 * 1000,
  },

  // Test projects for different scenarios
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    
    // Uncomment for multi-browser testing
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },
    
    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] },
    // },
  ],

  // Development server configuration
  webServer: process.env.SKIP_WEBSERVER ? undefined : {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000, // 2 minutes to start server
  },
});