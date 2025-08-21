# Enhanced Loading Detection System - Integration Guide

## Overview

The Enhanced Loading Detection System provides comprehensive loading state detection and waiting mechanisms for browser tests, combining the existing loading helpers with advanced detection capabilities, performance monitoring, and intelligent waiting strategies.

## Architecture

```
Enhanced Loading Detection System
├── Enhanced Loading Detection Engine (Core)
├── Existing Loading Helpers (Integration)
├── Staged Test Execution (Performance)
└── Comprehensive Detection (Unified API)
```

## Key Features

### 1. Intelligent Selector Detection
- Advanced skeleton screen detection
- Dynamic content population monitoring  
- Shimmer and pulse animation tracking
- Custom loading indicator support

### 2. Performance Monitoring Integration
- Real-time performance metrics collection
- System stress detection and adaptive backoff
- Network request monitoring
- Memory and CPU usage tracking

### 3. Adaptive Loading Strategies
- Content complexity analysis
- Environment-specific timing controls
- Stress-aware loading detection
- Graceful degradation on failures

### 4. Comprehensive Coverage
- Basic elements loading
- Dashboard component rendering
- Workflow data population
- Interactive element validation

## Quick Start

### Basic Usage

```typescript
import { 
  waitForElementsToLoadEnhanced,
  waitForDashboardReadyEnhanced,
  waitForWorkflowsLoadedEnhanced,
  runComprehensiveLoadingDetection
} from '../utils/enhanced-loading-detection';

// Enhanced elements loading
const result = await waitForElementsToLoadEnhanced(page, {
  intelligentSelectors: true,
  performanceMonitoring: true,
  stressAwareLoading: true
});

// Enhanced dashboard loading
const dashboardResult = await waitForDashboardReadyEnhanced(page, {
  waitForCharts: true,
  waitForData: true,
  performanceMonitoring: true
});

// Enhanced workflow loading
const workflowResult = await waitForWorkflowsLoadedEnhanced(page, {
  waitForScenarios: true,
  waitForConnections: true,
  performanceMonitoring: true
});

// Comprehensive detection (auto-detects page type)
const comprehensive = await runComprehensiveLoadingDetection(page, {
  intelligentSelectors: true,
  performanceMonitoring: true
});
```

### Advanced Configuration

```typescript
import { EnhancedLoadingDetectionEngine } from '../utils/enhanced-loading-detection';

const engine = new EnhancedLoadingDetectionEngine();

const result = await engine.waitForElementsToLoad(page, {
  timeout: 60000,
  debugLogging: true,
  intelligentSelectors: true,
  performanceMonitoring: true,
  adaptiveTimeout: true,
  stressAwareLoading: true,
  customLoadingSelectors: [
    '.my-custom-loader',
    '[data-loading="true"]'
  ],
  customContentSelectors: [
    '.my-content-container',
    '[data-populated="true"]'
  ],
  minContentThreshold: 3
});
```

## Configuration Options

### Enhanced Loading Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `intelligentSelectors` | boolean | true | Enable advanced selector detection |
| `performanceMonitoring` | boolean | true | Monitor performance during loading |
| `adaptiveTimeout` | boolean | false | Adjust timeouts based on content complexity |
| `stressAwareLoading` | boolean | true | Detect and respond to system stress |
| `customLoadingSelectors` | string[] | [] | Additional loading indicator selectors |
| `customContentSelectors` | string[] | [] | Additional content completion selectors |
| `minContentThreshold` | number | 1 | Minimum content elements required |

### Standard Loading Options (inherited)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `timeout` | number | 30000 | Maximum wait time in milliseconds |
| `checkInterval` | number | 100 | Check interval in milliseconds |
| `maxRetries` | number | 3 | Maximum retry attempts |
| `debugLogging` | boolean | false | Enable debug logging |

## Result Structure

### LoadingDetectionResult

```typescript
interface LoadingDetectionResult {
  success: boolean;              // Whether loading completed successfully
  duration: number;              // Time taken for loading detection
  metrics?: PerformanceMetrics;  // Performance metrics (if monitoring enabled)
  stressIndicators?: SystemStressIndicators; // Stress indicators (if enabled)
  stagesCompleted: string[];     // Loading stages completed
  warnings: string[];           // Any warnings or issues encountered
  contentComplexity: 'low' | 'medium' | 'high'; // Detected content complexity
}
```

### Performance Metrics

```typescript
interface PerformanceMetrics {
  totalExecutionTime: number;
  stageTimings: Record<string, number>;
  networkMetrics: {
    totalRequests: number;
    averageResponseTime: number;
    failedRequests: number;
    slowRequests: number;
  };
  stressEvents: Array<{
    timestamp: number;
    severity: 'low' | 'medium' | 'high';
    recovery_time: number;
  }>;
  memoryUsage: {
    peak: number;
    average: number;
    leaks_detected: boolean;
  };
  cpuUsage: {
    peak: number;
    average: number;
    throttling_detected: boolean;
  };
}
```

## Integration Patterns

### 1. Replace Existing Helpers

```typescript
// Before (using existing helpers)
import { 
  waitForElementsToLoad,
  waitForDashboardReady 
} from '../browser/loading-sequence-helpers';

await waitForElementsToLoad(page, { timeout: 30000 });
await waitForDashboardReady(page, { waitForCharts: true });

// After (using enhanced helpers)
import { 
  waitForElementsToLoadEnhanced,
  waitForDashboardReadyEnhanced
} from '../utils/enhanced-loading-detection';

const elementsResult = await waitForElementsToLoadEnhanced(page, {
  timeout: 30000,
  performanceMonitoring: true
});

const dashboardResult = await waitForDashboardReadyEnhanced(page, {
  waitForCharts: true,
  performanceMonitoring: true
});

// Access additional insights
console.log('Content complexity:', elementsResult.contentComplexity);
console.log('Performance metrics:', dashboardResult.metrics);
```

### 2. Staged Test Integration

```typescript
import { StagedTestExecutionEngine } from '../utils/staged-test-execution';
import { waitForElementsToLoadEnhanced } from '../utils/enhanced-loading-detection';

// Combine staged execution with enhanced loading
const stagedEngine = new StagedTestExecutionEngine();

// Custom stage with enhanced loading
stagedEngine.addStage('enhanced-loading', {
  name: 'Enhanced Loading Detection',
  timeout: 45000,
  priority: 5,
  requiredElements: [],
  customValidation: async (page) => {
    const result = await waitForElementsToLoadEnhanced(page, {
      performanceMonitoring: false, // Avoid double monitoring
      stressAwareLoading: true
    });
    return result.success;
  }
});

const metrics = await stagedEngine.executeStages(page);
```

### 3. Comprehensive Page Testing

```typescript
import { runComprehensiveLoadingDetection } from '../utils/enhanced-loading-detection';

test('Comprehensive Page Loading', async ({ page }) => {
  await page.goto('/');
  
  const results = await runComprehensiveLoadingDetection(page, {
    intelligentSelectors: true,
    performanceMonitoring: true,
    stressAwareLoading: true
  });
  
  // Validate all detection types
  expect(results.elements.success).toBe(true);
  
  if (results.dashboard) {
    expect(results.dashboard.success).toBe(true);
    expect(results.dashboard.contentComplexity).toBe('high');
  }
  
  if (results.workflows) {
    expect(results.workflows.success).toBe(true);
  }
  
  // Overall validation
  expect(results.overall.success).toBe(true);
  console.log('Total detection time:', results.overall.totalDuration);
  console.log('Average complexity:', results.overall.averageComplexity);
});
```

## Best Practices

### 1. Environment-Specific Configuration

```typescript
// Development environment
const devConfig = {
  timeout: 60000,
  debugLogging: true,
  performanceMonitoring: true,
  stressAwareLoading: true
};

// CI/Production environment
const ciConfig = {
  timeout: 45000,
  debugLogging: false,
  performanceMonitoring: false,
  stressAwareLoading: true,
  maxRetries: 5
};

const config = process.env.NODE_ENV === 'development' ? devConfig : ciConfig;
const result = await waitForElementsToLoadEnhanced(page, config);
```

### 2. Error Handling and Fallbacks

```typescript
try {
  const result = await waitForElementsToLoadEnhanced(page, {
    intelligentSelectors: true,
    timeout: 30000
  });
  
  if (!result.success) {
    console.warn('Enhanced loading failed, checking warnings:', result.warnings);
    
    // Analyze warnings for fallback strategy
    if (result.warnings.some(w => w.includes('Fallback'))) {
      console.log('Fallback mechanisms were used successfully');
    }
  }
  
} catch (error) {
  console.error('Enhanced loading detection failed:', error);
  
  // Ultimate fallback to basic loading
  const { waitForElementsToLoad } = await import('../browser/loading-sequence-helpers');
  await waitForElementsToLoad(page, { timeout: 15000 });
}
```

### 3. Performance Monitoring

```typescript
const result = await waitForElementsToLoadEnhanced(page, {
  performanceMonitoring: true,
  stressAwareLoading: true
});

if (result.metrics) {
  // Log performance insights
  console.log('Loading performance:', {
    totalTime: result.metrics.totalExecutionTime,
    networkRequests: result.metrics.networkMetrics.totalRequests,
    slowRequests: result.metrics.networkMetrics.slowRequests,
    stressEvents: result.metrics.stressEvents.length
  });
  
  // Performance assertions
  expect(result.metrics.totalExecutionTime).toBeLessThan(30000);
  expect(result.metrics.networkMetrics.failedRequests).toBeLessThan(3);
}

if (result.stressIndicators) {
  // Monitor system stress
  if (result.stressIndicators.stressLevel > 0.8) {
    console.warn('High system stress detected:', result.stressIndicators);
  }
}
```

### 4. Custom Loading Patterns

```typescript
// Define application-specific loading patterns
const customConfig = {
  customLoadingSelectors: [
    '.app-loading-overlay',
    '[data-testid="loading-state"]',
    '.content-shimmer'
  ],
  customContentSelectors: [
    '.data-loaded[data-count]',
    '.chart-rendered[data-chart-ready="true"]',
    '.list-populated:not(:empty)'
  ],
  minContentThreshold: 2
};

const result = await waitForElementsToLoadEnhanced(page, {
  ...customConfig,
  intelligentSelectors: true
});
```

## Migration Guide

### From Existing Helpers

1. **Replace import statements:**
   ```typescript
   // Old
   import { waitForElementsToLoad } from '../browser/loading-sequence-helpers';
   
   // New
   import { waitForElementsToLoadEnhanced } from '../utils/enhanced-loading-detection';
   ```

2. **Update function calls:**
   ```typescript
   // Old
   await waitForElementsToLoad(page, { timeout: 30000 });
   
   // New
   const result = await waitForElementsToLoadEnhanced(page, { timeout: 30000 });
   expect(result.success).toBe(true);
   ```

3. **Add performance monitoring:**
   ```typescript
   const result = await waitForElementsToLoadEnhanced(page, {
     timeout: 30000,
     performanceMonitoring: true
   });
   
   if (result.metrics) {
     console.log('Performance metrics:', result.metrics);
   }
   ```

### Gradual Adoption

1. **Start with basic replacement** in non-critical tests
2. **Add performance monitoring** for insights
3. **Enable intelligent selectors** for better detection
4. **Implement stress-aware loading** for resilience
5. **Use comprehensive detection** for complex pages

## Troubleshooting

### Common Issues

1. **Timeouts with intelligent selectors:**
   - Reduce `minContentThreshold`
   - Add specific `customContentSelectors`
   - Disable `adaptiveTimeout`

2. **Performance monitoring overhead:**
   - Disable in CI environments
   - Use selective monitoring for specific tests
   - Reduce timeout values

3. **False positives in stress detection:**
   - Adjust stress detection sensitivity
   - Add delays between detections
   - Use `waitWithBackoff` for retries

### Debug Logging

```typescript
const result = await waitForElementsToLoadEnhanced(page, {
  debugLogging: true,
  intelligentSelectors: true,
  performanceMonitoring: true
});

console.log('Debug information:', {
  stagesCompleted: result.stagesCompleted,
  warnings: result.warnings,
  contentComplexity: result.contentComplexity,
  duration: result.duration
});
```

## Integration with Existing Codebase

The enhanced loading detection system is designed to be **fully backward compatible** with existing loading helpers. It can be gradually adopted without breaking existing tests:

1. **Existing helpers continue to work** unchanged
2. **Enhanced helpers provide additional insights** 
3. **Gradual migration path** allows for smooth transition
4. **Performance monitoring** can be selectively enabled
5. **Fallback mechanisms** ensure reliability

This comprehensive system enhances the existing loading detection capabilities while maintaining compatibility and providing powerful new insights for test reliability and performance optimization.