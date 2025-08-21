# Scenarios Module Validation Suite

This validation suite ensures that the refactored scenarios module maintains 100% functional compatibility with the original monolithic implementation.

## Overview

The refactored scenarios module splits a large monolithic file into modular components:
- **schemas/**: Zod validation schemas 
- **types/**: TypeScript type definitions
- **utils/**: Utility functions (blueprint analysis, etc.)
- **tools/**: Individual tool implementations

This validation suite verifies that:
1. All tools register correctly
2. Schema validation behaves identically  
3. Blueprint processing produces same results
4. API endpoints map consistently
5. Error handling is preserved
6. Performance meets or exceeds benchmarks

## Quick Start

```bash
# Run full validation suite
npm run validate:scenarios

# Quick validation (skip performance tests)
npm run validate:scenarios:quick

# Verbose output with detailed results
npm run validate:scenarios:verbose
```

## Validation Categories

### 🔧 Compatibility Tests
Validates that the refactored module maintains API compatibility:
- Tool registration verification
- Schema validation consistency
- Blueprint processing accuracy
- Error handling preservation

**Command:** `npm run validate:compatibility`

### 🧪 Regression Tests  
Compares outputs between original and refactored implementations:
- Identical input/output validation
- API response format consistency
- Edge case handling verification
- Error message preservation

**Command:** `npm run validate:regression`

### 📊 Performance Benchmarks
Ensures no performance regressions:
- Tool registration speed
- Schema validation performance
- Blueprint processing efficiency
- Memory usage optimization

**Command:** `npm run test:performance`

### 🔍 Integration Tests
Full workflow validation:
- Complete CRUD operations
- Multi-tool interactions  
- Error recovery workflows
- Concurrent execution handling

**Command:** `npm run test -- --testPathPattern=scenarios.*integration`

## Test Structure

```
tests/scenarios/
├── integration/           # Full workflow tests
│   ├── scenarios-full-suite.test.ts
│   └── api-compatibility.test.ts
├── unit/                  # Component-specific tests
│   ├── types/
│   │   └── blueprint.test.ts
│   ├── schemas/
│   │   ├── blueprint-update.test.ts
│   │   └── scenario-filters.test.ts
│   └── utils/
│       └── blueprint-analysis.test.ts
└── performance/           # Performance benchmarks
    └── benchmarks.test.ts
```

## Validation Scripts

### `validate-scenarios-refactoring.js`
Main compatibility validation script that:
- Tests tool registration
- Validates schema behavior
- Checks blueprint processing
- Verifies error handling
- Measures performance

### `regression-test.js`
Comprehensive regression testing that:
- Loads both implementations
- Executes identical test scenarios
- Compares outputs for exact matches
- Reports any discrepancies

### `run-all-validations.js`
Master orchestrator that:
- Coordinates all validation types
- Generates comprehensive reports
- Provides summary statistics
- Creates detailed logs

## Configuration

### Command Line Options

- `--verbose`: Detailed output with intermediate results
- `--quick`: Skip time-intensive performance tests
- `--help`: Show detailed usage information

### Environment Variables

- `NODE_ENV=test`: Enable test-specific configurations
- `VALIDATION_TIMEOUT=30000`: Set timeout for validation tests
- `VALIDATION_OUTPUT_DIR`: Custom directory for validation reports

## Output and Reports

Validation results are saved to `./validation-reports/` with timestamped filenames:

- **JSON Report**: Machine-readable results with detailed metrics
- **Markdown Report**: Human-readable summary with recommendations  
- **Log Files**: Individual test category outputs for debugging

### Sample Output

```
🚀 Starting Scenarios Module Validation Suite
============================================================

🔧 Running Compatibility Tests...
✅ Compatibility tests PASSED (234ms)

🧪 Running Regression Tests...
✅ Regression tests PASSED (1,456ms)

📊 Running Performance Benchmarks...
✅ Performance benchmarks PASSED (3,221ms)

🔍 Running Integration Tests...
✅ Integration tests PASSED (892ms)

============================================================
VALIDATION PASSED
============================================================

🎉 All validations passed! The refactored scenarios module is ready for deployment.
```

## Exit Codes

- **0**: All validations passed successfully
- **1**: Some validations failed - requires attention
- **2**: Critical error - validation suite crashed

## Troubleshooting

### Common Issues

1. **Tool Registration Failures**
   - Check import paths in refactored modules
   - Verify FastMCP compatibility
   - Ensure all required dependencies

2. **Schema Validation Discrepancies**
   - Compare Zod schema definitions
   - Check default value handling
   - Verify error message consistency

3. **Performance Regressions**
   - Profile individual components
   - Check for unnecessary computations
   - Verify caching mechanisms

4. **Output Mismatches**
   - Compare JSON structures deeply
   - Check timestamp/dynamic field handling
   - Verify data transformation logic

### Debug Mode

Run with verbose logging to see detailed test execution:

```bash
npm run validate:scenarios:verbose
```

### Manual Testing

For specific component testing:

```bash
# Test specific schemas
node -e "import('./src/tools/scenarios/schemas/blueprint-update.js').then(s => console.log('Schemas loaded'))"

# Test blueprint utilities
node -e "import('./src/tools/scenarios/utils/blueprint-analysis.js').then(u => console.log('Utils loaded'))"

# Validate specific tools
npm run test -- --testNamePattern="list-scenarios"
```

## CI/CD Integration

Add to your CI pipeline:

```yaml
- name: Validate Scenarios Refactoring
  run: npm run validate:scenarios
  
- name: Upload Validation Reports
  uses: actions/upload-artifact@v3
  with:
    name: validation-reports
    path: validation-reports/
```

## Best Practices

1. **Run before deployment**: Always validate before pushing refactored code
2. **Check all categories**: Don't skip performance or integration tests
3. **Review failures carefully**: Even minor discrepancies may indicate issues
4. **Keep baselines updated**: Update performance benchmarks as needed
5. **Document changes**: Note any intentional behavioral changes

## Contributing

When adding new validation tests:

1. Follow existing patterns for consistency
2. Include both positive and negative test cases
3. Add performance benchmarks for new functionality
4. Update this README with new test categories
5. Ensure tests are deterministic and repeatable

## Support

For issues with the validation suite:

1. Check the troubleshooting section above
2. Review validation logs in `./validation-reports/`
3. Run individual test categories to isolate issues
4. Enable verbose mode for detailed debugging

---

**Note**: This validation suite is critical for ensuring the refactored scenarios module maintains backward compatibility. All tests should pass before deploying the refactored code to production.