# Scenarios Schema Documentation

This directory contains all Zod schemas extracted from the main scenarios.ts file, organized according to the refactoring research plan.

## Structure

The schemas are organized into the following categories:

### 1. Scenario Filters (`scenario-filters.ts`)
**Purpose**: Input validation schemas for filtering operations, querying, and diagnostics

**Schemas**:
- `ScenarioFiltersSchema` - For filtering scenarios in list operations
- `ScenarioDetailSchema` - For retrieving detailed scenario information
- `RunScenarioSchema` - For running/executing scenarios
- `TroubleshootScenarioSchema` - For troubleshooting individual scenarios
- `GenerateTroubleshootingReportSchema` - For generating comprehensive troubleshooting reports

### 2. Blueprint Update (`blueprint-update.ts`)
**Purpose**: Update and modification schemas for scenario creation, updates, and blueprint operations

**Schemas**:
- `CreateScenarioSchema` - For creating new scenarios
- `UpdateScenarioSchema` - For updating existing scenarios
- `DeleteScenarioSchema` - For deleting scenarios
- `CloneScenarioSchema` - For cloning scenarios
- `ValidateBlueprintSchema` - For validating blueprints
- `ExtractBlueprintConnectionsSchema` - For extracting connections from blueprints
- `OptimizeBlueprintSchema` - For optimizing blueprints

### 3. Index (`index.ts`)
**Purpose**: Schema aggregation and re-exports

**Features**:
- Re-exports all schemas and their TypeScript types
- Provides `ScenariosSchemas` object for organized access
- Includes `SchemaValidation` utilities
- Defines `ScenarioOperationInput` union type

## Usage Examples

### Basic Schema Import

```typescript
import { ScenarioFiltersSchema, CreateScenarioSchema } from './schemas/index.js';

// Validate filter input
const filterResult = ScenarioFiltersSchema.safeParse({
  teamId: 'team_123',
  limit: 10,
  offset: 0
});

// Validate create scenario input
const createResult = CreateScenarioSchema.safeParse({
  name: 'My New Scenario',
  teamId: 'team_456'
});
```

### Using Organized Schema Collections

```typescript
import { ScenariosSchemas } from './schemas/index.js';

// Access filter schemas
const filters = ScenariosSchemas.filters;
const result = filters.ScenarioFiltersSchema.parse(input);

// Access update schemas
const updates = ScenariosSchemas.updates;
const createResult = updates.CreateScenarioSchema.parse(createInput);

// Access blueprint schemas
const blueprints = ScenariosSchemas.blueprints;
const validateResult = blueprints.ValidateBlueprintSchema.parse(blueprintInput);
```

### Using Schema Validation Utilities

```typescript
import { SchemaValidation, ScenarioFiltersSchema } from './schemas/index.js';

// Safe validation with error handling
const result = SchemaValidation.validate(ScenarioFiltersSchema, input);
if (result.success) {
  console.log('Valid data:', result.data);
} else {
  console.error('Validation error:', result.error);
}

// Simple safe parse (returns null on error)
const parsed = SchemaValidation.safeParse(ScenarioFiltersSchema, input);
if (parsed) {
  console.log('Valid data:', parsed);
}
```

### TypeScript Type Usage

```typescript
import type { 
  ScenarioFilters, 
  CreateScenario, 
  ValidateBlueprint 
} from './schemas/index.js';

function processFilters(filters: ScenarioFilters) {
  // filters is properly typed
  if (filters.teamId) {
    // TypeScript knows teamId is string | undefined
  }
}

function createScenario(data: CreateScenario) {
  // data is properly typed with all required/optional fields
  return { id: 'new_id', name: data.name };
}
```

## Migration Guide

When refactoring code to use the extracted schemas:

### Before (Direct Import from scenarios.ts)
```typescript
// ❌ Old approach - importing from main file
import { ScenarioFiltersSchema } from '../scenarios.ts';
```

### After (Using Extracted Schemas)
```typescript
// ✅ New approach - importing from schemas directory
import { ScenarioFiltersSchema } from './schemas/index.js';

// Or import specific category
import { ScenarioFiltersSchema } from './schemas/scenario-filters.js';
```

## Validation Testing

A comprehensive validation test suite is available in `validate-schemas.ts`:

```bash
# Run validation tests
npx tsx src/tools/scenarios/schemas/validate-schemas.ts

# Or after compilation
node dist/tools/scenarios/schemas/validate-schemas.js
```

The test suite validates:
- All schema parsing with sample data
- Type inference correctness
- Schema utilities functionality
- Export/import consistency

## Schema Preservation

All schemas maintain:
- ✅ **Exact validation logic** - No behavior changes
- ✅ **Original descriptions** - All `.describe()` calls preserved
- ✅ **Strict mode** - `.strict()` validation maintained
- ✅ **Default values** - All `.default()` values intact
- ✅ **TypeScript types** - Full type inference support

## Integration Notes

### Backwards Compatibility
The extracted schemas are fully backwards compatible with existing code that imports from the main scenarios.ts file.

### Performance Benefits
- Reduced bundle size for components that only need specific schemas
- Faster compilation due to smaller dependency graphs
- Better tree-shaking support

### Developer Experience
- Better IDE support with focused imports
- Clearer code organization
- Easier schema discovery and documentation