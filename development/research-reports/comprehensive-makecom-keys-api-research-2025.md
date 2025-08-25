# Comprehensive Make.com Keys API Research Report 2025

**Research Conducted**: August 25, 2025  
**Task ID**: task_1756162727764_yhgybn3u6  
**Focus**: Complete analysis of Make.com Keys API endpoints and capabilities for FastMCP tool development  
**Research Sources**: Make.com Developer Hub, API Documentation, Community Resources  

## Executive Summary

The Make.com Keys API provides comprehensive endpoints for managing authentication keys in custom keychains. This research reveals a well-structured REST API that supports multiple key types, CRUD operations, and granular permission management through scoped access control. The API is designed for managing authentication credentials across HTTP modules and encryptor applications within the Make.com platform.

## API Overview

### Base URL Structure
```
https://{zone_url}/api/v2/keys
```
Where `{zone_url}` varies by geographical region (e.g., `eu1.make.com`, `us1.make.com`)

### Authentication Requirements
- **Method**: Bearer Token Authentication
- **Header**: `Authorization: Token {api_token}`
- **Content-Type**: `application/json`
- **Required Scopes**: `keys:read` and/or `keys:write`

## Complete API Endpoints

### 1. List Keys
**Endpoint**: `GET /api/v2/keys`

**Description**: Retrieves the list of keys in your custom keychain with optional filtering

**Query Parameters**:
```typescript
interface ListKeysParams {
  teamId: number;           // Required: Team ID
  typeName?: string;        // Optional: Filter by key type
  cols?: string[];          // Optional: Specify returned columns
}
```

**Response**:
```typescript
interface ListKeysResponse {
  keys: Array<{
    id: number;
    name: string;
    typeName: string;
    teamId: number;
    packageName: string | null;
    theme: string;
  }>;
}
```

**Example Request**:
```bash
curl -X GET "https://eu1.make.com/api/v2/keys?teamId=22&typeName=basicauth" \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -H "Content-Type: application/json"
```

### 2. Create Key
**Endpoint**: `POST /api/v2/keys`

**Description**: Creates a new authentication key in the keychain

**Request Body**:
```typescript
interface CreateKeyRequest {
  teamId: number;
  name: string;
  typeName: string;
  parameters: Record<string, any>; // Type-specific parameters
}
```

**Response**:
```typescript
interface CreateKeyResponse {
  id: number;
  name: string;
  typeName: string;
  teamId: number;
  // Additional fields based on key type
}
```

**Example Request**:
```bash
curl -X POST "https://eu1.make.com/api/v2/keys" \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "teamId": 22,
    "name": "My HTTP Basic Auth key",
    "typeName": "basicauth",
    "parameters": {
      "authUser": "Martin",
      "authPass": "your-password"
    }
  }'
```

### 3. Get Key Details
**Endpoint**: `GET /api/v2/keys/{keyId}`

**Description**: Retrieves detailed information for a specific key

**Path Parameters**:
- `keyId` (integer, required): Unique key identifier

**Query Parameters**:
- `cols[]` (optional): Specify returned columns

**Response**:
```typescript
interface KeyDetailsResponse {
  id: number;
  name: string;
  typeName: string;
  teamId: number;
  packageName: string | null;
  theme: string;
  parameters: Record<string, any>;
  createdAt: string;
  updatedAt: string;
}
```

### 4. Update Key
**Endpoint**: `PATCH /api/v2/keys/{keyId}`

**Description**: Updates key name, connection parameters, or both

**Request Body**:
```typescript
interface UpdateKeyRequest {
  name?: string;
  parameters?: Record<string, any>;
}
```

**Example Request**:
```bash
curl -X PATCH "https://eu1.make.com/api/v2/keys/123" \
  -H "Authorization: Token YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Key Name",
    "parameters": {
      "authUser": "NewUsername"
    }
  }'
```

### 5. Delete Key
**Endpoint**: `DELETE /api/v2/keys/{keyId}`

**Description**: Permanently deletes the specified key

**Query Parameters**:
- `confirmed` (boolean): Must be true to confirm deletion

**Response**: `204 No Content` on success

**Example Request**:
```bash
curl -X DELETE "https://eu1.make.com/api/v2/keys/123?confirmed=true" \
  -H "Authorization: Token YOUR_API_TOKEN"
```

### 6. List Key Types
**Endpoint**: `GET /api/v2/keys/types`

**Description**: Retrieves all available key types and their configuration parameters

**Response**:
```typescript
interface KeyTypesResponse {
  keyTypes: Array<{
    name: string;
    label: string;
    parameters: Array<{
      name: string;
      type: string;
      label: string;
      required: boolean;
      default?: any;
      options?: string[];
    }>;
  }>;
}
```

## Comprehensive Key Types

### 1. AES Key (`aes-key`)
**Purpose**: Symmetric encryption for data security

**Parameters**:
```typescript
interface AESKeyParameters {
  key: string;              // Required: Encryption key
  keyEncoding: 'base64' | 'hex' | 'plain';  // Default: 'hex'
}
```

### 2. API Key Auth (`apikeyauth`)
**Purpose**: API key authentication for HTTP requests

**Parameters**:
```typescript
interface APIKeyAuthParameters {
  key: string;              // Required: API key value (password type)
  placement: 'header' | 'query';  // Default: 'header'
  name?: string;            // Parameter name for placement
}
```

### 3. HTTP Basic Auth (`basicauth`)
**Purpose**: Username/password authentication

**Parameters**:
```typescript
interface BasicAuthParameters {
  authUser: string;         // Required: Username
  authPass: string;         // Required: Password
}
```

### 4. Apple Push Notifications (`apn`)
**Purpose**: iOS push notification authentication

**Parameters**:
```typescript
interface APNParameters {
  // Specific to Apple Push Notification service
  // Parameters vary based on certificate/token auth
}
```

### 5. Client Certificate Auth (`clientcertauth`)
**Purpose**: Certificate-based authentication

**Parameters**:
```typescript
interface ClientCertParameters {
  certificate: string;      // Client certificate
  privateKey: string;       // Private key
  passphrase?: string;      // Optional passphrase
}
```

### 6. Additional Key Types
- **auth**: Generic authentication
- **eet**: Electronic Evidence of Transfer
- **gpg-private**: GPG private key
- **gpg-public**: GPG public key
- **webpay**: Web payment authentication

## Authentication & Security

### API Scopes
```typescript
enum KeysScopes {
  READ = 'keys:read',      // View keys and key types
  WRITE = 'keys:write'     // Create, update, delete keys
}
```

### Scope Permissions
- **`keys:read`**: 
  - Get all keys for a team
  - Get key types
  - View key details
  
- **`keys:write`**: 
  - Create new keys
  - Update existing keys
  - Delete keys

### Security Best Practices

1. **Token Management**:
   - Store API tokens securely using environment variables
   - Never expose tokens in client-side code
   - Implement token rotation policies
   - Use minimum required scopes

2. **Key Storage**:
   - Keys are encrypted at rest in Make.com's keychain
   - Parameters containing sensitive data are protected
   - Audit logging for key operations

3. **Access Control**:
   - Team-based access isolation
   - Scope-based permissions
   - Confirmation required for deletion operations

## Data Models & TypeScript Interfaces

### Core Types
```typescript
// Base key interface
interface MakeKey {
  id: number;
  name: string;
  typeName: string;
  teamId: number;
  packageName: string | null;
  theme: string;
  createdAt: string;
  updatedAt: string;
}

// Key creation request
interface CreateKeyRequest {
  teamId: number;
  name: string;
  typeName: string;
  parameters: Record<string, any>;
}

// Key update request
interface UpdateKeyRequest {
  name?: string;
  parameters?: Record<string, any>;
}

// API response wrapper
interface ApiResponse<T> {
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, any>;
  };
}

// List response
interface KeyListResponse {
  keys: MakeKey[];
  pagination?: {
    total: number;
    page: number;
    limit: number;
  };
}
```

### Key Type Definitions
```typescript
// Key type metadata
interface KeyType {
  name: string;
  label: string;
  description?: string;
  parameters: KeyTypeParameter[];
}

interface KeyTypeParameter {
  name: string;
  type: 'text' | 'password' | 'select' | 'number' | 'boolean';
  label: string;
  required: boolean;
  default?: any;
  options?: string[];
  validation?: {
    minLength?: number;
    maxLength?: number;
    pattern?: string;
  };
}
```

### Error Handling
```typescript
interface KeysApiError {
  code: string;
  message: string;
  statusCode: number;
  details?: {
    field?: string;
    value?: any;
    constraint?: string;
  };
}

// Common error codes
enum KeysErrorCodes {
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',
  INVALID_KEY_TYPE = 'INVALID_KEY_TYPE',
  MISSING_PARAMETERS = 'MISSING_PARAMETERS',
  TEAM_ACCESS_DENIED = 'TEAM_ACCESS_DENIED',
  INVALID_SCOPE = 'INVALID_SCOPE'
}
```

## FastMCP Tool Integration Patterns

### 1. Key Management Tool
```typescript
interface KeyManagementTool {
  name: 'manage_keys';
  description: 'Manage authentication keys in Make.com keychain';
  inputSchema: {
    type: 'object';
    properties: {
      action: {
        type: 'string';
        enum: ['list', 'create', 'update', 'delete', 'get_types'];
      };
      teamId: { type: 'number' };
      keyId?: { type: 'number' };
      keyData?: CreateKeyRequest;
    };
    required: ['action', 'teamId'];
  };
}
```

### 2. Key Validation Tool
```typescript
interface KeyValidationTool {
  name: 'validate_key';
  description: 'Validate key configuration and test connectivity';
  inputSchema: {
    type: 'object';
    properties: {
      keyId: { type: 'number' };
      testEndpoint?: { type: 'string' };
    };
    required: ['keyId'];
  };
}
```

### 3. Bulk Key Operations
```typescript
interface BulkKeyOperations {
  name: 'bulk_key_operations';
  description: 'Perform batch operations on multiple keys';
  inputSchema: {
    type: 'object';
    properties: {
      operation: {
        type: 'string';
        enum: ['bulk_create', 'bulk_update', 'bulk_delete'];
      };
      keys: {
        type: 'array';
        items: { type: 'object' };
      };
    };
  };
}
```

## Real-World Usage Patterns

### Common Workflows

1. **Key Lifecycle Management**:
   ```typescript
   // Create key
   const newKey = await createKey({
     teamId: 22,
     name: 'Production API Key',
     typeName: 'apikeyauth',
     parameters: { key: 'api_key_value', placement: 'header' }
   });
   
   // Update key
   await updateKey(newKey.id, {
     name: 'Updated Production API Key'
   });
   
   // Delete key
   await deleteKey(newKey.id, { confirmed: true });
   ```

2. **Key Type Discovery**:
   ```typescript
   const keyTypes = await getKeyTypes();
   const apiKeyType = keyTypes.find(type => type.name === 'apikeyauth');
   ```

3. **Team-based Key Management**:
   ```typescript
   const teamKeys = await listKeys({ teamId: 22, typeName: 'basicauth' });
   ```

### Integration Considerations

1. **Error Handling**: Implement robust error handling for API failures
2. **Rate Limiting**: Respect API rate limits and implement backoff strategies  
3. **Caching**: Cache key types and non-sensitive metadata
4. **Validation**: Validate parameters before API calls
5. **Logging**: Log key operations for audit trails (excluding sensitive data)

## API Limitations & Considerations

1. **Rate Limits**: Standard Make.com API rate limits apply
2. **Team Isolation**: Keys are scoped to teams, no cross-team access
3. **Parameter Validation**: Key type parameters must match required schema
4. **Deletion Confirmation**: Confirmation parameter required for deletions
5. **Sensitive Data**: Password-type parameters are not returned in responses

## Future Considerations

1. **Key Rotation**: Potential for automated key rotation features
2. **Key Templates**: Reusable key configurations for common scenarios
3. **Enhanced Security**: Additional authentication methods and security features
4. **Bulk Operations**: Native support for bulk key management operations
5. **Key Dependencies**: Tracking which scenarios/apps use specific keys

## Implementation Recommendations

### For FastMCP Tools:

1. **Comprehensive Key Manager**: Build a unified interface for all key operations
2. **Type-Safe Implementation**: Use TypeScript interfaces for all API interactions
3. **Parameter Validation**: Implement client-side validation before API calls
4. **Error Recovery**: Provide clear error messages and recovery suggestions
5. **Security Focus**: Never log sensitive parameters, secure token storage
6. **Team Context**: Always operate within correct team scope
7. **Batch Processing**: Implement efficient batch operations where beneficial

This research provides a complete foundation for implementing Make.com Keys API integration within FastMCP tools, enabling comprehensive authentication key management capabilities.