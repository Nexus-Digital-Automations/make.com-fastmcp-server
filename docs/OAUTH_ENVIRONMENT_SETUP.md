# OAuth 2.0 + PKCE Environment Setup for Make.com Integration

This document provides complete setup instructions for configuring OAuth 2.0 + PKCE authentication with Make.com in the FastMCP server.

## Required Environment Variables

### Core OAuth Configuration

```bash
# Make.com OAuth Client Configuration (Required)
MAKE_OAUTH_CLIENT_ID=your_make_client_id_here
MAKE_OAUTH_CLIENT_SECRET=your_make_client_secret_here  # Optional for PKCE public clients
MAKE_OAUTH_REDIRECT_URI=https://your-domain.com/auth/make/callback

# OAuth Scopes (Optional - defaults provided)
MAKE_OAUTH_SCOPE="scenario:read scenario:write connection:read connection:write webhook:manage user:read"

# OAuth Endpoints (Optional - Make.com defaults provided)
MAKE_OAUTH_AUTH_ENDPOINT=https://www.make.com/oauth/v2/authorize
MAKE_OAUTH_TOKEN_ENDPOINT=https://www.make.com/oauth/v2/token
MAKE_OAUTH_REVOKE_ENDPOINT=https://www.make.com/oauth/v2/revoke
MAKE_OAUTH_USERINFO_ENDPOINT=https://www.make.com/oauth/v2/oidc/userinfo

# Security Settings
MAKE_OAUTH_USE_PKCE=true  # Always enabled for security (default: true)
```

### Session Management Configuration

```bash
# Redis Configuration for Session Storage
REDIS_URL=redis://localhost:6379
# OR individual settings:
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_DB=0

# Session Encryption (Strongly Recommended for Production)
OAUTH_SESSION_ENCRYPTION_KEY=64_character_hex_key_here  # 32 bytes = 64 hex chars
```

### Development vs Production Settings

#### Development Environment (.env.development)

```bash
# Development settings
NODE_ENV=development
MAKE_OAUTH_REDIRECT_URI=http://localhost:3000/auth/make/callback
REDIS_URL=redis://localhost:6379

# Generate encryption key for development
OAUTH_SESSION_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

#### Production Environment (.env.production)

```bash
# Production settings (HTTPS required)
NODE_ENV=production
MAKE_OAUTH_REDIRECT_URI=https://your-domain.com/auth/make/callback
REDIS_URL=rediss://your-production-redis-url:6380

# Use secure, generated encryption key
OAUTH_SESSION_ENCRYPTION_KEY=your_secure_64_character_hex_key
```

## Make.com OAuth Setup

### 1. Create Make.com OAuth Application

1. Log in to your Make.com account
2. Go to Developer Settings → OAuth Applications
3. Click "Create New Application"
4. Configure your application:
   - **Name**: Your FastMCP Application Name
   - **Redirect URI**: `https://your-domain.com/auth/make/callback`
   - **Scopes**: Select required permissions
   - **Application Type**: Web Application

### 2. Configure Required Scopes

Based on your FastMCP usage, select appropriate scopes:

**Basic FastMCP Operations:**

- `user:read` - User profile information
- `scenario:read` - Read scenario configurations
- `scenario:write` - Create/modify scenarios
- `connection:read` - Read connection settings
- `connection:write` - Manage connections

**Advanced Operations:**

- `scenario:execute` - Trigger scenario execution
- `webhook:manage` - Webhook management
- `team:read` - Team/organization access
- `blueprint:read` - Blueprint access
- `execution:read` - Execution history

### 3. Environment Variable Configuration

```bash
# Copy from Make.com OAuth application
MAKE_OAUTH_CLIENT_ID=your_client_id_from_make
MAKE_OAUTH_CLIENT_SECRET=your_client_secret_from_make
MAKE_OAUTH_REDIRECT_URI=https://your-domain.com/auth/make/callback
```

## Security Best Practices

### 1. HTTPS Requirements

- **Production**: Always use HTTPS for redirect URIs
- **Development**: HTTP allowed for localhost only
- **Certificate**: Use valid SSL certificates in production

### 2. Encryption Key Management

```bash
# Generate secure encryption key
openssl rand -hex 32

# Store securely (never commit to version control)
echo "OAUTH_SESSION_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env.production
```

### 3. Redis Security

```bash
# Use Redis AUTH
REDIS_URL=redis://username:password@host:port/db

# Use TLS for production
REDIS_URL=rediss://username:password@host:port/db

# Configure Redis ACLs for enhanced security
# See Redis documentation for ACL setup
```

### 4. Environment Separation

- Use different OAuth applications for development/staging/production
- Never share client secrets between environments
- Use environment-specific redirect URIs

## Usage Examples

### 1. Basic OAuth Flow Integration

```typescript
import { MakeOAuthMiddleware } from "../middleware/make-oauth-middleware.js";
import { OAuthSessionStore } from "../lib/oauth-session-store.js";

// Initialize session store
const sessionStore = new OAuthSessionStore({
  redis: {
    url: process.env.REDIS_URL,
  },
  encryption: {
    enabled: true,
    key: process.env.OAUTH_SESSION_ENCRYPTION_KEY,
  },
});

// Initialize OAuth middleware
const oauthMiddleware = new MakeOAuthMiddleware(sessionStore);

// Start OAuth flow
const { authorizationUrl, state } = await oauthMiddleware.initiateOAuthFlow(
  sessionId,
  "scenario:read scenario:write connection:read",
);

// Redirect user to authorizationUrl
```

### 2. MakeApiClient with OAuth

```typescript
import { MakeApiClient } from "../lib/make-api-client.js";

// Create OAuth-enabled API client
const apiClient = MakeApiClient.createWithOAuth(
  {
    baseUrl: "https://api.make.com/v2",
    timeout: 30000,
    apiKey: "", // Not used with OAuth
  },
  accessToken,
  userId,
);

// Use client with OAuth authentication
const scenarios = await apiClient.getScenarios();
```

### 3. Token Management

```typescript
// Check token status
const authInfo = apiClient.getAuthInfo();
console.log("Authentication method:", authInfo.method); // 'oauth'
console.log("Token expires:", authInfo.tokenExpiry);
console.log("Is expired:", authInfo.isExpired);

// Validate current token
const validation = await apiClient.validateCurrentToken();
if (!validation.valid && validation.needsRefresh) {
  // Handle token refresh through OAuth middleware
  await oauthMiddleware.refreshAccessToken(sessionId);
}
```

## Testing Configuration

### 1. Verify Environment Variables

```bash
# Check required variables are set
node -e "
const { getMakeOAuthConfig } = require('./dist/config/make-oauth-config.js');
try {
  const config = getMakeOAuthConfig();
  console.log('✅ OAuth configuration valid');
  console.log('Client ID:', config.clientId);
  console.log('Redirect URI:', config.redirectUri);
  console.log('Uses PKCE:', config.usePKCE);
} catch (error) {
  console.error('❌ OAuth configuration error:', error.message);
}
"
```

### 2. Test Redis Connection

```bash
# Test Redis connectivity
node -e "
const { OAuthSessionStore } = require('./dist/lib/oauth-session-store.js');
const store = new OAuthSessionStore();
store.getStatus().connected
  ? console.log('✅ Redis connected')
  : console.log('❌ Redis connection failed');
store.close();
"
```

### 3. Validate OAuth Flow

```bash
# Test OAuth configuration
npm run test:oauth  # If implemented
```

## Troubleshooting

### Common Issues

1. **Invalid Redirect URI**

   ```
   Error: redirect_uri_mismatch
   Solution: Ensure MAKE_OAUTH_REDIRECT_URI matches your Make.com app configuration
   ```

2. **Missing Client ID**

   ```
   Error: Make.com OAuth client ID is required
   Solution: Set MAKE_OAUTH_CLIENT_ID environment variable
   ```

3. **Redis Connection Error**

   ```
   Error: Redis connection failed
   Solution: Check REDIS_URL and ensure Redis server is running
   ```

4. **Session Encryption Error**
   ```
   Error: Encryption key not available
   Solution: Set OAUTH_SESSION_ENCRYPTION_KEY (64 hex characters)
   ```

### Debug Mode

Enable debug logging for OAuth operations:

```bash
DEBUG=oauth:* npm run dev
```

### Health Check Endpoints

The implementation includes health check capabilities:

```typescript
// Check OAuth middleware status
const status = oauthMiddleware.getPublicConfig();

// Check session store status
const storeStatus = sessionStore.getStatus();

// Check API client authentication
const authInfo = apiClient.getAuthInfo();
```

## Production Deployment Checklist

- [ ] HTTPS enabled for all OAuth endpoints
- [ ] Valid SSL certificate configured
- [ ] Redis production cluster configured
- [ ] Session encryption key securely generated and stored
- [ ] Environment variables properly set
- [ ] Make.com OAuth application configured for production domain
- [ ] Rate limiting configured according to Make.com plan
- [ ] Monitoring and alerting configured for OAuth failures
- [ ] Backup authentication method available (API key fallback)

## Support

For additional support:

- Check the comprehensive OAuth research report: `development/research-reports/research-report-task_1756017793285_gbzbh6g29.md`
- Review Make.com OAuth documentation
- Check FastMCP OAuth implementation: `src/lib/oauth-authenticator.ts`
