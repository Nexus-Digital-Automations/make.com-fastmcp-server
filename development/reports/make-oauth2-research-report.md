# Make.com OAuth 2.0 API Documentation Research Report

## Executive Summary

This comprehensive research report documents Make.com's OAuth 2.0 implementation, authentication flows, API scopes, and best practices for secure integration. Make.com provides a robust OAuth 2.0 implementation following industry standards with enhanced security features including mandatory PKCE support for public clients and comprehensive scope-based access control.

## 1. OAuth 2.0 Endpoints and Configuration

### Primary Authorization Server Endpoints

Based on Make.com's OpenID Connect discovery document (`.well-known/openid-configuration`):

- **Authorization Endpoint**: `https://www.make.com/oauth/v2/authorize`
- **Token Endpoint**: `https://www.make.com/oauth/v2/token`
- **UserInfo Endpoint**: `https://www.make.com/oauth/v2/oidc/userinfo`
- **JWKS Endpoint**: `https://www.make.com/oauth/v2/oidc/jwks`
- **Token Revocation Endpoint**: `https://www.make.com/oauth/v2/revoke`

### OpenID Connect Discovery

- **Discovery Endpoint**: `https://www.make.com/.well-known/openid-configuration`
- **Issuer**: `https://www.make.com`

## 2. Supported OAuth 2.0 Flows and Protocols

### Grant Types

- **Authorization Code**: Primary supported grant type for secure server-to-server communication
- **Authorization Code with PKCE**: Mandatory for Single Page Applications (SPAs) and mobile applications

### Response Types

- `code` - Standard authorization code flow
- `id_token` - OpenID Connect implicit flow
- `code id_token` - Hybrid flow combining authorization code and ID token

### Protocol Support

- **OAuth 2.0**: Full RFC 6749 compliance
- **OpenID Connect (OIDC)**: Complete OIDC implementation
- **PKCE (RFC 7636)**: Mandatory for public clients, optional for confidential clients

### Security Features

- **Code Challenge Method**: S256 (SHA-256) - industry standard
- **ID Token Signing**: RS256 algorithm
- **Subject Type**: Public
- **Token Endpoint Authentication**: Client Secret Post

## 3. OAuth 2.0 Client Registration Requirements

### Prerequisites

Before implementing OAuth 2.0, developers must register their OAuth 2.0 client with Make's authorization server to obtain:

1. **Client ID** (required for all clients)
2. **Client Secret** (only for confidential clients)

### Redirect URL Requirements

For custom app development, use one of the following redirect URLs:

- `https://www.make.com/oauth/cb/app`
- `https://www.integromat.com/oauth/cb/app` (legacy support)

## 4. API Scopes and Permissions

### Scope Structure

Make.com uses a hierarchical scope system with two permission levels:

- **`:read`** - Retrieve information and view resources
- **`:write`** - Create, modify, or delete resources

### Core API Scopes

#### Organization Management

- **Organizations**: Manage organizational structures, analytics, and administrative functions
- **Teams**: Create, update, and manage team structures within organizations
- **Users**: User management, role assignments, and access control

#### Scenario and Automation

- **Scenarios**:
  - `scenarios:read` - Retrieve scenario details, logs, and configurations
  - `scenarios:write` - Create, update, delete scenarios and folders
  - `scenarios:run` - Execute scenarios via API
- **Templates**: Access and manage scenario templates and blueprints

#### Data and Connections

- **Connections**:
  - `connections:read` - Retrieve connection details and verify connectivity
  - `connections:write` - Create, update, delete, and manage connection data
- **Data Stores**: Manage persistent data storage within Make platform

#### Applications

- **Custom Apps**: Develop, configure, and manage custom application integrations
- **Native Apps**: Access and configure built-in Make applications

#### Analytics and Monitoring

- **Analytics**: Access usage statistics, performance metrics, and operational data
- **Custom Properties**: Manage custom metadata and properties

### Access Control Model

- **Role-Based Permissions**: Scopes are mapped to user roles within organizations
- **Granular Control**: Fine-grained permissions for specific operations
- **Administrative Scopes**: Special permissions for White Label platform administrators

## 5. Token Management and Lifecycle

### Access Token Characteristics

- **Short-lived**: Recommended duration of minutes to hours for security
- **Bearer Token**: Used in API Authorization headers
- **Scope-bound**: Limited to authorized permissions
- **Automatic Refresh**: Handled by Make platform when refresh tokens are available

### Refresh Token Handling

- **Token Rotation**: New refresh token issued on each use (security best practice)
- **Automatic Detection**: Make detects refresh token reuse and revokes compromised tokens
- **Expiration Management**: Platform handles token expiration and renewal automatically
- **Manual Reauthorization**: Required when refresh tokens expire or are revoked

### Token Security Best Practices

1. **Secure Storage**: Use platform-appropriate secure storage mechanisms
2. **Short Expiration**: Keep access tokens short-lived (minutes rather than hours)
3. **Rotation Strategy**: Implement refresh token rotation
4. **Revocation**: Immediate token revocation on security events
5. **Monitoring**: Track unusual token usage patterns

## 6. Custom App OAuth 2.0 Implementation

### Authentication Flow Structure

The typical OAuth 2.0 flow for custom apps follows this sequence:

1. **Pre-authorize** (optional): Pre-flight request before authorization
2. **Authorize**: User authorization and consent
3. **Token Exchange**: Code exchange for access/refresh tokens
4. **Connection Validation** (optional): Verify connection integrity
5. **Token Refresh**: Automatic token renewal
6. **Token Invalidation**: Clean token revocation

### Available IML Variables

- `now`: Current date/time
- `oauth.scope`: Required OAuth scopes
- `oauth.redirectUri`: Callback URL for authorization
- `parameters`: Connection input parameters

### Response Handling

- `response.data`: Save connection-specific data
- `response.expires`: Set connection or refresh token expiration
- Extended response format with data and expiration metadata

### Implementation Constraints

- No AWS directive support in OAuth flows
- No pagination support during authentication
- Manual reauthorization required when tokens expire

## 7. Security Considerations and Best Practices

### PKCE Implementation

- **Mandatory for Public Clients**: SPAs and mobile applications must use PKCE
- **S256 Challenge Method**: SHA-256 hashing for code challenges
- **Enhanced Security**: Prevents authorization code interception attacks

### Scope Management

- **Principle of Least Privilege**: Request minimal necessary scopes
- **Incremental Authorization**: Request additional scopes as needed
- **Dynamic Scoping**: Adjust permissions based on user context

### Token Security

- **Secure Transmission**: Always use HTTPS for token exchange
- **Storage Protection**: Never store tokens in plain text
- **Rotation Policy**: Implement automatic refresh token rotation
- **Monitoring**: Detect and respond to suspicious token activity

### Error Handling

- **403 Access Denied**: Insufficient scope permissions
- **401 Unauthorized**: Invalid or expired tokens
- **400 Bad Request**: Malformed OAuth requests

## 8. Integration Recommendations

### For Confidential Clients (Server-side Applications)

1. Use authorization code flow with client secret
2. Implement secure token storage on server
3. Use refresh token rotation for enhanced security
4. Monitor token usage patterns

### For Public Clients (SPAs/Mobile Apps)

1. Mandatory PKCE implementation with S256 challenge method
2. Short-lived access tokens (recommend 15-30 minutes)
3. Secure storage using platform APIs (Keychain, Credential Locker)
4. Implement automatic token refresh

### For Custom App Development

1. Register OAuth client with Make developer platform
2. Configure appropriate redirect URLs
3. Implement complete authentication flow (authorize → token → refresh)
4. Use Make's IML variables for dynamic configuration
5. Handle token expiration and manual reauthorization

## 9. Error Handling and Troubleshooting

### Common OAuth Errors

- **Invalid Client**: Client ID not registered or incorrect
- **Invalid Grant**: Authorization code expired or already used
- **Invalid Scope**: Requested scopes not available or unauthorized
- **Access Denied**: User declined authorization or insufficient permissions

### Debugging Resources

- Make Community Forums for implementation questions
- Developer Hub documentation for technical specifications
- OpenID Connect discovery for endpoint verification

## 10. Compliance and Standards

### Standards Adherence

- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 6750**: Bearer Token Usage
- **RFC 7636**: PKCE Extension
- **OpenID Connect Core**: Identity layer on OAuth 2.0

### Security Compliance

- Industry-standard token encryption and signing
- Mandatory PKCE for public clients
- Comprehensive scope-based access control
- Token rotation and revocation capabilities

## Conclusion

Make.com provides a comprehensive, secure OAuth 2.0 implementation that follows industry best practices and standards. The platform supports both confidential and public clients with appropriate security measures, offers granular scope-based permissions, and provides robust token management capabilities. Developers can confidently integrate with Make.com's OAuth 2.0 system knowing it implements current security standards including mandatory PKCE for public clients and automatic token rotation.

For implementation, developers should prioritize security best practices including minimal scope requests, secure token storage, and proper error handling. The combination of Make.com's robust OAuth implementation and following these best practices ensures secure, reliable integration with the Make automation platform.

---

_Report compiled from official Make.com developer documentation, OpenID Connect discovery, and OAuth 2.0 security best practices research._
_Date: August 26, 2025_
