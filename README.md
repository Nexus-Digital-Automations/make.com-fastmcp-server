# Make.com Simple FastMCP Server

A clean, simple FastMCP TypeScript server that provides essential Make.com API access through the Model Context Protocol (MCP). This server offers a minimal, production-ready implementation with 14 comprehensive tools, 3 resources, and 3 prompts for Make.com automation management.

## Features

### 🚀 Make.com API Tools (14 total)

**Scenario Management:**

- `list-scenarios` - List Make.com scenarios with optional limits
- `get-scenario` - Get details of specific scenarios
- `create-scenario` - Create new scenarios with blueprints
- `update-scenario` - Update existing scenario configurations
- `delete-scenario` - Delete scenarios
- `run-scenario` - Execute scenarios manually

**Connection Management:**

- `list-connections` - List Make.com connections with optional limits
- `get-connection` - Get connection details and status
- `create-connection` - Create new app connections
- `delete-connection` - Remove connections

**User & Organization Management:**

- `list-users` - List users with optional limits
- `get-user` - Get user details and permissions
- `list-organizations` - List available organizations
- `list-teams` - List teams within organizations

### 📊 Resources (3 total)

- **make://scenarios** - Dynamic access to scenario data
- **make://connections** - Dynamic access to connection data
- **make://users** - Dynamic access to user data

### 🤖 Prompts (3 total)

- **create-automation-scenario** - AI-guided scenario creation with best practices
- **optimize-scenario** - Intelligent scenario optimization suggestions
- **troubleshoot-connection** - Connection troubleshooting guidance

## Quick Start Guide

### 1. Get Your Make.com API Key

1. Login to [Make.com](https://make.com)
2. Go to **Settings** → **API**
3. Click **"Generate API Key"**
4. Copy the generated key

### 2. Set Up the Server

```bash
git clone <repository-url>
cd make.com-fastmcp-server
npm install
cp .env.example .env
# Edit .env and add your MAKE_API_KEY
npm run build
```

### 3. Test the Server

```bash
# Test server startup
npm start
# Should show: "Make.com Simple FastMCP Server started successfully"
```

### 4. Connect to Claude Desktop

Add this to your Claude Desktop config file:

```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "node",
      "args": [
        "/full/path/to/make.com-fastmcp-server/dist/simple-fastmcp-server.js"
      ],
      "env": {
        "MAKE_API_KEY": "your_actual_make_api_key_here",
        "MAKE_BASE_URL": "https://us1.make.com/api/v2"
      }
    }
  }
}
```

**Config file location:**

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

## Configuration

### Essential Configuration

```bash
# Required - Your Make.com API key
MAKE_API_KEY=your_make_api_key_here

# Optional - API base URL (defaults to US region)
MAKE_BASE_URL=https://us1.make.com/api/v2

# Optional - Scope to specific team/organization
MAKE_TEAM_ID=your_team_id_here
MAKE_ORGANIZATION_ID=your_organization_id_here
```

## Usage

### Available Scripts

```bash
npm run build        # Compile TypeScript to JavaScript
npm run dev          # Run in development mode with tsx
npm run start        # Run compiled JavaScript
npm run lint         # Run ESLint on source code
npm run lint:fix     # Fix ESLint issues automatically
npm run typecheck    # Run TypeScript type checking without emitting
npm run clean        # Clean build directory
```

## Simple Architecture

This is a minimal, single-file FastMCP TypeScript server:

```
├── src/simple-fastmcp-server.ts  # Complete server implementation
├── dist/simple-fastmcp-server.js # Compiled JavaScript
├── package.json                  # 4 core dependencies only
├── .env.example                 # Configuration template
├── .env                         # Your configuration
├── claude-desktop-config.json   # Claude Desktop template
└── README.md                    # This guide
```

### Dependencies (4 total)

- **fastmcp** - FastMCP framework
- **axios** - HTTP client for Make.com API
- **zod** - Runtime type validation
- **dotenv** - Environment variable loading

### Key Features

- **Zero configuration complexity** - Just add your API key
- **Type safety** - Full TypeScript with Zod validation
- **Production ready** - Proper error handling and logging
- **MCP compliant** - Works with any MCP client (Claude Desktop, etc.)
- **Simple deployment** - Single compiled JavaScript file

## Troubleshooting

### Common Issues

**Server won't start:**

```bash
npm run build  # Ensure TypeScript compiles
node dist/simple-fastmcp-server.js  # Test direct execution
```

**API key invalid:**

- Verify your MAKE_API_KEY in .env
- Check the key has required permissions in Make.com
- Ensure you're using the correct MAKE_BASE_URL region

**Claude Desktop not connecting:**

- Use absolute paths in configuration
- Restart Claude Desktop after config changes
- Check console for error messages

## What's Different?

This is a **simplified version** of a Make.com FastMCP server focused on:

- ✅ Essential Make.com API operations (14 tools)
- ✅ Clean TypeScript implementation
- ✅ Zero configuration complexity
- ✅ Production-ready error handling
- ❌ No middleware/authentication complexity
- ❌ No web frontend or complex deployment
- ❌ No advanced monitoring/logging systems

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with proper TypeScript typing
4. Test with `npm run build && npm run typecheck && npm run lint`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
