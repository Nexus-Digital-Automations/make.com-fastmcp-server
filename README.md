# Make.com FastMCP Server

[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-3.15-green.svg)](https://github.com/jspv/fastmcp)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A production-ready FastMCP TypeScript server providing comprehensive Make.com API integration through the Model Context Protocol (MCP). This server offers enterprise-grade automation management with **14 tools**, **3 resources**, and **3 AI-powered prompts** for seamless Make.com workflow orchestration.

> **✅ Validation Status**: All 25+ validation checks passed - ready for production deployment

## ✨ Key Features

### 🛡️ Production-Ready Architecture

- **Type Safety**: Full TypeScript implementation with strict mode
- **Zero Errors**: Comprehensive validation with 0 linting violations
- **Error Handling**: Robust error categorization and recovery
- **Performance**: Minimal dependencies (4 core + 8 dev)
- **Standards Compliant**: Full MCP protocol implementation

### 🚀 Comprehensive Make.com Integration

#### **🎯 Tools (14 total)**

Complete CRUD operations for all Make.com resources:

| Category         | Tools                                                                                                     | Description                                 |
| ---------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| **Scenarios**    | `list-scenarios`, `get-scenario`, `create-scenario`, `update-scenario`, `delete-scenario`, `run-scenario` | Complete scenario lifecycle management      |
| **Connections**  | `list-connections`, `get-connection`, `create-connection`, `delete-connection`                            | Connection management and status monitoring |
| **Organization** | `list-users`, `get-user`, `list-organizations`, `list-teams`                                              | User and organizational data access         |

#### **📊 Resources (3 total)**

Direct data access through MCP resources:

- **`make://scenarios`** - Real-time scenario data and configurations
- **`make://connections`** - Live connection status and metadata
- **`make://users`** - User profiles and permission data

#### **🤖 AI-Powered Prompts (3 total)**

Intelligent automation assistance:

- **`create-automation-scenario`** - AI-guided workflow creation with best practices
- **`optimize-scenario`** - Performance analysis and optimization suggestions
- **`troubleshoot-connection`** - Intelligent connection debugging and resolution

## 🚀 Quick Start Guide

### Step 1: Prerequisites

- **Node.js** >= 18.0.0 ([Download](https://nodejs.org/))
- **Make.com account** with API access
- **Claude Desktop** or compatible MCP client

### Step 2: Get Your Make.com API Key

1. 🔑 Login to [Make.com](https://make.com)
2. Navigate to **Settings** → **API**
3. Click **"Generate API Key"**
4. 📋 Copy the generated key (save it securely!)

### Step 3: Install the Server

```bash
# Clone the repository
git clone <repository-url>
cd make.com-fastmcp-server

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env and add your MAKE_API_KEY

# Build the server
npm run build
```

### Step 4: Validate Installation

```bash
# Verify build process
npm run typecheck  # ✅ Should pass with no errors
npm run lint       # ✅ Should show no violations

# Test server startup
npm start
# ✅ Should show: "Make.com Simple FastMCP Server started successfully"
```

### Step 5: Connect to Claude Desktop

**Add to your Claude Desktop config file:**

```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/make.com-fastmcp-server/dist/simple-fastmcp-server.js"
      ],
      "env": {
        "MAKE_API_KEY": "your_actual_api_key_here",
        "MAKE_BASE_URL": "https://us1.make.com/api/v2"
      }
    }
  }
}
```

**📁 Config file locations:**

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

**⚡ Important**:

- Use **absolute paths** (not relative paths like `./` or `~/`)
- Restart Claude Desktop after config changes
- Verify your API key has the necessary permissions in Make.com

## ⚙️ Configuration

### Essential Environment Variables

| Variable               | Required | Default                       | Description                               |
| ---------------------- | -------- | ----------------------------- | ----------------------------------------- |
| `MAKE_API_KEY`         | **Yes**  | -                             | Your Make.com API key                     |
| `MAKE_BASE_URL`        | No       | `https://us1.make.com/api/v2` | API endpoint (region-specific)            |
| `MAKE_TEAM_ID`         | No       | -                             | Scope to specific team (optional)         |
| `MAKE_ORGANIZATION_ID` | No       | -                             | Scope to specific organization (optional) |

### Regional Configuration

**Choose your Make.com region:**

```bash
# 🇺🇸 US Region (default)
MAKE_BASE_URL=https://us1.make.com/api/v2

# 🇪🇺 EU Region
MAKE_BASE_URL=https://eu1.make.com/api/v2

# 🏢 Enterprise/Custom Instance
MAKE_BASE_URL=https://your-instance.make.com/api/v2
```

### Complete Configuration Example

```bash
# Required - Your API credentials
MAKE_API_KEY=your_make_api_key_here

# Regional endpoint
MAKE_BASE_URL=https://us1.make.com/api/v2

# Optional scoping (for enterprise accounts)
MAKE_TEAM_ID=12345
MAKE_ORGANIZATION_ID=67890
```

## 🛠️ Usage Examples

### MCP Tool Usage in Claude Desktop

Once connected, you can interact with your Make.com account directly through Claude:

**📋 List scenarios:**

```
Can you show me all my Make.com scenarios?
```

**🚀 Run a scenario:**

```
Please run scenario ID 123456 in Make.com
```

**🔗 Check connections:**

```
What connections do I have set up in Make.com? Show me their status.
```

**🤖 AI-Guided Creation:**

```
Help me create a new automation scenario for processing incoming emails
```

### Available Development Scripts

| Command             | Description                      | When to Use                  |
| ------------------- | -------------------------------- | ---------------------------- |
| `npm run build`     | Compile TypeScript → JavaScript  | Before production deployment |
| `npm run dev`       | Development mode with hot reload | During development           |
| `npm run start`     | Run compiled server              | Production execution         |
| `npm run lint`      | Check code quality               | Before commits               |
| `npm run lint:fix`  | Auto-fix linting issues          | Code cleanup                 |
| `npm run typecheck` | Validate TypeScript types        | Pre-commit validation        |
| `npm run clean`     | Remove build artifacts           | Clean builds                 |

### Production Deployment

```bash
# Prepare for production
npm run build
npm run typecheck  # Must pass with 0 errors
npm run lint       # Must pass with 0 violations

# Deploy (choose your method)
npm start                    # Direct execution
pm2 start dist/simple-fastmcp-server.js  # PM2 process manager
docker build -t make-fastmcp .           # Docker deployment
```

## 🏗️ Architecture

### Minimal Single-File Design

**Validated & Production-Ready Architecture**

```
make.com-fastmcp-server/
├── src/simple-fastmcp-server.ts     # Complete server (672 lines)
├── dist/simple-fastmcp-server.js    # Compiled output
├── package.json                     # Minimal dependencies
├── .env.example                     # Comprehensive config template
├── development/
│   └── research-reports/            # Implementation research
├── VALIDATION-REPORT.md             # Validation results
├── README.md                        # This documentation
└── TODO.json                        # Task management
```

### Dependency Analysis ✅ Validated

| Type             | Count       | Dependencies                                                   |
| ---------------- | ----------- | -------------------------------------------------------------- |
| **Runtime**      | **4**       | `fastmcp@3.15.1`, `axios@1.11.0`, `zod@4.1.1`, `dotenv@17.2.1` |
| **Development**  | **8**       | TypeScript, ESLint, build tools                                |
| **Total Bundle** | **Minimal** | Production-optimized                                           |

### Technical Stack

- **🔷 TypeScript 5.9** - Strict mode, zero type errors
- **⚡ FastMCP Framework** - MCP protocol implementation
- **🌐 Axios HTTP Client** - Robust API communication
- **✅ Zod Validation** - Runtime type safety
- **🔧 ESLint + Prettier** - Code quality enforcement

## 🔧 Troubleshooting

### Quick Diagnostic Commands

```bash
# Complete validation check
npm run typecheck && npm run lint && npm run build

# Test server functionality
npm start

# Check environment configuration
cat .env
```

### Common Issues & Solutions

#### **❌ Server Won't Start**

**Symptoms:** Server fails to launch or exits immediately

**Solutions:**

```bash
# 1. Verify build process
npm run build
npm run typecheck  # Must show 0 errors

# 2. Check environment variables
grep MAKE_API_KEY .env

# 3. Test direct execution
node dist/simple-fastmcp-server.js

# 4. Verify dependencies
npm install
```

#### **❌ API Authentication Errors**

**Symptoms:** `MAKE_API_KEY environment variable is required` or `401 Unauthorized`

**Solutions:**

- ✅ Verify `MAKE_API_KEY` exists in `.env` file
- ✅ Check API key permissions in Make.com Settings → API
- ✅ Ensure correct `MAKE_BASE_URL` for your region
- ✅ Test API key with curl:
  ```bash
  curl -H "Authorization: Token YOUR_API_KEY" https://us1.make.com/api/v2/users
  ```

#### **❌ Claude Desktop Connection Issues**

**Symptoms:** Claude Desktop doesn't show Make.com tools

**Solutions:**

- ✅ Use **absolute paths** in config (not `~/` or `./`)
- ✅ Restart Claude Desktop after configuration changes
- ✅ Check config file location:
  - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
  - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- ✅ Validate JSON syntax in config file
- ✅ Check Claude Desktop console for error messages

#### **❌ TypeScript/Build Errors**

**Symptoms:** Compilation failures or type errors

**Solutions:**

```bash
# Clear build cache
npm run clean
npm install

# Check TypeScript version compatibility
npm ls typescript

# Verify all dependencies
npm audit fix
```

#### **❌ Rate Limiting Issues**

**Symptoms:** `Rate limit exceeded` errors

**Solutions:**

- ✅ Check Make.com plan limits (240 requests/min for Teams)
- ✅ Add delays between requests in high-volume operations
- ✅ Monitor API usage in Make.com dashboard

### Validation Status

> ✅ **All 25+ validation checks passed**  
> See `VALIDATION-REPORT.md` for detailed test results

### Getting Help

1. 📖 Check the [comprehensive validation report](./VALIDATION-REPORT.md)
2. 🔍 Review [error handling research](./development/research-reports/)
3. 🐛 Create an issue with full error logs and environment details

## 🎯 Project Goals & Design Philosophy

This FastMCP server is designed for **simplicity** and **production readiness**:

### ✅ What's Included

- **🎯 Complete Make.com Integration** - All essential API operations (14 tools)
- **⚡ Production-Ready Architecture** - TypeScript strict mode, zero errors
- **🛡️ Robust Error Handling** - Comprehensive error categorization
- **📊 Full MCP Compliance** - Resources, tools, and prompts
- **🔧 Zero Configuration** - Works out-of-the-box with API key
- **✅ Comprehensive Validation** - All 25+ checks passed

### 🚫 Intentionally Excluded

- **No complex middleware** - Keeps codebase simple and maintainable
- **No web frontend** - Pure MCP server, no UI complexity
- **No advanced monitoring** - Basic error handling (extensible with research)
- **No authentication layers** - Direct API key usage for simplicity

## 📈 Future Enhancements

Based on comprehensive research in `development/research-reports/`:

### Phase 1: Enhanced Error Handling

- **Winston/Pino logging** integration
- **Structured error categorization**
- **Request correlation IDs**

### Phase 2: Performance & Monitoring

- **Health check endpoints**
- **Performance metrics collection**
- **Rate limiting improvements**

### Phase 3: Production Operations

- **Comprehensive monitoring integration**
- **Advanced alerting capabilities**
- **Log aggregation support**

_All enhancement research is complete and implementation-ready._

## 🤝 Contributing

### Development Workflow

1. 🍴 **Fork** the repository
2. 🌿 **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. 💻 **Implement** changes with proper TypeScript typing
4. ✅ **Validate** your changes:
   ```bash
   npm run typecheck  # Must pass with 0 errors
   npm run lint       # Must pass with 0 violations
   npm run build      # Must compile successfully
   ```
5. 📝 **Test** functionality with Make.com API
6. 🚀 **Submit** a pull request

### Code Quality Standards

- **TypeScript strict mode** compliance
- **ESLint + Prettier** formatting
- **Comprehensive error handling**
- **MCP protocol compliance**

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🔗 Additional Resources

- **[Comprehensive Validation Report](./VALIDATION-REPORT.md)** - Detailed testing results
- **[Error Handling Research](./development/research-reports/)** - Implementation guidance
- **[FastMCP Documentation](https://github.com/jspv/fastmcp)** - Framework details
- **[Make.com API Docs](https://www.make.com/en/api-documentation)** - API reference
- **[MCP Protocol Spec](https://spec.modelcontextprotocol.io/)** - Protocol specification

---

**🚀 Ready to automate your workflows with Make.com through Claude? Get started in under 5 minutes!**
