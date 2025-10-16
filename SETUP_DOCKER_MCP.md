# Docker MCP Gateway Setup

Complete guide for registering and managing Kali MCP Server using Docker Desktop's MCP Gateway.

**🤖 For AI-assisted security testing with Warp Terminal**, see the comprehensive [**Warp AI Terminal Guide**](docs/WARP_TERMINAL_GUIDE.md) - includes beginner-friendly setup, AI prompts, troubleshooting, and best practices.

---

## 📋 Table of Contents

- [What is Docker MCP Gateway](#what-is-docker-mcp-gateway)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Server Registration](#server-registration)
- [Configuration](#configuration)
- [Testing](#testing)
- [Management](#management)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

---

## 🎯 What is Docker MCP Gateway

### Overview for Non-Programmers

Docker MCP Gateway is a feature in Docker Desktop that acts as a **secure master control center** for managing security tool servers. Think of it as a safe, organized command center that:

- **Manages all your security tool servers** in one place (like a switchboard operator)
- **Enforces safety controls** automatically (no raw sockets, non-root user)
- **Makes tools available** to AI assistants like Warp and Claude
- **Creates temporary containers** on-demand (clean slate every time)

**Benefits:**
- **Centralized registration** - Register servers once, use from multiple clients (Warp, Claude, etc.)
- **Automatic discovery** - MCP clients can auto-detect registered servers
- **Consistent security** - Enforced security policies across all servers
- **Simplified updates** - Update server image once, affects all clients
- **Resource management** - Control resource allocation per server

**How it works (simplified):**
1. Docker Desktop's Gateway manages MCP server lifecycle
2. Servers are launched on-demand when MCP clients request them
3. Communication happens via stdio (standard input/output) - like a secure pipeline
4. Containers are ephemeral (created on demand, removed after use) - fresh every time

---

## 📦 Prerequisites

### Required

1. **Docker Desktop 4.30 or newer**
   - [Download for macOS](https://www.docker.com/products/docker-desktop)
   - [Download for Windows](https://www.docker.com/products/docker-desktop)
   - [Download for Linux](https://docs.docker.com/desktop/install/linux-install/)

2. **Kali MCP Server Docker image**
   ```bash
   docker build -t kali-mcp-server:latest .
   ```

3. **Operating System:**
   - macOS (Intel or Apple Silicon)
   - Windows 10/11 with WSL2
   - Linux (Ubuntu, Debian, Fedora)

### Recommended

- **MCP-compatible client:** Claude Desktop, Warp Terminal, or another MCP client
- **Basic Docker knowledge:** Understanding of containers and images
- **Command line familiarity:** For verification and debugging

---

## 🚀 Installation

### Step 1: Install Docker Desktop

If Docker Desktop isn't already installed:

**macOS:**
```bash
# Via Homebrew
brew install --cask docker

# Or download from docker.com
open https://www.docker.com/products/docker-desktop
```

**Windows:**
1. Download Docker Desktop installer
2. Run installer
3. Enable WSL2 backend during installation
4. Restart computer

**Linux:**
Follow distribution-specific instructions at [docs.docker.com](https://docs.docker.com/desktop/install/linux-install/)

---

### Step 2: Enable MCP Gateway

**Via Docker Desktop UI:**

1. Open **Docker Desktop**
2. Click **Settings** (gear icon)
3. Navigate to **Features** or **Extensions**
4. Find **"MCP Gateway"**, **"MCP"**, or **"Model Context Protocol"**
5. Toggle to **Enabled**
6. Click **Apply & Restart**

**Note:** The exact location varies by Docker Desktop version. Look for:
- Settings → Features → MCP
- Settings → Extensions → MCP
- Settings → Advanced → MCP Support

**Verify MCP is enabled:**
```bash
# Check Docker Desktop logs
# macOS: ~/Library/Containers/com.docker.docker/Data/log
# Windows: %APPDATA%\Docker\log
# Linux: ~/.docker/desktop/log

# Look for: "MCP Gateway initialized" or similar
```

---

### Step 3: Build Kali MCP Server Image

```bash
# Clone repository
git clone https://github.com/scottcrosby-securebine/kali-mcp-server.git
cd kali-mcp-server

# Build image
docker build -t kali-mcp-server:latest .

# Verify
docker images | grep kali-mcp-server
```

**Expected output:**
```
kali-mcp-server   latest   abc123def456   5 minutes ago   3.2GB
```

---

## 📝 Server Registration

### Configuration File Location

Docker MCP uses configuration files to register servers. The location varies:

**macOS:**
- Primary: `~/.docker/mcp/registry.yaml`
- Custom: `~/.docker/mcp/custom.yaml`

**Linux:**
- Primary: `~/.docker/mcp/registry.yaml`
- Custom: `~/.docker/desktop/mcp/custom.yaml`

**Windows:**
- Primary: `%USERPROFILE%\.docker\mcp\registry.yaml`
- Custom: `%USERPROFILE%\.docker\mcp\custom.yaml`

**Note:** Use `custom.yaml` for user-defined servers to avoid conflicts with Docker Desktop updates.

---

### Configuration Format

Docker MCP supports **YAML** or **JSON** formats.

#### Option A: YAML Configuration

Create/edit `~/.docker/mcp/custom.yaml`:

```yaml
version: "1.0"

servers:
  kali-mcp-server:
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - kali-mcp-server:latest
    env:
      PYTHONUNBUFFERED: "1"
    description: "Kali Linux penetration testing tools (42 tools)"
    tags:
      - security
      - pentesting
      - kali
```

#### Option B: JSON Configuration

```json
{
  "version": "1.0",
  "servers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--security-opt",
        "no-new-privileges",
        "kali-mcp-server:latest"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      },
      "description": "Kali Linux penetration testing tools (42 tools)",
      "tags": ["security", "pentesting", "kali"]
    }
  }
}
```

---

### Configuration Parameters

| Parameter | Required | Description | Example |
|-----------|----------|-------------|---------|
| `type` | Yes | Transport type | `stdio` |
| `command` | Yes | Executable to run | `docker` |
| `args` | Yes | Command arguments | `["run", "-i", "--rm", ...]` |
| `env` | No | Environment variables | `{"PYTHONUNBUFFERED": "1"}` |
| `description` | No | Human-readable description | "Kali pentest tools" |
| `tags` | No | Searchable tags | `["security", "kali"]` |

**Important flags in `args`:**
- `-i`: Interactive (keeps stdin open for MCP communication)
- `--rm`: Remove container after exit (prevents accumulation)
- `--security-opt no-new-privileges`: Security hardening (required)

---

### Apply Configuration

After creating/editing the configuration:

**Option 1: Restart Docker Desktop**
```bash
# Completely quit Docker Desktop
# Then restart
```

**Option 2: Reload MCP Configuration** (if available in your version)
```
Docker Desktop → Settings → MCP → Reload Configuration
```

**Option 3: Use CLI** (if Docker CLI supports it)
```bash
docker mcp reload
# Or
docker context update --mcp-reload
```

---

## ⚙️ Configuration

### Basic Configuration

Minimal working configuration:

```yaml
servers:
  kali-mcp-server:
    type: stdio
    command: docker
    args: [run, -i, --rm, --security-opt, no-new-privileges, kali-mcp-server:latest]
```

---

### Advanced Configuration

#### Resource Limits

Control CPU and memory usage:

```yaml
servers:
  kali-mcp-server:
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - --memory=2g
      - --cpus=2
      - --memory-swap=2g
      - kali-mcp-server:latest
```

#### Network Isolation

Use custom Docker networks:

```yaml
servers:
  kali-mcp-server:
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - --network
      - pentest_isolated
      - kali-mcp-server:latest
```

**Create network first:**
```bash
docker network create pentest_isolated
```

#### Volume Mounts

Mount directories (use with caution):

```yaml
servers:
  kali-mcp-server:
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - -v
      - /path/to/wordlists:/wordlists:ro
      - kali-mcp-server:latest
```

⚠️ **Warning:** Only mount read-only (`:ro`) and non-sensitive directories.

#### Environment Variables

Pass environment variables to the server:

```yaml
servers:
  kali-mcp-server:
    env:
      PYTHONUNBUFFERED: "1"
      KALI_MCP_TIMEOUT: "600"
      KALI_MCP_MAX_OUTPUT: "1000"
      TZ: "America/New_York"
```

---

### Multiple Server Configurations

Register different configurations for different use cases:

```yaml
servers:
  kali-fast:
    type: stdio
    command: docker
    args: [run, -i, --rm, --memory=1g, --cpus=1, kali-mcp-server:latest]
    description: "Fast scans with limited resources"
    tags: [quick, limited]

  kali-full:
    type: stdio
    command: docker
    args: [run, -i, --rm, --memory=4g, --cpus=4, kali-mcp-server:latest]
    description: "Full scans with more resources"
    tags: [comprehensive, performance]

  kali-isolated:
    type: stdio
    command: docker
    args: [run, -i, --rm, --network, isolated_net, kali-mcp-server:latest]
    description: "Network-isolated testing"
    tags: [isolated, secure]
```

---

## ✅ Testing

### Verify Registration

**Method 1: Docker Desktop UI**
1. Open Docker Desktop
2. Navigate to MCP Servers section
3. Look for "kali-mcp-server"
4. Status should be "Available" or "Ready"

**Method 2: Manual Test**
```bash
# Test server manually
docker run -i --rm --security-opt no-new-privileges kali-mcp-server:latest

# Should see MCP server start
# Press Ctrl+C to exit
```

**Method 3: MCP Client**
- Open your MCP client (Claude Desktop, Warp, etc.)
- Check server list - "kali-mcp-server" should appear
- Try: "List tools from kali-mcp-server"

---

### Test Commands

**List available tools:**
```
"What tools are available in kali-mcp-server?"
```

**Run a simple scan:**
```
"Use kali-mcp-server to get WHOIS information for github.com"
```

**Test network connectivity:**
```
"Use kali-mcp-server to scan scanme.nmap.org"
```

---

## 🔧 Management

### View Registered Servers

**Via configuration file:**
```bash
# macOS/Linux
cat ~/.docker/mcp/custom.yaml

# Windows
type %USERPROFILE%\.docker\mcp\custom.yaml
```

**Via Docker Desktop:**
- Navigate to Settings → MCP → Servers
- View list of registered servers

---

### Update Server

When updating the server code or image:

```bash
# Pull latest code
git pull origin main

# Rebuild image
docker build -t kali-mcp-server:latest .

# Restart Docker Desktop to reload
# Or trigger reload via Settings → MCP → Reload
```

**No configuration changes needed** - uses the same image tag.

---

### Disable Server

**Temporary disable:**
```yaml
servers:
  kali-mcp-server:
    enabled: false  # Add this line
    type: stdio
    command: docker
    args: [...]
```

**Permanent removal:**
Delete the server entry from `custom.yaml` and reload.

---

### Monitor Usage

**View container logs:**
```bash
# While server is running
docker ps  # Get container ID
docker logs <container-id>
```

**Check resource usage:**
```bash
docker stats  # While container is running
```

---

## 🔒 Security

### Security Model

Docker MCP enforces several security controls:

1. **`--security-opt no-new-privileges`**
   - **Required** by Docker MCP
   - Prevents privilege escalation inside container
   - Blocks `setcap` and similar mechanisms

2. **Ephemeral containers**
   - Created on-demand
   - Removed after use (` --rm` flag)
   - No persistent state

3. **Stdio communication**
   - No network ports exposed
   - Local-only communication
   - Client controls server lifecycle

---

### Best Practices

1. **Always use `--rm` flag**
   ```yaml
   args: [run, -i, --rm, ...]
   ```

2. **Always use `--security-opt no-new-privileges`**
   ```yaml
   args: [..., --security-opt, no-new-privileges, ...]
   ```

3. **Limit resources**
   ```yaml
   args: [..., --memory=2g, --cpus=2, ...]
   ```

4. **Avoid mounting sensitive directories**
   ```yaml
   # Don't do this:
   args: [..., -v, /etc:/host_etc, ...]
   
   # Only mount if absolutely necessary, and read-only:
   args: [..., -v, /path/to/wordlists:/wordlists:ro, ...]
   ```

5. **Use custom networks**
   ```bash
   docker network create pentest_net
   ```
   ```yaml
   args: [..., --network, pentest_net, ...]
   ```

6. **Keep images updated**
   ```bash
   # Rebuild monthly
   docker build --pull -t kali-mcp-server:latest .
   ```

---

### Authorization

**Before using MCP server:**
- ✅ Get written permission to test target systems
- ✅ Document authorization scope
- ✅ Use only on systems you own or have permission to test
- ✅ Comply with all applicable laws

**Unauthorized computer access is illegal.**

---

## 🐛 Troubleshooting

### Server Not Found

**Problem:** MCP clients can't see the server.

**Solutions:**

1. **Check configuration file exists:**
   ```bash
   ls -la ~/.docker/mcp/custom.yaml
   ```

2. **Validate YAML/JSON syntax:**
   ```bash
   # Online validator or:
   python3 -c "import yaml; yaml.safe_load(open('~/.docker/mcp/custom.yaml'))"
   ```

3. **Restart Docker Desktop:**
   - Quit completely
   - Restart
   - Wait for full initialization

4. **Check Docker Desktop logs:**
   ```bash
   # macOS
   tail -f ~/Library/Containers/com.docker.docker/Data/log/host/*.log
   ```

---

### Server Won't Start

**Problem:** Container exits immediately or shows errors.

**Debug:**

```bash
# Test manually
docker run -it --rm kali-mcp-server:latest

# Check for errors
docker run -it --rm kali-mcp-server:latest /bin/bash

# Verify image
docker images | grep kali-mcp-server

# Rebuild if necessary
docker build --no-cache -t kali-mcp-server:latest .
```

---

### Permission Denied

**Problem:** "Operation not permitted" errors.

**Expected behavior:**
- ✅ ICMP operations (nmap uses `-Pn` to bypass)
- ✅ Raw sockets (Docker MCP security model)

**Unexpected errors:**

Check configuration has security flags:
```yaml
args:
  - --security-opt
  - no-new-privileges  # Must be present
```

---

### Configuration Not Loading

**Problem:** Changes to `custom.yaml` not reflected.

**Solutions:**

1. **Verify file location:**
   ```bash
   # Should be in ~/.docker/mcp/ directory
   ls -la ~/.docker/mcp/
   ```

2. **Check file permissions:**
   ```bash
   chmod 644 ~/.docker/mcp/custom.yaml
   ```

3. **Force reload:**
   - Restart Docker Desktop completely
   - Or use Settings → MCP → Reload

---

### Network Connectivity Issues

**Problem:** Scans fail to reach targets.

**Debug:**

```bash
# Test Docker networking
docker run -it --rm kali-mcp-server:latest ping -c 3 8.8.8.8

# Check network mode
docker run -it --rm kali-mcp-server:latest ip addr

# Verify DNS
docker run -it --rm kali-mcp-server:latest nslookup google.com
```

---

## 📊 Configuration Examples

### Minimal (Development)

```yaml
servers:
  kali-dev:
    type: stdio
    command: docker
    args: [run, -i, --rm, kali-mcp-server:latest]
```

### Standard (Recommended)

```yaml
servers:
  kali-mcp-server:
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - --memory=2g
      - --cpus=2
      - kali-mcp-server:latest
    env:
      PYTHONUNBUFFERED: "1"
```

### Production (Hardened)

```yaml
servers:
  kali-prod:
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - --read-only
      - --tmpfs
      - /tmp
      - --memory=2g
      - --cpus=2
      - --network
      - pentest_isolated
      - kali-mcp-server:latest
    env:
      PYTHONUNBUFFERED: "1"
```

---

## 📚 Additional Resources

- **Warp AI Terminal Guide:** [docs/WARP_TERMINAL_GUIDE.md](docs/WARP_TERMINAL_GUIDE.md) - **Recommended**: Complete AI-assisted security testing guide
- **Docker MCP Documentation:** Check Docker Desktop docs
- **MCP Specification:** [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Kali Tools:** [README.md](README.md)
- **Deployment Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

---

## 📞 Support

- **GitHub Issues:** [Report problems](https://github.com/scottcrosby-securebine/kali-mcp-server/issues)
- **Docker Forums:** [Docker Community](https://forums.docker.com/)
- **MCP Community:** [MCP Discussions](https://github.com/modelcontextprotocol)

---

## ✅ Checklist

Before using Docker MCP Gateway with Kali MCP Server:

- [ ] Docker Desktop 4.30+ installed
- [ ] MCP Gateway enabled in Docker Desktop
- [ ] Kali MCP Server image built
- [ ] Configuration file created (`~/.docker/mcp/custom.yaml`)
- [ ] Server registered with correct parameters
- [ ] Security flags included (`--security-opt no-new-privileges`)
- [ ] Docker Desktop restarted
- [ ] Server appears in MCP client
- [ ] Test scan successful
- [ ] Authorization documented

---

**Remember:** Always get proper authorization before conducting security testing.

---

*Last Updated: October 2025*  
*Version: v2.0.0-release-prep*
