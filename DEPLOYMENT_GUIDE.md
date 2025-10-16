# Kali MCP Server - Deployment Guide

Complete deployment instructions for all environments and MCP clients.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
  - [Option A: Docker Desktop (Standard)](#option-a-docker-desktop-standard)
  - [Option B: Docker MCP Gateway (Recommended)](#option-b-docker-mcp-gateway-recommended)
  - [Option C: Local Python](#option-c-local-python)
- [MCP Client Configuration](#mcp-client-configuration)
- [Security Best Practices](#security-best-practices)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)

---

## 🎯 Overview

The Kali MCP Server provides **42 professional security testing tools** through the Model Context Protocol (MCP). This enables AI assistants like Warp Terminal and Claude Desktop to perform authorized security assessments on your behalf.

**🤖 For AI-assisted security testing with Warp Terminal**, see the comprehensive [**Warp AI Terminal Guide**](docs/WARP_TERMINAL_GUIDE.md) - includes beginner-friendly setup, AI prompts, troubleshooting, and best practices.

**Key Features:**
- **ARM64 optimized** for Apple Silicon Macs
- **Docker MCP compatible** with security constraints
- **Non-root execution** for enhanced security
- **Input sanitization** to prevent command injection
- **Comprehensive logging** for audit trails

**Important:** This software is for **authorized security testing only**. Unauthorized access to computer systems is illegal.

---

## 📦 Prerequisites

### Required

- **Operating System:**
  - macOS (Intel or Apple Silicon)
  - Linux (x86_64 or ARM64)
  - Windows with WSL2

- **Docker Desktop:** 4.30+ recommended
  - [Download for macOS](https://www.docker.com/products/docker-desktop)
  - [Download for Windows](https://www.docker.com/products/docker-desktop)
  - [Download for Linux](https://docs.docker.com/desktop/install/linux-install/)

- **OR Python:** 3.10 or higher (for local deployment)

- **Disk Space:** ~3-4GB for Docker image

- **Network:** Outbound internet access for package downloads

### Optional

- **Git:** For cloning repository
- **MCP Client:** Warp Terminal, Claude Desktop, or another MCP-compatible client
- **Docker MCP Gateway:** For centralized server management (recommended)

---

## 🚀 Deployment Options

### Option A: Docker Desktop (Standard)

The simplest deployment method - run the server as a Docker container spawned by your MCP client.

#### Step 1: Clone Repository

```bash
git clone https://github.com/scottcrosby-securebine/kali-mcp-server.git
cd kali-mcp-server
```

#### Step 2: Build Image

```bash
docker build -t kali-mcp-server:latest .
```

**Expected output:**
```
[+] Building 1800.5s (20/20) FINISHED
 => exporting to image
 => => naming to docker.io/library/kali-mcp-server:latest
```

**Build time:** 15-30 minutes (downloads Kali packages, compiles Go tools)

#### Step 3: Test Container

```bash
# Interactive test
docker run -it --rm --security-opt no-new-privileges kali-mcp-server:latest
```

You should see the MCP server start and display initialization messages.

Press `Ctrl+C` to exit.

#### Step 4: Configure MCP Client

Your MCP client needs to spawn the container via stdio. Example for Claude Desktop:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kali-mcp-server": {
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
      }
    }
  }
}
```

**Important flags:**
- `-i`: Interactive (keeps stdin open)
- `--rm`: Remove container after exit
- `--security-opt no-new-privileges`: Security hardening

#### Step 5: Restart Client

Restart your MCP client to load the new configuration.

---

### Option B: Docker MCP Gateway (Recommended)

Use Docker Desktop's built-in MCP Gateway for centralized server management.

**✨ This is the recommended approach** for AI-assisted security testing with Warp Terminal.

#### Benefits

- **Centralized management** - Register once, use from multiple clients (Warp, Claude, etc.)
- **Automatic discovery** - Clients can auto-detect registered servers
- **Consistent security** - Enforced security policies
- **Easier updates** - Update image once, affects all clients
- **AI-friendly** - Optimized for Warp AI workflows

#### Requirements

- Docker Desktop 4.30+
- MCP Gateway enabled in Docker Desktop settings

#### Setup Process

1. **Enable MCP Gateway in Docker Desktop**

   Open Docker Desktop → Settings → Features → Enable "MCP Gateway" or "MCP"

   (Exact location may vary by Docker Desktop version)

2. **Build the image**

   ```bash
   docker build -t kali-mcp-server:latest .
   ```

3. **Register the server**

   See [SETUP_DOCKER_MCP.md](SETUP_DOCKER_MCP.md) for detailed registration instructions.

   Quick registration (conceptual):
   ```json
   {
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
         }
       }
     }
   }
   ```

4. **Verify registration**

   Check Docker Desktop → MCP Servers → Verify "kali-mcp-server" appears

5. **Connect from clients**

   - **Warp Terminal** (Recommended): See [Warp AI Terminal Guide](docs/WARP_TERMINAL_GUIDE.md) - Complete AI-assisted security testing guide
   - **Claude Desktop:** Should auto-discover registered servers
   - **Other clients:** Consult client documentation

---

### Option C: Local Python

Run the server directly with Python (without Docker).

**When to use:**
- Development and testing
- Docker not available
- Want to modify server code
- Need direct tool access

**Trade-offs:**
- ❌ More setup complexity
- ❌ Requires installing Kali tools manually
- ✅ Faster startup
- ✅ Easier debugging

#### Step 1: Install Python Dependencies

```bash
# Clone repository
git clone https://github.com/scottcrosby-securebine/kali-mcp-server.git
cd kali-mcp-server

# Create virtual environment
python3 -m venv .venv

# Activate (macOS/Linux)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Step 2: Install Kali Tools

The server requires various security tools. On **Kali Linux**, most are pre-installed. On other systems:

**macOS (Homebrew):**
```bash
brew install nmap sqlmap nikto dirb ffuf gobuster
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y nmap dnsutils whois netcat-openbsd \
                    nikto wpscan sqlmap dirb ffuf gobuster \
                    hydra john sslscan
```

**Note:** Not all tools may be available via package managers. See tool-specific documentation.

#### Step 3: Run Server

```bash
# Ensure virtual environment is activated
python3 kali_pentest_server.py
```

#### Step 4: Configure MCP Client

Use absolute paths in your configuration:

```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "command": "python3",
      "args": [
        "/absolute/path/to/kali-mcp-server/kali_pentest_server.py"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

**⚠️ Critical:** Use absolute paths, not `~` or relative paths.

---

## 🔧 MCP Client Configuration

### Warp Terminal (Recommended)

**🤖 For complete Warp AI Terminal setup**, see the comprehensive [**Warp AI Terminal Guide**](docs/WARP_TERMINAL_GUIDE.md).

The guide includes:
- Beginner-friendly Docker MCP Gateway setup
- AI-assisted workflows for all 42 security tools
- Extensive "Ask Warp AI" prompts
- Troubleshooting with AI assistance
- Real-world security testing scenarios

**Quick summary:**
1. Enable Docker MCP Gateway in Docker Desktop
2. Register kali-mcp-server using the provided YAML examples
3. Configure Warp to use Docker MCP Gateway provider
4. Access via Warp AI features for guided security testing

---

### Claude Desktop

**Config locations:**
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**Full example:**
```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--security-opt",
        "no-new-privileges",
        "--network",
        "bridge",
        "kali-mcp-server:latest"
      ],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

**After editing:** Restart Claude Desktop completely (Quit → Reopen)

---

### Other MCP Clients

For clients not listed here, follow the client's MCP server registration documentation.

Key points:

- **Transport:** stdio (standard input/output)
- **Command:** `docker` or `python3`
- **Args:** Container run command or script path
- **Environment:** `PYTHONUNBUFFERED=1` recommended

---

## 🔒 Security Best Practices

### Container Security

1. **Always use `--security-opt no-new-privileges`**
   - Prevents privilege escalation inside container
   - Required by Docker MCP Gateway

2. **Use `--rm` flag**
   - Removes container after exit
   - Prevents container accumulation

3. **Avoid unnecessary mounts**
   - Don't mount sensitive host directories
   - Only mount if absolutely required

4. **Keep images updated**
   ```bash
   # Rebuild monthly
   docker build --pull -t kali-mcp-server:latest .
   ```

### Network Security

1. **Don't expose ports**
   - MCP uses stdio, no network ports needed
   - Avoid `-p` or `--publish` flags

2. **Use default bridge network**
   - Provides isolation from host
   - Allows outbound connections for scanning

3. **Firewall considerations**
   - Outbound: Allow for tool updates and scanning
   - Inbound: Not required (no listening services)

### Operational Security

1. **Get authorization before testing**
   - Written permission required
   - Document scope and limitations

2. **Use dedicated test networks**
   - Isolated lab environment preferred
   - Avoid production networks

3. **Monitor tool usage**
   - Review MCP client logs regularly
   - Track what tools are being used

4. **Rotate credentials**
   - If using password-based auth tools
   - Avoid storing credentials in scripts

---

## ⚡ Performance Tuning

### Docker Resource Limits

Control resource usage to prevent system impact:

```bash
docker run -i --rm \
  --security-opt no-new-privileges \
  --memory=2g \
  --cpus=2 \
  kali-mcp-server:latest
```

**Recommended limits:**
- **Memory:** 2-4GB (default: unlimited)
- **CPUs:** 2-4 cores (default: unlimited)

### Build Optimization

Speed up builds with layer caching:

```dockerfile
# In Dockerfile, install dependencies first
COPY requirements.txt .
RUN pip install -r requirements.txt

# Then copy code (changes more frequently)
COPY kali_pentest_server.py .
```

### Tool-Specific Tips

1. **nmap scans:**
   - Use `-F` for fast scans (top 100 ports)
   - Limit port ranges: `-p 1-1000` instead of full range

2. **Directory brute-forcing:**
   - Start with small wordlists
   - Use `-w common.txt` before `-w big.txt`

3. **Vulnerability scanning:**
   - Run targeted scans first
   - Full scans can take 30+ minutes

---

## 🐛 Troubleshooting

### Container Won't Start

**Symptom:** `docker run` exits immediately

**Debug:**
```bash
# Check container logs
docker logs $(docker ps -lq)

# Run interactively for errors
docker run -it --rm kali-mcp-server:latest /bin/bash

# Verify image built correctly
docker images | grep kali-mcp-server
```

**Common causes:**
- Missing dependencies in Dockerfile
- Syntax errors in Python code
- Incompatible base image

---

### Permission Denied Errors

**Symptom:** "Operation not permitted" during scans

**Expected behavior:**
- ✅ ICMP ping failures (nmap uses `-Pn` to bypass)
- ✅ Raw socket operations (not supported in Docker MCP)

**Unexpected errors:**
- ❌ File system permission errors
- ❌ Network connection failures

**Solution:**
```bash
# Verify network connectivity
docker run -it --rm kali-mcp-server:latest ping -c 3 8.8.8.8

# Check security policies
docker run -it --rm --cap-add=NET_RAW kali-mcp-server:latest
# (Note: --cap-add won't work with --security-opt no-new-privileges)
```

---

### MCP Client Not Connecting

**Symptom:** Server doesn't appear in client tools list

**Checklist:**
1. ✅ Use absolute paths in configuration
2. ✅ Valid JSON syntax (use validator)
3. ✅ Correct config file location
4. ✅ Client completely restarted
5. ✅ Docker daemon running

**Debug:**
```bash
# Test Docker command manually
docker run -i --rm --security-opt no-new-privileges kali-mcp-server:latest

# Check client logs
# Claude Desktop: Help → View Logs
```

---

### Slow Performance

**Symptom:** Scans taking much longer than expected

**Solutions:**

1. **Reduce scan scope:**
   ```
   # Instead of full port scan
   nmap -p- target

   # Use fast scan
   nmap -F target
   ```

2. **Allocate more resources:**
   ```bash
   docker run --memory=4g --cpus=4 ...
   ```

3. **Check system load:**
   ```bash
   # macOS
   top

   # Linux
   htop
   ```

---

## 🔄 Maintenance

### Regular Updates

**Monthly:**
```bash
cd kali-mcp-server

# Pull latest code
git pull origin main

# Rebuild with latest packages
docker build --pull --no-cache -t kali-mcp-server:latest .

# Test
docker run -it --rm kali-mcp-server:latest
```

**After major Kali releases:**
```bash
# Force rebuild with new base image
docker build --pull --no-cache -t kali-mcp-server:latest .
```

### Tool Updates

**Exploit database:**
```bash
docker run -it --rm kali-mcp-server:latest searchsploit -u
```

**Metasploit:**
```bash
docker run -it --rm kali-mcp-server:latest msfupdate
```

### Cleanup

**Remove old images:**
```bash
# List images
docker images

# Remove specific version
docker rmi kali-mcp-server:old-tag

# Prune unused images
docker image prune
```

**Remove stopped containers:**
```bash
docker container prune
```

---

## 📊 Deployment Comparison

| Feature | Docker (Standard) | Docker MCP Gateway | Local Python |
|---------|-------------------|-------------------|--------------|
| **Setup Time** | 30 minutes | 45 minutes | 1-2 hours |
| **Isolation** | ✅ Full | ✅ Full | ❌ Partial |
| **Updates** | Easy | Easy | Manual |
| **Performance** | Good | Good | Excellent |
| **Portability** | ✅ High | ✅ High | ❌ Low |
| **Debugging** | Medium | Medium | Easy |
| **Tool Coverage** | 100% | 100% | Varies |
| **Recommended For** | Most users | Multi-client | Development |

---

## 🎯 Production Checklist

Before deploying to production use:

- [ ] Image built successfully
- [ ] Container starts without errors
- [ ] All 42 tools accessible
- [ ] MCP client connects successfully
- [ ] Test scans complete successfully
- [ ] Security flags applied (`--security-opt no-new-privileges`)
- [ ] Resource limits configured
- [ ] Logging enabled and monitored
- [ ] Authorization documented
- [ ] Legal compliance verified

---

## 📚 Additional Resources

- **[Warp AI Terminal Guide](docs/WARP_TERMINAL_GUIDE.md)** - **RECOMMENDED**: Complete AI-assisted security testing guide
- [QUICK_START.md](QUICK_START.md) - 5-minute setup guide
- [SETUP_DOCKER_MCP.md](SETUP_DOCKER_MCP.md) - Docker MCP Gateway configuration details
- [README.md](README.md) - Complete tool reference
- [LICENSE](LICENSE) - Terms and conditions

---

## 📞 Support

- **GitHub Issues:** Report bugs and request features
- **Discussions:** Community tips and best practices
- **Security:** Report vulnerabilities privately

---

**Remember:** Always obtain proper authorization before conducting security testing.

---

*Last Updated: October 2025*  
*Version: v2.0.0-release-prep*
