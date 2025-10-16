# Warp Terminal Integration - Kali MCP Server

Complete guide for integrating Kali MCP Server with Warp Terminal via Docker Desktop's MCP support.

---

## 🎯 Overview

[Warp](https://www.warp.dev/) is a modern, AI-powered terminal that supports the Model Context Protocol (MCP). This guide shows you how to integrate the Kali MCP Server with Warp Terminal, enabling AI-assisted security testing directly from your terminal.

**Benefits:**
- 🤖 **AI-powered terminal** with natural language commands
- 🔧 **42 security tools** accessible via Warp AI
- 🔒 **Local execution** - data stays on your machine
- ⚡ **Fast workflows** - combine terminal commands with security tools
- 📊 **Rich output** - formatted results in terminal

---

## 📋 Prerequisites

Before you begin, ensure you have:

1. **Warp Terminal** installed
   - [Download Warp](https://www.warp.dev/)
   - Available for macOS and Linux

2. **Docker Desktop** 4.30+ with MCP support
   - [Download Docker Desktop](https://www.docker.com/products/docker-desktop)
   - MCP Toolkit enabled in settings

3. **Kali MCP Server image** built
   ```bash
   docker build -t kali-mcp-server:latest .
   ```

4. **Basic understanding** of:
   - Docker containers
   - MCP (Model Context Protocol)
   - Security testing concepts

---

## 🚀 Quick Start (5 Steps)

### Step 1: Enable Docker MCP

Open Docker Desktop → Settings → Features → Enable **"MCP Toolkit"**

(Location may vary by Docker Desktop version - look for MCP or Extensions)

**Verify MCP is enabled:**
```bash
# Check Docker Desktop logs for MCP initialization
# Should see "MCP Toolkit enabled" or similar
```

---

### Step 2: Register Kali MCP Server

Docker MCP uses a configuration file to register servers. The exact location varies by system:

**macOS:**  
`~/.docker/mcp/registry.yaml` or `~/.docker/mcp/custom.yaml`

**Linux:**  
`~/.docker/mcp/registry.yaml`

**Configuration format** (YAML):
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
      - kali-mcp-server:latest
    env:
      PYTHONUNBUFFERED: "1"
```

**Or JSON format** (if using custom.yaml):
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

**Apply changes:**
```bash
# Restart Docker Desktop to reload MCP configuration
# Or use Docker Desktop → Settings → MCP → Reload
```

---

### Step 3: Verify Registration

Check that Docker Desktop recognizes the server:

**Via Docker Desktop UI:**
1. Open Docker Desktop
2. Navigate to **MCP Servers** (location varies by version)
3. Verify **"kali-mcp-server"** appears in the list
4. Status should show "Available" or "Ready"

**Via command line:**
```bash
# Test server manually
docker run -i --rm --security-opt no-new-privileges kali-mcp-server:latest

# Should start and show MCP initialization logs
# Press Ctrl+C to exit
```

---

### Step 4: Configure Warp

Open Warp Terminal and configure MCP integration:

**Method A: Warp Settings UI**

1. Open Warp → **Settings** (or Preferences)
2. Navigate to **AI** or **MCP** section
3. Add **Docker Desktop** as an MCP provider
4. Enable **Auto-discover servers**
5. Verify **"kali-mcp-server"** appears in available servers list

**Method B: Warp Configuration File**

If Warp uses a config file for MCP (location varies):

```yaml
mcp:
  providers:
    - type: docker_desktop
      enabled: true
      auto_discover: true
  
  servers:
    - name: kali-mcp-server
      provider: docker_desktop
      enabled: true
```

---

### Step 5: Test Integration

**Launch Warp Terminal** and try these commands:

#### Test 1: Check Server Availability

In Warp, invoke the AI assistant and ask:
```
List all MCP servers available
```

You should see **"kali-mcp-server"** in the response.

#### Test 2: List Tools

```
What tools are available from kali-mcp-server?
```

Expected response: List of 42 security testing tools.

#### Test 3: Run a Simple Scan

```
Use kali-mcp-server to scan 192.168.1.100 with nmap
```

Expected response: nmap scan results showing open ports and services.

---

## 💡 Usage Examples

### Basic Scans

**Network reconnaissance:**
```
Scan my test server at 192.168.1.50 for open ports
```

**DNS enumeration:**
```
Enumerate DNS records for example.com
```

**WHOIS lookup:**
```
Get WHOIS information for github.com
```

---

### Advanced Workflows

**Combine terminal and MCP commands:**
```bash
# In Warp terminal
export TARGET="testlab.local"

# Then ask AI:
# "Scan $TARGET with nmap and run a vulnerability scan"
```

**Multi-step reconnaissance:**
```
Perform quick recon on example.com:
1. DNS enumeration
2. Subdomain discovery with subfinder
3. Port scan top 1000 ports
```

**Web application testing:**
```
Test https://testapp.local:
1. Run nikto scan
2. Check for common vulnerabilities with nuclei
3. Scan for SQL injection with sqlmap on /login?id=1
```

---

### Warp-Specific Features

**Workflows:** Create Warp workflows that use MCP tools

```yaml
name: "Quick Security Scan"
steps:
  - command: "mcp call kali-mcp-server nmap_scan target={{target}}"
  - command: "mcp call kali-mcp-server dns_enum domain={{target}}"
  - command: "mcp call kali-mcp-server whatweb_scan target=https://{{target}}"
```

**Blocks:** Save common MCP commands as Warp blocks

**History:** Warp preserves MCP command history for quick re-runs

---

## 🔧 Advanced Configuration

### Custom Server Settings

**Resource limits:**
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
```

**Network isolation:**
```yaml
servers:
  kali-mcp-server:
    args:
      - run
      - -i
      - --rm
      - --security-opt
      - no-new-privileges
      - --network
      - isolated_test_network
      - kali-mcp-server:latest
```

**Environment variables:**
```yaml
servers:
  kali-mcp-server:
    env:
      PYTHONUNBUFFERED: "1"
      KALI_MCP_TIMEOUT: "600"
      KALI_MCP_LOG_LEVEL: "INFO"
```

---

### Multiple Servers

Run different configurations simultaneously:

```yaml
servers:
  kali-mcp-fast:
    # Fast scans with limited resources
    command: docker
    args: [run, -i, --rm, --cpus=1, --memory=1g, kali-mcp-server:latest]
  
  kali-mcp-full:
    # Full scans with more resources
    command: docker
    args: [run, -i, --rm, --cpus=4, --memory=4g, kali-mcp-server:latest]
```

---

## 🐛 Troubleshooting

### Warp Can't See Server

**Problem:** Server doesn't appear in Warp's MCP server list

**Solutions:**

1. **Verify Docker MCP is enabled:**
   ```bash
   # Check Docker Desktop settings
   # MCP Toolkit should be enabled
   ```

2. **Restart both applications:**
   ```bash
   # Quit Docker Desktop completely
   # Quit Warp Terminal
   # Start Docker Desktop
   # Start Warp Terminal
   ```

3. **Check registration file:**
   ```bash
   # macOS
   cat ~/.docker/mcp/registry.yaml
   
   # Verify kali-mcp-server is listed
   # Check for YAML syntax errors
   ```

4. **Test server manually:**
   ```bash
   docker run -i --rm kali-mcp-server:latest
   # Should start without errors
   ```

---

### Permission Errors

**Problem:** "Operation not permitted" when running scans

**Solution:**

This is expected behavior for certain operations:
- ✅ **Normal:** ICMP ping operations (nmap uses `-Pn` to bypass)
- ✅ **Normal:** Raw socket operations (Docker MCP security model)

If you see **unexpected** permission errors:

```bash
# Verify security flags are correct
# Check ~/.docker/mcp/registry.yaml includes:
args:
  - --security-opt
  - no-new-privileges
```

---

### Connection Timeouts

**Problem:** Commands timeout or hang

**Common causes:**
1. Target host unreachable
2. Firewall blocking connections
3. Scan taking longer than expected

**Solutions:**

```bash
# Test network connectivity
docker run -it --rm kali-mcp-server:latest ping -c 3 8.8.8.8

# Increase timeout in Warp settings
# Or use faster scan options:
"Use nmap with fast scan (-F flag) on target"
```

---

### No Output

**Problem:** Tool executes but returns no results

**Debug steps:**

1. **Test tool directly:**
   ```bash
   docker run -it --rm kali-mcp-server:latest nmap -sT -Pn -F scanme.nmap.org
   ```

2. **Check Warp logs:**
   - Warp → Settings → Advanced → View Logs
   - Look for MCP connection errors

3. **Verify target format:**
   - IPs: `192.168.1.100`
   - Domains: `example.com`
   - URLs: `https://example.com`

---

### Server Appears Offline

**Problem:** Server shows as "offline" or "unavailable" in Warp

**Solutions:**

1. **Restart Docker MCP:**
   ```bash
   # In Docker Desktop
   # Settings → MCP → Restart MCP Service
   ```

2. **Rebuild the image:**
   ```bash
   docker build --no-cache -t kali-mcp-server:latest .
   ```

3. **Check Docker daemon:**
   ```bash
   docker ps
   # Should show running containers or empty list (not error)
   ```

---

## ⚡ Performance Tips

### Optimize for Warp

1. **Use fast scan modes:**
   ```
   "Quick scan 192.168.1.0/24" → Uses nmap -F
   "Fast recon example.com" → Uses quick_recon tool
   ```

2. **Limit output size:**
   ```
   "Scan top 100 ports on target"
   # Instead of full port range
   ```

3. **Allocate appropriate resources:**
   ```yaml
   # In MCP config
   args:
     - --memory=2g  # Sufficient for most scans
     - --cpus=2     # Balance between speed and system load
   ```

---

## 🔒 Security Considerations

### Warp Terminal Security

1. **Command history:**
   - Warp stores command history locally
   - Sensitive targets may appear in history
   - Clear history regularly if needed

2. **MCP logs:**
   - Warp may log MCP interactions
   - Review log settings in Warp preferences

3. **Network exposure:**
   - MCP communication is local (stdio)
   - No network exposure of MCP protocol
   - Scans originate from Docker network

### Best Practices

1. **Use dedicated test networks:**
   ```yaml
   # Create isolated Docker network
   docker network create test_network
   
   # Use in MCP config
   args:
     - --network
     - test_network
   ```

2. **Limit scope:**
   - Only scan authorized targets
   - Document authorization
   - Use IP whitelists

3. **Monitor usage:**
   - Review Warp MCP logs
   - Track which tools are used
   - Audit scan targets

---

## 🎯 Use Cases

### Penetration Testing Workflow

```
1. "Enumerate example.com with DNS tools"
2. "Discover subdomains using subfinder"
3. "Scan discovered hosts with nmap"
4. "Run web vulnerability scan with nikto"
5. "Check for SQL injection on identified endpoints"
```

### Security Monitoring

```
"Monitor my lab network 192.168.1.0/24:
- Scan for new hosts
- Check open ports
- Identify services
- Report changes"
```

### Vulnerability Research

```
"Research Apache 2.4.49:
- Search exploit-db
- Check Metasploit modules
- Show CVE details"
```

---

## 📚 Additional Resources

- **Warp Documentation:** [warp.dev/docs](https://docs.warp.dev/)
- **MCP Specification:** [modelcontextprotocol.io](https://modelcontextprotocol.io/)
- **Kali Tools Reference:** [README.md](README.md)
- **Deployment Guide:** [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Docker MCP Setup:** [SETUP_DOCKER_MCP.md](SETUP_DOCKER_MCP.md)

---

## 🆘 Getting Help

- **GitHub Issues:** [Report bugs](https://github.com/YOUR-USERNAME/kali-mcp-server/issues)
- **Warp Community:** [Warp Discord/Forums](https://www.warp.dev/community)
- **MCP Community:** [MCP GitHub Discussions](https://github.com/modelcontextprotocol)

---

## 🎉 Success!

You now have Warp Terminal integrated with Kali MCP Server, providing:
- ✅ 42 professional security tools
- ✅ AI-powered terminal interface  
- ✅ Natural language security testing
- ✅ Local, secure execution

**Remember:** Always get authorization before testing any systems.

---

**Quick Reference Card:**

```bash
# Enable Docker MCP
Docker Desktop → Settings → Enable MCP Toolkit

# Register server
Edit ~/.docker/mcp/registry.yaml

# Restart
Quit and restart Docker Desktop + Warp

# Test
"List MCP servers"
"What tools are in kali-mcp-server?"

# Use
"Scan 192.168.1.100 with nmap"
```

---

*Last Updated: October 2025*  
*Version: v2.0.0-release-prep*
