# Kali MCP Server - Quick Start Guide

Get your Kali MCP Server running in **5 minutes or less**.

---

## ⚡ Prerequisites

Before you begin, ensure you have:

- **Docker Desktop** installed ([Download here](https://www.docker.com/products/docker-desktop))
- **OR** Python 3.10+ and pip for local deployment
- **MCP-capable client** (Claude Desktop, Warp Terminal, or another MCP client)
- **Network access** to download dependencies
- **~3GB disk space** for the Docker image

---

## 🚀 Three Simple Steps

### Step 1: Get the Code

```bash
git clone https://github.com/YOUR-USERNAME/kali-mcp-server.git
cd kali-mcp-server
```

### Step 2: Build the Docker Image

```bash
docker build -t kali-mcp-server:latest .
```

⏱️ **Build time:** 15-30 minutes (downloads Kali packages and compiles Go tools)

### Step 3: Configure Your MCP Client

The server communicates via stdio (standard input/output), so your MCP client needs to spawn it with the correct command.

---

## 📱 Client Configuration Examples

### Option A: Claude Desktop

**macOS Config Location:**  
`~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows Config Location:**  
`%APPDATA%\Claude\claude_desktop_config.json`

**Configuration:**
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

**Restart Claude Desktop** after saving the configuration.

---

### Option B: Docker MCP Toolkit (Warp Terminal)

If using Docker Desktop's MCP integration:

1. **Enable MCP** in Docker Desktop Settings
2. **Register the server** (see SETUP_DOCKER_MCP.md for details)
3. **Connect from Warp** (see WARP_SETUP.md for full guide)

Quick registration entry:
```json
{
  "servers": {
    "kali-mcp-server": {
      "type": "stdio",
      "command": "docker",
      "args": ["run", "-i", "--rm", "--security-opt", "no-new-privileges", "kali-mcp-server:latest"]
    }
  }
}
```

---

### Option C: Local Python Deployment

If you prefer running without Docker:

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python3 kali_pentest_server.py
```

**MCP Client Configuration (local mode):**
```json
{
  "mcpServers": {
    "kali-mcp-server": {
      "command": "python3",
      "args": ["/absolute/path/to/kali_pentest_server.py"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

⚠️ **Important:** Use absolute paths, not `~` or relative paths.

---

## ✅ Verify Installation

### Test in Claude Desktop

1. Open Claude Desktop
2. Look for the 🔌 (plug) icon or MCP status indicator
3. Verify "kali-mcp-server" appears in the available tools list

**Ask Claude:**
```
"List all available tools from kali-mcp-server"
```

You should see 42 security testing tools listed.

### Test Basic Commands

Try these simple requests:

**Network Scanning:**
```
"Use nmap to scan 192.168.1.100 for open ports"
"Perform a quick reconnaissance on example.com"
```

**Information Gathering:**
```
"Get WHOIS information for github.com"
"Search searchsploit for Apache vulnerabilities"
```

**DNS Enumeration:**
```
"Enumerate DNS records for example.com"
"Discover subdomains of example.com using subfinder"
```

---

## 🎯 Available Tool Categories

Your server includes **42 tools** across 8 categories:

| Category | Tools | Example Use |
|----------|-------|-------------|
| **Network Recon** | 11 tools | `nmap_scan`, `dns_enum`, `subfinder_scan` |
| **Web Testing** | 11 tools | `nikto_scan`, `sqlmap_scan`, `wpscan_scan` |
| **SSL/TLS** | 3 tools | `sslscan_scan`, `testssl_scan`, `sslyze_scan` |
| **SMB/Windows** | 5 tools | `enum4linux_scan`, `crackmapexec_scan` |
| **Password Testing** | 3 tools | `hydra_attack`, `john_crack`, `hashcat_crack` |
| **Vuln Research** | 3 tools | `searchsploit_search`, `metasploit_search` |
| **OSINT** | 2 tools | `theharvester_scan`, `whois_lookup` |
| **Combined Ops** | 4 tools | `quick_recon`, `full_recon`, `web_audit` |

---

## 🐛 Quick Troubleshooting

### Server Not Starting

**Problem:** Container exits immediately or shows errors.

**Solution:**
```bash
# Run interactively to see logs
docker run -it --rm kali-mcp-server:latest

# Check for error messages
# Common issues: missing dependencies, port conflicts
```

---

### Client Can't Connect

**Problem:** MCP client doesn't show the server or tools.

**Solutions:**
1. **Use absolute paths** in configuration (not `~` or relative paths)
2. **Restart your MCP client** completely (quit and reopen)
3. **Check config file syntax** - ensure valid JSON (use a validator)
4. **View client logs:**
   - Claude Desktop: Help → View Logs
   - Check for connection errors or spawn failures

---

### Permission Errors

**Problem:** "Operation not permitted" errors during scans.

**Solution:**  
This is expected for certain operations. The server uses `-Pn` flags with nmap to avoid raw socket operations. All scans work within Docker's security constraints.

If you see permission errors:
- ✅ **Normal:** ICMP ping operations (nmap uses `-Pn` to skip these)
- ❌ **Problem:** File system or network errors (check Docker settings)

---

### No Output from Tools

**Problem:** Tool executes but returns no results.

**Common Causes:**
1. **Target unreachable** - Verify network connectivity
2. **Firewall blocking** - Check target allows your IP
3. **Invalid target format** - Use correct format (IPs, domains, URLs)

**Debug:**
```bash
# Test Docker networking
docker run -it --rm kali-mcp-server:latest ping -c 3 8.8.8.8

# Test tool directly
docker run -it --rm kali-mcp-server:latest nmap -sT -Pn -F scanme.nmap.org
```

---

### Rebuild After Updates

**Problem:** Code changes or Dockerfile updates not reflected.

**Solution:**
```bash
# Force rebuild without cache
docker build --no-cache -t kali-mcp-server:latest .

# Remove old images (optional)
docker image prune
```

---

## 📚 Next Steps

Now that your server is running:

1. **Read the full documentation:**
   - [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) - Comprehensive deployment options
   - [WARP_SETUP.md](WARP_SETUP.md) - Warp Terminal integration
   - [SETUP_DOCKER_MCP.md](SETUP_DOCKER_MCP.md) - Docker MCP Toolkit details
   - [README.md](README.md) - Complete tool reference

2. **Practice on authorized targets:**
   - Use your own lab environment
   - Try vulnerable testing sites (e.g., testphp.vulnweb.com)
   - **Never** test unauthorized systems

3. **Explore advanced features:**
   - Combined operations (multi-tool workflows)
   - Custom scan profiles
   - Integration with your pentesting workflow

---

## ⚠️ Legal & Security Reminder

**Before using any tool:**

- ✅ **ONLY** test systems you own
- ✅ **GET WRITTEN PERMISSION** for any external testing
- ✅ **COMPLY** with all applicable laws and regulations
- ✅ **DOCUMENT** your authorization

**Unauthorized computer access is illegal and may result in criminal prosecution.**

See [LICENSE](LICENSE) for terms and conditions.

---

## 🆘 Getting Help

- **Issues:** Report bugs via [GitHub Issues](https://github.com/YOUR-USERNAME/kali-mcp-server/issues)
- **Documentation:** Check README.md and deployment guides
- **Community:** Join discussions for tips and best practices

---

## 🎉 Success!

You now have a fully functional Kali MCP Server providing **42 professional security testing tools** through an AI-friendly interface.

**Happy (authorized) hacking!** 🎯🔒

---

**Quick Reference Card:**

```bash
# Build
docker build -t kali-mcp-server:latest .

# Test
docker run -it --rm kali-mcp-server:latest

# Configure client
Edit MCP client config with stdio command

# Verify
Ask: "List available tools from kali-mcp-server"

# Use
Ask: "Scan 192.168.1.100 with nmap"
```

---

*Generated: October 2025*  
*Version: v2.0.0-release-prep*
