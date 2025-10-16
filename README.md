# 🔐 Kali MCP Server

**Kali Linux Penetration Testing MCP Server v2**

A comprehensive Model Context Protocol (MCP) server providing 42 professional-grade security testing tools from Kali Linux, optimized for ARM64 (Apple Silicon) Macs and Docker MCP Gateway.

[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![ARM64](https://img.shields.io/badge/ARM64-Optimized-green)](https://www.apple.com/mac/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-brightgreen)](https://modelcontextprotocol.io/)

---

## ⚠️ LEGAL WARNING & ETHICAL USE

**READ THIS CAREFULLY BEFORE USING THIS SOFTWARE**

This MCP server provides powerful penetration testing and security assessment tools. You **MUST**:

✅ **DO:**
- Only use on systems you own
- Only use on systems you have explicit written permission to test
- Use for educational and authorized security assessments
- Comply with all applicable laws and regulations
- Document proper authorization before testing

❌ **DO NOT:**
- Test systems without authorization
- Use for malicious purposes
- Violate computer fraud or abuse laws
- Test production systems without proper approval
- Share or distribute unauthorized access

**Unauthorized access to computer systems is ILLEGAL** and may result in criminal prosecution. The authors assume **NO LIABILITY** for misuse of this software.

---

## 📖 Documentation

**⭐ AI-First Security Testing:**
- 🤖 [**Warp AI Terminal Guide**](docs/WARP_TERMINAL_GUIDE.md) - **RECOMMENDED**: Comprehensive AI-assisted security testing with Warp Terminal and Docker MCP Gateway

**Quick Start:**
- 🚀 [**Quick Start Guide**](QUICK_START.md) - Get started in 5 minutes

**Complete Guides:**
- 📚 [**Deployment Guide**](DEPLOYMENT_GUIDE.md) - Comprehensive deployment instructions
- 🐳 [**Docker MCP Gateway Setup**](SETUP_DOCKER_MCP.md) - Detailed Docker MCP Gateway configuration

---

## 📋 Table of Contents

- [Documentation](#documentation)
- [Overview](#overview)
- [Architecture](#architecture)
- [ARM64 Compatibility](#arm64-compatibility)
- [Installation](#installation)
- [Usage](#usage)
- [Tool Reference](#tool-reference)
- [Docker MCP Security Model](#docker-mcp-security-model)
- [Troubleshooting](#troubleshooting)
- [Performance Considerations](#performance-considerations)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

This MCP server provides AI assistants like Claude with access to professional penetration testing tools for authorized security assessments. It includes:

- **42 Security Tools** organized into 8 categories
- **ARM64 Optimized** for Apple Silicon Macs (M1/M2/M3)
- **Docker MCP Compatible** - runs securely without raw socket access
- **Input Sanitization** - prevents command injection attacks
- **Non-root Execution** - enhanced security posture
- **Comprehensive Logging** - tracks all operations

### Key Features

| Feature | Description |
|---------|-------------|
| **Network Reconnaissance** | 11 tools including nmap (6 variants), DNS enumeration (5 tools) |
| **Web Testing** | 11 tools including nikto, sqlmap, directory fuzzing |
| **SSL/TLS Testing** | 3 tools for cipher and vulnerability assessment |
| **SMB/Windows** | 5 tools for Windows/AD enumeration |
| **Password Cracking** | 3 tools - hydra, john, hashcat (CPU-only on ARM64) |
| **Vulnerability Research** | 3 tools - searchsploit, Metasploit search/info, nuclei |
| **OSINT** | 2 tools - theHarvester, whois lookups |
| **Combined Operations** | 4 multi-tool workflows for comprehensive assessments |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│          Warp Terminal / Claude Desktop / MCP Clients        │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP Protocol (stdio)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Docker MCP Gateway                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Security Controls:                                    │  │
│  │ • --security-opt no-new-privileges                   │  │
│  │ • Non-root user execution                            │  │
│  │ • No raw socket capabilities                         │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Docker Bridge
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Kali Linux Docker Container (ARM64)            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ kali_pentest_server.py (FastMCP)                     │  │
│  │ • Input sanitization with shlex.quote()              │  │
│  │ • Command execution via subprocess                   │  │
│  │ • Output formatting and truncation                   │  │
│  └──────────────────────┬───────────────────────────────┘  │
│                         │                                   │
│  ┌──────────────────────▼───────────────────────────────┐  │
│  │ Security Tools (42):                                 │  │
│  │ • nmap (6 variants), dnsrecon, subfinder, amass     │  │
│  │ • nikto, wpscan, sqlmap, ffuf, gobuster, nuclei     │  │
│  │ • sslscan, testssl, sslyze                          │  │
│  │ • enum4linux, crackmapexec, smbclient               │  │
│  │ • hydra, john, hashcat                              │  │
│  │ • searchsploit, metasploit, theHarvester            │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
                   Target Systems
            (Authorized Testing Only)
```

---

## 💻 ARM64 Compatibility

This MCP server is specifically optimized for **Apple Silicon (ARM64)** Macs. The official Kali Linux Docker image supports ARM64, and most tools work excellently.

### ✅ Fully Compatible Tools

All tools listed below work perfectly on ARM64:

- **Network**: nmap, dnsrecon, dnsenum, fierce, subfinder, amass, whois
- **Web**: nikto, wpscan, sqlmap, dirb, ffuf, gobuster, wfuzz, whatweb, wafw00f, nuclei
- **SSL/TLS**: sslscan, sslyze, testssl.sh
- **SMB/Windows**: enum4linux, nbtscan, crackmapexec, smbclient, responder
- **Passwords**: hydra, john (CPU-mode)
- **Research**: searchsploit, metasploit-framework
- **OSINT**: theHarvester, whois

### ⚠️ Tools with Limitations on ARM64

| Tool | Limitation | Notes |
|------|------------|-------|
| **hashcat** | CPU-Only Mode | No GPU acceleration on ARM64; use `--force` flag |
| **metasploit** | Some Module Issues | Most modules work; some x86-specific exploits unavailable |

### ❌ Excluded Tools (Raw Socket Requirements)

These tools require raw socket capabilities incompatible with Docker MCP's security model:

- **netdiscover** - Requires CAP_NET_RAW for ARP scanning
- **arp-scan** - Requires CAP_NET_RAW for ARP operations
- **masscan** - Requires CAP_NET_RAW for raw packet operations

**Alternative**: Use `nmap -sT -Pn` for TCP connect scans without raw sockets, or nmap's various scan modes for comprehensive port scanning.

---

## 📦 Installation

### Quick Installation

For quick setup, see the [**Quick Start Guide**](QUICK_START.md).

For comprehensive installation instructions, see the [**Deployment Guide**](DEPLOYMENT_GUIDE.md).

### Prerequisites

1. **Docker Desktop** - [Download here](https://www.docker.com/products/docker-desktop)
2. **Docker MCP Gateway** - See [Docker MCP Gateway Setup Guide](SETUP_DOCKER_MCP.md)
3. **Apple Silicon Mac** (M1/M2/M3) or ARM64-compatible system
4. **Warp Terminal**, **Claude Desktop**, or other MCP client

### Building the Docker Image

1. **Clone or download this repository**

```bash
git clone https://github.com/YOUR-USERNAME/kali-mcp-server.git
cd kali-mcp-server
```

2. **Build the Docker image**

```bash
docker build -t kali-mcp-server:latest .
```

**Expected build time**: 15-30 minutes (includes downloading Kali packages and compiling Go tools)

3. **Verify the build**

```bash
docker images | grep kali-mcp-server
```

You should see:
```
kali-mcp-server   latest   <image-id>   <time>   ~3.2GB
```

---

## 🚀 Usage

### Configuration Guides

Choose your preferred client:

- **Warp Terminal** (Recommended): See [Warp AI Terminal Guide](docs/WARP_TERMINAL_GUIDE.md) - AI-assisted security testing
- **Claude Desktop**: See [Quick Start Guide](QUICK_START.md) or [Deployment Guide](DEPLOYMENT_GUIDE.md)
- **Docker MCP Gateway**: See [Docker MCP Gateway Setup Guide](SETUP_DOCKER_MCP.md)

### Example Usage

Once configured, you can ask Claude things like:

#### **Network Reconnaissance**
```
"Scan 192.168.1.100 with nmap to find open ports"
"Use subfinder to discover subdomains of example.com"
"Perform comprehensive DNS enumeration on target.local"
```

#### **Web Application Testing**
```
"Run nikto scan on http://testsite.local"
"Test http://example.com/login?id=1 for SQL injection"
"Scan WordPress site at http://blog.local for vulnerable plugins"
"Use ffuf to find hidden directories at http://target.com/FUZZ"
```

#### **SSL/TLS Testing**
```
"Test SSL configuration of api.example.com"
"Run comprehensive SSL scan on secure.local:8443"
"Check example.com for SSL vulnerabilities"
```

#### **SMB & Windows**
```
"Enumerate SMB shares on 192.168.1.50"
"Scan the network 192.168.1.0/24 for NetBIOS information"
"Use crackmapexec to enumerate SMB on target host"
```

#### **Password Testing**
```
"Use hydra to test SSH on 192.168.1.100 with username admin"
"Crack MD5 hashes in /tmp/hashes.txt using john"
```

#### **Research & OSINT**
```
"Search searchsploit for Apache 2.4.49 vulnerabilities"
"Search Metasploit for WordPress exploits"
"Gather information about example.com using theHarvester"
"Get WHOIS information for github.com"
```

#### **Combined Operations**
```
"Perform quick reconnaissance on example.com"
"Do a full security audit of https://testapp.local"
"Sweep my test network 192.168.1.0/24 for devices"
```

---

## 🛠️ Tool Reference

### Network Reconnaissance & Scanning (11 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `nmap_scan` | Basic TCP connect port scan | `target`, `ports` | `nmap_scan target="192.168.1.1" ports="80,443"` |
| `nmap_port_scan` | Scan specific ports | `target`, `ports` | `nmap_port_scan target="192.168.1.1" ports="22,80,443"` |
| `nmap_service_scan` | Service version detection | `target`, `ports` | `nmap_service_scan target="example.com"` |
| `nmap_comprehensive_scan` | Service detection with NSE scripts | `target`, `ports` | `nmap_comprehensive_scan target="192.168.1.100"` |
| `nmap_script_scan` | Run specific NSE script categories | `target`, `ports`, `scripts` | `nmap_script_scan target="192.168.1.100" scripts="vuln"` |
| `nmap_vuln_scan` | Vulnerability scanning with NSE vuln scripts | `target` | `nmap_vuln_scan target="192.168.1.100"` |
| `dns_enum` | DNS enumeration (nslookup, dig, host) | `domain` | `dns_enum domain="example.com"` |
| `dns_recon` | Advanced DNS reconnaissance | `domain` | `dns_recon domain="target.com"` |
| `subfinder_scan` | Fast subdomain discovery | `domain` | `subfinder_scan domain="example.com"` |
| `amass_enum` | Comprehensive OWASP Amass enumeration | `domain`, `mode` | `amass_enum domain="target.com" mode="passive"` |
| `fierce_scan` | DNS recon with zone transfer attempts | `domain` | `fierce_scan domain="example.com"` |

### Web Application Testing (11 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `nikto_scan` | Web server vulnerability scanner | `target`, `port` | `nikto_scan target="example.com" port="80"` |
| `wpscan_scan` | WordPress vulnerability scanner | `target`, `enumerate` | `wpscan_scan target="http://blog.com" enumerate="vp"` |
| `dirb_scan` | Directory brute-forcing | `target`, `wordlist` | `dirb_scan target="http://example.com" wordlist="common"` |
| `ffuf_scan` | Fast web fuzzer | `target`, `wordlist`, `extensions` | `ffuf_scan target="http://example.com/FUZZ"` |
| `gobuster_scan` | High-speed directory/DNS brute-forcing | `target`, `wordlist`, `mode` | `gobuster_scan target="http://example.com" mode="dir"` |
| `wfuzz_scan` | Advanced web fuzzing | `target`, `wordlist`, `hide_code` | `wfuzz_scan target="http://example.com/FUZZ"` |
| `sqlmap_scan` | SQL injection testing | `target`, `data`, `parameter` | `sqlmap_scan target="http://example.com/page?id=1"` |
| `whatweb_scan` | Web technology fingerprinting | `target`, `aggression` | `whatweb_scan target="example.com" aggression="1"` |
| `wafw00f_scan` | WAF detection | `target` | `wafw00f_scan target="http://example.com"` |
| `nuclei_scan` | Template-based vulnerability scanner | `target`, `templates`, `severity` | `nuclei_scan target="http://example.com" severity="high"` |
| `web_headers` | HTTP header analysis | `target` | `web_headers target="http://example.com"` |

### SSL/TLS Testing (3 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `sslscan_scan` | SSL/TLS cipher and protocol testing | `target`, `port` | `sslscan_scan target="example.com" port="443"` |
| `testssl_scan` | Comprehensive SSL/TLS vulnerability assessment | `target`, `port` | `testssl_scan target="api.example.com"` |
| `sslyze_scan` | Fast SSL/TLS configuration analysis | `target`, `port` | `sslyze_scan target="secure.example.com"` |

### SMB & Windows Enumeration (5 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `enum4linux_scan` | SMB/CIFS enumeration | `target` | `enum4linux_scan target="192.168.1.50"` |
| `nbtscan_scan` | NetBIOS nameserver scanner | `target` | `nbtscan_scan target="192.168.1.0/24"` |
| `crackmapexec_scan` | Windows/AD network enumeration | `target`, `protocol` | `crackmapexec_scan target="192.168.1.100" protocol="smb"` |
| `responder_analyze` | Information about Responder tool | - | `responder_analyze` (returns usage info) |
| `smb_enum` | SMB share enumeration | `target` | `smb_enum target="192.168.1.50"` |

### Password & Credential Testing (3 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `hydra_attack` | Network service password brute-forcing | `target`, `service`, `username`, `password_list` | `hydra_attack target="192.168.1.100" service="ssh" username="admin"` |
| `john_crack` | Password hash cracking | `hash_file`, `format` | `john_crack hash_file="/tmp/hashes.txt" format="raw-md5"` |
| `hashcat_crack` | Advanced password cracking (CPU-only on ARM64) | `hash_file`, `mode`, `wordlist` | `hashcat_crack hash_file="/tmp/hashes.txt" mode="0"` |

### Vulnerability Research & Exploitation (3 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `searchsploit_search` | Search exploit database | `query` | `searchsploit_search query="Apache 2.4"` |
| `metasploit_search` | Search Metasploit modules | `query` | `metasploit_search query="wordpress"` |
| `metasploit_info` | Get Metasploit module information | `module` | `metasploit_info module="exploit/windows/smb/ms17_010_eternalblue"` |

### OSINT & Information Gathering (2 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `theharvester_scan` | Email, subdomain, and host gathering | `domain`, `source` | `theharvester_scan domain="example.com" source="google"` |
| `whois_lookup` | Domain registration information | `domain` | `whois_lookup domain="example.com"` |

### Combined Operations (4 tools)

| Tool | Description | Parameters | Example |
|------|-------------|------------|---------|
| `quick_recon` | Fast multi-tool reconnaissance | `target` | `quick_recon target="example.com"` |
| `full_recon` | Comprehensive multi-tool assessment | `target` | `full_recon target="example.com"` |
| `web_audit` | Complete web application audit | `target` | `web_audit target="http://testapp.local"` |
| `network_sweep` | Full network discovery | `target` | `network_sweep target="192.168.1.0/24"` |

---

## 🔒 Docker MCP Security Model

### Security Restrictions

Docker MCP Gateway implements several security controls that affect tool behavior:

#### 1. **`--security-opt no-new-privileges`**

This flag prevents processes from gaining elevated capabilities at runtime, even if set with `setcap` during Docker build.

**Impact**: Tools like `nmap` cannot acquire `CAP_NET_RAW` capability for raw socket operations.

**Solution**: All nmap scans use `-sT` (TCP connect) and `-Pn` (skip ping/host discovery) flags to work without raw sockets.

#### 2. **Non-root User Execution**

Container runs as user `pentest` (UID 1000), not root.

**Impact**: Cannot bind to privileged ports (<1024) or perform operations requiring root.

**Benefit**: Enhanced security - compromised container cannot escalate to root.

#### 3. **No Raw Socket Access**

Raw socket capabilities are intentionally disabled for security.

**Impact**: 
- ❌ Cannot use ICMP ping for host discovery
- ❌ Cannot perform ARP scans
- ❌ Cannot use SYN scans (`-sS` in nmap)

**Alternatives**:
- ✅ Use TCP connect scans (`-sT`)
- ✅ Skip host discovery with `-Pn` flag
- ✅ Use application-layer protocols for enumeration

### Security Best Practices

When using this MCP server:

1. **Always get written authorization** before testing any system
2. **Document your authorization** and keep records
3. **Use VPN or controlled networks** for testing
4. **Monitor logs** - all operations are logged to stderr
5. **Rate limit scans** to avoid detection/blocking
6. **Respect scope limits** - only test authorized targets
7. **Report findings responsibly** through proper channels

---

## 🐛 Troubleshooting

### Common Issues

#### **1. "Operation not permitted" errors with nmap**

**Problem**: Nmap trying to use raw sockets for ping/discovery.

**Solution**: All nmap functions already use `-Pn` flag. If error persists, verify target is reachable via TCP.

```bash
# Test connectivity first
docker run --rm kali-mcp-server:v2 python3 -c "import subprocess; subprocess.run(['nc', '-zv', 'target.com', '80'])"
```

#### **2. Tools not found**

**Problem**: Tool not installed in Docker image.

**Solution**: Rebuild Docker image:

```bash
docker build --no-cache -t kali-mcp-server:v2 .
```

#### **3. Timeout errors**

**Problem**: Scan taking too long.

**Solution**: 
- Reduce scan scope (fewer ports, smaller network range)
- Use faster scan options (`-F` for nmap fast scan)
- Increase timeout values in code if needed

#### **4. No output from tool**

**Problem**: Tool completed but produced no output.

**Solution**: Check tool-specific requirements:
- WordPress URL for wpscan must be accessible
- SQL injection target must have injectable parameter
- DNS tools require valid domain names

#### **5. Scan performance optimization**

**Problem**: Large scans taking too long.

**Solution**: 
- Use nmap's `-F` (fast scan) for top 100 ports
- Limit port ranges: `ports="1-1000"` instead of full range
- Use `nmap_port_scan` for specific ports
- Consider parallel execution for multiple targets

#### **6. hashcat "No devices found" error**

**Problem**: GPU acceleration not available on ARM64.

**Solution**: This is expected - hashcat uses CPU-only mode on ARM64. The `--force` flag is already added to bypass GPU requirement.

#### **7. Metasploit module failures**

**Problem**: Some Metasploit modules don't work on ARM64.

**Solution**: 
- Use `searchsploit` for vulnerability research
- Some x86-specific payloads won't work on ARM64
- Most reconnaissance modules work fine

---

## ⚡ Performance Considerations

### ARM64 vs x86_64 Performance

| Tool Category | ARM64 Performance | Notes |
|---------------|-------------------|-------|
| **Network Scanning** | ✅ Excellent | nmap performs well on ARM64 |
| **Web Testing** | ✅ Excellent | Go-based tools (ffuf, gobuster) very fast |
| **SSL/TLS Testing** | ✅ Excellent | testssl.sh, sslscan work great |
| **Password Cracking** | ⚠️ Slower | CPU-only hashcat; john works but slower |
| **Port Scanning** | ✅ Excellent | nmap with multiple scan modes available |
| **Exploitation** | ⚠️ Limited | Some Metasploit modules unavailable |

### Optimization Tips

1. **Use appropriate scan scopes**
   - Use nmap's various scan modes for different purposes
   - Use nmap's `-F` (fast) flag for quick scans
   - Limit port ranges to commonly used ports (e.g., 1-1000)

2. **Parallel operations**
   - Combined operations (quick_recon, full_recon) run sequentially
   - For parallel scans, call individual tools separately

3. **Resource limits**
   - Docker containers share host resources
   - Large scans may impact system performance
   - Monitor Docker Desktop resource usage

4. **Wordlist selection**
   - Use "common" wordlists for faster brute-forcing
   - "big" wordlists take significantly longer
   - Consider custom targeted wordlists

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. **Fork** the repository
2. **Create a feature branch**: `git checkout -b feature/new-tool`
3. **Add new tools** following existing patterns:
   - Single-line docstrings
   - Parameters default to `""`
   - Use `subprocess.run()` with command lists
   - Sanitize inputs with `shlex.quote()`
   - Add to appropriate category
4. **Test on ARM64** Mac to ensure compatibility
5. **Update README** with new tool documentation
6. **Submit pull request** with detailed description

### Adding New Tools

When adding tools, ensure they:
- ✅ Work on ARM64 architecture
- ✅ Don't require raw socket capabilities
- ✅ Follow MCP best practices (single-line docstrings, no type hints)
- ✅ Include input sanitization
- ✅ Return formatted strings
- ✅ Have proper error handling

---

## 📄 License

MIT License

Copyright (c) 2025 Kali MCP Server Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 📞 Support & Contact

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Join community discussions for tips and best practices
- **Security**: Report security vulnerabilities privately

---

## 🙏 Acknowledgments

- **Kali Linux Team** - For the comprehensive penetration testing distribution
- **MCP Community** - For the Model Context Protocol framework
- **Tool Authors** - For creating the security testing tools included
- **Docker** - For containerization technology

---

## 📚 Additional Resources

### Project Documentation

- [Warp AI Terminal Guide](docs/WARP_TERMINAL_GUIDE.md) - **Recommended**: Complete AI-assisted security testing guide
- [Quick Start Guide](QUICK_START.md) - 5-minute setup
- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Complete deployment instructions
- [Docker MCP Gateway Setup](SETUP_DOCKER_MCP.md) - Docker MCP Gateway configuration

### External Resources

- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Docker MCP Gateway Documentation](https://docs.docker.com/mcp/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

**Remember**: With great power comes great responsibility. Use these tools ethically and legally.

Happy (authorized) hacking! 🎯🔒
