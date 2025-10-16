# Warp Terminal Guide for Kali MCP Server

**Using Docker MCP Gateway with Warp AI - A Complete Guide for Security Engineers**

---

## ⚠️ CRITICAL LEGAL AND ETHICAL WARNING

**READ THIS BEFORE PROCEEDING**

This guide provides access to powerful penetration testing and security assessment tools. You **MUST**:

✅ **AUTHORIZED TESTING ONLY:**
- Only use on systems you own
- Only use on systems you have **explicit written authorization** to test
- Obtain proper authorization before conducting any security testing
- Document your authorization and maintain records

❌ **PROHIBITED ACTIVITIES:**
- Testing systems without authorization
- Using tools for malicious purposes
- Violating computer fraud and abuse laws
- Testing production systems without proper approval procedures
- Sharing or facilitating unauthorized access

**Unauthorized access to computer systems is ILLEGAL** in virtually all jurisdictions and may result in:
- Criminal prosecution
- Civil liability
- Professional consequences
- Damage to your organization

**The authors and maintainers assume NO LIABILITY for misuse of these tools.**

**ALWAYS REVIEW AI-GENERATED COMMANDS** before execution. Warp AI is a powerful assistant, but YOU are responsible for every command you run.

---

## 📖 Table of Contents

- [Introduction](#introduction)
- [What is the Docker MCP Gateway?](#what-is-the-docker-mcp-gateway)
- [What is Warp AI?](#what-is-warp-ai)
- [Why Use This Setup?](#why-use-this-setup)
- [Prerequisites](#prerequisites)
- [Understanding the Architecture](#understanding-the-architecture)
- [Quick Setup Guide](#quick-setup-guide)
- [Adding the Kali MCP Server](#adding-the-kali-mcp-server)
- [Configuring Warp Terminal](#configuring-warp-terminal)
- [Using Warp AI Features](#using-warp-ai-features)
- [Common Security Operations](#common-security-operations)
- [Managing Multiple MCP Servers](#managing-multiple-mcp-servers)
- [Troubleshooting with Warp AI](#troubleshooting-with-warp-ai)
- [Warp AI Prompt Library](#warp-ai-prompt-library)
- [Best Practices and Security](#best-practices-and-security)
- [Warp Terminal Tips and Tricks](#warp-terminal-tips-and-tricks)
- [Quick Reference Card](#quick-reference-card)
- [Conclusion](#conclusion)
- [Appendix: Real-World Scenarios](#appendix-real-world-scenarios)

---

## Introduction

Welcome, security professionals! This guide will help you set up and use **Docker MCP Gateway** with **Warp Terminal's AI** to conduct authorized security assessments using the Kali MCP Server.

**No programming experience required!** This guide uses a modern approach where:
- One gateway manages all your security tool servers
- Warp AI helps you understand every command and tool output
- You can add multiple tool sets (not just Kali!)
- Everything runs in secure Docker containers with enforced safety controls

### What You'll Learn

1. How to set up the Docker MCP Gateway (the "master controller")
2. How to add the Kali MCP Server with 42 professional security tools
3. How to connect Warp Terminal for AI-assisted security testing
4. How to use Warp AI to conduct safe, authorized assessments
5. How to add other security toolsets to the same gateway

### Who This Guide Is For

- **Network and security engineers** conducting authorized assessments
- **Security professionals** new to AI-assisted testing
- **Penetration testers** looking for safer, faster workflows
- **Anyone** with proper authorization to test systems

You do NOT need to be a programmer or developer. This guide explains everything in plain language.

---

## What is the Docker MCP Gateway?

Think of the Docker MCP Gateway as a **master security control center** that safely manages all your security testing tools.

### Simple Analogy

Imagine you have multiple specialized security toolkits:
- One for network reconnaissance (Kali MCP Server)
- One for your firewall (OPNsense)
- One for your virtualization servers (Proxmox)
- One for other security tools

The Docker MCP Gateway is like a **secure command center** that:
- Manages all these toolkits in one place
- Lets Warp AI talk to all of them through one safe connection
- Enforces strict security controls on every tool
- Makes it easy to add or remove toolkits
- Keeps everything organized and traceable

### Without Gateway (Old Way)

```
Warp Terminal → Direct connection to Kali Tools
                (Have to configure each toolkit separately)
                (Harder to enforce security controls)
```

### With Gateway (New Way - What You'll Use)

```
Warp Terminal (AI Assistant)
    ↓ (One secure connection)
Docker MCP Gateway (Security Control Center)
    ├─→ Kali MCP Server (42 security testing tools)
    ├─→ OPNsense MCP Server (firewall management) 
    ├─→ Proxmox MCP Server (VM management)
    └─→ Other Security Tools
         ↓
    Authorized Target Systems
    (WITH WRITTEN PERMISSION ONLY)
```

**Benefits:**
- ✅ One Warp configuration for everything
- ✅ Centralized security controls
- ✅ Easy to add new security toolkits
- ✅ All tools available in one AI conversation
- ✅ Enforced safety restrictions (no raw sockets, non-root, limited privileges)

---

## What is Warp AI?

Warp is a modern terminal with a built-in AI assistant. It's like having an experienced security engineer available 24/7 to:

- **Explain commands** before you run them
- **Help troubleshoot** when scans fail or behave unexpectedly
- **Generate safe commands** for security testing tasks
- **Interpret tool output** - explain what nmap, nikto, or sqlmap results mean
- **Provide guidance** for unfamiliar tools or techniques
- **Validate scope** - help you confirm you're testing authorized targets

### Key Warp Features for Security Engineers

1. **AI Command Help** (`Ctrl+Shift+Space`): Ask AI about anything
2. **Command Explanations**: Highlight any command and ask "What does this do?"
3. **Error Diagnosis**: When a scan fails, AI explains why
4. **Output Interpretation**: AI explains complex security tool output
5. **Command History**: Searchable history with `Ctrl+R`
6. **Workflows**: Save common security testing sequences

### Why This Matters for Security Testing

- **Safer**: AI can help you validate commands before execution
- **Faster**: Quick answers without searching documentation
- **Better Results**: AI helps interpret findings and suggest next steps
- **Learning**: Continuously learn as AI explains tools and techniques
- **Compliance**: AI can help verify you're following proper procedures

---

## Why Use This Setup?

### For Security Engineers Who Aren't Programmers

1. **AI Guidance**: Warp AI helps with Docker commands and tool syntax
2. **Simplified Management**: One gateway manages all security tools
3. **Safety Controls**: Docker enforces security restrictions automatically
4. **Easy Troubleshooting**: Warp AI diagnoses Docker and tool issues
5. **Scalable**: Start with Kali tools, add firewalls and other tools later

### Real-World Example

**Scenario**: You need to assess a web application's security posture.

**Without Gateway and Warp AI**: 
- Open multiple terminals for different tools
- Remember exact command syntax for nmap, nikto, sqlmap
- Interpret cryptic error messages alone
- Manually correlate findings across tools

**With Gateway and Warp AI**:
- Open one Warp terminal
- Ask: "Scan testapp.local for web vulnerabilities - check ports, run nikto, and test for SQL injection"
- AI coordinates tools, explains results, suggests next steps
- All findings in one conversation with context

### ARM64 (Apple Silicon) Optimization

This setup is optimized for Apple Silicon Macs (M1/M2/M3):

✅ **Fully Compatible**: All 42 tools work on ARM64
⚠️ **hashcat**: CPU-only mode (no GPU acceleration on ARM64)
✅ **Performance**: Excellent for most security testing tasks

### Docker Security Model

The Docker MCP Gateway enforces strict security controls:

**Security Restrictions:**
- **No raw sockets**: Cannot perform low-level network operations
- **Non-root execution**: Tools run as unprivileged user
- **No new privileges**: Cannot escalate permissions inside container
- **Isolated network**: Container has controlled network access

**Practical Implications:**
- ✅ nmap works with `-sT` (TCP connect) and `-Pn` (skip ping) flags
- ✅ Most security tools work without modification
- ❌ No ICMP ping scans (but TCP works fine)
- ❌ No ARP scanning (not needed for most assessments)
- ❌ No raw packet operations (use application-layer protocols instead)

These restrictions **enhance security** while still providing 42 professional tools for authorized testing.

---

## Prerequisites

### System Requirements

- **Operating System**: macOS (Apple Silicon or Intel)
- **Docker Desktop**: Version 4.30.0 or newer ([Download here](https://www.docker.com/products/docker-desktop/))
- **Warp Terminal**: Latest version ([Download here](https://www.warp.dev/))
- **Disk Space**: At least 4GB free for Docker images
- **Memory**: 8GB+ RAM recommended for running security tools

### Network Requirements

- **Outbound Access**: To download Docker images and tool updates
- **Target Access**: Network connectivity to **authorized** test systems
- **VPN (Optional)**: For safe access to test environments

### Legal and Authorization Requirements

**CRITICAL - Read Carefully:**

✅ **Before Using Any Tool:**
1. **Get Written Authorization**: Documented permission to test target systems
2. **Define Scope**: Clear list of authorized targets, dates, and tools
3. **Establish Communication**: Contact with system owners during testing
4. **Have Change Control**: If testing production systems, follow change procedures
5. **Document Everything**: Keep records of authorization and activities

❌ **You CANNOT Test:**
- Systems you don't own without written permission
- Production systems without change control approval
- Systems outside documented scope
- Systems where authorization has expired

### Knowledge Requirements

**None!** This guide assumes you're new to:
- Docker containers
- MCP servers and gateways  
- YAML configuration files
- Command-line Docker operations

Warp AI will help you learn as you go!

---

## Understanding the Architecture

Let's understand how all the pieces fit together.

### The Big Picture

```
┌─────────────────────────────────────────────────────────────┐
│                       Your Mac                              │
│                                                             │
│  ┌─────────────────┐                                       │
│  │  Warp Terminal  │                                       │
│  │  (with AI)      │                                       │
│  └────────┬────────┘                                       │
│           │                                                 │
│           │ stdio connection (secure, local)                │
│           ↓                                                 │
│  ┌────────────────────────────────────────────────┐       │
│  │     Docker MCP Gateway Container               │       │
│  │     (The Master Security Control Center)       │       │
│  │                                                 │       │
│  │  Manages all your security tool servers:      │       │
│  │  • Reads catalog files (custom.yaml)          │       │
│  │  • Enforces security restrictions             │       │
│  │  • Routes AI requests safely                  │       │
│  └─────────┬──────────────────────────────────────┘       │
│            │                                                │
│            ├──────────────┬──────────────┬────────────┐   │
│            ↓              ↓              ↓            ↓   │
│  ┌──────────────┐ ┌──────────────┐ ┌─────────┐ ┌────────┐│
│  │   Kali MCP   │ │   OPNsense   │ │ Proxmox │ │ Other  ││
│  │   Server     │ │  MCP Server  │ │   MCP   │ │ Tools  ││
│  │  (42 tools)  │ │  (firewall)  │ │ (VMs)   │ │        ││
│  └──────┬───────┘ └──────┬───────┘ └────┬────┘ └────────┘│
│         │                │               │                 │
│         │ Security restrictions enforced:│                 │
│         │ • No raw sockets              │                 │
│         │ • Non-root user               │                 │
│         │ • No privilege escalation     │                 │
│         │                                                  │
└─────────┼────────────────┼───────────────┼─────────────────┘
          │                │               │
          ↓                ↓               ↓
    ┌──────────┐    ┌──────────┐    ┌──────────┐
    │ Target   │    │ Firewall │    │ VMs      │
    │ Systems  │    │ (mgmt)   │    │ (mgmt)   │
    └──────────┘    └──────────┘    └──────────┘
       (ONLY WITH WRITTEN AUTHORIZATION)
```

### Key Components

1. **Warp Terminal**: Where you type commands and ask AI for help
2. **Docker MCP Gateway**: The master control center that manages everything
3. **Kali MCP Server**: Container with 42 security testing tools
4. **Catalog Files**: YAML files that define available security tool servers
5. **Target Systems**: ONLY systems you have written authorization to test

### Configuration Files Explained

Your Docker MCP Gateway uses several configuration files:

```
~/.docker/mcp/
├── catalogs/
│   ├── docker-mcp.yaml      # Official servers (GitHub, AWS, etc.)
│   └── custom.yaml           # YOUR custom servers (Kali, OPNsense, etc.)
├── config.yaml               # Server-specific configurations
├── registry.yaml             # List of all registered servers
└── tools.yaml                # Tool-specific settings (usually empty)
```

**You'll mainly work with `custom.yaml`** to add your Kali MCP server!

**Simple Explanation:**
- `custom.yaml` is like your **phonebook** of security tool servers
- `registry.yaml` is like your **favorites list** of which servers to use
- `config.yaml` stores **specific settings** for each server

---

## Quick Setup Guide

Let's get everything set up step-by-step. Warp AI will help you at each stage.

### Step 1: Install Docker Desktop

1. Download Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop/)
2. Install and open Docker Desktop
3. Wait for Docker to start (you'll see a green "Running" status)
4. Accept the Docker Desktop service agreement if prompted

**Verify Docker is running:**

```bash
docker --version
```

You should see something like: `Docker version 24.0.x, build ...`

**Ask Warp AI if you get an error:**
```
"I got this error when checking Docker version: [paste error]. How do I fix it?"
```

### Step 2: Enable MCP in Docker Desktop

1. Open **Docker Desktop**
2. Click **Settings** (gear icon)
3. Navigate to **Features** (may be under Extensions or Advanced depending on version)
4. Find **"MCP"** or **"Model Context Protocol"** or **"MCP Gateway"**
5. Toggle to **Enabled**
6. Click **Apply & Restart**

**Note**: The exact location varies by Docker Desktop version. Look for "MCP" in settings.

**Ask Warp AI if you can't find it:**
```
"Where is the MCP setting in Docker Desktop version [your version]?"
```

### Step 3: Create the MCP Directory Structure

This creates all the folders you need:

```bash
mkdir -p ~/.docker/mcp/catalogs
```

**Verify it was created:**

```bash
ls -la ~/.docker/mcp/
```

**Ask Warp AI:**
```
"What does the mkdir -p command do?"
```

### Step 4: Create Empty Configuration Files

Let's create the configuration files that the gateway needs:

```bash
# Create empty config files
touch ~/.docker/mcp/config.yaml
touch ~/.docker/mcp/registry.yaml
touch ~/.docker/mcp/tools.yaml
```

**Explanation**: These files will be used by the Docker MCP Gateway. We'll add content to them in the next steps.

**Ask Warp AI:**
```
"Explain what these YAML files are for in the Docker MCP Gateway"
```

**Congratulations!** The basic setup is complete. Next, we'll add the Kali MCP Server.

---

## Adding the Kali MCP Server

Now let's add the Kali MCP Server with its 42 security tools to your gateway.

### Step 1: Build the Kali MCP Server Docker Image

First, get the Kali MCP server code (if you haven't already):

```bash
cd ~/Documents
git clone https://github.com/YOUR-USERNAME/kali-mcp-server.git
cd kali-mcp-server
```

**Build the Docker image:**

```bash
docker build -t kali-mcp-server:latest .
```

⏱️ **Build time**: 15-30 minutes (downloads Kali tools and packages)

**Ask Warp AI while building:**
```
"Explain what 'docker build' is doing while it runs"
```

**Verify the build completed:**

```bash
docker images | grep kali-mcp-server
```

You should see: `kali-mcp-server   latest   [image-id]   [time]   ~3.2GB`

### Step 2: Add to Your Custom Catalog

Create/edit your custom catalog file:

```bash
nano ~/.docker/mcp/catalogs/custom.yaml
```

**Add this content:**

```yaml
version: 2
name: custom
displayName: Custom Security Servers
registry:
  kali-mcp-server:
    description: "Kali Linux penetration testing MCP server with 42 professional security tools. Provides network reconnaissance (nmap variants, DNS enumeration, subdomain discovery), web application testing (nikto, sqlmap, WordPress scanning, fuzzing), SSL/TLS testing, SMB/Windows enumeration, password testing, vulnerability research (searchsploit, Metasploit), OSINT, and combined operations. ARM64 optimized for Apple Silicon. Runs with security restrictions: no raw sockets, non-root user, no new privileges."
    title: "Kali Security Testing Server"
    type: server
    dateAdded: "2025-01-16T00:00:00Z"
    image: kali-mcp-server:latest
    tools:
      # Network Reconnaissance (11 tools)
      - name: nmap_scan
      - name: nmap_port_scan
      - name: nmap_service_scan
      - name: nmap_comprehensive_scan
      - name: nmap_script_scan
      - name: nmap_vuln_scan
      - name: dns_enum
      - name: dns_recon
      - name: subfinder_scan
      - name: amass_enum
      - name: fierce_scan
      # Web Application Testing (11 tools)
      - name: nikto_scan
      - name: wpscan_scan
      - name: dirb_scan
      - name: ffuf_scan
      - name: gobuster_scan
      - name: wfuzz_scan
      - name: sqlmap_scan
      - name: whatweb_scan
      - name: wafw00f_scan
      - name: nuclei_scan
      - name: web_headers
      # SSL/TLS Testing (3 tools)
      - name: sslscan_scan
      - name: testssl_scan
      - name: sslyze_scan
      # SMB/Windows (5 tools)
      - name: enum4linux_scan
      - name: nbtscan_scan
      - name: crackmapexec_scan
      - name: responder_analyze
      - name: smb_enum
      # Password Testing (3 tools)
      - name: hydra_attack
      - name: john_crack
      - name: hashcat_crack
      # Vulnerability Research (3 tools)
      - name: searchsploit_search
      - name: metasploit_search
      - name: metasploit_info
      # OSINT (2 tools)
      - name: theharvester_scan
      - name: whois_lookup
      # Combined Operations (4 tools)
      - name: quick_recon
      - name: full_recon
      - name: web_audit
      - name: network_sweep
    metadata:
      category: security
      tags:
        - pentesting
        - security
        - kali
        - network-security
        - web-security
        - ARM64-optimized
      license: MIT
      owner: local
```

**💡 Field Explanations for Non-Programmers:**

- `version: 2` - The catalog format version (always use 2)
- `registry:` - Your list of available security servers
- `kali-mcp-server:` - The unique name for this server
- `description:` - What this server does (helps Warp AI understand it)
- `image:` - The Docker container to run
- `tools:` - List of all 42 security testing tools available
- `metadata:` - Tags and categories for organization

**⚠️ ARM64 Note**: If you're on Apple Silicon, the image is already ARM64-compatible. No special configuration needed!

**Save the file:**
- Press `Ctrl+X`
- Press `Y` to confirm
- Press `Enter`

**Ask Warp AI:**
```
"Explain what each section of this YAML file does for the Kali MCP server"
```

### Step 3: Register the Server in the Registry

Edit the registry file:

```bash
nano ~/.docker/mcp/registry.yaml
```

**Add this:**

```yaml
registry:
  kali-mcp-server:
    ref: ""
```

**Explanation**: This tells the Docker MCP Gateway that you want to use the `kali-mcp-server` defined in your custom catalog.

**Save**: `Ctrl+X`, `Y`, `Enter`

### Step 4: Restart Docker Desktop

**To apply changes:**
1. Quit Docker Desktop completely (right-click icon → Quit Docker Desktop)
2. Wait 10 seconds
3. Open Docker Desktop again
4. Wait for it to fully start

**Ask Warp AI:**
```
"How do I verify the Docker MCP Gateway has loaded my custom.yaml configuration?"
```

**Congratulations!** The Kali MCP Server is now registered with your Docker MCP Gateway!

---

## Configuring Warp Terminal

Now let's connect Warp Terminal to your Docker MCP Gateway.

### Step 1: Open Warp Settings

1. Open Warp Terminal
2. Press `Cmd+,` (Command + Comma) to open Settings
3. Look for **Features**, **AI**, or **MCP** section in the left sidebar
4. Find **Model Context Protocol (MCP)** or **AI Providers**

**Note**: The exact location varies by Warp version. Look for "MCP" or "AI" related settings.

### Step 2: Configure Docker MCP Gateway Provider

In Warp's MCP settings:

1. **Add Provider**: Click "Add Provider" or "Configure"
2. **Type**: Select "Docker" or "Docker Desktop MCP"
3. **Enable Auto-discovery**: Toggle ON (if available)
4. **Save Changes**

**Alternative (if manual configuration needed):**

If Warp requires manual server configuration:

```json
{
  "mcp-providers": {
    "docker-mcp-gateway": {
      "type": "docker_desktop",
      "auto_discover": true,
      "enabled": true
    }
  }
}
```

**Ask Warp AI:**
```
"How do I configure Docker MCP Gateway as a provider in Warp Terminal?"
```

### Step 3: Verify Connection

**Restart Warp Terminal** completely:
1. Quit Warp (`Cmd+Q`)
2. Reopen Warp

**Verify the connection by asking Warp AI:**

```
"List all available MCP servers"
```

You should see **"kali-mcp-server"** in the response!

**Try listing tools:**

```
"What tools are available from kali-mcp-server?"
```

Expected response: List of 42 security testing tools organized by category.

**If you don't see the server, ask Warp AI:**
```
"The Docker MCP Gateway isn't showing my kali-mcp-server. How do I troubleshoot this?"
```

### Step 4: Test with a Simple Command

**Run a simple, safe test:**

```
"Use kali-mcp-server to get WHOIS information for github.com"
```

Expected response: Domain registration information for github.com.

**Congratulations!** Warp Terminal is now connected to your Kali MCP Server through the Docker MCP Gateway!

---

## Using Warp AI Features

Now that everything is connected, let's learn how to use Warp AI effectively for security testing.

### Feature 1: Command Explanations

**Scenario**: You see a Docker command but don't understand it.

**How to use:**
1. Highlight the command text in Warp
2. Press `Ctrl+Shift+Space` or click the AI sparkle icon
3. Type: "Explain this command"

**Example:**

```bash
docker run -i --rm --security-opt no-new-privileges kali-mcp-server:latest
```

**Ask Warp AI:**
```
"Explain what each part of this Docker command does and why we use these flags"
```

Warp AI will explain:
- `-i`: Interactive mode for stdin communication
- `--rm`: Removes container after it exits (cleanup)
- `--security-opt no-new-privileges`: Security hardening
- Purpose of each flag for the MCP Gateway

### Feature 2: Error Diagnosis

**Scenario**: A security tool fails with an error.

**Example error:**

```
Error: nmap: Operation not permitted
```

**Ask Warp AI:**
```
"I got 'Operation not permitted' when running nmap through kali-mcp-server. Why did this happen and how should nmap be configured for Docker MCP Gateway?"
```

Warp AI will explain:
- This is expected - Docker MCP Gateway restricts raw sockets
- nmap uses `-Pn` flag automatically to work without ICMP ping
- This is a security feature, not a problem
- TCP connect scans (`-sT`) work fine

### Feature 3: Generating Safe Commands

**Scenario**: You want to perform a security task but don't know exact syntax.

**Ask Warp AI:**
```
"I need to scan a test web application at testapp.local for common vulnerabilities. What's the safe way to do this using kali-mcp-server tools?"
```

Warp AI will suggest:
- Start with nmap to find open web ports
- Run nikto for web server scanning
- Consider nuclei for template-based vuln scanning
- Remind you to confirm authorization first

### Feature 4: Interpreting Tool Output

**Scenario**: You run a security tool and get complex output.

**Example**: You ask:
```
"Scan testapp.local with nikto"
```

And get output like:
```
+ Server: Apache/2.4.41
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined.
+ Cookie PHPSESSID created without the httponly flag
...
```

**Ask Warp AI:**
```
"Explain this nikto output in simple terms. Which findings are most critical and what do they mean?"
```

Warp AI will:
- Explain each vulnerability
- Rank findings by severity
- Suggest remediation steps
- Note what's informational vs. exploitable

### Feature 5: Authorization and Scope Validation

**Before running any security test**, always validate with Warp AI:

```
"I'm about to scan the network range 192.168.1.0/24 with nmap. What should I verify before running this? What are the legal and ethical considerations?"
```

Warp AI will remind you to:
- Verify written authorization
- Confirm targets are in-scope
- Check if testing window is active
- Ensure proper change control (if production)
- Document the activity

**Critical**: AI can guide you, but YOU are responsible for authorization compliance.

---

## Common Security Operations

Here are practical workflows for conducting authorized security assessments using Kali MCP Server's 42 tools.

**⚠️ AUTHORIZATION REQUIRED FOR ALL OPERATIONS BELOW**

### Workflow 1: Network Discovery

**Goal**: Identify active hosts and open ports on authorized networks.

**Tools**: `nmap_scan`, `nmap_port_scan`, `nmap_service_scan`, `nmap_comprehensive_scan`, `nmap_script_scan`, `nmap_vuln_scan`

**Ask Warp AI for guidance:**

```
"I have authorization to scan the network 192.168.1.0/24. What's a safe scanning approach that won't disrupt services?"
```

**Example Commands:**

**Quick port scan:**
```
"Use nmap_scan to scan 192.168.1.100 for common ports"
```

**Service identification:**
```
"Run nmap_service_scan on 192.168.1.100 to identify running services"
```

**Comprehensive assessment:**
```
"Perform nmap_comprehensive_scan on 192.168.1.100 - I have authorization and this is a test environment"
```

**Ask Warp AI to interpret results:**
```
"Review these nmap results. What services are running and are any outdated or potentially vulnerable?"
```

**⚠️ Remember**: Docker MCP Gateway security restrictions mean nmap uses `-Pn` (no ping) and `-sT` (TCP connect) automatically. This is safe and expected.

### Workflow 2: DNS and Subdomain Enumeration

**Goal**: Discover DNS records and subdomains for authorized domains.

**Tools**: `dns_enum`, `dns_recon`, `subfinder_scan`, `amass_enum`, `fierce_scan`

**Ask Warp AI:**

```
"I need to enumerate subdomains for example.com (I have authorization). Which tools should I use and in what order?"
```

**Example Workflow:**

**Step 1 - Basic DNS enumeration:**
```
"Use dns_enum to check DNS records for authorized-domain.com"
```

**Step 2 - Advanced DNS reconnaissance:**
```
"Run dns_recon on authorized-domain.com to find additional records"
```

**Step 3 - Subdomain discovery:**
```
"Use subfinder_scan to discover subdomains of authorized-domain.com"
```

**Step 4 - Comprehensive OSINT:**
```
"Run amass_enum in passive mode on authorized-domain.com"
```

**Ask Warp AI:**
```
"Compare the subdomains found by subfinder vs amass. Which tool is more thorough and when should I use each?"
```

### Workflow 3: Web Application Testing

**Goal**: Assess web application security (authorized targets only).

**Tools**: `nikto_scan`, `wpscan_scan`, `dirb_scan`, `ffuf_scan`, `gobuster_scan`, `wfuzz_scan`, `sqlmap_scan`, `whatweb_scan`, `wafw00f_scan`, `nuclei_scan`, `web_headers`

**⚠️ CRITICAL**: Only test web applications you have written authorization to assess.

**Ask Warp AI:**

```
"I have authorization to test the web application at https://testapp.local. What's a comprehensive but safe testing workflow?"
```

**Suggested Workflow:**

**Step 1 - Technology identification:**
```
"Use whatweb_scan to identify the technology stack of https://testapp.local"
```

**Step 2 - WAF detection:**
```
"Check if https://testapp.local has a WAF using wafw00f_scan"
```

**Step 3 - General vulnerability scanning:**
```
"Run nikto_scan on https://testapp.local (authorized testing)"
```

**Step 4 - Directory discovery:**
```
"Use gobuster_scan to find hidden directories on https://testapp.local with common wordlist"
```

**Step 5 - Template-based scanning:**
```
"Scan https://testapp.local with nuclei_scan for common vulnerabilities"
```

**For WordPress sites:**
```
"If this is a WordPress site, run wpscan_scan on https://testapp.local to check for vulnerable plugins"
```

**Ask Warp AI to prioritize findings:**
```
"Review these scan results from nikto, nuclei, and gobuster. What are the top 3 most critical findings I should investigate first?"
```

### Workflow 4: SQL Injection Testing

**Goal**: Test web application for SQL injection vulnerabilities (authorized only).

**Tool**: `sqlmap_scan`

**⚠️ WARNING**: SQL injection testing can disrupt services. Only test during authorized maintenance windows.

**Ask Warp AI:**

```
"I have authorization to test https://testapp.local/login?id=1 for SQL injection during tonight's maintenance window. What precautions should I take?"
```

**Example:**

```
"Test https://testapp.local/login?id=1 for SQL injection using sqlmap_scan - I have written authorization and this is a test environment"
```

**Ask Warp AI to explain results:**
```
"SQLmap found the parameter is injectable. Explain what this means and what the security impact is"
```

### Workflow 5: SSL/TLS Security Testing

**Goal**: Assess SSL/TLS configuration and identify weak ciphers or protocols.

**Tools**: `sslscan_scan`, `testssl_scan`, `sslyze_scan`

**Ask Warp AI:**

```
"I need to test the SSL configuration of api.example.com (authorized). Which tool provides the most comprehensive results?"
```

**Example Workflow:**

**Quick scan:**
```
"Run sslscan_scan on api.example.com port 443"
```

**Comprehensive assessment:**
```
"Use testssl_scan to do a full SSL/TLS security assessment of api.example.com"
```

**Fast alternative:**
```
"Scan api.example.com with sslyze_scan for quick SSL analysis"
```

**Ask Warp AI:**
```
"These SSL scan results show several ciphers. Which ones are weak and should be disabled?"
```

### Workflow 6: SMB and Windows Enumeration

**Goal**: Enumerate Windows systems and SMB shares (authorized networks only).

**Tools**: `enum4linux_scan`, `nbtscan_scan`, `crackmapexec_scan`, `smb_enum`

**Ask Warp AI:**

```
"I have authorization to enumerate SMB on the Windows server at 192.168.1.50. What's the safest approach?"
```

**Example Workflow:**

**Step 1 - SMB share enumeration:**
```
"Use smb_enum to list SMB shares on 192.168.1.50"
```

**Step 2 - Comprehensive SMB/CIFS enumeration:**
```
"Run enum4linux_scan on 192.168.1.50 to enumerate users, shares, and groups"
```

**Step 3 - Network-wide NetBIOS scanning:**
```
"Scan the network 192.168.1.0/24 for NetBIOS information using nbtscan_scan (authorized)"
```

**Step 4 - Advanced enumeration:**
```
"Use crackmapexec_scan with SMB protocol on 192.168.1.50"
```

**Ask Warp AI:**
```
"What information from this SMB enumeration is most valuable for security assessment?"
```

### Workflow 7: Password Security Testing

**Goal**: Test password strength and hash cracking (authorized only, test credentials).

**Tools**: `hydra_attack`, `john_crack`, `hashcat_crack`

**⚠️ CRITICAL**: Only test with authorization. Do not attempt to crack production credentials.

**Ask Warp AI:**

```
"I have test password hashes I need to crack as part of an authorized security assessment. What's the workflow for testing password strength?"
```

**Example Workflow:**

**Hash cracking with john:**
```
"I have MD5 hashes in /tmp/test-hashes.txt (authorized test data). Use john_crack to crack them with format raw-md5"
```

**Advanced cracking with hashcat:**
```
"Use hashcat_crack on /tmp/test-hashes.txt in mode 0 (MD5) - Note: CPU-only on ARM64 Macs"
```

**Network service brute-forcing:**
```
"Test SSH on testserver.local with username 'admin' using hydra_attack (authorized penetration test)"
```

**⚠️ ARM64 Note**: `hashcat_crack` uses CPU-only mode on Apple Silicon (no GPU acceleration).

**Ask Warp AI:**
```
"These passwords were cracked in under 10 seconds. What does this say about the password policy?"
```

### Workflow 8: Vulnerability Research

**Goal**: Research known vulnerabilities for discovered software versions.

**Tools**: `searchsploit_search`, `metasploit_search`, `metasploit_info`

**Ask Warp AI:**

```
"I found Apache 2.4.49 running during my authorized scan. How do I research known vulnerabilities for this version?"
```

**Example Workflow:**

**Search exploit database:**
```
"Search searchsploit for Apache 2.4.49 vulnerabilities"
```

**Search Metasploit modules:**
```
"Look for Metasploit modules related to Apache 2.4.49 using metasploit_search"
```

**Get module details:**
```
"Get detailed information about the exploit/linux/http/apache_mod_cgi_bash_env_exec module using metasploit_info"
```

**Ask Warp AI:**
```
"Which of these vulnerabilities are most critical and applicable to my authorized target?"
```

### Workflow 9: OSINT (Open Source Intelligence)

**Goal**: Gather publicly available information about authorized targets.

**Tools**: `theharvester_scan`, `whois_lookup`

**Example Workflow:**

**WHOIS lookup:**
```
"Get WHOIS information for authorized-domain.com"
```

**Email and subdomain harvesting:**
```
"Use theharvester_scan to gather information about authorized-domain.com from Google sources"
```

**Ask Warp AI:**
```
"What information from WHOIS and theHarvester is most useful for understanding the target's infrastructure?"
```

### Workflow 10: Combined Operations

**Goal**: Perform comprehensive, multi-tool assessments efficiently.

**Tools**: `quick_recon`, `full_recon`, `web_audit`, `network_sweep`

**These tools combine multiple individual tools for faster workflows:**

**Quick reconnaissance:**
```
"Run quick_recon on authorized-target.com - this combines nmap, whatweb, and SSL checks"
```

**Full reconnaissance (takes longer):**
```
"Perform full_recon on authorized-target.com - comprehensive assessment with multiple tools"
```

**Web application audit:**
```
"Run web_audit on https://testapp.local - complete web security assessment"
```

**Network sweep:**
```
"Scan the authorized network 192.168.1.0/24 with network_sweep - discovers hosts and services"
```

**⚠️ Note**: Combined operations can take 15-30+ minutes depending on scope.

**Ask Warp AI:**
```
"Which combined operation should I use for a quick initial assessment vs. a thorough penetration test?"
```

---

## Managing Multiple MCP Servers

One of the biggest advantages of the Docker MCP Gateway is managing multiple security tool servers. Here's how to add more tools beyond Kali.

### Understanding Multi-Server Setup

Your `custom.yaml` can contain multiple security tool servers:

```yaml
version: 2
name: custom
displayName: Custom Security Servers
registry:
  kali-mcp-server:
    # Kali configuration here (42 security tools)
  
  opnsense-mcp:
    # Firewall management here
  
  proxmox-mcp:
    # VM management here
```

### Example: Adding a Second Server

Let's say you want to add OPNsense firewall management.

**Step 1 - Build or pull the OPNsense MCP server:**

```bash
# Example - adjust based on actual server
docker pull opnsense-mcp-server:latest
```

**Step 2 - Add to custom.yaml:**

```bash
nano ~/.docker/mcp/catalogs/custom.yaml
```

Add under `registry:` (after your kali-mcp-server section):

```yaml
  opnsense-mcp:
    description: "OPNsense firewall management server"
    title: "OPNsense Firewall Manager"
    type: server
    dateAdded: "2025-01-16T00:00:00Z"
    image: opnsense-mcp-server:latest
    tools:
      - name: list_firewall_rules
      - name: get_system_status
    metadata:
      category: security
      tags:
        - firewall
        - opnsense
      license: MIT
      owner: local
```

**Step 3 - Add to registry:**

```bash
nano ~/.docker/mcp/registry.yaml
```

Add:

```yaml
  opnsense-mcp:
    ref: ""
```

**Step 4 - Restart Docker Desktop**

Your new server will be available!

### Using Multiple Servers Together

**Example conversation with Warp AI:**

```
"Check the security status of my authorized network: first scan with kali-mcp-server nmap, then review firewall rules with opnsense-mcp"
```

Warp AI will:
1. Connect to kali-mcp-server to run nmap
2. Connect to opnsense-mcp to check firewall rules
3. Correlate the information and present unified findings

**Ask Warp AI:**
```
"What other MCP servers would complement the Kali security tools for a complete security assessment workflow?"
```

---

## Troubleshooting with Warp AI

When things go wrong, Warp AI is your troubleshooting partner. Here are common issues and how to diagnose them with AI assistance.

### Problem 1: Docker MCP Gateway Won't Start

**Symptom:**

```
Error: Cannot connect to MCP gateway
```

**Ask Warp AI:**
```
"Docker MCP Gateway won't start. How do I troubleshoot this?"
```

**Step 1 - Check if Docker is running:**

```bash
docker ps
```

**Step 2 - Check Docker Desktop status:**
- Open Docker Desktop
- Look for green "Running" indicator
- Check for error messages

**Step 3 - Restart Docker Desktop:**
- Quit Docker Desktop completely
- Wait 10 seconds
- Restart

**Ask Warp AI:**
```
"Docker Desktop says it's running but Docker MCP Gateway still won't start. What should I check next?"
```

### Problem 2: Kali MCP Server Not Showing Up

**Symptom**: You added the server but Warp doesn't see it.

**Ask Warp AI:**
```
"I added kali-mcp-server to custom.yaml but it's not showing up in Warp. How do I debug this?"
```

**Step 1 - Verify the configuration file:**

```bash
cat ~/.docker/mcp/catalogs/custom.yaml
```

**Ask Warp AI:**
```
"Can you check if this YAML syntax is correct? [paste your custom.yaml content]"
```

**Step 2 - Check if the image exists:**

```bash
docker images | grep kali-mcp-server
```

**Step 3 - Verify registry.yaml:**

```bash
cat ~/.docker/mcp/registry.yaml
```

**Step 4 - Restart everything:**
1. Quit Warp Terminal
2. Restart Docker Desktop
3. Wait for full initialization
4. Reopen Warp Terminal

**Ask Warp AI:**
```
"Still not showing up. What Docker logs should I check?"
```

### Problem 3: Can't Connect to Target

**Symptom:**

```
Error: Connection timed out
Error: No route to host
```

**Ask Warp AI:**
```
"My Kali MCP scan can't connect to the target 192.168.1.100 with 'Connection timed out'. What should I check?"
```

**Warp AI will guide you through:**

1. **Test basic connectivity:**
   ```bash
   ping 192.168.1.100
   ```

2. **Check if target allows connections:**
   ```bash
   telnet 192.168.1.100 80
   ```

3. **Verify you're on the correct network:**
   ```bash
   ifconfig | grep inet
   ```

4. **Confirm target is in authorized scope**

**Ask Warp AI:**
```
"Ping works but nmap scan times out. What might be blocking the connection?"
```

### Problem 4: Permission Denied Errors

**Symptom:**

```
Error: Operation not permitted
nmap: sendto: Operation not permitted
```

**This is EXPECTED behavior** - Docker MCP Gateway restricts raw sockets for security.

**Ask Warp AI:**
```
"I'm getting 'Operation not permitted' with nmap. Is this normal for Docker MCP Gateway?"
```

**Warp AI will explain:**
- ✅ **Normal**: Docker MCP Gateway blocks raw socket operations (ICMP ping, ARP, SYN scans)
- ✅ **Expected**: nmap automatically uses `-Pn` (skip ping) and `-sT` (TCP connect) 
- ✅ **Works fine**: TCP connect scans work without raw sockets
- ✅ **Security feature**: This restriction enhances container security

**The tools are working correctly** - this is not an error!

**Ask Warp AI:**
```
"Explain why Docker MCP Gateway blocks raw sockets and how this affects security scanning"
```

### Problem 5: Docker Out of Space

**Symptom:**

```
Error: No space left on device
```

**Ask Warp AI:**
```
"Docker says 'no space left on device'. How do I clean up Docker images and containers?"
```

**Warp AI will suggest:**

```bash
# See disk usage
docker system df

# Clean up unused containers, networks, and images
docker system prune -a
```

**Follow-up:**
```
"I cleaned up but still seeing space issues. What else can I check?"
```

### Problem 6: Warp Can't See MCP Servers

**Symptom**: Warp AI doesn't recognize your MCP servers.

**Ask Warp AI:**
```
"Warp AI doesn't show any MCP servers. How do I verify MCP is configured correctly?"
```

**Step 1 - Verify MCP is enabled in Warp:**

1. Open Warp Settings (`Cmd+,`)
2. Go to **Features** or **AI**
3. Check **Model Context Protocol (MCP)** is enabled

**Step 2 - Check Docker MCP provider:**

**Ask Warp AI:**
```
"How do I verify Docker Desktop MCP provider is configured in Warp?"
```

**Step 3 - Restart Warp completely:**

- Quit Warp (`Cmd+Q`)
- Wait 5 seconds
- Open Warp again

**Step 4 - Test connection:**

```
"List all available MCP servers"
```

### Problem 7: Slow Performance / Scans Take Forever

**Symptom**: Security scans are very slow or timing out.

**Ask Warp AI:**
```
"My nmap scan is taking forever on 192.168.1.100. How can I speed this up without compromising results?"
```

**Common causes and solutions:**

1. **Too many ports:**
   ```
   "Instead of scanning all 65535 ports, scan just common ports: run nmap_scan with ports 1-1000"
   ```

2. **Network latency:**
   ```
   "The target network is slow. What nmap timing options can I use for slow networks?"
   ```

3. **Large wordlists:**
   ```
   "My gobuster scan with big wordlist is too slow. Suggest a faster wordlist for initial reconnaissance"
   ```

4. **Resource limits:**
   **Ask Warp AI:**
   ```
   "How do I check if Docker resource limits are slowing down my Kali MCP scans?"
   ```

**ARM64-specific note:**
- Most tools perform well on Apple Silicon
- `hashcat_crack` uses CPU-only mode (slower than GPU)
- This is expected and normal

### Problem 8: hashcat "No devices found" Error

**Symptom:**

```
Error: No devices found/left
hashcat: Device #1: Not a native Intel OpenCL runtime
```

**This is EXPECTED on ARM64 (Apple Silicon)** - not an error!

**Ask Warp AI:**
```
"hashcat says 'no devices found' on my M1 Mac. Is this an error?"
```

**Warp AI will explain:**
- ✅ **Normal**: hashcat runs in CPU-only mode on ARM64 Macs
- ✅ **Expected**: No GPU acceleration available on Apple Silicon
- ✅ **Works**: CPU-mode still cracks passwords, just slower
- ✅ **Automatic**: The `--force` flag is already added

**This is normal behavior** - hashcat is working correctly in CPU mode!

**Ask Warp AI:**
```
"Compare hashcat CPU performance on ARM64 vs alternatives like john for password cracking"
```

---

## Warp AI Prompt Library

Here's a collection of useful prompts organized by category. Save these for quick reference!

### Setup and Docker Prompts

```
"Show me all running Docker containers"

"How do I see Docker container logs for the MCP gateway?"

"What Docker images do I have installed?"

"How much disk space is Docker using?"

"How do I stop all Docker containers?"

"Restart the Docker MCP Gateway"

"What does the --security-opt no-new-privileges flag do?"

"Explain why we use --rm flag with Docker containers"
```

### Configuration Help Prompts

```
"Help me create a custom.yaml file for my Kali MCP server"

"Check if my custom.yaml file has valid YAML syntax"

"Explain each field in the custom.yaml server definition"

"How do I add multiple servers to custom.yaml?"

"What's the difference between custom.yaml and registry.yaml?"

"Where should I put my Docker MCP configuration files?"

"Show me an example custom.yaml with resource limits"
```

### Docker MCP Gateway Prompts

```
"List all MCP servers registered in my gateway"

"Show me what tools are available from kali-mcp-server"

"How do I check if the Docker MCP Gateway is running?"

"Verify my kali-mcp-server configuration"

"What security restrictions does Docker MCP Gateway enforce?"

"How do I add a second security tool server to the gateway?"
```

### Kali Security Operations Prompts

**Network Reconnaissance:**
```
"Scan 192.168.1.100 for open ports using nmap_scan (authorized testing)"

"Identify services running on testserver.local with nmap_service_scan"

"Run comprehensive nmap scan with scripts on authorized target"

"Scan network 192.168.1.0/24 for active hosts (authorized)"

"Check for vulnerabilities on testserver.local using nmap_vuln_scan"
```

**DNS and Subdomains:**
```
"Enumerate DNS records for authorized-domain.com"

"Discover subdomains of authorized-domain.com using subfinder"

"Run comprehensive subdomain enumeration with amass in passive mode"

"Perform DNS reconnaissance on authorized-domain.com with dnsrecon"
```

**Web Application Testing:**
```
"Scan https://testapp.local with nikto (authorized testing)"

"Test https://testapp.local for common web vulnerabilities using nuclei"

"Check if https://testapp.local is a WordPress site and scan for vulnerable plugins"

"Find hidden directories on https://testapp.local using gobuster with common wordlist"

"Test https://testapp.local/login?id=1 for SQL injection (authorized, test environment)"

"Identify the web technology stack of https://testapp.local"

"Check if https://testapp.local has a WAF using wafw00f"
```

**SSL/TLS Testing:**
```
"Test SSL configuration of api.example.com"

"Run comprehensive SSL scan on secure.example.com with testssl"

"Check api.example.com for weak SSL ciphers using sslscan"
```

**SMB/Windows:**
```
"Enumerate SMB shares on 192.168.1.50 (authorized)"

"Run enum4linux on authorized Windows server 192.168.1.50"

"Scan network 192.168.1.0/24 for NetBIOS information (authorized)"
```

**Vulnerability Research:**
```
"Search for Apache 2.4.49 vulnerabilities in exploit-db"

"Find Metasploit modules for WordPress"

"Get details about the Metasploit module exploit/linux/http/apache_mod_cgi_bash_env_exec"
```

**OSINT:**
```
"Get WHOIS information for github.com"

"Gather information about authorized-domain.com using theHarvester"
```

**Combined Operations:**
```
"Perform quick reconnaissance on authorized-domain.com"

"Run full security audit of https://testapp.local (authorized)"

"Scan my test lab network 192.168.1.0/24 for devices and services"
```

### Learning and Understanding Prompts

```
"Explain how Docker MCP Gateway keeps my security testing safe"

"What's the difference between a custom.yaml catalog and registry?"

"Teach me basic Docker commands I should know"

"Explain nmap scan types and when to use each"

"What does the -Pn flag in nmap do and why is it needed in Docker?"

"How does the Docker security model affect Kali MCP tools?"

"What are the most important security tools in the Kali MCP server?"

"Explain ARM64 compatibility for security testing tools"
```

### Troubleshooting Prompts

```
"I got this error: [paste error]. What does it mean and how do I fix it?"

"Why can't Docker MCP Gateway find my kali-mcp-server image?"

"My target server SSH connection is failing. What should I check?"

"Docker MCP Gateway is running but Warp can't connect. Help me debug."

"Why does nmap say 'Operation not permitted' and is this normal?"

"How do I reset my Docker MCP configuration and start fresh?"

"My scans are very slow. How can I optimize performance?"

"hashcat says 'no devices found' on my M1 Mac. Is something wrong?"
```

### Legal and Ethical Prompts

```
"What authorization do I need before scanning a network?"

"Help me create a checklist to verify I have proper authorization"

"What should I document before conducting a security assessment?"

"Review my testing scope: [details]. Am I missing anything?"

"What are the legal risks of security testing without authorization?"

"How do I verify my target is in the authorized scope?"

"What records should I keep during a penetration test?"
```

---

## Best Practices and Security

### Legal and Authorization Best Practices

**MOST IMPORTANT - Always Get Authorization:**

1. **Written Permission Required:**
   - Get explicit written authorization before any security testing
   - Include specific targets, dates, tools, and scope
   - Keep authorization documents secure and accessible

2. **Document Everything:**
   - Testing dates and times
   - Tools and commands used
   - Findings discovered
   - Actions taken

3. **Communicate During Testing:**
   - Notify system owners before testing begins
   - Have emergency contact information
   - Report critical findings immediately
   - Coordinate testing windows

4. **Respect Scope Limits:**
   - ONLY test authorized targets
   - Stay within documented IP ranges/domains
   - Do not exceed authorized tool lists
   - Stop if you discover unexpected scope

5. **Review AI Commands:**
   - ❌ NEVER blindly execute AI-generated commands
   - ✅ ALWAYS review what the command will do
   - ✅ Verify targets are authorized
   - ✅ Ask AI to explain anything unclear

**Ask Warp AI before testing:**
```
"Before I begin testing, help me verify I have proper authorization. What should I check?"
```

### Docker MCP Gateway Best Practices

#### 1. Organize Your Catalog Files

Keep your servers organized in `custom.yaml`:

```yaml
# Group by function
registry:
  # Security Testing Tools
  kali-mcp-server:
    # config
  
  # Firewall Management
  opnsense-mcp:
    # config
  
  # Infrastructure Management
  proxmox-mcp:
    # config
```

#### 2. Use Descriptive Server Names

**Good names:**
- `kali-mcp-server`
- `opnsense-firewall`
- `production-proxmox`

**Bad names:**
- `server1`
- `mcp`
- `test`

#### 3. Document Your Setup

Create a README in your network documentation:

**Ask Warp AI:**
```
"Create a template README to document my MCP security testing setup"
```

#### 4. Keep Docker Images Updated

Regularly update your security tool images:

```bash
# Pull latest base images
docker pull kalilinux/kali-rolling:arm64

# Rebuild your images
cd ~/Documents/kali-mcp-server
docker build -t kali-mcp-server:latest .

# Remove old images
docker image prune
```

**Ask Warp AI:**
```
"How often should I rebuild my Kali MCP server image to get security updates?"
```

#### 5. Monitor Docker Resource Usage

**Check regularly:**

```bash
docker system df
```

**Clean up when needed:**

```bash
docker system prune -a
```

**Ask Warp AI:**
```
"My Docker is using a lot of disk space. What can I safely delete?"
```

### Security Testing Best Practices

#### 1. Start with Least Invasive Tests

**Progressive testing approach:**
1. OSINT and passive reconnaissance first (whois, DNS)
2. Then active scanning (nmap, subdomain discovery)
3. Then service probing (nikto, nuclei)
4. Finally, exploit testing (sqlmap, metasploit) - ONLY if authorized

#### 2. Use Appropriate Scan Intensities

**Ask Warp AI:**
```
"What's the difference between quick_recon and full_recon? Which should I use for initial assessment?"
```

**Guidance:**
- `quick_recon` - Fast, non-intrusive, good for initial assessment
- `nmap -F` - Scan top 100 ports (fast)
- `full_recon` - Comprehensive, takes time, authorized maintenance windows
- `nuclei` with specific templates - Targeted, efficient

#### 3. Rate Limit Your Scans

**Ask Warp AI:**
```
"How can I slow down my nmap scan to avoid overwhelming the target?"
```

#### 4. Test During Approved Windows

- Schedule intrusive tests during maintenance windows
- Notify stakeholders before testing
- Have rollback plans if issues occur
- Test non-production first when possible

#### 5. Backup Before Testing

**Before making changes or testing:**

```
"Document the current state of authorized-target.com before security testing"
```

### Using Warp AI Effectively

#### When to Use Warp AI

✅ **Use Warp AI for:**
- Understanding unfamiliar tools and commands
- Troubleshooting errors and scan failures  
- Explaining tool output and findings
- Generating safe testing workflows
- Learning new security testing techniques
- Verifying command syntax before execution

#### When to Use Official Documentation

✅ **Use Official Documentation for:**
- Critical production assessments
- Regulatory compliance testing
- Final verification before exploiting vulnerabilities
- Detailed tool capabilities and all options
- Legal and liability information

**Best practice**: Use Warp AI to learn and understand, then verify with official documentation for production testing.

---

## Warp Terminal Tips and Tricks

### Essential Keyboard Shortcuts

```
Ctrl+Shift+Space    - Open Warp AI
Ctrl+R              - Search command history
Ctrl+Shift+F        - Search in output
Cmd+K               - Clear screen
Cmd+T               - New tab
Cmd+D               - Split pane horizontally
Cmd+Shift+D         - Split pane vertically
Cmd+[number]        - Switch to tab number
Cmd+W               - Close current tab
```

### Organizing Your Warp Workspace

#### Use Tabs for Different Activities

- **Tab 1**: Network reconnaissance
- **Tab 2**: Web application testing
- **Tab 3**: Report generation and documentation
- **Tab 4**: Docker management and troubleshooting

**Name your tabs:**
Right-click on tab → Rename Tab

#### Use Warp Workflows

Save frequently used testing sequences as Workflows.

**Ask Warp AI:**
```
"How do I create a Warp Workflow for my daily authorized security scans?"
```

**Example Workflow**: "Authorized Network Check"
```bash
# Verify authorization is current
echo "Authorization expires: [DATE] - Targets: [SCOPE]"

# Check Docker MCP Gateway status
docker ps | grep mcp-gateway

# Quick scan of authorized targets
echo "Run: quick_recon on authorized-targets"
```

### Pro Tips for Security Engineers

#### Tip 1: Create Command Aliases

**Ask Warp AI:**
```
"How do I create command aliases in zsh for common Docker MCP operations?"
```

Example aliases:
```bash
# Add to ~/.zshrc
alias mcp-status='docker ps | grep mcp'
alias kali-tools='echo "List kali-mcp-server tools"'
alias scan-auth='echo "Verify authorization before testing"'
```

#### Tip 2: Save Common Testing Commands

Create a cheat sheet file:

```bash
nano ~/security-testing-cheatsheet.txt
```

Add:
```
# Security Testing Cheat Sheet

## Pre-Testing
- Verify authorization is current and documented
- Confirm targets are in scope
- Notify stakeholders

## Network Reconnaissance
- Quick scan: "Run nmap_scan on [target] (authorized)"
- Service ID: "Identify services on [target] with nmap_service_scan"
- Full scan: "Comprehensive nmap_comprehensive_scan on [target] (authorized)"

## Web Testing
- Tech stack: "Identify web technology on [target] with whatweb"
- Quick scan: "Scan [target] with nikto (authorized)"
- Directory discovery: "Find directories on [target] with gobuster"

## SSL Testing
- Quick SSL check: "Test SSL on [target] with sslscan"
- Full assessment: "Comprehensive SSL scan with testssl on [target]"

## Remember: AUTHORIZATION REQUIRED FOR ALL TESTING
```

#### Tip 3: Use Warp AI for Learning

**Daily learning routine:**
```
"Teach me one advanced security testing technique I should know"

"Explain a Docker security concept"

"What's a useful feature of Kali MCP server I might not know about?"

"Describe a real-world penetration testing scenario and how to approach it"
```

#### Tip 4: Build Your Troubleshooting Playbook

Create `~/security-troubleshooting-playbook.md`:

```markdown
# Security Testing Troubleshooting Playbook

## Scan Not Connecting to Target
1. Verify authorization is current
2. Check network connectivity: `ping [target]`
3. Verify target in scope: Review authorization document
4. Test from different network if allowed
5. Ask Warp AI: "Target unreachable - what should I check?"

## Tool Returns No Results
1. Verify target is correct
2. Check if service is actually running
3. Try alternative tool
4. Ask Warp AI: "Tool returned empty results - why might this happen?"

## Permission Denied Errors
1. Check if it's Docker security restriction (expected)
2. Verify Docker MCP Gateway security-opt flags
3. Ask Warp AI: "Is this permission error expected for Docker MCP Gateway?"

## Slow Performance
1. Reduce scan scope (fewer ports, smaller wordlists)
2. Check Docker resource allocation
3. Try during off-peak hours
4. Ask Warp AI: "How can I optimize scan performance?"
```

#### Tip 5: Leverage Warp's Command Blocks

Warp groups commands in blocks. You can:
- Click any block to see its full output
- Search within a block (`Ctrl+Shift+F`)
- Copy block output easily
- Collapse blocks to keep workspace clean
- Share blocks with team members

### Integration with Other Tools

#### Combine with Git for Documentation

**Ask Warp AI:**
```
"How do I create a Git repository to track my security assessment documentation and findings?"
```

#### Use with Reporting Tools

**Ask Warp AI:**
```
"How can I format security tool output for inclusion in an assessment report?"
```

#### Log Testing Activities

```bash
# Create activity log
echo "=== Security Assessment Log $(date) ===" >> ~/security-logs/assessment-$(date +%Y-%m-%d).log

# Log each activity
echo "$(date '+%H:%M:%S') - Ran nmap_scan on authorized-target" >> ~/security-logs/assessment-$(date +%Y-%m-%d).log
```

---

## Quick Reference Card

### Most Common Operations

| Task | How to Do It | Ask Warp AI |
|------|--------------|-------------|
| List servers | "List all MCP servers" | "Show available security tool servers" |
| Check authorization | Review authorization docs | "Help me verify my testing authorization" |
| Network scan | "Scan [target] with nmap_scan (authorized)" | "What's the safest way to scan this target?" |
| Web vulnerability scan | "Scan [target] with nikto (authorized)" | "How should I approach web app testing?" |
| Check SSL | "Test SSL on [target] with sslscan" | "What SSL scan tool is fastest?" |
| Find subdomains | "Discover subdomains of [domain] with subfinder" | "Best tools for subdomain enumeration?" |
| Test SQL injection | "Test [url] for SQLi with sqlmap (authorized)" | "What precautions for SQL injection testing?" |
| Research vulnerability | "Search searchsploit for [software] [version]" | "How do I research CVEs for this version?" |
| Quick assessment | "Run quick_recon on [target] (authorized)" | "What does quick_recon check?" |

### Common Docker Commands

| Task | Command | What It Does |
|------|---------|--------------|
| List containers | `docker ps` | Show running containers |
| View logs | `docker logs [container-id]` | See container output |
| Stop container | `docker stop [container-id]` | Stop a container |
| Remove container | `docker rm [container-id]` | Delete a container |
| List images | `docker images` | Show downloaded images |
| Disk usage | `docker system df` | Check Docker disk space |
| Clean up | `docker system prune -a` | Remove unused containers/images |
| Restart Docker | Quit Docker Desktop, restart | Full Docker restart |

### Common Warp AI Questions

```
"How do I [task]?"

"What does this error mean: [error]"

"Explain this tool output: [paste output]"

"Is this safe to run: [command]"

"What's the best way to [objective]?"

"How do I verify I have proper authorization to test [target]?"

"What should I document during security testing?"

"Interpret these scan results: [paste results]"
```

### Security Testing Workflow Checklist

**Before Testing:**
- [ ] Written authorization obtained and current
- [ ] Targets verified in scope
- [ ] Testing window confirmed
- [ ] Stakeholders notified
- [ ] Backup/rollback plan documented

**During Testing:**
- [ ] Log all activities with timestamps
- [ ] Document findings as discovered
- [ ] Stay within authorized scope
- [ ] Report critical findings immediately
- [ ] Review AI commands before execution

**After Testing:**
- [ ] Complete final documentation
- [ ] Notify stakeholders testing complete
- [ ] Secure all findings and logs
- [ ] Recommendations provided
- [ ] Authorization documents archived

---

## Conclusion

Congratulations! You now know how to use the Docker MCP Gateway with Warp Terminal to conduct authorized security assessments using the Kali MCP Server's 42 professional tools.

### Key Takeaways

1. **Gateway Architecture**: One gateway manages all your security tool servers
2. **Warp AI**: Your 24/7 security testing assistant for commands and troubleshooting
3. **Legal First**: Always get written authorization before any security testing
4. **42 Professional Tools**: Comprehensive capabilities for network, web, SMB, SSL, and vulnerability testing
5. **Safety Built-In**: Docker MCP Gateway enforces security restrictions automatically
6. **ARM64 Ready**: Optimized for Apple Silicon Macs
7. **Scalable**: Easy to add firewalls, VM management, and other security tools

### Next Steps

1. ✅ Set up your Docker MCP Gateway (if you haven't already)
2. ✅ Add your Kali MCP server to the gateway
3. ✅ Configure Warp Terminal
4. ✅ **Get written authorization for testing targets**
5. ✅ Try the basic workflows with authorized systems
6. ✅ Explore adding other MCP servers (firewall, VM management)
7. ✅ Build your testing playbook and documentation

### Getting More Help

**Resources:**
- **Warp AI**: Press `Ctrl+Shift+Space` anytime
- **This Guide**: Bookmark for reference
- **Kali Documentation**: Tool-specific details
- **Docker Documentation**: [docs.docker.com](https://docs.docker.com/)
- **MCP Protocol**: [Model Context Protocol docs](https://modelcontextprotocol.io/)

**Additional Project Documentation:**
- [README.md](../README.md) - Complete tool reference and overview
- [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) - Detailed deployment instructions
- [SETUP_DOCKER_MCP.md](../SETUP_DOCKER_MCP.md) - Docker MCP Gateway configuration details
- [QUICK_START.md](../QUICK_START.md) - 5-minute quick setup

**Community:**
- GitHub Issues - Report bugs and request features
- Warp Community - Terminal tips and tricks
- Docker Forums - Container troubleshooting

---

## Appendix: Real-World Scenarios

### Scenario 1: First Day with Docker MCP Gateway

**Your goal**: Get comfortable with the basics.

**Step 1**: Check gateway is running
```bash
docker ps | grep mcp-gateway
```

**Step 2**: Ask Warp AI
```
"Show me all MCP servers registered in my gateway"
```

**Step 3**: Test Kali MCP connection
```
"List all available tools from kali-mcp-server"
```

**Step 4**: Run a safe, simple test
```
"Use kali-mcp-server to get WHOIS information for github.com"
```

**Step 5**: Interpret results
```
"Explain what this WHOIS information tells me about github.com"
```

### Scenario 2: Authorized Penetration Test

**Problem**: Client authorized you to test their web application at https://client-testapp.com.

**Before Starting - Verify Authorization:**

**Ask Warp AI:**
```
"I'm about to start a penetration test. Help me create a checklist to verify I have proper authorization."
```

**Step 1**: Document authorization
- Written authorization received: [DATE]
- Authorized targets: client-testapp.com
- Authorized tools: All Kali MCP tools
- Testing window: [DATES and TIMES]
- Contact: [CLIENT NAME and PHONE]

**Step 2**: Start with passive reconnaissance

```
"Get WHOIS information for client-testapp.com (authorized penetration test)"

"Use dns_enum to check DNS records for client-testapp.com (authorized)"
```

**Step 3**: Active reconnaissance

```
"Identify the web technology stack of https://client-testapp.com with whatweb (authorized)"

"Check if https://client-testapp.com has a WAF using wafw00f (authorized)"
```

**Step 4**: Vulnerability scanning

```
"Run nikto_scan on https://client-testapp.com (authorized client penetration test)"

"Scan https://client-testapp.com with nuclei for common vulnerabilities (authorized)"
```

**Step 5**: Directory discovery

```
"Find hidden directories on https://client-testapp.com using gobuster with common wordlist (authorized)"
```

**Step 6**: Targeted testing (based on findings)

**Ask Warp AI:**
```
"Based on these scan results, what should I investigate next? Prioritize by severity."
```

**Step 7**: Document and report

**Ask Warp AI:**
```
"How should I organize and document my penetration testing findings for client reporting?"
```

### Scenario 3: Adding Another MCP Server

**Task**: Add OPNsense firewall management to complement your Kali security tools.

**Step 1**: Build/pull the OPNsense MCP server image

**Ask Warp AI:**
```
"I want to add OPNsense MCP server to my gateway. Walk me through the process."
```

**Step 2**: Add to custom.yaml

```bash
nano ~/.docker/mcp/catalogs/custom.yaml
# Add OPNsense server entry
```

**Step 3**: Update registry

```bash
nano ~/.docker/mcp/registry.yaml
# Add OPNsense to registry
```

**Step 4**: Restart Docker Desktop

**Step 5**: Verify in Warp

```
"List all MCP servers - I just added OPNsense"

"Show me tools available from opnsense-mcp"
```

**Step 6**: Test combined operations

```
"First, scan my authorized network with kali-mcp-server nmap, then check firewall rules with opnsense-mcp"
```

### Scenario 4: Preparing for Security Assessment

**Task**: You have a security assessment scheduled for next week.

**Step 1**: Verify current authorization

**Ask Warp AI:**
```
"I have a security assessment next week. What should I verify about my authorization and scope before testing?"
```

**Step 2**: Update tools

```bash
# Update Kali MCP server image
cd ~/Documents/kali-mcp-server
git pull origin main
docker build -t kali-mcp-server:latest .
```

**Step 3**: Test your setup

```
"Run a test scan on scanme.nmap.org to verify my Kali MCP server is working correctly"
```

**Step 4**: Prepare documentation template

**Ask Warp AI:**
```
"Create a template for documenting a security assessment, including authorization, findings, and recommendations sections"
```

**Step 5**: Create testing checklist

**Ask Warp AI:**
```
"Help me create a comprehensive testing checklist for a web application security assessment using Kali MCP tools"
```

**Step 6**: Set up logging

```bash
# Create assessment log directory
mkdir -p ~/security-assessments/[client-name]-$(date +%Y-%m-%d)

# Start activity log
echo "=== Security Assessment: [CLIENT] ===" > ~/security-assessments/[client-name]-$(date +%Y-%m-%d)/activity-log.txt
echo "Date: $(date)" >> ~/security-assessments/[client-name]-$(date +%Y-%m-%d)/activity-log.txt
echo "Authorization: [DETAILS]" >> ~/security-assessments/[client-name]-$(date +%Y-%m-%d)/activity-log.txt
```

**Step 7**: Review scope and rules of engagement

**Ask Warp AI:**
```
"Review my planned testing approach and identify any potential issues or missing authorization details: [DESCRIBE YOUR PLAN]"
```

---

**Version**: 1.0  
**Last Updated**: January 2025  
**For Kali MCP Server v2.0**

**Remember**: With great power comes great responsibility. Always conduct security testing ethically, legally, and with proper authorization.

**Happy (authorized) security testing! 🛡️🔒**
