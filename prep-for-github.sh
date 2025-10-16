#!/bin/bash
# Kali MCP Server - GitHub Release Preparation Script
# This script completes the cleanup and preparation for public release

set -e  # Exit on error

REPO_DIR="/Users/scottacrosby/Google Drive/My Drive/warp_files/projects/MCPs/kali-mcp-server-v2"
cd "$REPO_DIR"

echo "🔧 Completing sanitization..."

# Fix IMPLEMENTATION_NOTES.md (redo with simpler pattern)
sed -i '' -e 's|docker1\.local\.securebine\.com|example.com|g' \
          -e 's|10\.0\.0\.101|192.168.1.100|g' \
          -e 's|authentik1\.local\.securebine\.com|service.example.com|g' \
          -e 's|/Users/.*/kali-mcp-server-v2|/path/to/kali-mcp-server|g' \
          IMPLEMENTATION_NOTES.md

# Fix IMPLEMENTATION_SUMMARY.md (redo with simpler pattern)
sed -i '' -e 's|/Users/.*/kali-mcp-server-v2|/path/to/kali-mcp-server|g' \
          -e 's|local\.securebine\.com|example.com|g' \
          -e 's|scottacrosby||g' \
          IMPLEMENTATION_SUMMARY.md

echo "✅ Sanitization complete"

# Global PII sweep
echo "🔍 Running final PII sweep..."
grep -RIn --exclude-dir=.git -E "securebine|scottacrosby|/Users/scottacrosby|10\.0\.0\." . || echo "✅ No remaining PII found"

echo "📝 Creating new documentation files..."

# Create .gitignore
cat > .gitignore << 'GITIGNORE_END'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Virtual environments
venv/
env/
ENV/
env.bak/
venv.bak/

# macOS
.DS_Store
.AppleDouble
.LSOverride
._*
.Spotlight-V100
.Trashes
.Trash-*/
ehthumbs.db
Thumbs.db

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# Logs
*.log
logs/
tmp/
temp/

# Testing and coverage
.pytest_cache/
.mypy_cache/
.coverage
htmlcov/

# Build artifacts
build/
dist/
*.egg-info/

# Docker
.dockerignore

# Environment files
.env
.env.local
.env.production
*.env

# Backup files
*.bak
*.backup
*~
GITIGNORE_END

echo "✅ Created .gitignore"

# Create LICENSE
cat > LICENSE << 'LICENSE_END'
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
LICENSE_END

echo "✅ Created LICENSE"

# The script continues with creating all remaining files...
# Due to length, the full script continues in a separate file creation

echo "🎉 Phase 1 & 2 Complete - Files sanitized and core docs created"
echo "📋 Next: Run deploy_guide_creator.sh to create remaining guides"
