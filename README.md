<div align="center">

# Content Registry MCP

**MCP server for content registry mcp operations**

[![PyPI](https://img.shields.io/pypi/v/meok-content-registry-mcp)](https://pypi.org/project/meok-content-registry-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Content Registry MCP provides AI-powered tools via the Model Context Protocol (MCP).

## Tools

| Tool | Description |
|------|-------------|
| `register_content` | Register content with a cryptographic hash and timestamp. Returns a registration |
| `verify_content` | Verify registered content integrity by comparing hashes. Provide content + regis |
| `search_registry` | Search the registry by title/tag query, hash, author, content type, or status. |
| `get_provenance_chain` | Get the full provenance trail for a registered content item - all events from re |
| `revoke_registration` | Revoke a content registration. Content record is preserved but marked as revoked |

## Installation

```bash
pip install meok-content-registry-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "content-registry": {
      "command": "python",
      "args": ["-m", "meok_content_registry_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
