#!/usr/bin/env python3

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import json, hashlib, time
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("content-registry-mcp")
_REGISTRY: dict = {}
@mcp.tool(name="register_content")
async def register_content(title: str, content: str, author: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    cid = hashlib.sha256(content.encode()).hexdigest()[:16]
    _REGISTRY[cid] = {"title": title, "author": author, "hash": cid, "registered_at": time.time()}
    return {"content_id": cid, "status": "registered"}
@mcp.tool(name="verify_ownership")
async def verify_ownership(content_id: str, author: str, api_key: str = "") -> str:
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    entry = _REGISTRY.get(content_id)
    return {"verified": entry is not None and entry["author"] == author, "registered_at": entry["registered_at"] if entry else None}
if __name__ == "__main__":
    mcp.run()
