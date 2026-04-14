#!/usr/bin/env python3
import json, hashlib, time
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("content-registry-mcp")
_REGISTRY: dict = {}
@mcp.tool(name="register_content")
async def register_content(title: str, content: str, author: str) -> str:
    cid = hashlib.sha256(content.encode()).hexdigest()[:16]
    _REGISTRY[cid] = {"title": title, "author": author, "hash": cid, "registered_at": time.time()}
    return json.dumps({"content_id": cid, "status": "registered"})
@mcp.tool(name="verify_ownership")
async def verify_ownership(content_id: str, author: str) -> str:
    entry = _REGISTRY.get(content_id)
    return json.dumps({"verified": entry is not None and entry["author"] == author, "registered_at": entry["registered_at"] if entry else None})
if __name__ == "__main__":
    mcp.run()
