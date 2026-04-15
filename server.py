#!/usr/bin/env python3
"""Content Registry MCP Server - Register, verify, and track content provenance with cryptographic hashing."""

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import json, hashlib, time, uuid
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

# Rate limiting
_rate_limits: dict = defaultdict(list)
RATE_WINDOW = 60
MAX_REQUESTS = 30

def _check_rate(key: str) -> bool:
    now = time.time()
    _rate_limits[key] = [t for t in _rate_limits[key] if now - t < RATE_WINDOW]
    if len(_rate_limits[key]) >= MAX_REQUESTS:
        return False
    _rate_limits[key].append(now)
    return True

# In-memory registry (persists for server lifetime)
_REGISTRY: dict = {}
_PROVENANCE_LOG: list = []  # Append-only event log
_HASH_INDEX: dict = {}  # content_hash -> registration_id

mcp = FastMCP("content-registry", instructions="Register content with cryptographic hashes and timestamps, verify integrity, search the registry, and track full provenance chains. Uses SHA-256 hashing.")


def _compute_content_hash(content: str) -> str:
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _log_event(registration_id: str, event_type: str, details: dict) -> dict:
    """Append an immutable event to the provenance log."""
    event = {
        "event_id": str(uuid.uuid4())[:12],
        "registration_id": registration_id,
        "event_type": event_type,
        "timestamp": time.time(),
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "details": details,
    }
    _PROVENANCE_LOG.append(event)
    return event


@mcp.tool()
def register_content(title: str, content: str, author: str, content_type: str = "text", tags: str = "", api_key: str = "") -> str:
    """Register content with a cryptographic hash and timestamp. Returns a registration ID for future verification."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    if not content.strip():
        return json.dumps({"error": "Content cannot be empty"})
    if not title.strip():
        return json.dumps({"error": "Title cannot be empty"})
    if not author.strip():
        return json.dumps({"error": "Author cannot be empty"})

    content_hash = _compute_content_hash(content)

    # Check for duplicate registration
    if content_hash in _HASH_INDEX:
        existing_id = _HASH_INDEX[content_hash]
        existing = _REGISTRY.get(existing_id)
        if existing and existing.get("status") == "active":
            return json.dumps({
                "error": "duplicate_content",
                "message": "Content with identical hash already registered",
                "existing_registration_id": existing_id,
                "existing_title": existing["title"],
                "registered_by": existing["author"],
                "registered_at": existing["registered_at_iso"],
            })

    registration_id = f"CR-{str(uuid.uuid4())[:8]}"
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    now = time.time()
    entry = {
        "registration_id": registration_id,
        "title": title,
        "author": author,
        "content_type": content_type,
        "content_hash": content_hash,
        "content_length": len(content),
        "word_count": len(content.split()),
        "tags": tag_list,
        "status": "active",
        "registered_at": now,
        "registered_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": 1,
        "previous_versions": [],
    }

    _REGISTRY[registration_id] = entry
    _HASH_INDEX[content_hash] = registration_id

    _log_event(registration_id, "registration", {
        "title": title,
        "author": author,
        "content_hash": content_hash,
        "content_type": content_type,
    })

    return json.dumps({
        "registration_id": registration_id,
        "content_hash": content_hash,
        "status": "registered",
        "title": title,
        "author": author,
        "registered_at": entry["registered_at_iso"],
        "verification_url": f"https://registry.meok.ai/verify/{registration_id}",
    })


@mcp.tool()
def verify_content(content: str, registration_id: str = "", expected_hash: str = "", api_key: str = "") -> str:
    """Verify registered content integrity by comparing hashes. Provide content + registration_id or expected_hash."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    if not content.strip():
        return json.dumps({"error": "Content cannot be empty"})

    current_hash = _compute_content_hash(content)

    # Verify against registration
    if registration_id:
        entry = _REGISTRY.get(registration_id)
        if not entry:
            return json.dumps({
                "verified": False,
                "reason": f"Registration ID '{registration_id}' not found",
                "computed_hash": current_hash,
            })

        hash_match = current_hash == entry["content_hash"]
        is_revoked = entry["status"] == "revoked"

        _log_event(registration_id, "verification_attempt", {
            "computed_hash": current_hash,
            "stored_hash": entry["content_hash"],
            "match": hash_match,
        })

        result = {
            "verified": hash_match and not is_revoked,
            "hash_match": hash_match,
            "registration_id": registration_id,
            "registered_title": entry["title"],
            "registered_author": entry["author"],
            "registered_at": entry["registered_at_iso"],
            "registration_status": entry["status"],
            "computed_hash": current_hash,
            "registered_hash": entry["content_hash"],
            "version": entry["version"],
        }

        if is_revoked:
            result["warning"] = "Registration has been revoked"
        if not hash_match:
            result["warning"] = "Content has been modified since registration"

        return json.dumps(result)

    # Verify against expected hash
    if expected_hash:
        match = current_hash == expected_hash.lower()
        return json.dumps({
            "verified": match,
            "computed_hash": current_hash,
            "expected_hash": expected_hash,
            "match": match,
        })

    # Check if content exists in registry by hash
    existing_id = _HASH_INDEX.get(current_hash)
    if existing_id:
        entry = _REGISTRY[existing_id]
        return json.dumps({
            "found_in_registry": True,
            "registration_id": existing_id,
            "title": entry["title"],
            "author": entry["author"],
            "registered_at": entry["registered_at_iso"],
            "status": entry["status"],
            "content_hash": current_hash,
        })

    return json.dumps({
        "found_in_registry": False,
        "content_hash": current_hash,
        "message": "Content not found in registry. Use register_content to register it.",
    })


@mcp.tool()
def search_registry(query: str = "", content_hash: str = "", author: str = "", content_type: str = "", status: str = "active", limit: int = 20, api_key: str = "") -> str:
    """Search the registry by title/tag query, hash, author, content type, or status."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    if not any([query, content_hash, author, content_type]):
        return json.dumps({"error": "At least one search parameter required (query, content_hash, author, or content_type)"})

    results = []
    query_lower = query.lower()

    for reg_id, entry in _REGISTRY.items():
        if status and entry["status"] != status.lower():
            continue

        match = True
        if query_lower:
            title_match = query_lower in entry["title"].lower()
            tag_match = any(query_lower in tag.lower() for tag in entry["tags"])
            if not (title_match or tag_match):
                match = False
        if content_hash and entry["content_hash"] != content_hash.lower():
            match = False
        if author and author.lower() not in entry["author"].lower():
            match = False
        if content_type and entry["content_type"].lower() != content_type.lower():
            match = False

        if match:
            results.append({
                "registration_id": entry["registration_id"],
                "title": entry["title"],
                "author": entry["author"],
                "content_type": entry["content_type"],
                "content_hash": entry["content_hash"][:16] + "...",
                "status": entry["status"],
                "registered_at": entry["registered_at_iso"],
                "tags": entry["tags"],
                "version": entry["version"],
            })

    # Sort by registration time, newest first
    results.sort(key=lambda x: x["registered_at"], reverse=True)
    results = results[:limit]

    return json.dumps({
        "query": {"text": query, "hash": content_hash, "author": author, "type": content_type, "status": status},
        "total_results": len(results),
        "results": results,
        "registry_size": len(_REGISTRY),
        "searched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@mcp.tool()
def get_provenance_chain(registration_id: str, api_key: str = "") -> str:
    """Get the full provenance trail for a registered content item - all events from registration through any modifications or verifications."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    entry = _REGISTRY.get(registration_id)
    if not entry:
        return json.dumps({"error": f"Registration '{registration_id}' not found"})

    # Collect all events for this registration
    events = [e for e in _PROVENANCE_LOG if e["registration_id"] == registration_id]
    events.sort(key=lambda x: x["timestamp"])

    # Build chain summary
    event_counts = defaultdict(int)
    for event in events:
        event_counts[event["event_type"]] += 1

    # Compute chain hash (hash of all event IDs in order - tamper detection)
    chain_data = "|".join(e["event_id"] for e in events)
    chain_hash = hashlib.sha256(chain_data.encode()).hexdigest()[:24] if events else "empty"

    first_event = events[0] if events else None
    last_event = events[-1] if events else None

    return json.dumps({
        "registration_id": registration_id,
        "title": entry["title"],
        "author": entry["author"],
        "current_status": entry["status"],
        "content_hash": entry["content_hash"],
        "version": entry["version"],
        "chain_hash": chain_hash,
        "total_events": len(events),
        "event_summary": dict(event_counts),
        "first_event": first_event["timestamp_iso"] if first_event else None,
        "last_event": last_event["timestamp_iso"] if last_event else None,
        "events": events,
        "previous_versions": entry["previous_versions"],
        "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@mcp.tool()
def revoke_registration(registration_id: str, reason: str, revoked_by: str, api_key: str = "") -> str:
    """Revoke a content registration. Content record is preserved but marked as revoked."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": "https://meok.ai/pricing"})
    if not _check_rate(api_key or "anon"):
        return json.dumps({"error": "Rate limit exceeded. Try again in 60 seconds."})

    if not reason.strip():
        return json.dumps({"error": "Reason for revocation is required"})
    if not revoked_by.strip():
        return json.dumps({"error": "Revoking party identity is required"})

    entry = _REGISTRY.get(registration_id)
    if not entry:
        return json.dumps({"error": f"Registration '{registration_id}' not found"})

    if entry["status"] == "revoked":
        return json.dumps({
            "error": "already_revoked",
            "message": "Registration is already revoked",
            "registration_id": registration_id,
        })

    # Check authorization (only original author or with reason)
    is_author = revoked_by.lower() == entry["author"].lower()

    # Perform revocation
    entry["status"] = "revoked"
    entry["revoked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry["revoked_by"] = revoked_by
    entry["revocation_reason"] = reason

    # Remove from hash index so same content can be re-registered
    if entry["content_hash"] in _HASH_INDEX:
        del _HASH_INDEX[entry["content_hash"]]

    _log_event(registration_id, "revocation", {
        "reason": reason,
        "revoked_by": revoked_by,
        "is_original_author": is_author,
    })

    return json.dumps({
        "registration_id": registration_id,
        "status": "revoked",
        "title": entry["title"],
        "original_author": entry["author"],
        "revoked_by": revoked_by,
        "is_original_author": is_author,
        "reason": reason,
        "revoked_at": entry["revoked_at"],
        "note": "Registration revoked. Content record preserved for audit trail." + (
            "" if is_author else " WARNING: Revoked by non-original author."
        ),
    })


if __name__ == "__main__":
    mcp.run()
