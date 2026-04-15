# Content Registry MCP Server

> By [MEOK AI Labs](https://meok.ai) — Register, verify, and track content provenance with SHA-256 cryptographic hashing

## Installation

```bash
pip install content-registry-mcp
```

## Usage

```bash
python server.py
```

## Tools

### `register_content`
Register content with a cryptographic hash and timestamp. Returns a registration ID for verification.

**Parameters:**
- `title` (str): Content title
- `content` (str): Content body
- `author` (str): Author name
- `content_type` (str): Content type (default 'text')
- `tags` (str): Comma-separated tags

### `verify_content`
Verify registered content integrity by comparing SHA-256 hashes.

**Parameters:**
- `content` (str): Content to verify
- `registration_id` (str): Registration ID to verify against
- `expected_hash` (str): Expected hash to compare

### `search_registry`
Search the registry by title/tag query, hash, author, content type, or status.

**Parameters:**
- `query` (str): Search query
- `content_hash` (str): Hash filter
- `author` (str): Author filter
- `content_type` (str): Type filter
- `status` (str): Status filter (default 'active')
- `limit` (int): Max results (default 20)

### `get_provenance_chain`
Get the full provenance trail for a registered content item — all events from registration through modifications and verifications.

**Parameters:**
- `registration_id` (str): Registration identifier

### `revoke_registration`
Revoke a content registration. Record is preserved but marked as revoked.

**Parameters:**
- `registration_id` (str): Registration identifier
- `reason` (str): Reason for revocation
- `revoked_by` (str): Revoking party identity

## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT — MEOK AI Labs
