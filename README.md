# jina-web-inspector

User-owned read-only TMCP web inspector built on the official Jina Reader API (`https://r.jina.ai`).

It keeps the existing anonymous `read_url` path and adds focused tools for screenshots, rendered HTML, DOM structure, elements, frames, styles, resources, forms, accessibility-like semantics, and page metadata.

## Security boundary

- No arbitrary JavaScript execution tool.
- No cookie, Authorization header, custom header, or credential input.
- Only public `http`/`https` URLs are accepted; obvious loopback/private literal addresses are rejected.
- Form values, inline script bodies, cookies, storage values, and request headers are not returned.
- URLs in structured inspection output have credentials, query strings, and fragments removed.
- Output size and match counts are bounded.

## Jina capability boundary

Anonymous Jina Reader currently allows rendered HTML, CSS selector targeting, screenshots/pageshots, viewport control, wait/respond timing, and Shadow DOM flattening. Jina script injection and iframe-content merging require an API key, so this server does not expose tools that pretend to provide live DOM geometry, computed styles, console/network logs, Performance API state, storage values, or cross-origin frame contents.

`inspect_accessibility` is an HTML/ARIA semantic inventory, not Chromium's accessibility protocol tree.

## Tools

- `get_capabilities`
- `read_url`
- `capture_screenshot`
- `get_rendered_html`
- `inspect_elements`
- `inspect_dom`
- `inspect_frames`
- `inspect_styles`
- `inspect_resources`
- `inspect_forms`
- `inspect_accessibility`
- `inspect_page_metadata`

## Runtime

The local TMCP service binds to `127.0.0.1:17848` using Streamable HTTP at `/mcp` and exposes `/health` for readback.
