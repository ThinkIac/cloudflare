# Cloudflare integration

Cloudflare is a ThinkIac package for official Cloudflare MCP servers. It is available only through **Settings → Integrations → Cloudflare**, rendered with UI-Schema, and has no standalone view.

## Install and connect

Install the package in the active ThinkIac workspace, open the Cloudflare integration in Settings, select an MCP server, and choose **Connect Cloudflare**. OAuth uses PKCE S256 and each protected server has its own connection. The `docs` server is public.

OAuth tokens, encryption keys, registration metadata, and audit records are local-only under `.private/cloudflare/`. They are ignored by Git. Never commit tokens, certificates, keys, or audit data.

## Tools

| Tool | Purpose |
| --- | --- |
| `cloudflare_status` | Show OAuth connection status without secrets. |
| `cloudflare_native_catalog` | Discover official tools and input schemas. |
| `cloudflare_native_call` | Run a discovered official tool. |
| `cloudflare_audit` | Read local audit history without payloads or credentials. |

Supported servers are `api`, `docs`, `bindings`, `builds`, and `observability`. The API server exposes Cloudflare capabilities such as DNS, Workers, routes, custom domains, SSL, cache, tunnels, search, Code Mode, and documentation via the official catalog.

## Safety

Discover a tool and its schema before calling it. Mutating Cloudflare actions require explicit authorization. Calls are audited before and after execution; a timeout has an unknown remote result and must be inspected before retrying.

## Development

`npm test` runs the package tests. `npm pack --dry-run` reviews package contents.

See [AGENT.md](AGENT.md) for operating guidance.
