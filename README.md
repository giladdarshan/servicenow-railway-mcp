# ServiceNow Railway MCP With OAuth

Minimal MCP server for Railway with OAuth bearer tokens for ServiceNow.

## Railway variables

Set these in Railway:

- `PUBLIC_BASE_URL`
- `OAUTH_CLIENT_ID`
- `OAUTH_CLIENT_SECRET`
- `OAUTH_SCOPE`
- `OAUTH_TOKEN_TTL_SECONDS`

Example values are in `.env.example`.

## URLs

- MCP endpoint: `/mcp`
- Token endpoint: `/oauth/token`
- OAuth metadata: `/.well-known/oauth-authorization-server`
- Protected resource metadata: `/.well-known/oauth-protected-resource/mcp`
