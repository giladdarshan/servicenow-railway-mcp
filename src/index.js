import { randomUUID } from 'node:crypto';
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import * as z from 'zod/v4';

const port = Number(process.env.PORT || 3000);
const app = createMcpExpressApp({ host: '0.0.0.0' });

const baseUrl = process.env.PUBLIC_BASE_URL;
const clientId = process.env.OAUTH_CLIENT_ID;
const clientSecret = process.env.OAUTH_CLIENT_SECRET;
const scope = process.env.OAUTH_SCOPE || 'mcp:tools';
const tokenTtlSeconds = Number(process.env.OAUTH_TOKEN_TTL_SECONDS || 3600);

if (!baseUrl) {
  throw new Error('PUBLIC_BASE_URL is required');
}

if (!clientId || !clientSecret) {
  throw new Error('OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET are required');
}

const mcpUrl = new URL('/mcp', baseUrl);
const tokenUrl = new URL('/oauth/token', baseUrl);
const metadataUrl = new URL('/.well-known/oauth-authorization-server', baseUrl);
const resourceMetadataUrl = new URL('/.well-known/oauth-protected-resource/mcp', baseUrl);

const tokens = new Map();

function createServer() {
  const server = new McpServer(
    {
      name: 'servicenow-railway-mcp',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  server.registerTool(
    'add',
    {
      description: 'Add two numbers.',
      inputSchema: {
        a: z.number().describe('First number'),
        b: z.number().describe('Second number')
      }
    },
    async ({ a, b }) => ({
      content: [{ type: 'text', text: String(a + b) }],
      structuredContent: { result: a + b }
    })
  );

  server.registerTool(
    'multiply',
    {
      description: 'Multiply two numbers.',
      inputSchema: {
        a: z.number().describe('First number'),
        b: z.number().describe('Second number')
      }
    },
    async ({ a, b }) => ({
      content: [{ type: 'text', text: String(a * b) }],
      structuredContent: { result: a * b }
    })
  );

  return server;
}

function sendOauthError(res, status, error, description) {
  res.status(status).json({
    error,
    error_description: description
  });
}

function parseClientCredentials(req) {
  const authHeader = req.headers.authorization;

  if (authHeader?.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');

    if (separator === -1) {
      return {};
    }

    return {
      clientId: decoded.slice(0, separator),
      clientSecret: decoded.slice(separator + 1)
    };
  }

  return {
    clientId: req.body.client_id,
    clientSecret: req.body.client_secret
  };
}

const verifier = {
  async verifyAccessToken(token) {
    const tokenInfo = tokens.get(token);

    if (!tokenInfo) {
      throw new InvalidTokenError('Invalid token');
    }

    if (tokenInfo.expiresAt <= Date.now()) {
      tokens.delete(token);
      throw new InvalidTokenError('Expired token');
    }

    return {
      token,
      clientId: tokenInfo.clientId,
      scopes: tokenInfo.scopes,
      expiresAt: Math.floor(tokenInfo.expiresAt / 1000)
    };
  }
};

app.set('trust proxy', true);
app.use(express.urlencoded({ extended: false }));

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    endpoint: mcpUrl.pathname,
    oauth: {
      token_endpoint: tokenUrl.href,
      authorization_server_metadata: metadataUrl.href,
      protected_resource_metadata: resourceMetadataUrl.href
    }
  });
});

app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: baseUrl,
    token_endpoint: tokenUrl.href,
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    scopes_supported: [scope]
  });
});

app.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  res.json({
    resource: mcpUrl.href,
    authorization_servers: [baseUrl],
    scopes_supported: [scope],
    bearer_methods_supported: ['header']
  });
});

app.post('/oauth/token', (req, res) => {
  const { clientId: requestClientId, clientSecret: requestClientSecret } = parseClientCredentials(req);
  const requestedScope = req.body.scope || scope;

  if (req.body.grant_type !== 'client_credentials') {
    sendOauthError(res, 400, 'unsupported_grant_type', 'Only client_credentials is supported.');
    return;
  }

  if (requestClientId !== clientId || requestClientSecret !== clientSecret) {
    sendOauthError(res, 401, 'invalid_client', 'Client authentication failed.');
    return;
  }

  if (requestedScope !== scope) {
    sendOauthError(res, 400, 'invalid_scope', `Only scope "${scope}" is supported.`);
    return;
  }

  const accessToken = randomUUID();
  const expiresAt = Date.now() + tokenTtlSeconds * 1000;

  tokens.set(accessToken, {
    clientId,
    scopes: [scope],
    expiresAt
  });

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: tokenTtlSeconds,
    scope
  });
});

app.get('/oauth/token', (_req, res) => {
  res.status(405).set('Allow', 'POST').send('Method Not Allowed');
});

app.post(
  '/mcp',
  requireBearerAuth({
    verifier,
    requiredScopes: [scope],
    resourceMetadataUrl: resourceMetadataUrl.href
  }),
  async (req, res) => {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true
    });

    res.once('close', () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error('MCP request failed', error);

      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error'
          },
          id: null
        });
      }
    }
  }
);

app.get('/mcp', (_req, res) => {
  res.status(405).set('Allow', 'POST').send('Method Not Allowed');
});

app.delete('/mcp', (_req, res) => {
  res.status(405).set('Allow', 'POST').send('Method Not Allowed');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`MCP server listening on port ${port}`);
});
