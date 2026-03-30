import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InvalidRequestError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import * as z from 'zod/v4';

class InMemoryClientsStore {
  constructor(client) {
    this.client = client;
  }

  async getClient(clientId) {
    return clientId === this.client.client_id ? this.client : undefined;
  }

  async registerClient() {
    return this.client;
  }
}

class ServiceNowAuthProvider {
  constructor(client, validateResource, tokenTtlSeconds) {
    this.clientsStore = new InMemoryClientsStore(client);
    this.client = client;
    this.validateResource = validateResource;
    this.tokenTtlSeconds = tokenTtlSeconds;
    this.codes = new Map();
    this.accessTokens = new Map();
    this.refreshTokens = new Map();
  }

  async authorize(client, params, res) {
    if (!client.redirect_uris.includes(params.redirectUri)) {
      throw new InvalidRequestError('Unregistered redirect_uri');
    }

    const code = randomUUID();
    this.codes.set(code, {
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      scopes: params.scopes || [],
      resource: params.resource
    });

    const redirectUrl = new URL(params.redirectUri);
    redirectUrl.searchParams.set('code', code);

    if (params.state) {
      redirectUrl.searchParams.set('state', params.state);
    }

    res.redirect(302, redirectUrl.href);
  }

  async challengeForAuthorizationCode(client, authorizationCode) {
    const code = this.codes.get(authorizationCode);

    if (!code || code.clientId !== client.client_id) {
      throw new InvalidRequestError('Invalid authorization code');
    }

    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(client, authorizationCode, _codeVerifier, redirectUri, resource) {
    const code = this.codes.get(authorizationCode);

    if (!code || code.clientId !== client.client_id) {
      throw new InvalidRequestError('Invalid authorization code');
    }

    if (redirectUri && redirectUri !== code.redirectUri) {
      throw new InvalidRequestError('redirect_uri does not match the authorization request');
    }

    const tokenResource = resource || code.resource;

    if (this.validateResource && !this.validateResource(tokenResource)) {
      throw new InvalidRequestError(`Invalid resource: ${tokenResource}`);
    }

    this.codes.delete(authorizationCode);
    return this.issueTokens(client.client_id, code.scopes, tokenResource);
  }

  async exchangeRefreshToken(client, refreshToken, scopes, resource) {
    const refreshTokenInfo = this.refreshTokens.get(refreshToken);

    if (!refreshTokenInfo || refreshTokenInfo.clientId !== client.client_id) {
      throw new InvalidTokenError('Invalid refresh token');
    }

    if (refreshTokenInfo.expiresAt <= Date.now()) {
      this.refreshTokens.delete(refreshToken);
      throw new InvalidTokenError('Refresh token expired');
    }

    const nextScopes = scopes && scopes.length > 0 ? scopes : refreshTokenInfo.scopes;
    const nextResource = resource || refreshTokenInfo.resource;

    if (this.validateResource && !this.validateResource(nextResource)) {
      throw new InvalidRequestError(`Invalid resource: ${nextResource}`);
    }

    return this.issueTokens(client.client_id, nextScopes, nextResource);
  }

  async verifyAccessToken(token) {
    const tokenInfo = this.accessTokens.get(token);

    if (!tokenInfo) {
      throw new InvalidTokenError('Invalid token');
    }

    if (tokenInfo.expiresAt <= Date.now()) {
      this.accessTokens.delete(token);
      throw new InvalidTokenError('Token expired');
    }

    return {
      token,
      clientId: tokenInfo.clientId,
      scopes: tokenInfo.scopes,
      expiresAt: Math.floor(tokenInfo.expiresAt / 1000),
      resource: tokenInfo.resource
    };
  }

  issueTokens(clientId, scopes, resource) {
    const accessToken = randomUUID();
    const refreshToken = randomUUID();
    const expiresAt = Date.now() + this.tokenTtlSeconds * 1000;
    const refreshExpiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;

    this.accessTokens.set(accessToken, {
      clientId,
      scopes,
      resource,
      expiresAt
    });

    this.refreshTokens.set(refreshToken, {
      clientId,
      scopes,
      resource,
      expiresAt: refreshExpiresAt
    });

    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: this.tokenTtlSeconds,
      refresh_token: refreshToken,
      scope: scopes.join(' ')
    };
  }
}

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

const port = Number(process.env.PORT || 3000);
const app = createMcpExpressApp({ host: '0.0.0.0' });

const baseUrl = process.env.PUBLIC_BASE_URL;
const clientId = process.env.OAUTH_CLIENT_ID;
const clientSecret = process.env.OAUTH_CLIENT_SECRET;
const redirectUri = process.env.OAUTH_REDIRECT_URI;
const scope = process.env.OAUTH_SCOPE || 'mcp:tools';
const tokenTtlSeconds = Number(process.env.OAUTH_TOKEN_TTL_SECONDS || 3600);

if (!baseUrl) {
  throw new Error('PUBLIC_BASE_URL is required');
}

if (!clientId || !clientSecret || !redirectUri) {
  throw new Error('OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, and OAUTH_REDIRECT_URI are required');
}

const issuerUrl = new URL(baseUrl);
const mcpUrl = new URL('/mcp', baseUrl);
const registeredClient = {
  client_id: clientId,
  client_secret: clientSecret,
  client_name: 'ServiceNow MCP Client',
  redirect_uris: redirectUri.split(","),
  token_endpoint_auth_method: 'client_secret_post',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  scope
};

const validateResource = resource => {
  if (!resource) {
    return true;
  }

  return resource.toString() === mcpUrl.href;
};

const provider = new ServiceNowAuthProvider(registeredClient, validateResource, tokenTtlSeconds);

app.use(
  mcpAuthRouter({
    provider,
    issuerUrl,
    resourceServerUrl: mcpUrl,
    scopesSupported: [scope],
    resourceName: 'ServiceNow Railway MCP'
  })
);

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    endpoint: mcpUrl.pathname,
    oauth: {
      authorization_endpoint: new URL('/authorize', baseUrl).href,
      token_endpoint: new URL('/token', baseUrl).href,
      protected_resource_metadata: getOAuthProtectedResourceMetadataUrl(mcpUrl)
    }
  });
});

app.post(
  '/mcp',
  requireBearerAuth({
    verifier: provider,
    requiredScopes: [scope],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl)
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
