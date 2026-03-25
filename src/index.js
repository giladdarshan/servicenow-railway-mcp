import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import * as z from 'zod/v4';

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

const app = createMcpExpressApp();
const port = Number(process.env.PORT || 3000);

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    endpoint: '/mcp'
  });
});

app.post('/mcp', async (req, res) => {
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
});

app.get('/mcp', (_req, res) => {
  res.status(405).set('Allow', 'POST').send('Method Not Allowed');
});

app.delete('/mcp', (_req, res) => {
  res.status(405).set('Allow', 'POST').send('Method Not Allowed');
});

app.listen(port, () => {
  console.log(`MCP server listening on port ${port}`);
});
