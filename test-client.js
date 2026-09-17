const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');

const BASE_URL = process.env.GARITA_BASE_URL || 'http://localhost:3000';

(async () => {
  console.log('=== Consiguiendo una llave de acceso gratis (POST /crear-llave) ===');
  const keyRes = await fetch(BASE_URL + '/crear-llave', { method: 'POST' });
  const keyData = await keyRes.json();
  console.log(keyData.mensaje);
  const apiKey = keyData.apiKey;

  const client = new Client({ name: 'garita-test-client', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(BASE_URL + '/mcp'), {
    requestInit: { headers: { Authorization: 'Bearer ' + apiKey } }
  });
  await client.connect(transport);

  console.log('\n=== Tools disponibles ===');
  const tools = await client.listTools();
  console.log(tools.tools.map(t => t.name));

  console.log('\n=== audit_mcp_server: ejemplo demo (debe dar 55) ===');
  const auditRes = await client.callTool({
    name: 'audit_mcp_server',
    arguments: {
      manifest: {
        serverInfo: { name: 'finance-ops-mcp', requiresAuth: false },
        tools: [
          { name: 'transfer_funds', description: 'Transfiere fondos entre cuentas del usuario',
            inputSchema: { type: 'object', properties: { amount: { type: 'number' }, to_account: { type: 'string' } } } },
          { name: 'get_balance', description: 'Consulta el saldo actual de una cuenta',
            annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
            inputSchema: { type: 'object', properties: { account_id: { type: 'string' } } } },
          { name: 'run_query', description: 'Ejecuta una consulta SQL personalizada sobre la base de datos de transacciones',
            inputSchema: { type: 'object', properties: { sql: { type: 'string' } } } }
        ]
      }
    }
  });
  console.log(auditRes.content[0].text);

  console.log('\n=== simulate_approval: ataque Infinity ===');
  const simRes = await client.callTool({
    name: 'simulate_approval',
    arguments: {
      action: { tool: 'noop_tool', description: 'no hace nada peligroso', arguments: { amount: 1e400 } }
    }
  });
  console.log(simRes.content[0].text);

  console.log('\n=== simulate_approval: caso normal de solo lectura ===');
  const simRes2 = await client.callTool({
    name: 'simulate_approval',
    arguments: {
      action: { tool: 'get_balance', description: 'Consulta el saldo actual', arguments: { account_id: 'abc' } }
    }
  });
  console.log(simRes2.content[0].text);

  console.log('\n=== Agotando los usos gratis restantes para ver el mensaje de "compra créditos" ===');
  let lastResult;
  for (let i = 0; i < 6; i++) {
    lastResult = await client.callTool({
      name: 'audit_mcp_server',
      arguments: { manifest: { tools: [{ name: 'noop', description: 'sin riesgo' }] } }
    });
  }
  console.log(lastResult.content[0].text);
  console.log('isError:', lastResult.isError === true);

  await client.close();
  process.exit(0);
})().catch(e => { console.error('ERROR:', e); process.exit(1); });
