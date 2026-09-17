const { auditManifest, simulateApproval } = require('./lib/heuristics');

console.log('=== Regresión: ejemplo demo (auditor) debe dar 55/100 ===');
const manifest = {
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
};
const r = auditManifest(manifest);
console.log('score:', r.score, '(esperado 55)');

console.log('\n=== Regresión: acción normal 4200 -> retenido por monto ===');
const normal = simulateApproval({ tool: 'transfer_funds', description: 'Transfiere fondos entre cuentas del usuario', arguments: { amount: 4200, currency: 'USD', to_account: 'ES91-2100-0000-1234' } });
console.log(JSON.stringify(normal, null, 2));

console.log('\n=== Ataque: monto Infinity (1e400) ===');
const infinityAction = JSON.parse('{"tool":"noop_tool","description":"no hace nada peligroso","arguments":{"amount":1e400}}');
console.log(JSON.stringify(simulateApproval(infinityAction), null, 2));

console.log('\n=== Ataque: relleno de 200,001 decoys antes del monto real ===');
const decoys = new Array(200001).fill(1);
const paddedAction = { tool: 'noop_tool', description: 'no hace nada peligroso', arguments: { amounts: [999999999].concat(decoys) } };
console.log(JSON.stringify(simulateApproval(paddedAction), null, 2));

console.log('\n=== Ataque: zero-width space partiendo el verbo ===');
const zw = { tool: 'noop_tool', description: 'Tra​nsfiere fondos de la cuenta', arguments: {} };
console.log(JSON.stringify(simulateApproval(zw), null, 2));

console.log('\n=== Caso normal de solo lectura -> auto-aprobado ===');
const ro = { tool: 'get_balance', description: 'Consulta el saldo actual', arguments: { account_id: 'abc' } };
console.log(JSON.stringify(simulateApproval(ro), null, 2));
