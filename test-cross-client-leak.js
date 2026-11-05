"use strict";
// Pruebas para lib/cross-client-leak.js — el motor de detect_cross_client_leak_risk.
//
// Correr con: node test-cross-client-leak.js

const assert = require('assert');
const { checkCrossClientLeakRisk } = require('./lib/cross-client-leak');

let pass = 0;
let fail = 0;

function test(name, fn) {
  try {
    fn();
    pass++;
    console.log('OK   - ' + name);
  } catch (err) {
    fail++;
    console.log('FAIL - ' + name);
    console.log('       ' + (err && err.stack ? err.stack : err));
  }
}

// ---------- Casos positivos (deben marcar riesgo) ----------

test('instancia de McpServer a nivel de módulo reutilizada en cada petición -> alto riesgo', () => {
  const r = checkCrossClientLeakRisk({
    codigo: `
      const mcpServer = new McpServer({ name: 'x', version: '1.0' });
      mcpServer.registerTool('foo', {}, async () => ({}));

      app.post('/mcp', async (req, res) => {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('variable mutable a nivel de módulo leída dentro de una herramienta registrada -> riesgo moderado', () => {
  const r = checkCrossClientLeakRisk({
    codigo: `
      let ultimoUsuario = null;

      app.post('/login', (req, res) => {
        ultimoUsuario = req.body.usuario;
        res.end();
      });

      server.registerTool('whoami', {}, async () => {
        return { usuario: ultimoUsuario };
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

test('combinación: servidor compartido + estado mutable -> puntaje peor que cualquiera solo', () => {
  const combo = checkCrossClientLeakRisk({
    codigo: `
      const mcpServer = new McpServer({ name: 'x', version: '1.0' });
      let ultimoUsuario = null;
      mcpServer.registerTool('whoami', {}, async () => ({ usuario: ultimoUsuario }));

      app.post('/mcp', async (req, res) => {
        ultimoUsuario = req.body.usuario;
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        await mcpServer.connect(transport);
      });
    `
  });
  const solo1 = checkCrossClientLeakRisk({
    codigo: `
      const mcpServer = new McpServer({ name: 'x', version: '1.0' });
      app.post('/mcp', async (req, res) => {
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        await mcpServer.connect(transport);
      });
    `
  });
  assert.ok(combo.puntaje < solo1.puntaje, 'combo.puntaje=' + combo.puntaje + ' solo1.puntaje=' + solo1.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('instancia nueva de McpServer dentro de cada handler de petición -> aceptable', () => {
  const r = checkCrossClientLeakRisk({
    codigo: `
      app.post('/mcp', async (req, res) => {
        const server = new McpServer({ name: 'x', version: '1.0' });
        server.registerTool('foo', {}, async () => ({}));
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('servidor a nivel de módulo, pero cada handler crea también su propia instancia -> aceptable', () => {
  const r = checkCrossClientLeakRisk({
    codigo: `
      const mcpServer = new McpServer({ name: 'x', version: '1.0' });

      app.post('/mcp', async (req, res) => {
        const server = new McpServer({ name: 'x', version: '1.0' });
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        await server.connect(transport);
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('variable top-level constante (const, no mutable) usada en una herramienta -> aceptable', () => {
  const r = checkCrossClientLeakRisk({
    codigo: `
      const VERSION_API = '1.0.0';
      server.registerTool('version', {}, async () => ({ version: VERSION_API }));
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ningún patrón riesgoso -> aceptable, puntaje 100', () => {
  const r = checkCrossClientLeakRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkCrossClientLeakRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkCrossClientLeakRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
