"use strict";
// Pruebas para lib/dns-rebinding.js — el motor de detect_dns_rebinding_risk
// (Escudo de Rebinding DNS).
//
// Correr con: node test-dns-rebinding.js

const assert = require('assert');
const { checkDnsRebindingRisk } = require('./lib/dns-rebinding');

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

test('StreamableHTTPServerTransport sin ninguna validación de Origin -> alto riesgo', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => crypto.randomUUID()
});
await server.connect(transport);
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('SSEServerTransport sin validación de Origin -> alto riesgo', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
app.get('/sse', (req, res) => {
  const transport = new SSEServerTransport('/messages', res);
  server.connect(transport);
});
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('Ruta Express "/mcp" registrada sin validación de Origin -> alto riesgo', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
app.post('/mcp', async (req, res) => {
  const result = await handleMcpRequest(req.body);
  res.json(result);
});
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('Ruta FastAPI "/mcp" registrada sin validación de Origin -> alto riesgo', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
@app.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    return await handle_mcp(body)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('afirmar que bindear a localhost ya protege, sin validar Origin -> hallazgo adicional y peor puntaje', () => {
  const sinClaim = checkDnsRebindingRisk({
    codigo: `
app.post('/mcp', async (req, res) => {
  const result = await handleMcpRequest(req.body);
  res.json(result);
});
app.listen(3000, '127.0.0.1');
    `
  });
  const conClaim = checkDnsRebindingRisk({
    codigo: `
// El servidor solo escucha en localhost, así que es seguro y no hace falta validar nada más
app.post('/mcp', async (req, res) => {
  const result = await handleMcpRequest(req.body);
  res.json(result);
});
app.listen(3000, '127.0.0.1');
    `
  });
  assert.ok(conClaim.puntaje < sinClaim.puntaje, 'afirmar que localhost ya protege debe restar puntos aparte: ' + conClaim.puntaje + ' vs ' + sinClaim.puntaje);
  assert.ok(conClaim.hallazgos.length > sinClaim.hallazgos.length);
});

test('múltiples endpoints sin validar -> el puntaje baja más que con uno solo', () => {
  const uno = checkDnsRebindingRisk({
    codigo: `app.post('/mcp', async (req, res) => { res.json(await handleMcpRequest(req.body)); });`
  });
  const varios = checkDnsRebindingRisk({
    codigo: `
app.post('/mcp', async (req, res) => { res.json(await handleMcpRequest(req.body)); });
const t1 = new StreamableHTTPServerTransport({});
const t2 = new SSEServerTransport('/messages', res);
    `
  });
  assert.ok(varios.puntaje <= uno.puntaje, 'más de un endpoint sin validar debe pesar al menos igual: ' + varios.puntaje + ' vs ' + uno.puntaje);
});

test('patrón express.Router: app.route(\'/mcp\').post(handler) sin validación de Origin -> alto riesgo', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
app.route('/mcp').post(async (req, res) => {
  const result = await handleMcpRequest(req.body);
  res.json(result);
});
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('salto de línea entre "app" y ".post(" (estilo de lint) sin validación de Origin -> alto riesgo', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
app
  .post('/mcp', async (req, res) => {
    const result = await handleMcpRequest(req.body);
    res.json(result);
  });
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('StreamableHTTPServerTransport con validación explícita del header Origin -> aceptable', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
app.post('/mcp', (req, res, next) => {
  if (req.headers.origin !== ALLOWED_ORIGIN) {
    return res.status(403).send('origen no permitido');
  }
  next();
});
const transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => crypto.randomUUID()
});
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('ruta FastAPI con función validate_origin() reconocible -> aceptable', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
@app.post("/mcp")
async def mcp_endpoint(request: Request):
    validate_origin(request.headers.get("origin"))
    body = await request.json()
    return await handle_mcp(body)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('lista ALLOWED_ORIGINS definida y usada cerca del endpoint -> aceptable', () => {
  const r = checkDnsRebindingRisk({
    codigo: `
ALLOWED_ORIGINS = ["https://app.garita.dev"]

@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    if request.headers.get("origin") not in ALLOWED_ORIGINS:
        abort(403)
    return handle_mcp(request.json)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna configuración de transporte MCP en el código -> aceptable', () => {
  const r = checkDnsRebindingRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos[0].severidad, 'ok');
});

// ---------- Casos de entrada inválida ----------

test('sin "codigo" -> lanza error', () => {
  assert.throws(() => checkDnsRebindingRisk({}), /codigo/i);
});

test('"codigo" vacío -> lanza error', () => {
  assert.throws(() => checkDnsRebindingRisk({ codigo: '   ' }), /codigo/i);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
process.exit(fail > 0 ? 1 : 0);
