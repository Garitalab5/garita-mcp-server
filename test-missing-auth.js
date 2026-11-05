"use strict";
var assert = require('assert');
var lib = require('./lib/missing-auth');
var checkMissingAuthRisk = lib.checkMissingAuthRisk;

var pass = 0, fail = 0;
function test(name, fn) {
  try {
    fn();
    pass++;
    console.log('OK   ' + name);
  } catch (e) {
    fail++;
    console.log('FAIL ' + name + ' -> ' + e.message);
  }
}

// 1. StreamableHTTPServerTransport sin ninguna verificación de auth cerca
test('StreamableHTTPServerTransport sin auth -> critico', function () {
  var codigo =
    'const transport = new StreamableHTTPServerTransport({\n' +
    '  sessionIdGenerator: () => crypto.randomUUID()\n' +
    '});\n' +
    'await server.connect(transport);';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.ok(r.hallazgos.some(function (h) { return h.severidad === 'critical'; }));
});

// 2. Ruta /sse de Express sin auth (mirror del patrón real de CVE-2026-44895)
test('ruta /sse sin auth -> critico', function () {
  var codigo =
    "app.get('/sse', (req, res) => {\n" +
    "  const transport = new SSEServerTransport('/messages', res);\n" +
    '  server.connect(transport);\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// 3. Ruta /mcp de Express sin auth
test("app.post('/mcp', ...) sin auth -> critico", function () {
  var codigo =
    "app.post('/mcp', async (req, res) => {\n" +
    '  const result = await handleMcpRequest(req.body);\n' +
    '  res.json(result);\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// 4. FastAPI @app.post("/mcp") sin auth
test('FastAPI @app.post("/mcp") sin auth -> critico', function () {
  var codigo =
    '@app.post("/mcp")\n' +
    'async def mcp_endpoint(request: Request):\n' +
    '    body = await request.json()\n' +
    '    return await handle_mcp(body)';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// 5. Sin auth + CORS abierto -> peor puntaje que sin auth solo (mirror CVE-2026-44895)
test('sin auth + CORS "*" -> peor que sin auth solo', function () {
  var sinCors =
    "app.post('/mcp', async (req, res) => {\n" +
    '  const result = await handleMcpRequest(req.body);\n' +
    '  res.json(result);\n' +
    '});';
  var conCors =
    "app.post('/mcp', async (req, res) => {\n" +
    "  res.setHeader('Access-Control-Allow-Origin', '*');\n" +
    '  const result = await handleMcpRequest(req.body);\n' +
    '  res.json(result);\n' +
    '});';
  var r1 = checkMissingAuthRisk({ codigo: sinCors });
  var r2 = checkMissingAuthRisk({ codigo: conCors });
  assert.ok(r2.puntaje < r1.puntaje);
  assert.strictEqual(r2.veredicto, 'Alto riesgo');
});

// 6. Sin auth + middleware cors() sin argumentos (CORS abierto por defecto)
test('sin auth + cors() sin argumentos -> agrava', function () {
  var codigo =
    "app.use(cors());\n" +
    "app.post('/mcp', async (req, res) => {\n" +
    '  res.json(await handleMcpRequest(req.body));\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.ok(r.hallazgos.some(function (h) { return h.etiqueta.indexOf('CORS') !== -1; }));
});

// 7. Múltiples sinks sin auth -> puntaje escala
test('multiples sinks sin auth -> puntaje mas bajo que uno solo', function () {
  var uno =
    "app.post('/mcp', async (req, res) => { res.json(await handleMcpRequest(req.body)); });";
  var dos =
    "app.post('/mcp', async (req, res) => { res.json(await handleMcpRequest(req.body)); });\n" +
    "app.get('/sse', (req, res) => { const t = new SSEServerTransport('/messages', res); server.connect(t); });";
  var r1 = checkMissingAuthRisk({ codigo: uno });
  var r2 = checkMissingAuthRisk({ codigo: dos });
  assert.ok(r2.puntaje <= r1.puntaje);
});

// 8. Negativo: verificación explícita del header Authorization antes de la ruta
test('verificacion de header Authorization -> ok', function () {
  var codigo =
    "app.post('/mcp', (req, res, next) => {\n" +
    "  if (req.headers.authorization !== 'Bearer ' + process.env.API_KEY) {\n" +
    "    return res.status(401).send('no autorizado');\n" +
    '  }\n' +
    '  next();\n' +
    '});\n' +
    "app.post('/mcp', async (req, res) => { res.json(await handleMcpRequest(req.body)); });";
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

// 9. Negativo: función checkAndConsume (patrón real usado por el propio servidor de Garita)
test('checkAndConsume(apiKey) cerca -> ok', function () {
  var codigo =
    "app.post('/mcp', async (req, res) => {\n" +
    '  const apiKey = req.headers["x-api-key"];\n' +
    '  const check = await licensing.checkAndConsume(apiKey);\n' +
    '  if (!check.ok) return res.status(402).json(check);\n' +
    '  res.json(await handleMcpRequest(req.body));\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

// 10. Negativo: FastAPI leyendo el header authorization con request.headers.get
test('FastAPI request.headers.get("authorization") -> ok', function () {
  var codigo =
    '@app.post("/mcp")\n' +
    'async def mcp_endpoint(request: Request):\n' +
    '    token = request.headers.get("authorization")\n' +
    '    verify_token(token)\n' +
    '    body = await request.json()\n' +
    '    return await handle_mcp(body)';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

// 11. Negativo: middleware requireAuth( reconocible
test('requireAuth( antes de la ruta -> ok', function () {
  var codigo =
    "app.use(requireAuth());\n" +
    "app.post('/mcp', async (req, res) => { res.json(await handleMcpRequest(req.body)); });";
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

// 14. patrón express.Router: app.route('/mcp').post(handler) sin auth
test("app.route('/mcp').post(handler) sin auth -> critico", function () {
  var codigo =
    "app.route('/mcp').post(async (req, res) => {\n" +
    '  res.json(await handleMcpRequest(req.body));\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// 15. salto de línea entre "app" y ".post(" (estilo de lint) sin auth
test('salto de linea entre "app" y ".post(" sin auth -> critico', function () {
  var codigo =
    "app\n" +
    "  .post('/mcp', async (req, res) => {\n" +
    '    res.json(await handleMcpRequest(req.body));\n' +
    '  });';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// 16. Header Authorization construido para una llamada SALIENTE (no valida
// a quien llama al endpoint) -> sigue siendo critico, no debe confundirse
// con una validación de auth entrante
test('header Authorization saliente hacia otro servicio no cuenta como auth entrante -> critico', function () {
  var codigo =
    "app.post('/mcp', async (req, res) => {\n" +
    '  const upstream = await fetch("https://otra-api.example.com/data", {\n' +
    '    headers: { Authorization: \'Bearer \' + process.env.UPSTREAM_TOKEN }\n' +
    '  });\n' +
    '  res.json(await handleMcpRequest(req.body, upstream));\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// 17. Negativo de control para el fix anterior: la construcción del header
// Authorization SALIENTE sigue sin romper el caso legítimo ya cubierto (test 8)
test('header Authorization saliente + validación real de auth entrante -> ok', function () {
  var codigo =
    "app.post('/mcp', (req, res, next) => {\n" +
    "  if (req.headers.authorization !== 'Bearer ' + process.env.API_KEY) {\n" +
    "    return res.status(401).send('no autorizado');\n" +
    '  }\n' +
    '  next();\n' +
    '});\n' +
    "app.post('/mcp', async (req, res) => {\n" +
    '  const upstream = await fetch("https://otra-api.example.com/data", {\n' +
    '    headers: { Authorization: \'Bearer \' + process.env.UPSTREAM_TOKEN }\n' +
    '  });\n' +
    '  res.json(await handleMcpRequest(req.body, upstream));\n' +
    '});';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

// 12. Sin ningún sink -> ok, mensaje de "no encontrado"
test('sin transporte MCP en el codigo -> ok, no encontrado', function () {
  var codigo = 'function sumar(a, b) { return a + b; }';
  var r = checkMissingAuthRisk({ codigo: codigo });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.ok(r.hallazgos[0].etiqueta.indexOf('No se encontró') !== -1);
});

// 13. Entrada inválida -> lanza error
test('codigo vacio -> lanza error', function () {
  assert.throws(function () { checkMissingAuthRisk({ codigo: '   ' }); });
});

test('sin input -> lanza error', function () {
  assert.throws(function () { checkMissingAuthRisk({}); });
});

console.log('\n' + pass + '/' + (pass + fail) + ' pruebas pasando.');
process.exit(fail > 0 ? 1 : 0);
