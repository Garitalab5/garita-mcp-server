"use strict";
// Pruebas para lib/token-passthrough.js — el motor de detect_token_passthrough_risk.
//
// Correr con: node test-token-passthrough.js

const assert = require('assert');
const { checkTokenPassthroughRisk } = require('./lib/token-passthrough');

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

test('middleware Express deja pasar sin verificar autorización (patrón CVE-2026-48039) -> alto riesgo', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      async function dispatch(req, res, next) {
        console.log('petición entrante', req.method, req.url);
        await next();
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('middleware FastAPI/Starlette llama a call_next sin verificar autorización -> alto riesgo', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
async def dispatch(self, request, call_next):
    log.info("request received: %s", request.url)
    response = await call_next(request)
    return response
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('reenvío directo del header Authorization entrante hacia una llamada saliente -> alto riesgo', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      async function proxyToMetaAds(req, res) {
        const upstream = await fetch('https://graph.facebook.com/v20.0/ads', {
          headers: { Authorization: req.headers.authorization }
        });
        return res.json(await upstream.json());
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('token capturado en variable y reenviado sin reemisión hacia otra API -> alto riesgo', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function handler(req, res) {
        const incomingToken = req.headers.authorization;
        return axios.get('https://api.terceros.com/data', {
          headers: { Authorization: incomingToken }
        });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('token reasignado a una variable nueva (alias) y reenviado sin reemisión -> alto riesgo', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function handler(req, res) {
        const incomingToken = req.headers.authorization;
        const t2 = incomingToken;
        return axios.get('https://api.terceros.com/data', {
          headers: { Authorization: t2 }
        });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('jwt.decode() sobre el token entrante, con "audience" en las opciones pero sin jwt.verify() en el código -> alto riesgo', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function leerToken(req) {
        const payload = jwt.decode(req.headers.authorization, { audience: 'mi-servidor-mcp' });
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  const tieneHallazgoDecode = r.hallazgos.some(h => h.etiqueta.indexOf('jwt.decode()') !== -1);
  assert.ok(tieneHallazgoDecode);
});

test('jwt.decode() junto con jwt.verify() en el mismo código -> no se marca como decode sin verificar', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function leerToken(token) {
        const payload = jwt.decode(token);
        const verificado = jwt.verify(token, process.env.JWT_SECRET, { audience: 'mi-servidor-mcp' });
        return verificado;
      }
    `
  });
  const tieneHallazgoDecode = r.hallazgos.some(h => h.etiqueta.indexOf('jwt.decode()') !== -1);
  assert.ok(!tieneHallazgoDecode);
});

test('combinación: middleware sin validar + JWT sin audience -> puntaje peor que cualquiera de los dos solos', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      async function dispatch(req, res, next) {
        await next();
      }
      function verificar(token) {
        return jwt.verify(token, SECRET);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  const solo1 = checkTokenPassthroughRisk({ codigo: `async function dispatch(req, res, next) { await next(); }` });
  assert.ok(r.puntaje < solo1.puntaje, 'r.puntaje=' + r.puntaje + ' solo1.puntaje=' + solo1.puntaje);
});

test('jwt.verify sin validar "audience" (sola) -> riesgo moderado', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function verificarToken(token) {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

test('token colocado como parámetro de una URL (template literal) -> riesgo moderado', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function construirUrl(token) {
        return \`https://api.ejemplo.com/data?access_token=\${token}\`;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('middleware con verificación de autorización explícita antes de next() -> aceptable', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      async function dispatch(req, res, next) {
        const user = await authenticateRequest(req);
        if (!user) {
          return res.status(401).json({ error: 'unauthorized' });
        }
        await next();
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('token capturado pero reemitido (exchangeToken) antes de reenviarlo -> aceptable', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      async function handler(req, res) {
        const incomingToken = req.headers.authorization;
        const ownToken = await exchangeToken(incomingToken);
        return axios.get('https://api.terceros.com/data', {
          headers: { Authorization: ownToken }
        });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('jwt.verify con "audience" validado explícitamente -> aceptable', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      function verificarToken(token) {
        return jwt.verify(token, process.env.JWT_SECRET, { audience: 'mi-servidor-mcp', issuer: 'https://auth.ejemplo.com' });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('llamada saliente con el token de servicio propio (no el header entrante) -> aceptable', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `
      async function llamarApiPropia() {
        return fetch('https://api.interna.com/data', {
          headers: { Authorization: \`Bearer \${process.env.SERVICE_TOKEN}\` }
        });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin llamadas de interés en el código -> aceptable, puntaje 100', () => {
  const r = checkTokenPassthroughRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkTokenPassthroughRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkTokenPassthroughRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
