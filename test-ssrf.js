"use strict";
// Pruebas para lib/ssrf.js — el motor de detect_ssrf_risk.
//
// Correr con: node test-ssrf.js

const assert = require('assert');
const { checkSsrfRisk } = require('./lib/ssrf');

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

test('fetch con variable sin ninguna validación cerca -> alto riesgo', () => {
  const r = checkSsrfRisk({
    codigo: `
      async function traerUrl(req) {
        const url = req.body.url;
        const res = await fetch(url);
        return res.text();
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('requests.get de Python con variable sin validar -> riesgo', () => {
  const r = checkSsrfRisk({
    codigo: `
def traer_url(webhook_url):
    resp = requests.get(webhook_url, timeout=5)
    return resp.text
    `
  });
  assert.ok(r.puntaje < 80, 'puntaje=' + r.puntaje);
});

test('REGRESIÓN: comentario que MENCIONA una validación pero no existe código real de validación -> sigue siendo alto riesgo (evasión real encontrada y corregida)', () => {
  const r = checkSsrfRisk({
    codigo: `
      // usamos un allowlist de hosts permitidos para esto
      async function traerUrl(req) {
        const url = req.body.url;
        const res = await fetch(url);
        return res.text();
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo', 'el comentario no debe contar como validación real');
});

test('IP de metadata de AWS hardcodeada dentro de una llamada fetch -> alto riesgo', () => {
  const r = checkSsrfRisk({
    codigo: `const creds = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/');`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('localhost/loopback hardcodeado dentro de axios -> alto riesgo', () => {
  const r = checkSsrfRisk({
    codigo: `const admin = await axios.get('http://127.0.0.1:8080/admin/secrets');`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('TLS desactivado junto con una petición a URL externa -> alto riesgo', () => {
  const r = checkSsrfRisk({
    codigo: `
      const https = require('https');
      const agent = new https.Agent({ rejectUnauthorized: false });
      const res = await fetch(userSuppliedUrl, { agent });
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('sigue redirecciones sin revalidar el destino -> riesgo moderado o peor', () => {
  const r = checkSsrfRisk({
    codigo: `
      // valida contra una lista de hosts permitidos, pero no revisa a dónde redirige
      if (!allowlist.includes(new URL(targetUrl).hostname)) throw new Error('no permitido');
      const res = await axios.get(targetUrl, { redirect: 'follow', maxRedirects: 5 });
    `
  });
  assert.ok(r.puntaje < 100);
});

test('sin restricción de esquema aunque valide la IP -> riesgo moderado', () => {
  const r = checkSsrfRisk({
    codigo: `
      const dest = req.query.target;
      if (isPrivateIp(dest)) throw new Error('IP privada no permitida');
      const res = await fetch(dest);
    `
  });
  assert.ok(r.puntaje < 100);
  assert.ok(r.puntaje >= 50, 'no debería ser "alto riesgo" solo por esto: puntaje=' + r.puntaje);
});

test('combinación de varios problemas puntúa peor que uno solo', () => {
  const soloUno = checkSsrfRisk({
    codigo: `const res = await fetch(req.body.url);`
  });
  const combinado = checkSsrfRisk({
    codigo: `
      const https = require('https');
      const agent = new https.Agent({ rejectUnauthorized: false });
      const res = await fetch(req.body.url, { agent, redirect: 'follow', maxRedirects: 5 });
    `
  });
  assert.ok(combinado.puntaje < soloUno.puntaje, 'combinado=' + combinado.puntaje + ' solo=' + soloUno.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo — evitar falsos positivos) ----------

test('fetch a una URL fija (string literal, sin concatenar) -> aceptable', () => {
  const r = checkSsrfRisk({
    codigo: `const res = await fetch('https://api.miempresa.com/v1/status');`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('fetch con variable pero validado contra lista de hosts permitidos y esquema -> aceptable', () => {
  const r = checkSsrfRisk({
    codigo: `
      const target = req.body.url;
      const parsed = new URL(target);
      if (parsed.protocol !== 'https:') throw new Error('esquema no permitido');
      if (!ALLOWLIST_HOSTS.includes(parsed.hostname)) throw new Error('host no permitido');
      const res = await fetch(target);
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('usa una librería conocida contra SSRF (ssrf-req-filter) -> aceptable', () => {
  const r = checkSsrfRisk({
    codigo: `
      const { useAgent } = require('ssrf-req-filter');
      const res = await fetch(userUrl, { agent: useAgent(userUrl) });
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('código sin ninguna llamada HTTP -> aceptable', () => {
  const r = checkSsrfRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('chequeo defensivo que MENCIONA la IP de metadata para BLOQUEARLA, fuera de una llamada HTTP -> no se marca como llamada peligrosa', () => {
  const r = checkSsrfRisk({
    codigo: `
      function esHostPeligroso(host) {
        // bloqueamos explícitamente el endpoint de metadata de la nube
        return host === '169.254.169.254' || host === 'metadata.google.internal';
      }
      if (esHostPeligroso(new URL(target).hostname)) throw new Error('bloqueado');
      const res = await fetch(target);
    `
  });
  // Con el chequeo previo (palabra "bloqueado"/función de validación) antes del fetch, debería contar como validado.
  assert.ok(r.puntaje >= 50, 'puntaje=' + r.puntaje);
});

test('texto vacío -> lanza error', () => {
  assert.throws(() => checkSsrfRisk({ codigo: '' }));
  assert.throws(() => checkSsrfRisk({}));
});

test('template literal con interpolación de variable se trata como no confiable', () => {
  const r = checkSsrfRisk({
    codigo: 'const res = await fetch(`https://${req.query.host}/data`);'
  });
  assert.ok(r.puntaje < 80, 'puntaje=' + r.puntaje);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
