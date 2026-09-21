"use strict";
// Pruebas para lib/vulnerabilidades.js — usan un fetch simulado (mock) con
// respuestas realistas de OSV.dev en vez de llamar a la API real.
//
// Por qué mock y no la API real: en este entorno de desarrollo, la política
// de red del sandbox bloquea la salida a api.osv.dev (confirmado con
// $HTTPS_PROXY/__agentproxy/status: "gateway answered 403 to CONNECT" —
// una restricción de este entorno de pruebas, no del código). El servidor
// real en Render sí tiene salida a internet normal. Estas pruebas validan
// la parte que sí depende de nuestro código — el parseo de la respuesta de
// OSV.dev (severidad, CVE, orden, truncado, errores) — sin depender de que
// la red esté disponible ni de que el contenido de OSV.dev no cambie con
// el tiempo. Antes de subir a producción, conviene probar una vez a mano
// con curl desde una red sin esa restricción (ver README).
//
// Correr con: node test-vulnerabilidades.js

const assert = require('assert');

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

async function testAsync(name, fn) {
  try {
    await fn();
    pass++;
    console.log('OK   - ' + name);
  } catch (err) {
    fail++;
    console.log('FAIL - ' + name);
    console.log('       ' + (err && err.stack ? err.stack : err));
  }
}

function withMockFetch(responder, fn) {
  const original = global.fetch;
  global.fetch = responder;
  // Cache-bust: cada test necesita su propia instancia del módulo porque
  // captura `fetch` en el ámbito global en cada llamada (no en el momento
  // de require), así que basta con reasignar global.fetch antes de llamar.
  delete require.cache[require.resolve('./lib/vulnerabilidades')];
  const mod = require('./lib/vulnerabilidades');
  return fn(mod).finally(() => { global.fetch = original; });
}

function jsonResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status: status,
    json: () => Promise.resolve(body)
  });
}

// Respuesta realista con una vulnerabilidad que tiene CVE en "aliases" y
// severidad CVSS, y otra sin ninguno de los dos (para forzar los fallbacks).
const RESPUESTA_CON_VULNS = {
  vulns: [
    {
      id: 'GHSA-xxxx-yyyy-zzzz',
      summary: 'Prototype pollution in ejemplo-paquete',
      published: '2026-01-10T00:00:00Z',
      modified: '2026-02-01T00:00:00Z',
      aliases: ['CVE-2026-11111'],
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }]
    },
    {
      id: 'OSV-2020-744',
      summary: 'Heap-double-free in mrb_default_allocf',
      published: '2020-07-04T00:00:01Z',
      modified: '2022-04-13T03:04:39Z',
      affected: [{ ecosystem_specific: { severity: 'HIGH' } }]
    },
    {
      id: 'OSV-9999-000',
      // sin summary, sin severity, sin aliases -> debe usar los fallback y no reventar
      details: 'x'.repeat(500)
    }
  ]
};

const RESPUESTA_VACIA = { vulns: [] };
const RESPUESTA_TRUNCADA = { vulns: [{ id: 'OSV-1', summary: 'algo' }], next_page_token: 'abc123==' };

async function main() {
  await testAsync('respuesta con vulnerabilidades -> parsea CVE, severidad, y ordena las más accionables primero', () =>
    withMockFetch(() => jsonResponse(200, RESPUESTA_CON_VULNS), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'ejemplo-paquete', version: '1.0.0' });
      assert.strictEqual(r.totalEncontradas, 3);
      assert.strictEqual(r.vulnerabilidades.length, 3);
      // La que tiene CVE + severidad debe ir primera.
      assert.strictEqual(r.vulnerabilidades[0].cve, 'CVE-2026-11111');
      assert.ok(/CVSS/.test(r.vulnerabilidades[0].severidad));
      assert.strictEqual(r.vulnerabilidades[0].link, 'https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz');
      // La segunda (severidad por ecosystem_specific, sin CVE) debe seguir.
      assert.strictEqual(r.vulnerabilidades[1].id, 'OSV-2020-744');
      assert.strictEqual(r.vulnerabilidades[1].severidad, 'HIGH');
      assert.strictEqual(r.vulnerabilidades[1].cve, null);
      // La tercera, sin nada, no debe reventar y debe traer un resumen recortado de "details".
      const tercera = r.vulnerabilidades.find(v => v.id === 'OSV-9999-000');
      assert.ok(tercera);
      assert.strictEqual(tercera.severidad, null);
      assert.ok(tercera.resumen.length <= 301); // 300 + el caracter "…" que se agrega al recortar
      assert.ok(/vulnerabilidad\(es\) conocida\(s\)/.test(r.veredicto));
    })
  );

  await testAsync('respuesta vacía -> veredicto limpio, sin vulnerabilidades, no revienta', () =>
    withMockFetch(() => jsonResponse(200, RESPUESTA_VACIA), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'PyPI', nombre: 'paquete-inventado' });
      assert.strictEqual(r.totalEncontradas, 0);
      assert.strictEqual(r.vulnerabilidades.length, 0);
      assert.ok(/Sin vulnerabilidades conocidas/.test(r.veredicto));
      assert.strictEqual(r.truncado, false);
    })
  );

  await testAsync('respuesta con next_page_token -> se marca como truncado', () =>
    withMockFetch(() => jsonResponse(200, RESPUESTA_TRUNCADA), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'Go', nombre: 'ejemplo' });
      assert.strictEqual(r.truncado, true);
    })
  );

  await testAsync('OSV.dev responde error HTTP -> lanza error controlado con el código', () =>
    withMockFetch(() => jsonResponse(400, { message: 'invalid ecosystem' }), async ({ checkKnownVulnerabilities }) => {
      await assert.rejects(
        () => checkKnownVulnerabilities({ ecosistema: 'EcosistemaInventado', nombre: 'x' }),
        /rechazó la consulta \(400\)/
      );
    })
  );

  await testAsync('falla de red -> lanza error controlado explicando que no se pudo contactar', () =>
    withMockFetch(() => Promise.reject(new Error('getaddrinfo ENOTFOUND')), async ({ checkKnownVulnerabilities }) => {
      await assert.rejects(
        () => checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' }),
        /No se pudo contactar/
      );
    })
  );

  await testAsync('sin ecosistema ni nombre -> lanza error controlado sin llegar a llamar a fetch', async () => {
    delete require.cache[require.resolve('./lib/vulnerabilidades')];
    const { checkKnownVulnerabilities } = require('./lib/vulnerabilidades');
    // checkKnownVulnerabilities es async, así que el "throw" de validación
    // se convierte en una promesa rechazada, no en una excepción síncrona.
    await assert.rejects(() => checkKnownVulnerabilities({}), /ecosistema.*nombre|nombre.*ecosistema/i);
  });

  // ronda 5 (2026-09): primera ronda de ataques dedicada a vulnerabilidades.js
  // — no es un motor de texto, así que en vez de evasiones se atacó la
  // ROBUSTEZ frente a una respuesta de OSV.dev malformada/desproporcionada.
  // Se confirmaron 3 excepciones no controladas (una respuesta con UN SOLO
  // registro raro reventaba TODA la herramienta, sin refund posible del uso
  // consumido) y 2 huecos de tamaño sin tope.

  await testAsync('ronda 5: entrada null dentro de "vulns" -> ya no revienta, se reporta como registro malformado', () =>
    withMockFetch(() => jsonResponse(200, { vulns: [null, { id: 'X-1', summary: 'real' }] }), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.strictEqual(r.totalEncontradas, 2);
      const malformada = r.vulnerabilidades.find(v => v.malformada);
      assert.ok(malformada, 'se esperaba que el registro null se reportara como malformado, no que desapareciera');
      assert.strictEqual(malformada.id, null);
      const real = r.vulnerabilidades.find(v => v.id === 'X-1');
      assert.ok(real, 'el registro válido junto al malformado debe seguir procesándose bien');
    })
  );

  await testAsync('ronda 5: "severity" con un elemento null -> ya no revienta, usa el siguiente elemento válido', () =>
    withMockFetch(() => jsonResponse(200, { vulns: [{ id: 'X-2', severity: [null, { type: 'CVSS_V3', score: 'AV:N' }] }] }), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.strictEqual(r.vulnerabilidades[0].severidad, 'AV:N');
    })
  );

  await testAsync('ronda 5: "affected" con un elemento null -> ya no revienta, usa el siguiente elemento válido', () =>
    withMockFetch(() => jsonResponse(200, { vulns: [{ id: 'X-3', affected: [null, { ecosystem_specific: { severity: 'HIGH' } }] }] }), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.strictEqual(r.vulnerabilidades[0].severidad, 'HIGH');
    })
  );

  await testAsync('ronda 5: "summary" desproporcionadamente grande (100,000 caracteres) se recorta', () =>
    withMockFetch(() => jsonResponse(200, { vulns: [{ id: 'X-4', summary: 'A'.repeat(100000) }] }), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.ok(r.vulnerabilidades[0].resumen.length <= 301, 'el resumen debe quedar acotado, no pasar 100,000 caracteres tal cual al agente');
    })
  );

  await testAsync('ronda 5: registro sin "id" -> link queda null, no una URL rota terminando en "undefined"', () =>
    withMockFetch(() => jsonResponse(200, { vulns: [{ summary: 'sin id' }] }), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.strictEqual(r.vulnerabilidades[0].link, null);
    })
  );

  await testAsync('ronda 5: respuesta con miles de entradas se recorta con un tope explícito, sin perder el conteo real', () =>
    withMockFetch(() => jsonResponse(200, { vulns: new Array(5000).fill(0).map((_, i) => ({ id: 'X-' + i, summary: 'v' })) }), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.strictEqual(r.totalEncontradas, 5000, 'el conteo real debe reflejar las 5000, aunque no se devuelvan todas');
      assert.ok(r.vulnerabilidades.length < 5000, 'el arreglo devuelto debe estar acotado');
      assert.strictEqual(r.demasiadosResultados, true);
    })
  );

  await testAsync('ronda 5 (control): respuesta normal, pocas entradas, no se marca como "demasiadosResultados"', () =>
    withMockFetch(() => jsonResponse(200, RESPUESTA_CON_VULNS), async ({ checkKnownVulnerabilities }) => {
      const r = await checkKnownVulnerabilities({ ecosistema: 'npm', nombre: 'x' });
      assert.strictEqual(r.demasiadosResultados, false);
    })
  );

  console.log('');
  console.log(pass + ' pruebas OK, ' + fail + ' fallidas.');
  if (fail > 0) process.exit(1);
}

main();
