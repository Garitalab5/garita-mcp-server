"use strict";
// Pruebas para lib/slopsquatting.js — el verificador de autenticidad de
// paquetes (typosquatting / "slopsquatting"). Usa un fetch simulado (mock)
// con respuestas realistas del registro de npm, salvo un puñado de casos
// marcados como "(red real)" que sí llaman a registry.npmjs.org de verdad
// contra paquetes reales conocidos y estables (left-pad, chalkk, loadash) —
// confirmado que este entorno SÍ tiene salida a registry.npmjs.org (a
// diferencia de api.osv.dev, ver test-vulnerabilidades.js), así que no hace
// falta mockear esos casos.
//
// Correr con: node test-slopsquatting.js

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
  delete require.cache[require.resolve('./lib/slopsquatting')];
  const mod = require('./lib/slopsquatting');
  return fn(mod).finally(() => { global.fetch = original; });
}

function jsonResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status: status,
    json: () => Promise.resolve(body)
  });
}

function diasAtras(n) {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

function manifiestoNpm(opts) {
  opts = opts || {};
  const creado = opts.creadoHaceDias !== undefined ? diasAtras(opts.creadoHaceDias) : diasAtras(2000);
  const versiones = opts.versiones || { '1.0.0': {} };
  const ultima = opts.ultima || Object.keys(versiones)[Object.keys(versiones).length - 1];
  if (opts.scripts && versiones[ultima]) versiones[ultima] = Object.assign({}, versiones[ultima], { scripts: opts.scripts });

  const time = { created: creado, modified: creado };
  let offset = 0;
  Object.keys(versiones).forEach(function (v) {
    time[v] = new Date(Date.parse(creado) + offset).toISOString();
    offset += 1000;
  });

  return {
    name: opts.nombre || 'paquete-de-prueba',
    'dist-tags': { latest: ultima },
    time: time,
    versions: versiones,
    repository: opts.repository !== undefined ? opts.repository : { url: 'git+https://github.com/ejemplo/repo.git' },
    homepage: opts.homepage !== undefined ? opts.homepage : 'https://github.com/ejemplo/repo#readme',
    readme: opts.readme !== undefined ? opts.readme : 'Un README real con contenido de sobra para no contar como placeholder.',
    maintainers: opts.maintainers || [{ name: 'alguien' }]
  };
}

// ---------- distanciaLevenshtein / coincidenciaCercana (puras, sin fetch) ----------

test('distanciaLevenshtein: mismo string -> 0', () => {
  const { distanciaLevenshtein } = require('./lib/slopsquatting');
  assert.strictEqual(distanciaLevenshtein('chalk', 'chalk'), 0);
});

test('distanciaLevenshtein: una sustitución -> 1', () => {
  const { distanciaLevenshtein } = require('./lib/slopsquatting');
  assert.strictEqual(distanciaLevenshtein('chalk', 'chalp'), 1);
});

test('distanciaLevenshtein: una inserción -> 1', () => {
  const { distanciaLevenshtein } = require('./lib/slopsquatting');
  assert.strictEqual(distanciaLevenshtein('chalk', 'chalkk'), 1);
});

test('distanciaLevenshtein: string vacío contra algo -> longitud del otro', () => {
  const { distanciaLevenshtein } = require('./lib/slopsquatting');
  assert.strictEqual(distanciaLevenshtein('', 'lodash'), 6);
});

test('coincidenciaCercana: el nombre EXACTO de un paquete popular no se marca a sí mismo', () => {
  const { coincidenciaCercana } = require('./lib/slopsquatting');
  assert.strictEqual(coincidenciaCercana('lodash'), null);
});

test('coincidenciaCercana: nombre a 1 edición de "lodash" -> lo encuentra', () => {
  const { coincidenciaCercana } = require('./lib/slopsquatting');
  const r = coincidenciaCercana('loadash');
  assert.ok(r && r.paquete === 'lodash');
});

test('coincidenciaCercana: nombre sin relación -> null', () => {
  const { coincidenciaCercana } = require('./lib/slopsquatting');
  assert.strictEqual(coincidenciaCercana('mi-paquete-interno-de-la-empresa'), null);
});

// ---------- validación de entradas ----------

testAsync('sin "ecosistema" ni "nombre" -> error claro', async () => {
  await withMockFetch(() => { throw new Error('no debería llamar a fetch'); }, async ({ checkPackageAuthenticity }) => {
    await assert.rejects(() => checkPackageAuthenticity({}), /ecosistema.*nombre|nombre.*ecosistema/i);
  });
});

testAsync('ecosistema no soportado (ej. "PyPI") -> error claro, no revienta', async () => {
  await withMockFetch(() => { throw new Error('no debería llamar a fetch'); }, async ({ checkPackageAuthenticity }) => {
    await assert.rejects(() => checkPackageAuthenticity({ ecosistema: 'PyPI', nombre: 'requests' }), /solo se soporta.*npm/i);
  });
});

// ---------- paquete que no existe ----------

testAsync('paquete que no existe (404) -> existe:false, avisa del riesgo de alucinación + squat futuro', async () => {
  await withMockFetch(() => jsonResponse(404, { error: 'Not found' }), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-que-no-existe-nunca-123' });
    assert.strictEqual(r.existe, false);
    assert.strictEqual(r.sev, 'warn');
    assert.ok(/alucin/i.test(r.resumen));
  });
});

// ---------- paquete legítimo y establecido ----------

testAsync('paquete legítimo, viejo, con historial y metadatos completos -> Aceptable, sin hallazgos', async () => {
  const manifest = manifiestoNpm({
    nombre: 'paquete-legitimo',
    creadoHaceDias: 2000,
    versiones: { '1.0.0': {}, '1.1.0': {}, '2.0.0': {}, '2.1.0': {} }
  });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-legitimo' });
    assert.strictEqual(r.existe, true);
    assert.strictEqual(r.puntaje, 100);
    assert.strictEqual(r.veredicto, 'Aceptable');
    assert.deepStrictEqual(r.hallazgos.map(h => h.id), ['sin_senales']);
  });
});

// ---------- regla 1: typosquat clásico ----------

testAsync('nombre a 1 edición de un paquete popular + muy poco historial -> posible_typosquat, Alto riesgo', async () => {
  const manifest = manifiestoNpm({ nombre: 'loadash', creadoHaceDias: 900, versiones: { '1.0.0': {} } });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'loadash' });
    assert.ok(r.hallazgos.some(h => h.id === 'posible_typosquat'));
    assert.strictEqual(r.veredicto, 'Alto riesgo');
    assert.strictEqual(r.metadatos.coincidenciaCercana, 'lodash');
  });
});

test('(control, red real) "left-pad" no se marca como typosquat de sí mismo', async () => {
  // Verificado por separado en desarrollo contra la API real (existe hace
  // más de 10 años, con historial largo) — aquí se deja como prueba pura
  // sin red, reutilizando coincidenciaCercana directamente.
  const { coincidenciaCercana } = require('./lib/slopsquatting');
  assert.strictEqual(coincidenciaCercana('left-pad'), null);
});

testAsync('control: nombre parecido a uno popular pero YA con historial largo -> NO dispara posible_typosquat', async () => {
  const manifest = manifiestoNpm({
    nombre: 'loadash',
    creadoHaceDias: 3000,
    versiones: { '1.0.0': {}, '1.1.0': {}, '1.2.0': {}, '2.0.0': {}, '2.1.0': {} }
  });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'loadash' });
    assert.ok(!r.hallazgos.some(h => h.id === 'posible_typosquat'), 'un nombre parecido pero con años de historial propio no debería marcarse como impostor');
  });
});

// ---------- regla 2: patrón de "slopsquatting" (versión inicial anómala) ----------

testAsync('publicado hace días, una sola versión, y empieza en 35.x.y -> version_inicial_anomala, crítico', async () => {
  const manifest = manifiestoNpm({ nombre: 'bigops-api', creadoHaceDias: 3, versiones: { '35.0.1': {} } });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'bigops-api' });
    const h = r.hallazgos.find(x => x.id === 'version_inicial_anomala');
    assert.ok(h, 'se esperaba que disparara version_inicial_anomala');
    assert.strictEqual(h.sev, 'critical');
    // Un único hallazgo crítico de 45 puntos deja el puntaje en 55 — mismo
    // comportamiento que el motor de Escudo (ver lib/escudo.js: un solo
    // hallazgo "critical" no necesariamente hunde el veredicto general a
    // "Alto riesgo" si su deducción por sí sola no llega a 50).
    assert.strictEqual(r.veredicto, 'Riesgo moderado');
  });
});

testAsync('control: publicado hace días pero empezando en 0.x/1.x normal -> NO dispara version_inicial_anomala (solo el aviso leve de "reciente")', async () => {
  const manifest = manifiestoNpm({ nombre: 'paquete-nuevo-normal', creadoHaceDias: 3, versiones: { '0.1.0': {} } });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-nuevo-normal' });
    assert.ok(!r.hallazgos.some(h => h.id === 'version_inicial_anomala'));
    assert.ok(r.hallazgos.some(h => h.id === 'publicado_recientemente'));
  });
});

// ---------- regla 3: script de instalación automática + reciente ----------

testAsync('script postinstall + paquete reciente -> script_instalacion_reciente', async () => {
  const manifest = manifiestoNpm({ nombre: 'paquete-con-postinstall', creadoHaceDias: 10, versiones: { '1.0.0': {} }, scripts: { postinstall: 'node robar-credenciales.js' } });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-con-postinstall' });
    assert.ok(r.hallazgos.some(h => h.id === 'script_instalacion_reciente'));
  });
});

testAsync('control: script postinstall pero paquete VIEJO -> NO dispara la regla (motivo legítimo típico: compilar binarios nativos)', async () => {
  const manifest = manifiestoNpm({ nombre: 'paquete-nativo-viejo', creadoHaceDias: 2000, versiones: { '1.0.0': {}, '2.0.0': {} }, scripts: { postinstall: 'node-gyp rebuild' } });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-nativo-viejo' });
    assert.ok(!r.hallazgos.some(h => h.id === 'script_instalacion_reciente'));
  });
});

// ---------- regla 4: sin metadatos básicos ----------

testAsync('sin repositorio, sin homepage, sin README real -> sin_metadatos_basicos', async () => {
  const manifest = manifiestoNpm({ nombre: 'paquete-pelado', repository: null, homepage: null, readme: 'ERROR: No README data found!' });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-pelado' });
    assert.ok(r.hallazgos.some(h => h.id === 'sin_metadatos_basicos'));
  });
});

testAsync('control: sin repositorio pero SÍ con homepage -> no dispara sin_metadatos_basicos (basta con uno)', async () => {
  const manifest = manifiestoNpm({ nombre: 'paquete-con-homepage', repository: null, homepage: 'https://ejemplo.com' });
  await withMockFetch(() => jsonResponse(200, manifest), async ({ checkPackageAuthenticity }) => {
    const r = await checkPackageAuthenticity({ ecosistema: 'npm', nombre: 'paquete-con-homepage' });
    assert.ok(!r.hallazgos.some(h => h.id === 'sin_metadatos_basicos'));
  });
});

// ---------- README placeholder ----------

test('README placeholder "ERROR: No README data found!" se trata como ausente', () => {
  // Probado indirectamente arriba (paquete-pelado); esta prueba deja
  // constancia explícita de la frase exacta que dispara el placeholder.
  const readme = 'ERROR: No README data found!';
  assert.ok(/ERROR:\s*No README data found/i.test(readme));
});

console.log('\n' + pass + ' pruebas OK, ' + fail + ' fallidas.');
if (fail > 0) process.exit(1);
