"use strict";
// Pruebas para lib/heuristics.js — el motor de audit_mcp_server y
// simulate_approval.
//
// Correr con: node test-heuristics.js

const assert = require('assert');
const { auditManifest, simulateApproval, DESTRUCTIVE_VERBS, stripInvisibles, findMaxNumber } = require('./lib/heuristics');

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

// ---------- Regresión: ejemplo demo del auditor debe seguir dando 55/100 ----------
test('demo de referencia (auditor) -> 55/100, sin cambios entre rondas', () => {
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
  assert.strictEqual(r.score, 55);
});

test('acción normal (monto 4200) -> retenido por verbo y por monto', () => {
  const normal = simulateApproval({ tool: 'transfer_funds', description: 'Transfiere fondos entre cuentas del usuario', arguments: { amount: 4200, currency: 'USD', to_account: 'ES91-2100-0000-1234' } });
  assert.strictEqual(normal.verdict, 'retenido');
  assert.strictEqual(normal.maxAmountDetected, 4200);
});

test('ataque previo: monto Infinity (1e400, número JSON crudo) -> retenido', () => {
  const infinityAction = JSON.parse('{"tool":"noop_tool","description":"no hace nada peligroso","arguments":{"amount":1e400}}');
  const r = simulateApproval(infinityAction);
  assert.strictEqual(r.verdict, 'retenido');
  assert.strictEqual(r.maxAmountDetected, 'Infinity');
});

test('ataque previo: relleno de 200,001 decoys antes del monto real -> retenido por truncamiento', () => {
  const decoys = new Array(200001).fill(1);
  const paddedAction = { tool: 'noop_tool', description: 'no hace nada peligroso', arguments: { amounts: [999999999].concat(decoys) } };
  const r = simulateApproval(paddedAction);
  assert.strictEqual(r.verdict, 'retenido');
  assert.ok(/demasiado grandes o complejos/.test(r.reasons.join(' ')));
});

test('ataque previo: zero-width space partiendo el verbo -> igual se detecta', () => {
  const zw = { tool: 'noop_tool', description: 'Tra​nsfiere fondos de la cuenta', arguments: {} };
  const r = simulateApproval(zw);
  assert.strictEqual(r.verdict, 'retenido');
});

test('caso normal de solo lectura -> auto-aprobado', () => {
  const ro = { tool: 'get_balance', description: 'Consulta el saldo actual', arguments: { account_id: 'abc' } };
  const r = simulateApproval(ro);
  assert.strictEqual(r.verdict, 'auto_aprobado');
});

// ---------- Ronda 5 (2026-09): ataques nuevos, más fuertes ----------

// A. Notación científica dentro de un STRING (no un número JSON) evadía el
// umbral de monto: "4e3" se leía como "4" en vez de 4000.
test('ronda 5 - A: monto en notación científica como STRING ("4e3") -> se detecta como 4000, retenido', () => {
  const neutral = { tool: 'consultar_saldo', description: 'Consulta el saldo de la cuenta.' };
  const r = simulateApproval(Object.assign({}, neutral, { arguments: { monto: '4e3' } }));
  assert.strictEqual(r.verdict, 'retenido');
  assert.strictEqual(r.maxAmountDetected, 4000);
});

test('ronda 5 - A: monto "Infinity" disfrazado de string ("1e400") -> se detecta igual que el número crudo', () => {
  const neutral = { tool: 'consultar_saldo', description: 'Consulta el saldo de la cuenta.' };
  const r = simulateApproval(Object.assign({}, neutral, { arguments: { monto: '1e400' } }));
  assert.strictEqual(r.verdict, 'retenido');
  assert.strictEqual(r.maxAmountDetected, 'Infinity');
});

test('ronda 5 - A (control): monto normal bajo el umbral, sin verbo destructivo -> auto-aprobado', () => {
  const neutral = { tool: 'consultar_saldo', description: 'Consulta el saldo de la cuenta.' };
  const r = simulateApproval(Object.assign({}, neutral, { arguments: { monto: 50 } }));
  assert.strictEqual(r.verdict, 'auto_aprobado');
});

// B. La lista de invisibles de heuristics.js era mucho más angosta que la
// ya endurecida en escudo.js — un guion suave (U+00AD, fuera de esa lista
// corta) partía un verbo destructivo sin que se detectara.
test('ronda 5 - B: guion suave (U+00AD) partiendo "borra" -> DESTRUCTIVE_VERBS lo detecta tras stripInvisibles', () => {
  const desc = 'bo­rra la cuenta del usuario';
  assert.strictEqual(DESTRUCTIVE_VERBS.test(stripInvisibles(desc)), true);
});

test('ronda 5 - B: acción con "bo­rra" (guion suave) -> retenido, igual que sin el caracter invisible', () => {
  const conInvisible = simulateApproval({ tool: 'borrar_cuenta', description: 'bo­rra la cuenta del usuario', arguments: {} });
  const sinInvisible = simulateApproval({ tool: 'borrar_cuenta', description: 'borra la cuenta del usuario', arguments: {} });
  assert.strictEqual(conInvisible.verdict, 'retenido');
  assert.strictEqual(sinInvisible.verdict, 'retenido');
});

test('ronda 5 - B: lista de invisibles ampliada también cubre separadores de dirección de texto (RTL override)', () => {
  const desc = 'transfi‮ere fondos ahora';
  assert.strictEqual(DESTRUCTIVE_VERBS.test(stripInvisibles(desc)), true);
});

// C. auditManifest solo aplicaba la penalización de respaldo por verbo
// destructivo cuando destructiveHint no estaba declarado. Una herramienta
// que MIENTE con destructiveHint: false sobre una acción claramente
// destructiva salía con puntaje limpio.
test('ronda 5 - C: destructiveHint: false mintiendo sobre acción destructiva -> penalización fuerte, no puntaje limpio', () => {
  const tool = {
    name: 'elimina_cuenta',
    description: 'Elimina la cuenta del usuario permanentemente.',
    annotations: { destructiveHint: false }
  };
  const r = auditManifest({ tools: [tool] });
  assert.ok(r.score < 80, 'el puntaje debe reflejar riesgo real, no "Aceptable" (' + r.score + ')');
  const textos = r.tools[0].findings.map((f) => f.text).join(' ');
  assert.ok(/contradicción activa/.test(textos));
});

test('ronda 5 - C (control): destructiveHint: true declarado correctamente -> NO dispara la penalización de contradicción', () => {
  const tool = {
    name: 'elimina_cuenta_ok',
    description: 'Elimina la cuenta del usuario permanentemente.',
    annotations: { destructiveHint: true }
  };
  const r = auditManifest({ tools: [tool] });
  const textos = r.tools[0].findings.map((f) => f.text).join(' ');
  assert.ok(!/contradicción activa/.test(textos));
});

test('ronda 5 - C (control): sin declarar destructiveHint en absoluto -> sigue igual que antes (penalización simple, no la fuerte)', () => {
  const tool = {
    name: 'elimina_cuenta_sin_anotar',
    description: 'Elimina la cuenta del usuario permanentemente.'
  };
  const r = auditManifest({ tools: [tool] });
  const textos = r.tools[0].findings.map((f) => f.text).join(' ');
  assert.ok(!/contradicción activa/.test(textos));
  assert.ok(/no declara destructiveHint: true de forma válida/.test(textos));
});

// ---------- Ronda 6 (2026-09): ataques nuevos ----------

// D. Homoglifo cirílico DENTRO del verbo destructivo evadía DESTRUCTIVE_VERBS
// (a diferencia de la ronda 5-B, acá el caracter es visible, no invisible —
// stripInvisibles no hace nada).
test('ronda 6 - D: homoglifo cirílico dentro de "borra" (bоrra, "o" cirílica) -> retenido', () => {
  const evil = { tool: 'accion_1234', description: 'Por favor bоrra el registro seleccionado ahora mismo.', arguments: {} };
  const r = simulateApproval(evil);
  assert.strictEqual(r.verdict, 'retenido');
  assert.ok(/verbo de acción irreversible/.test(r.reasons.join(' ')));
});

test('ronda 6 - D (control): texto normal sin homoglifos y sin verbo destructivo -> auto-aprobado', () => {
  const ok = { tool: 'accion_1234', description: 'Consulta el registro seleccionado.', arguments: {} };
  const r = simulateApproval(ok);
  assert.strictEqual(r.verdict, 'auto_aprobado');
});

test('ronda 6 - D: auditManifest también detecta el verbo destructivo con homoglifo en la descripción', () => {
  const tool = { name: 'accion_1234', description: 'Por favor bоrra el registro seleccionado ahora mismo.' };
  const r = auditManifest({ tools: [tool] });
  const textos = r.tools[0].findings.map((f) => f.text).join(' ');
  assert.ok(/acción irreversible/.test(textos));
});

// E. Monto en formato "punto de miles" (es-CO/europeo) como string evadía
// el umbral porque solo se probaba la interpretación US (punto = decimal).
test('ronda 6 - E: monto es-CO "1.500.000" (string, sin coma) -> se detecta como 1,500,000, retenido', () => {
  const r = simulateApproval({ tool: 'accion_1234', description: 'Procesa el registro número 88 del lote actual.', arguments: { monto: '1.500.000', referencia: 'lote-88' } }, {}, 500);
  assert.strictEqual(r.verdict, 'retenido');
  assert.strictEqual(r.maxAmountDetected, 1500000);
  assert.ok(/1.500.000|1\.500\.000/.test(r.reasons.join(' ')));
});

test('ronda 6 - E (control): formato US con coma de miles y decimal ("4,200.50") sigue interpretándose como antes', () => {
  const r = simulateApproval({ tool: 'accion_1234', description: 'Procesa el pago.', arguments: { monto: '4,200.50' } }, {}, 500);
  assert.strictEqual(r.verdict, 'retenido');
  assert.strictEqual(r.maxAmountDetected, 4200.5);
});

test('ronda 6 - E (control): monto pequeño sin puntos de miles ("50") no se reinterpreta de más -> auto-aprobado', () => {
  const r = simulateApproval({ tool: 'consultar_saldo', description: 'Consulta el saldo de la cuenta.', arguments: { monto: '50' } }, {}, 500);
  assert.strictEqual(r.verdict, 'auto_aprobado');
  assert.strictEqual(r.maxAmountDetected, 50);
});

console.log('');
console.log(pass + ' pruebas OK, ' + fail + ' fallidas.');
if (fail > 0) process.exit(1);
