"use strict";
// Pruebas para lib/excessive-agency.js — el motor de
// detect_excessive_agency_risk.
//
// Correr con: node test-excessive-agency.js

const assert = require('assert');
const { checkExcessiveAgencyRisk } = require('./lib/excessive-agency');

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

test('herramienta de transferencia sin campo de confirmación exigido -> alto riesgo', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        {
          name: 'transferFunds',
          description: 'Transfiere fondos de una cuenta a otra',
          inputSchema: { type: 'object', properties: { monto: { type: 'number' }, destino: { type: 'string' } }, required: ['monto', 'destino'] }
        }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('herramienta "withdraw" sin confirmación y sin tope en el monto -> peor que solo una de las dos', () => {
  const soloSinGatillo = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        { name: 'withdraw', description: 'Retira fondos', inputSchema: { type: 'object', properties: { amount: { type: 'number', maximum: 1000 } }, required: ['amount'] } }
      ]
    }
  });
  const ambas = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        { name: 'withdraw', description: 'Retira fondos', inputSchema: { type: 'object', properties: { amount: { type: 'number' } }, required: [] } }
      ]
    }
  });
  assert.ok(ambas.puntaje < soloSinGatillo.puntaje);
});

test('herramienta destructiva ("delete_account") sin confirmación -> alto riesgo', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        { name: 'delete_account', description: 'Elimina una cuenta de usuario de forma permanente', inputSchema: { type: 'object', properties: { accountId: { type: 'string' } }, required: ['accountId'] } }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('herramienta "pagar" gatillada pero con campo de monto sin tope máximo -> riesgo moderado', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        { name: 'pagar_proveedor', description: 'Paga a un proveedor registrado', inputSchema: { type: 'object', properties: { monto: { type: 'number' }, confirmacion: { type: 'boolean' } }, required: ['confirmacion'] } }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('herramienta de transferencia con confirmación exigida y monto con tope -> aceptable', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        {
          name: 'transferFunds',
          description: 'Transfiere fondos de una cuenta a otra',
          inputSchema: { type: 'object', properties: { monto: { type: 'number', maximum: 500 }, confirmacion: { type: 'boolean' } }, required: ['confirmacion', 'monto'] }
        }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('una herramienta separada de "pedir aprobación" en el manifiesto no cuenta como mitigación real', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: {
      tools: [
        { name: 'transferFunds', description: 'Transfiere fondos', inputSchema: { type: 'object', properties: { monto: { type: 'number' } }, required: ['monto'] } },
        { name: 'requestApproval', description: 'Pide aprobación humana antes de transferir', inputSchema: { type: 'object', properties: {} } }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('herramienta sin ninguna acción destructiva o de alto valor -> aceptable, puntaje 100', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: { tools: [{ name: 'consultar_saldo', description: 'Consulta el saldo de una cuenta', inputSchema: { type: 'object', properties: { accountId: { type: 'string' } } } }] }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('campo de monto con "maximum" numérico no se marca sin tope', () => {
  const r = checkExcessiveAgencyRisk({
    manifest: {
      tools: [{ name: 'transferFunds', description: 'Transfiere fondos', inputSchema: { type: 'object', properties: { monto: { type: 'number', maximum: 10000 }, confirmacion: { type: 'boolean' } }, required: ['confirmacion'] } }]
    }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('manifiesto sin "tools" ni herramienta suelta -> lanza error', () => {
  assert.throws(() => checkExcessiveAgencyRisk({ manifest: {} }));
});

test('sin campo "manifest" -> lanza error', () => {
  assert.throws(() => checkExcessiveAgencyRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
