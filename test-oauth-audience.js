"use strict";
// Pruebas para lib/oauth-audience.js — el motor de detect_oauth_audience_confusion_risk.
//
// Correr con: node test-oauth-audience.js

const assert = require('assert');
const { checkOAuthAudienceConfusionRisk } = require('./lib/oauth-audience');

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

test('validación de audiencia condicionada a una bandera de configuración -> alto riesgo', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token, config) {
        const payload = jwt.verify(token, SECRET);
        if (config.checkAudience) {
          if (payload.aud !== 'mi-servidor') {
            throw new Error('audiencia invalida');
          }
        }
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  const tieneCondicional = r.hallazgos.some(h => h.etiqueta.indexOf('bandera de configuración') !== -1);
  assert.ok(tieneCondicional);
});

test('comparación de audiencia que no coincide pero solo loguea (no rechaza) -> alto riesgo', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token) {
        const payload = jwt.verify(token, SECRET);
        if (payload.aud !== 'mi-servidor') {
          console.warn('audiencia no coincide, pero sigue');
        }
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('catch() silencia el error de audiencia lanzado por jwt.verify(..., {audience}) -> alto riesgo', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token) {
        try {
          const payload = jwt.verify(token, SECRET, { audience: 'mi-servidor' });
          return payload;
        } catch (e) {
          console.log('error verificando token', e);
        }
        return { sub: 'anonimo' };
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  const tieneCatch = r.hallazgos.some(h => h.etiqueta.indexOf('catch()') !== -1);
  assert.ok(tieneCatch);
});

test('ausencia total de chequeo de audiencia en el verificador propio -> alto riesgo', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token) {
        const payload = jwt.verify(token, SECRET);
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('validación de audiencia incondicional que rechaza con throw -> aceptable', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token) {
        const payload = jwt.verify(token, SECRET);
        if (payload.aud !== 'mi-servidor') {
          throw new Error('audiencia invalida');
        }
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('validación vía opción "audience" de la librería, con catch que RE-lanza -> aceptable', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token) {
        try {
          const payload = jwt.verify(token, SECRET, { audience: 'mi-servidor' });
          return payload;
        } catch (e) {
          throw new Error('token invalido: ' + e.message);
        }
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('rama de no-coincidencia que responde 403 (res.status) -> aceptable', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `
      function verificarToken(token, res) {
        const payload = jwt.verify(token, SECRET);
        if (payload.aud !== 'mi-servidor') {
          return res.status(403).json({ error: 'audiencia invalida' });
        }
        return payload;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ningún verificador de tokens en el código -> aceptable, puntaje 100', () => {
  const r = checkOAuthAudienceConfusionRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkOAuthAudienceConfusionRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkOAuthAudienceConfusionRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
