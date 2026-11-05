"use strict";
// Pruebas para lib/session-hijack.js — el motor de detect_session_hijack_risk.
//
// Correr con: node test-session-hijack.js

const assert = require('assert');
const { checkSessionHijackRisk } = require('./lib/session-hijack');

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

test('sesión buscada por índice [id] sin vínculo de dueño -> alto riesgo', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function handler(req, res) {
        const session = sessions[req.query.sessionId];
        if (!session) return res.status(404).send();
        req.session = session;
        next();
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('sesión buscada con .get(id) sin vínculo de dueño -> alto riesgo', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function handler(req, res) {
        const sess = sessionStore.get(req.body.sessionId);
        return res.json(sess.data);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('identificador de sesión generado con Math.random() -> riesgo (entropía débil)', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function crearSesion(userId) {
        const sessionId = Math.random().toString(36);
        sessions[sessionId] = { userId: userId };
        return sessionId;
      }
    `
  });
  assert.notStrictEqual(r.veredicto, 'Aceptable');
  const tieneHallazgoEntropia = r.hallazgos.some(h => h.etiqueta.indexOf('poca entropía') !== -1);
  assert.ok(tieneHallazgoEntropia);
});

test('identificador de sesión generado con un contador incremental -> riesgo (entropía débil)', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      let sessionCounter = 0;
      function crearSesion(userId) {
        const sessionId = sessionCounter++;
        sessions[sessionId] = { userId };
        return sessionId;
      }
    `
  });
  const tieneHallazgoEntropia = r.hallazgos.some(h => h.etiqueta.indexOf('poca entropía') !== -1);
  assert.ok(tieneHallazgoEntropia);
});

test('combinación: lookup sin vínculo + generación débil -> puntaje peor que cualquiera solo', () => {
  const combo = checkSessionHijackRisk({
    codigo: `
      function crearSesion(userId) {
        const sessionId = Math.random().toString(36);
        sessions[sessionId] = { userId };
      }
      function handler(req, res) {
        const session = sessions[req.query.sessionId];
        req.session = session;
      }
    `
  });
  const soloLookup = checkSessionHijackRisk({
    codigo: `
      function handler(req, res) {
        const session = sessions[req.query.sessionId];
        req.session = session;
      }
    `
  });
  assert.ok(combo.puntaje < soloLookup.puntaje, 'combo.puntaje=' + combo.puntaje + ' soloLookup.puntaje=' + soloLookup.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('sesión buscada por ID pero con comparación explícita de userId contra req.user -> aceptable', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function handler(req, res) {
        const session = sessions[req.query.sessionId];
        if (!session || session.userId !== req.user.id) {
          return res.status(403).send();
        }
        req.session = session;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('el identificador es en realidad un token firmado y verificado con jwt.verify -> aceptable', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function handler(req, res) {
        const session = sessions[req.query.sessionId];
        const decoded = jwt.verify(req.query.sessionId, SECRET);
        req.session = session;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('crear una sesión nueva (escritura sessions[id] = {...}) no cuenta como lookup riesgoso', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function crearSesion(userId) {
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions[sessionId] = { userId };
        return sessionId;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('identificador generado con crypto.randomBytes (criptográficamente seguro) -> aceptable', () => {
  const r = checkSessionHijackRisk({
    codigo: `
      function crearSesion(userId) {
        const sessionId = crypto.randomBytes(32).toString('hex');
        sessions[sessionId] = { userId };
        return sessionId;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna sesión en el código -> aceptable, puntaje 100', () => {
  const r = checkSessionHijackRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkSessionHijackRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkSessionHijackRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
