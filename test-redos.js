"use strict";
// Pruebas para lib/redos.js — el motor de detect_redos_risk.
//
// Correr con: node test-redos.js

const assert = require('assert');
const { checkRedosRisk } = require('./lib/redos');

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

test('regex con cuantificador anidado (a+)+ aplicada contra req.body sin tope -> alto riesgo', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(req) {
        var re = /(a+)+/;
        if (re.test(req.body.texto)) { return true; }
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('regex con cuantificador anidado (\\s*\\w+)* usada vía texto.match(re) -> alto riesgo', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(texto) {
        const RE = /(\\s*\\w+)*/;
        return texto.match(RE);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('alternancia con ramas superpuestas y cuantificador (a|ab)+ -> alto riesgo', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(req) {
        var re = /(a|ab)+/;
        return re.test(req.query.valor);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('RegExp(x) de JavaScript construido a partir de una variable (no literal) -> alto riesgo', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(userPattern, texto) {
        var re = new RegExp(userPattern);
        return re.test(texto);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  const esDinamico = r.hallazgos.some(h => h.etiqueta.indexOf('fuente que NO es un texto fijo') !== -1);
  assert.ok(esDinamico);
});

test('re.compile() de Python construido a partir de una variable -> alto riesgo', () => {
  const r = checkRedosRisk({
    codigo: `
def validar(patron_usuario, texto):
    re_compilado = re.compile(patron_usuario)
    return re_compilado.match(texto)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('re.match() de Python con patrón catastrófico literal y sujeto variable, sin mitigar -> alto riesgo', () => {
  const r = checkRedosRisk({
    codigo: `
def validar(texto_usuario):
    return re.match("(a|ab)+", texto_usuario)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación: evil aplicada + regex dinámico -> puntaje peor que cualquiera de los dos solos', () => {
  const combo = checkRedosRisk({
    codigo: `
      function validar(req, userPattern) {
        var re = /(a+)+/;
        re.test(req.body.texto);
        var dyn = new RegExp(userPattern);
        dyn.test(req.body.otro);
      }
    `
  });
  const solo1 = checkRedosRisk({
    codigo: `
      function validar(req) {
        var re = /(a+)+/;
        re.test(req.body.texto);
      }
    `
  });
  assert.ok(combo.puntaje < solo1.puntaje, 'combo.puntaje=' + combo.puntaje + ' solo1.puntaje=' + solo1.puntaje);
});

test('regex evil definida pero sin aplicación confirmada en el fragmento -> riesgo moderado', () => {
  const r = checkRedosRisk({
    codigo: `
      function construir() {
        var re = /(a+)+/;
        return re;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('regex evil aplicada solo contra un texto fijo (código de prueba propio) -> aceptable', () => {
  const r = checkRedosRisk({
    codigo: `
      function test() {
        var re = /(a+)+/;
        return re.test("aaaaaaaaaa!");
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('regex evil con tope de longitud antes de aplicarla -> aceptable (mitigado)', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(texto) {
        if (texto.length > 200) { throw new Error('demasiado largo'); }
        var re = /(a+)+/;
        return re.test(texto);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('regex evil envuelta en el motor seguro RE2 -> aceptable (mitigado)', () => {
  const r = checkRedosRisk({
    codigo: `
      const RE2 = require('re2');
      function validar(texto) {
        var re = new RE2(/(a+)+/);
        return re.test(texto);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('re.match() de Python con patrón catastrófico pero sujeto también literal -> aceptable', () => {
  const r = checkRedosRisk({
    codigo: `
def prueba():
    return re.match("(a|ab)+", "aaaaabbbb")
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('RegExp() llamado con un string literal (no dinámico) -> no se marca como regex dinámico', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(texto) {
        var re = new RegExp('^\\\\d{3}-\\\\d{4}$');
        return re.test(texto);
      }
    `
  });
  const esDinamico = r.hallazgos.some(h => h.etiqueta.indexOf('fuente que NO es un texto fijo') !== -1);
  assert.ok(!esDinamico);
});

test('regex simple sin cuantificadores anidados aplicada contra entrada externa -> aceptable', () => {
  const r = checkRedosRisk({
    codigo: `
      function validar(req) {
        var re = /^\\d{3}-\\d{4}$/;
        return re.test(req.body.texto);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna expresión regular en el código -> aceptable, puntaje 100', () => {
  const r = checkRedosRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkRedosRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkRedosRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
