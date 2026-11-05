"use strict";
// Pruebas para lib/dynamic-code.js — el motor de detect_dynamic_code_risk
// (Escudo de Código Dinámico).
//
// Correr con: node test-dynamic-code.js

const assert = require('assert');
const { checkDynamicCodeRisk } = require('./lib/dynamic-code');

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

test('eval() sobre contenido recuperado de un vector store (patrón CVE-2026-26030) -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
def filtrar(query, contenido_recuperado):
    filtro = eval(contenido_recuperado)
    return filtro
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('Function() armado por concatenación con una respuesta del modelo -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function ejecutarRespuesta(respuestaDelModelo) {
  var fn = Function('return ' + respuestaDelModelo);
  return fn();
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('vm.runInContext() con código dinámico del agente -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function correr(codigoDelAgente, contexto) {
  return vm.runInContext(codigoDelAgente, contexto);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('vm.runInNewContext() con una entrada externa -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function correr(input) {
  return vm.runInNewContext(input.codigo);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('exec() de Python sobre un parámetro de herramienta -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
def ejecutar_snippet(tool_input):
    exec(tool_input)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('setTimeout() con un string armado a partir de una variable -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function programar(comandoUsuario) {
  setTimeout("procesar(" + comandoUsuario + ")", 1000);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('setInterval() con un string armado a partir de una variable -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function repetir(codigoRemoto) {
  setInterval("ejecutar(" + codigoRemoto + ")", 5000);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('vm2 usado para "sandbozear" un eval dinámico -> hallazgo adicional y peor puntaje que sin la falsa mitigación', () => {
  const sinVm2 = checkDynamicCodeRisk({
    codigo: `
function correr(codigoDelAgente) {
  return eval(codigoDelAgente);
}
    `
  });
  const conVm2 = checkDynamicCodeRisk({
    codigo: `
const { VM } = require('vm2');
function correr(codigoDelAgente) {
  const vm = new VM({ timeout: 1000 });
  return vm.run(codigoDelAgente);
}
function tambien(codigoDelAgente2) {
  return eval(codigoDelAgente2);
}
    `
  });
  assert.ok(conVm2.puntaje <= sinVm2.puntaje, 'usar vm2 como "sandbox" no debe mejorar el puntaje frente al mismo riesgo sin vm2: ' + conVm2.puntaje + ' vs ' + sinVm2.puntaje);
  assert.ok(conVm2.hallazgos.some(h => /vm2/.test(h.etiqueta)), 'debe haber un hallazgo específico mencionando vm2');
});

test('múltiples sinks no literales -> el puntaje baja más que con uno solo', () => {
  const uno = checkDynamicCodeRisk({
    codigo: `function a(x) { return eval(x); }`
  });
  const varios = checkDynamicCodeRisk({
    codigo: `
function a(x) { return eval(x); }
function b(y) { return eval(y); }
function c(z) { return eval(z); }
    `
  });
  assert.ok(varios.puntaje <= uno.puntaje, 'más de un sink sin validar debe pesar al menos igual: ' + varios.puntaje + ' vs ' + uno.puntaje);
});

test('eval indirecto (0, eval)(x) evade el sink directo pegado -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function correr(codigoDelAgente) {
  var indirectEval = (0, eval);
  return indirectEval(codigoDelAgente);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('new Function con 3+ argumentos: el cuerpo dinámico va en el ÚLTIMO argumento, no en el primero -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function compilar(nombreParametro, cuerpoDelModelo) {
  var fn = new Function('a', nombreParametro, cuerpoDelModelo);
  return fn;
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('vm.Script(...).runInContext(...) — API de dos pasos de Node no reconocida antes -> alto riesgo', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
function correr(codigoDelAgente, contexto) {
  return new vm.Script(codigoDelAgente).runInContext(contexto);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('clase propia "VM" sin relación con vm2 (sin require) no debe atribuirse a vm2 como falsa mitigación', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
class VM {
  constructor(opts) { this.opts = opts; }
  run(codigo) { return codigo; }
}
function correr(codigoDelAgente) {
  var vm = new VM({ timeout: 1000 });
  return eval(codigoDelAgente);
}
    `
  });
  assert.ok(!r.hallazgos.some(h => /vm2/.test(h.etiqueta)), 'no debe haber un hallazgo mencionando vm2 sin un require/from de la librería vm2: ' + JSON.stringify(r.hallazgos));
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('eval() con un texto fijo que escribió el desarrollador -> aceptable', () => {
  const r = checkDynamicCodeRisk({
    codigo: `const resultado = eval("2 + 2");`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('Function() con un cuerpo fijo (sin depender de una entrada externa) -> aceptable', () => {
  const r = checkDynamicCodeRisk({
    codigo: `const suma = Function('a', 'b', 'return a + b;');`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('exec() de Python con un string fijo -> aceptable', () => {
  const r = checkDynamicCodeRisk({
    codigo: `exec("print('hola mundo')")`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('setTimeout() con una referencia a función (no un string) -> no se detecta como sink', () => {
  const r = checkDynamicCodeRisk({
    codigo: `setTimeout(procesarPedido, 1000);`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos[0].severidad, 'ok');
});

test('vm.runInContext() con código dinámico dentro de isolated-vm -> aceptable (aislamiento real)', () => {
  const r = checkDynamicCodeRisk({
    codigo: `
const ivm = require('isolated-vm');
function correr(codigoDelAgente) {
  const isolate = new ivm.Isolate({ memoryLimit: 128 });
  const context = isolate.createContextSync();
  return vm.runInContext(codigoDelAgente, context);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna ejecución de código dinámico en el código analizado -> aceptable', () => {
  const r = checkDynamicCodeRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos[0].severidad, 'ok');
});

// ---------- Casos de entrada inválida ----------

test('sin "codigo" -> lanza error', () => {
  assert.throws(() => checkDynamicCodeRisk({}), /codigo/i);
});

test('"codigo" vacío -> lanza error', () => {
  assert.throws(() => checkDynamicCodeRisk({ codigo: '   ' }), /codigo/i);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
process.exit(fail > 0 ? 1 : 0);
