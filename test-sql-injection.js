"use strict";
// Pruebas para lib/sql-injection.js — el motor de detect_sql_injection_risk.
//
// Correr con: node test-sql-injection.js

const assert = require('assert');
const { checkSqlInjectionRisk } = require('./lib/sql-injection');

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

test('db.query con concatenación de una variable -> alto riesgo', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
      async function buscar(nombre) {
        return db.query("SELECT * FROM users WHERE name = '" + nombre + "'");
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('cursor.execute con f-string interpolado -> alto riesgo', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
def buscar(id_usuario):
    cursor.execute(f"SELECT * FROM users WHERE id = {id_usuario}")
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('nombre de tabla interpolado directo en la consulta -> alto riesgo', () => {
  const r = checkSqlInjectionRisk({
    codigo: "function listar(tabla) { return db.query(`SELECT * FROM ${tabla}`); }"
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('patrón Datadog: afirma "solo lectura" sin aplicación real -> riesgo (no aceptable)', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
      // Esta herramienta es de SOLO LECTURA — nunca modifica la base de datos.
      async function buscar(nombreUsuario) {
        return db.query('SELECT * FROM users WHERE name = $1', [nombreUsuario]);
      }
    `
  });
  assert.ok(r.puntaje < 100, 'puntaje=' + r.puntaje);
  const tieneHallazgoLectura = r.hallazgos.some(h => h.etiqueta.includes('solo lectura'));
  assert.ok(tieneHallazgoLectura);
});

test('afirma "solo lectura" con un readOnly:true no relacionado (UI) lejos en el archivo NO debe contar como aplicación real -> riesgo', () => {
  const relleno = '  // relleno de distancia\n'.repeat(40);
  const r = checkSqlInjectionRisk({
    codigo: `
      // Esta herramienta es de solo lectura.
      async function buscar(nombreUsuario) {
        return db.query('SELECT * FROM users WHERE name = $1', [nombreUsuario]);
      }
${relleno}
      const uiConfig = { readOnly: true, theme: 'dark' };
    `
  });
  assert.ok(r.puntaje < 100, 'puntaje=' + r.puntaje);
  const tieneHallazgoLectura = r.hallazgos.some(h => h.etiqueta.includes('solo lectura'));
  assert.ok(tieneHallazgoLectura);
});

test('función local "prepare(valor)" passthrough no debe contar como consulta preparada real -> alto riesgo', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
      function prepare(valor) { return valor; }
      async function buscar(nombre) {
        const preparado = prepare(nombre);
        return db.query("SELECT * FROM users WHERE name = '" + preparado + "'");
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('connection.prepare( como método real de un objeto conocido SÍ cuenta como señal de validación -> aceptable', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
      function buscar(nombre) {
        const consultaPreparada = connection.prepare(nombre);
        return db.query('SELECT * FROM users WHERE name = ' + consultaPreparada);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('combinación de varios problemas puntúa peor que uno solo', () => {
  const soloUno = checkSqlInjectionRisk({
    codigo: `db.query("SELECT * FROM users WHERE id = " + id)`
  });
  const combinado = checkSqlInjectionRisk({
    codigo: `
      // read-only tool, nunca escribe
      db.query("SELECT * FROM users WHERE id = " + id)
    `
  });
  assert.ok(combinado.puntaje < soloUno.puntaje, 'combinado=' + combinado.puntaje + ' solo=' + soloUno.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo — evitar falsos positivos) ----------

test('consulta literal con parámetro preparado ($1) -> aceptable', () => {
  const r = checkSqlInjectionRisk({
    codigo: `db.query('SELECT * FROM users WHERE id = $1', [id])`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('consulta literal parametrizada en Python (%s con tupla) -> aceptable', () => {
  const r = checkSqlInjectionRisk({
    codigo: `cursor.execute("SELECT * FROM users WHERE id = %s", (id_usuario,))`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('escapado con connection.escape() antes de concatenar -> aceptable', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
      function buscar(nombre) {
        const nombreSeguro = connection.escape(nombre);
        return db.query('SELECT * FROM users WHERE name = ' + nombreSeguro);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('afirma "solo lectura" con aplicación real (SET TRANSACTION READ ONLY) -> aceptable', () => {
  const r = checkSqlInjectionRisk({
    codigo: `
      // Esta herramienta es de solo lectura.
      async function buscar(id) {
        await db.query('SET TRANSACTION READ ONLY');
        return db.query('SELECT * FROM users WHERE id = $1', [id]);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('código sin ninguna consulta SQL -> aceptable', () => {
  const r = checkSqlInjectionRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('texto vacío -> lanza error', () => {
  assert.throws(() => checkSqlInjectionRisk({ codigo: '' }));
  assert.throws(() => checkSqlInjectionRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
