"use strict";
// Pruebas para lib/unbounded-allocation.js — el motor de detect_unbounded_allocation_risk.
//
// Correr con: node test-unbounded-allocation.js

const assert = require('assert');
const { checkUnboundedAllocationRisk } = require('./lib/unbounded-allocation');

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

test('express.json() sin "limit" -> alto riesgo', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      const app = express();
      app.use(express.json());
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('acumulación manual de stream (req.on("data")) sin chequeo de tamaño -> alto riesgo', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function handler(req, res) {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => { res.json(JSON.parse(body)); });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('fs.readFileSync con ruta dinámica y sin chequeo de tamaño -> alto riesgo', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function leer(rutaUsuario) {
        return fs.readFileSync(rutaUsuario);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('new Array(cantidadVariable) sin tope -> alto riesgo', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function crear(userCount) {
        return new Array(userCount).fill(0);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('Buffer.alloc(size) con tamaño variable sin tope -> alto riesgo', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function crear(size) {
        return Buffer.alloc(size);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('bucle "for" acotado por una variable externa sin tope -> alto riesgo', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function procesar(cantidad, items) {
        for (let i = 0; i < cantidad; i++) {
          items.push(procesarUno(i));
        }
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación: body sin límite + array sin tope -> puntaje peor que cualquiera solo', () => {
  const combo = checkUnboundedAllocationRisk({
    codigo: `
      const app = express();
      app.use(express.json());
      function crear(userCount) {
        return new Array(userCount).fill(0);
      }
    `
  });
  const solo1 = checkUnboundedAllocationRisk({
    codigo: `
      const app = express();
      app.use(express.json());
    `
  });
  assert.ok(combo.puntaje < solo1.puntaje, 'combo.puntaje=' + combo.puntaje + ' solo1.puntaje=' + solo1.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('express.json({ limit: "2mb" }) -> aceptable', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      const app = express();
      app.use(express.json({ limit: '2mb' }));
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('acumulación manual de stream CON chequeo de tamaño -> aceptable', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function handler(req, res) {
        let body = '';
        let size = 0;
        req.on('data', chunk => {
          size += chunk.length;
          if (size > MAX_BODY_SIZE) { req.destroy(); return; }
          body += chunk;
        });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('fs.readFileSync con ruta dinámica pero CON fs.statSync antes -> aceptable', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function leer(rutaUsuario) {
        const info = fs.statSync(rutaUsuario);
        if (info.size > MAX_FILE_SIZE) { throw new Error('demasiado grande'); }
        return fs.readFileSync(rutaUsuario);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('fs.readFileSync con ruta literal fija -> aceptable', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function leer() {
        return fs.readFileSync('./config.json');
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('new Array(Math.min(userCount, MAX)) -> aceptable (tope aplicado en el propio argumento)', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function crear(userCount) {
        return new Array(Math.min(userCount, 1000)).fill(0);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('bucle "for" acotado por una variable externa pero CON chequeo de tope antes -> aceptable', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function procesar(cantidad, items) {
        if (cantidad > 10000) { throw new Error('demasiado'); }
        for (let i = 0; i < cantidad; i++) {
          items.push(procesarUno(i));
        }
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('bucle "for" acotado por un número fijo (literal) -> aceptable', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `
      function procesar(items) {
        for (let i = 0; i < 100; i++) {
          items.push(procesarUno(i));
        }
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ningún patrón riesgoso -> aceptable, puntaje 100', () => {
  const r = checkUnboundedAllocationRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkUnboundedAllocationRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkUnboundedAllocationRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
