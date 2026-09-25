"use strict";
// Pruebas para lib/traversal.js — el motor de detect_path_traversal_risk.
//
// Correr con: node test-traversal.js

const assert = require('assert');
const { checkPathTraversalRisk } = require('./lib/traversal');

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

test('fs.readFile con variable sin validar -> alto riesgo', () => {
  const r = checkPathTraversalRisk({
    codigo: `
      async function leerArchivo(req) {
        const nombre = req.query.archivo;
        const contenido = fs.readFileSync(EXCEL_FILES_PATH + nombre, 'utf8');
        return contenido;
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('open() de Python con variable sin validar -> riesgo', () => {
  const r = checkPathTraversalRisk({
    codigo: `
def leer_documento(nombre_archivo):
    ruta = os.path.join(CARPETA_BASE, nombre_archivo)
    with open(ruta, 'r') as f:
        return f.read()
    `
  });
  assert.ok(r.puntaje < 80, 'puntaje=' + r.puntaje);
});

test('ruta absoluta al CVE real de Excel (path traversal, sin resolver ../) -> alto riesgo', () => {
  const r = checkPathTraversalRisk({
    codigo: `
      function getExcelPath(nombreArchivo) {
        return path.join(process.env.EXCEL_FILES_PATH, nombreArchivo);
      }
      const data = fs.readFileSync(getExcelPath(nombreArchivo));
    `
  });
  assert.ok(r.puntaje < 80);
});

test('referencia directa a /etc/passwd dentro de una operación de archivo -> alto riesgo', () => {
  const r = checkPathTraversalRisk({
    codigo: `const contenido = fs.readFileSync('/etc/passwd', 'utf8');`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('referencia directa a llave SSH privada dentro de open() -> alto riesgo', () => {
  const r = checkPathTraversalRisk({
    codigo: `with open(os.path.expanduser('~/.ssh/id_rsa')) as f:\n    key = f.read()`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('valida contra "../" pero no rechaza rutas absolutas -> riesgo moderado', () => {
  const r = checkPathTraversalRisk({
    codigo: `
      const nombre = req.body.nombre;
      if (nombre.includes('..')) throw new Error('ruta inválida');
      const contenido = fs.readFileSync(path.join(BASE_DIR, nombre));
    `
  });
  assert.ok(r.puntaje < 100);
  assert.ok(r.puntaje >= 50, 'puntaje=' + r.puntaje);
});

test('combinación de varios problemas puntúa peor que uno solo', () => {
  const soloUno = checkPathTraversalRisk({
    codigo: `const data = fs.readFileSync(req.query.archivo);`
  });
  const combinado = checkPathTraversalRisk({
    codigo: `
      const ruta = req.query.archivo;
      const secreto = fs.readFileSync('/etc/shadow');
      const data = fs.readFileSync(ruta);
    `
  });
  assert.ok(combinado.puntaje < soloUno.puntaje, 'combinado=' + combinado.puntaje + ' solo=' + soloUno.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo — evitar falsos positivos) ----------

test('fs.readFile con una ruta fija (string literal) -> aceptable', () => {
  const r = checkPathTraversalRisk({
    codigo: `const config = fs.readFileSync('./config/settings.json', 'utf8');`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('valida contra "../" con path.resolve + startsWith contra el directorio base y rechaza rutas absolutas -> aceptable', () => {
  const r = checkPathTraversalRisk({
    codigo: `
      const nombre = req.query.archivo;
      if (path.isAbsolute(nombre)) throw new Error('ruta absoluta no permitida');
      const rutaFinal = path.resolve(BASE_DIR, nombre);
      if (!rutaFinal.startsWith(BASE_DIR)) throw new Error('fuera del directorio permitido');
      const contenido = fs.readFileSync(rutaFinal);
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('usa path.basename para quedarse solo con el nombre de archivo -> aceptable', () => {
  const r = checkPathTraversalRisk({
    codigo: `
      const nombreSeguro = path.basename(req.query.archivo);
      const contenido = fs.readFileSync(path.join(BASE_DIR, nombreSeguro));
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('usa secure_filename de Werkzeug (Python/Flask) -> aceptable', () => {
  const r = checkPathTraversalRisk({
    codigo: `
from werkzeug.utils import secure_filename
def guardar(nombre_subido):
    nombre = secure_filename(nombre_subido)
    with open(os.path.join(CARPETA, nombre), 'wb') as f:
        pass
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('código sin ninguna operación de archivo -> aceptable', () => {
  const r = checkPathTraversalRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('texto vacío -> lanza error', () => {
  assert.throws(() => checkPathTraversalRisk({ codigo: '' }));
  assert.throws(() => checkPathTraversalRisk({}));
});

test('template literal con interpolación de variable se trata como no confiable', () => {
  const r = checkPathTraversalRisk({
    codigo: 'const data = fs.readFileSync(`./uploads/${req.query.nombre}`);'
  });
  assert.ok(r.puntaje < 80, 'puntaje=' + r.puntaje);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
