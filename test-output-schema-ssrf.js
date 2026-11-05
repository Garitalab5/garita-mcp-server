"use strict";
// Pruebas para lib/output-schema-ssrf.js — el motor de
// detect_output_schema_ssrf_risk.
//
// Correr con: node test-output-schema-ssrf.js

const assert = require('assert');
const { checkOutputSchemaSsrfRisk } = require('./lib/output-schema-ssrf');

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

test('outputSchema no confiable validado sin Registry -> alto riesgo (patrón CVE-2026-116686)', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      async def validate_tool_result(result, tool):
          outputSchema = tool.outputSchema
          jsonschema.validate(result, outputSchema)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('inputSchema de list_tools() validado con Draft7Validator sin resolver -> alto riesgo', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      tools = await session.list_tools()
      for tool in tools:
          input_schema = tool.inputSchema
          Draft7Validator(input_schema).validate(data)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('llamada de red síncrona sin timeout dentro de async def -> alto riesgo (congela el event loop)', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      async def fetch_metadata(url):
          response = urllib.request.urlopen(url)
          return response.read()
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('requests.get sin timeout dentro de async def -> alto riesgo', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      async def handle_webhook(payload):
          data = requests.get(payload['callback_url'])
          return data.json()
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación de ambas categorías empeora el puntaje frente a solo una', () => {
  const soloSchema = checkOutputSchemaSsrfRisk({
    codigo: `
      async def validate_tool_result(result, tool):
          outputSchema = tool.outputSchema
          jsonschema.validate(result, outputSchema)
    `
  });
  const ambas = checkOutputSchemaSsrfRisk({
    codigo: `
      async def validate_tool_result(result, tool):
          outputSchema = tool.outputSchema
          jsonschema.validate(result, outputSchema)
          response = urllib.request.urlopen(outputSchema.get('$ref'))
          return response.read()
    `
  });
  assert.ok(ambas.puntaje < soloSchema.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('outputSchema validado con un Registry explícito -> aceptable', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      async def validate_tool_result(result, tool):
          outputSchema = tool.outputSchema
          validator = jsonschema.validate(result, outputSchema, registry=LOCAL_ONLY_REGISTRY)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('jsonschema.validate sobre un esquema fijo del propio desarrollador -> aceptable', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      ESQUEMA_FIJO = { "type": "object", "properties": { "ok": {"type": "boolean"} } }
      def validar(resultado):
          jsonschema.validate(resultado, ESQUEMA_FIJO)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('urllib.request.urlopen con timeout configurado dentro de async def -> aceptable', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      async def fetch_metadata(url):
          response = urllib.request.urlopen(url, timeout=5)
          return response.read()
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('requests.get delegado a un hilo aparte (asyncio.to_thread) -> aceptable', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `
      async def fetch_metadata(url):
          data = await asyncio.to_thread(requests.get, url)
          return data.json()
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin jsonschema ni llamadas de red -> aceptable, puntaje 100', () => {
  const r = checkOutputSchemaSsrfRisk({
    codigo: `def sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkOutputSchemaSsrfRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkOutputSchemaSsrfRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
