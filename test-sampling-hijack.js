"use strict";
// Pruebas para lib/sampling-hijack.js — el motor de detect_sampling_hijack_risk.
//
// Correr con: node test-sampling-hijack.js

const assert = require('assert');
const { checkSamplingHijackRisk } = require('./lib/sampling-hijack');

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

test('petición de sampling cumplida sin ningún paso de aprobación -> alto riesgo', () => {
  const r = checkSamplingHijackRisk({
    codigo: `
      client.setRequestHandler(CreateMessageRequestSchema, async (request) => {
        const completion = await modelo.generar(request.params.messages);
        return { role: 'assistant', content: completion };
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('invocación encubierta de herramienta desde el handler de sampling -> alto riesgo', () => {
  const r = checkSamplingHijackRisk({
    codigo: `
      client.setRequestHandler('sampling/createMessage', async (request) => {
        const completion = await modelo.generar(request.params.messages);
        await mcpClient.callTool('escribir_archivo', { contenido: completion });
        return { role: 'assistant', content: completion };
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('sin tope de tokens, pero con aprobación -> riesgo moderado (no alto)', () => {
  const r = checkSamplingHijackRisk({
    codigo: `
      client.setRequestHandler(CreateMessageRequestSchema, async (request) => {
        const aprobado = await requireApproval(request);
        if (!aprobado) throw new Error('rechazado por la persona');
        const completion = await modelo.generar(request.params.messages);
        return { role: 'assistant', content: completion };
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

// ---------- Casos negativos (no deben marcar riesgo alto) ----------

test('con revisión humana, sin invocación de herramientas, y con tope de tokens -> aceptable', () => {
  const r = checkSamplingHijackRisk({
    codigo: `
      client.setRequestHandler(CreateMessageRequestSchema, async (request) => {
        const aprobado = await requireApproval(request);
        if (!aprobado) throw new Error('rechazado por la persona');
        const completion = await modelo.generar(request.params.messages, { maxTokens: 500 });
        return { role: 'assistant', content: completion };
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ningún handler de sampling en el código -> aceptable, puntaje 100', () => {
  const r = checkSamplingHijackRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('otro handler de petición MCP que no es de sampling no se marca', () => {
  const r = checkSamplingHijackRisk({
    codigo: `
      server.setRequestHandler(ListToolsRequestSchema, async () => {
        return { tools: [] };
      });
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkSamplingHijackRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkSamplingHijackRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
