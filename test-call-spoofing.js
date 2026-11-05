"use strict";
// Pruebas para lib/call-spoofing.js — el motor de detect_call_spoofing_risk.
//
// Correr con: node test-call-spoofing.js

const assert = require('assert');
const { checkCallSpoofingRisk } = require('./lib/call-spoofing');

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

test('ejecuta herramienta a partir de patrón en texto libre, sin leer campo estructurado -> alto riesgo', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      const m = respuesta.content.match(/TOOL_CALL:\\s*(\\{.*\\})/);
      if (m) {
        const llamada = JSON.parse(m[1]);
        await mcpClient.callTool(llamada.nombre, llamada.argumentos);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('variante Python: re.search sobre content + json.loads + execute_tool -> alto riesgo', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      respuesta = modelo.generar(mensajes)
      m = re.search(r'TOOL_CALL:\\s*(\\{.*\\})', respuesta.content)
      if m:
          llamada = json.loads(m.group(1))
          execute_tool(llamada['nombre'], llamada['argumentos'])
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('ejecuta desde texto Y además lee el campo estructurado -> sigue siendo alto riesgo (vía el camino de texto)', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      if (respuesta.tool_calls && respuesta.tool_calls.length > 0) {
        await ejecutarLlamadasEstructuradas(respuesta.tool_calls);
      } else {
        const m = respuesta.content.match(/\`\`\`json([\\s\\S]*?)\`\`\`/);
        if (m) {
          const llamada = JSON.parse(m[1]);
          await mcpClient.callTool(llamada.nombre, llamada.argumentos);
        }
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación (ejecuta desde texto, nunca lee campo estructurado) es peor que solo el patrón de ejecución', () => {
  const conEstructurado = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      if (respuesta.tool_calls) { await ejecutarLlamadasEstructuradas(respuesta.tool_calls); }
      const m = respuesta.content.match(/TOOL_CALL:\\s*(\\{.*\\})/);
      if (m) { const llamada = JSON.parse(m[1]); await mcpClient.callTool(llamada.nombre, llamada.argumentos); }
    `
  });
  const sinEstructurado = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      const m = respuesta.content.match(/TOOL_CALL:\\s*(\\{.*\\})/);
      if (m) { const llamada = JSON.parse(m[1]); await mcpClient.callTool(llamada.nombre, llamada.argumentos); }
    `
  });
  assert.ok(sinEstructurado.puntaje < conEstructurado.puntaje);
});

test('solo escaneo de texto, sin disparo de ejecución ni campo estructurado -> riesgo moderado (no alto)', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      const m = respuesta.content.match(/TOOL_CALL:\\s*(\\{.*\\})/);
      if (m) {
        console.log('posible llamada encontrada en texto:', m[1]);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

test('escaneo de texto como posible respaldo, pero el campo estructurado sí se lee y no hay disparo conectado -> riesgo moderado', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      if (respuesta.tool_calls) { await ejecutarLlamadasEstructuradas(respuesta.tool_calls); }
      const posible = respuesta.content.match(/TOOL_CALL:\\s*(\\{.*\\})/);
      if (posible) { registrarParaRevision(posible[1]); }
    `
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('solo lee el campo estructurado de la API, sin ningún parseo de texto libre -> aceptable', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      const respuesta = await modelo.generar(mensajes);
      if (respuesta.tool_calls && respuesta.tool_calls.length > 0) {
        await ejecutarLlamadasEstructuradas(respuesta.tool_calls);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('la palabra TOOL_CALL aparece suelta (comentario/log) sin ningún parseo cerca -> aceptable', () => {
  const r = checkCallSpoofingRisk({
    codigo: `
      // Nota: este servidor antiguo usaba un formato TOOL_CALL: en texto, ya no se soporta.
      const respuesta = await modelo.generar(mensajes);
      if (respuesta.tool_calls) { await ejecutarLlamadasEstructuradas(respuesta.tool_calls); }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('código sin relación con llamadas a herramientas -> aceptable, puntaje 100', () => {
  const r = checkCallSpoofingRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkCallSpoofingRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkCallSpoofingRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
