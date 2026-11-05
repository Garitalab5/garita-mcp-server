"use strict";
// Pruebas para lib/vigia.js — el agente Vigía (Escalón 1 / "Centinela Básico").
//
// A diferencia de las otras suites, esto no prueba un motor de detección de
// texto — prueba que: (1) las 20 definiciones de herramientas estén completas
// y bien formadas, (2) cada handler esté conectado a la función lib correcta
// (con la forma de argumentos correcta — el punto donde más fácil se desliza
// un error, ej. posicional vs. objeto), y (3) el loop de orquestación
// (analizar) maneje bien tool_use / fin de conversación / licencia agotada /
// tope de vueltas — sin llamar a la API real de Anthropic ni gastar nada:
// se inyecta un cliente falso reemplazando la entrada de @anthropic-ai/sdk
// en el caché de módulos de Node ANTES de cargar lib/vigia.js.
//
// Correr con: node test-vigia.js

const assert = require('assert');
const Module = require('module');

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

async function testAsync(name, fn) {
  try {
    await fn();
    pass++;
    console.log('OK   - ' + name);
  } catch (err) {
    fail++;
    console.log('FAIL - ' + name);
    console.log('       ' + (err && err.stack ? err.stack : err));
  }
}

// ---------- Inyectar un cliente de Anthropic falso en el caché de módulos ----------
// lib/vigia.js hace `require('@anthropic-ai/sdk')` recién dentro de
// getClient() (no al cargar el módulo), así que alcanza con reemplazar la
// entrada resuelta en require.cache antes de llamar analizar().
const sdkPath = require.resolve('@anthropic-ai/sdk');
let fakeCreateImpl = null; // se asigna por test
function FakeAnthropic() {
  return { messages: { create: (...args) => fakeCreateImpl(...args) } };
}
require.cache[sdkPath] = new Module(sdkPath);
require.cache[sdkPath].exports = FakeAnthropic;
require.cache[sdkPath].loaded = true;

process.env.ANTHROPIC_API_KEY = 'fake-key-para-pruebas';
const vigia = require('./lib/vigia');
const licensing = require('./lib/licensing');

// ---------- 1) Las 30 definiciones de herramientas ----------

const NOMBRES_ESPERADOS = [
  'audit_mcp_server', 'simulate_approval', 'detect_poisoned_tool_descriptions',
  'check_known_vulnerabilities', 'detect_tool_rug_pull', 'detect_poisoned_config_files',
  'check_package_authenticity', 'detect_memory_poisoning', 'detect_ssrf_risk',
  'detect_path_traversal_risk', 'detect_command_injection_risk', 'detect_sql_injection_risk',
  'detect_token_passthrough_risk', 'detect_hardcoded_secrets_risk', 'detect_insecure_deserialization_risk',
  'detect_toxic_flow_risk', 'detect_ssti_risk', 'detect_dynamic_code_risk',
  'detect_dns_rebinding_risk', 'detect_missing_auth_risk', 'detect_mcp_stdio_launch_risk',
  'detect_redos_risk', 'detect_session_hijack_risk', 'detect_oauth_audience_confusion_risk',
  'detect_unbounded_allocation_risk', 'detect_cross_client_leak_risk', 'detect_sampling_hijack_risk',
  'detect_output_schema_ssrf_risk', 'detect_excessive_agency_risk', 'detect_call_spoofing_risk'
];

test('TOOL_DEFS tiene exactamente las 30 herramientas esperadas', () => {
  const nombres = vigia.TOOL_DEFS.map((t) => t.name).sort();
  assert.deepStrictEqual(nombres, NOMBRES_ESPERADOS.slice().sort());
});

test('cada TOOL_DEFS tiene name, description e input_schema válidos', () => {
  vigia.TOOL_DEFS.forEach((t) => {
    assert.ok(typeof t.name === 'string' && t.name.length > 0, 'name en ' + JSON.stringify(t));
    assert.ok(typeof t.description === 'string' && t.description.length > 10, 'description de ' + t.name);
    assert.strictEqual(t.input_schema.type, 'object', 'input_schema.type de ' + t.name);
    assert.ok(t.input_schema.properties && typeof t.input_schema.properties === 'object', 'properties de ' + t.name);
  });
});

test('cada nombre en TOOL_DEFS tiene un handler correspondiente en TOOL_HANDLERS', () => {
  vigia.TOOL_DEFS.forEach((t) => {
    assert.strictEqual(typeof vigia.TOOL_HANDLERS[t.name], 'function', 'falta handler para ' + t.name);
  });
});

// ---------- 2) Los handlers llaman a la función lib correcta, con la forma correcta ----------
// No repetimos las pruebas de cada motor (ya cubiertas en sus propias
// suites) — solo confirmamos que el "cableado" de vigia.js no tiene un
// desfase de argumentos (el error más fácil de cometer acá).

test('handler de audit_mcp_server llama a auditManifest(manifest) posicional', () => {
  // auditManifest usa nombres en inglés (score/verdict) — es de las dos
  // herramientas originales, de antes de adoptar la convención en español
  // para el resto del catálogo.
  const r = vigia.TOOL_HANDLERS['audit_mcp_server']({ manifest: { serverInfo: { name: 'x' }, tools: [{ name: 'leer_archivo', description: 'lee un archivo' }] } });
  assert.ok(typeof r.score === 'number');
  assert.ok(typeof r.verdict === 'string');
});

test('handler de simulate_approval llama a simulateApproval(action, rules, threshold) posicional', () => {
  const r = vigia.TOOL_HANDLERS['simulate_approval']({
    action: { tool: 'borrar_archivo', description: 'x', arguments: {}, annotations: { destructiveHint: true } }
  });
  assert.ok(r.verdict === 'retenido' || r.verdict === 'auto_aprobado');
});

test('handler de detect_ssrf_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_ssrf_risk']({ codigo: 'fetch(userUrl)' });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_toxic_flow_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_toxic_flow_risk']({ manifest: { tools: [{ name: 'leer_archivo', description: 'lee un archivo local' }] } });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_missing_auth_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_missing_auth_risk']({ codigo: "app.post('/mcp', handler)" });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_mcp_stdio_launch_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_mcp_stdio_launch_risk']({ codigo: 'new StdioClientTransport({ command: req.body.command, args: [] })' });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_redos_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_redos_risk']({ codigo: 'var re = /(a+)+/; re.test(req.body.texto);' });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_session_hijack_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_session_hijack_risk']({ codigo: 'const session = sessions[req.query.sessionId]; req.session = session;' });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_oauth_audience_confusion_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_oauth_audience_confusion_risk']({ codigo: 'const payload = jwt.verify(token, SECRET); return payload;' });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_unbounded_allocation_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_unbounded_allocation_risk']({ codigo: "app.use(express.json());" });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_cross_client_leak_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_cross_client_leak_risk']({ codigo: "function sumar(a,b){ return a+b; }" });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_sampling_hijack_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_sampling_hijack_risk']({ codigo: "function sumar(a,b){ return a+b; }" });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_output_schema_ssrf_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_output_schema_ssrf_risk']({ codigo: "function sumar(a,b){ return a+b; }" });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_excessive_agency_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_excessive_agency_risk']({ manifest: { tools: [{ name: 'leer_saldo', description: 'consulta el saldo de una cuenta' }] } });
  assert.ok(typeof r.puntaje === 'number');
});

test('handler de detect_call_spoofing_risk pasa el input tal cual', () => {
  const r = vigia.TOOL_HANDLERS['detect_call_spoofing_risk']({ codigo: "function sumar(a,b){ return a+b; }" });
  assert.ok(typeof r.puntaje === 'number');
});

// ---------- 3) El loop de orquestación (analizar) ----------

async function crearLlaveDePrueba() {
  const { apiKey } = await licensing.createKey();
  return apiKey;
}

function bloqueTexto(texto) {
  return { type: 'text', text: texto };
}
function bloqueToolUse(id, name, input) {
  return { type: 'tool_use', id, name, input };
}

async function main() {

await testAsync('sin usar ninguna herramienta -> devuelve el texto directo, sin herramientasUsadas', async () => {
  const apiKey = await crearLlaveDePrueba();
  fakeCreateImpl = async () => ({
    stop_reason: 'end_turn',
    content: [bloqueTexto('Hola, esto no tiene nada que ver con seguridad.')]
  });
  const r = await vigia.analizar({ mensaje: 'hola, ¿qué tal?', apiKey });
  assert.strictEqual(r.herramientasUsadas.length, 0);
  assert.ok(r.informe.includes('Hola'));
  assert.strictEqual(r.incompleto, undefined);
});

await testAsync('con una vuelta de tool_use -> ejecuta la herramienta real y descuenta un uso', async () => {
  const apiKey = await crearLlaveDePrueba();
  // OJO: se guarda el NÚMERO, no el objeto "record" — el fallback en memoria
  // de licensing.js (solo para pruebas locales, ver su propia advertencia)
  // devuelve la misma referencia en cada getKeyRecord(), así que si
  // guardáramos el objeto completo, lo veríamos mutar "retroactivamente"
  // cuando checkAndConsume() lo modifica más abajo. Con Upstash real en
  // producción esto no pasa (ahí cada lectura es un JSON nuevo).
  const antesUses = (await licensing.getKeyRecord(apiKey)).freeUsesRemaining;
  let vuelta = 0;
  fakeCreateImpl = async () => {
    vuelta++;
    if (vuelta === 1) {
      return {
        stop_reason: 'tool_use',
        content: [
          bloqueTexto('Voy a revisar ese código.'),
          bloqueToolUse('t1', 'detect_command_injection_risk', { codigo: "exec('rm -rf ' + userInput)" })
        ]
      };
    }
    return { stop_reason: 'end_turn', content: [bloqueTexto('Encontré un riesgo crítico de inyección de comandos.')] };
  };
  const r = await vigia.analizar({ mensaje: 'revisá esta función', apiKey });
  assert.strictEqual(r.herramientasUsadas.length, 1);
  assert.strictEqual(r.herramientasUsadas[0].herramienta, 'detect_command_injection_risk');
  assert.strictEqual(r.herramientasUsadas[0].ok, true);
  assert.strictEqual(r.licenciaAgotada, false);
  const despuesUses = (await licensing.getKeyRecord(apiKey)).freeUsesRemaining;
  assert.strictEqual(despuesUses, antesUses - 1);
});

await testAsync('varias herramientas en una sola vuelta -> se ejecutan y cobran todas', async () => {
  const apiKey = await crearLlaveDePrueba();
  fakeCreateImpl = async () => ({
    stop_reason: 'tool_use',
    content: [
      bloqueToolUse('t1', 'detect_ssrf_risk', { codigo: 'fetch(userUrl)' }),
      bloqueToolUse('t2', 'detect_hardcoded_secrets_risk', { codigo: 'const key = "sk-abc"' })
    ]
  });
  // Esta vuelta sola alcanza porque el "else" de la próxima llamada (if vuelta===1 ya consumido) no aplica — forzamos end_turn en la 2da llamada:
  let vuelta = 0;
  const original = fakeCreateImpl;
  fakeCreateImpl = async () => {
    vuelta++;
    if (vuelta === 1) return original();
    return { stop_reason: 'end_turn', content: [bloqueTexto('listo')] };
  };
  const r = await vigia.analizar({ mensaje: 'revisá esto', apiKey });
  assert.strictEqual(r.herramientasUsadas.length, 2);
  assert.deepStrictEqual(r.herramientasUsadas.map((h) => h.herramienta).sort(), ['detect_hardcoded_secrets_risk', 'detect_ssrf_risk']);
});

await testAsync('herramienta desconocida pedida por el modelo -> se reporta como no-ok sin tirar la sesión', async () => {
  const apiKey = await crearLlaveDePrueba();
  let vuelta = 0;
  fakeCreateImpl = async () => {
    vuelta++;
    if (vuelta === 1) {
      return { stop_reason: 'tool_use', content: [bloqueToolUse('t1', 'herramienta_que_no_existe', {})] };
    }
    return { stop_reason: 'end_turn', content: [bloqueTexto('no pude usar esa herramienta')] };
  };
  const r = await vigia.analizar({ mensaje: 'x', apiKey });
  assert.strictEqual(r.herramientasUsadas[0].ok, false);
});

await testAsync('licencia agotada a mitad del análisis -> corta el loop y lo marca como incompleto', async () => {
  const { apiKey, record } = await licensing.createKey();
  // Consumir todos los usos gratis de entrada para forzar el agotamiento en la primera herramienta real.
  for (let i = 0; i < record.freeUsesRemaining; i++) {
    await licensing.checkAndConsume(apiKey);
  }
  fakeCreateImpl = async () => ({
    stop_reason: 'tool_use',
    content: [bloqueToolUse('t1', 'detect_ssrf_risk', { codigo: 'fetch(x)' })]
  });
  const r = await vigia.analizar({ mensaje: 'x', apiKey });
  assert.strictEqual(r.licenciaAgotada, true);
  assert.strictEqual(r.incompleto, true);
});

await testAsync('tope de MAX_TURNS -> se corta y lo marca como incompleto', async () => {
  const apiKey = await crearLlaveDePrueba();
  fakeCreateImpl = async () => ({
    stop_reason: 'tool_use',
    content: [bloqueToolUse('t1', 'detect_ssrf_risk', { codigo: 'fetch(x)' })]
  });
  const r = await vigia.analizar({ mensaje: 'x', apiKey });
  assert.strictEqual(r.incompleto, true);
  assert.strictEqual(r.vueltas, vigia.MAX_TURNS);
});

await testAsync('sin "mensaje" -> lanza error antes de llamar a Anthropic', async () => {
  fakeCreateImpl = async () => { throw new Error('no debería llamarse'); };
  await assert.rejects(() => vigia.analizar({ mensaje: '', apiKey: 'x' }), /mensaje/i);
});

await testAsync('sin ANTHROPIC_API_KEY configurada -> error claro, no un crash genérico', async () => {
  const anterior = process.env.ANTHROPIC_API_KEY;
  delete process.env.ANTHROPIC_API_KEY;
  try {
    await assert.rejects(() => vigia.analizar({ mensaje: 'x', apiKey: 'y' }), /ANTHROPIC_API_KEY/);
  } finally {
    process.env.ANTHROPIC_API_KEY = anterior;
  }
});

} // fin de main()

main().then(() => {
  console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
  process.exit(fail > 0 ? 1 : 0);
}).catch((err) => {
  console.error('Error inesperado corriendo las pruebas:', err);
  process.exit(1);
});
