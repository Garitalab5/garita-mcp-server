"use strict";
// Escudo de Esquema de Salida — detector de SSRF + denegación de servicio
// vía resolución de referencias externas en un "outputSchema"/"inputSchema"
// no confiable
// ================================================================================
// Problema real: cuando un CLIENTE de MCP valida el resultado estructurado
// de una herramienta contra el "outputSchema" que el propio SERVIDOR le
// mandó, y usa una librería de JSON Schema (jsonschema en Python) con su
// resolución de referencias por defecto, un servidor malicioso o
// comprometido puede meter un "$ref"/"$dynamicRef"/"$id" que apunte a una
// URL externa (http://, https://, o incluso file://) — el CLIENTE termina
// haciendo esa petición él mismo (SSRF clásico, CWE-918), pudiendo alcanzar
// metadata de nube, servicios internos o archivos locales.
//
// El segundo problema, más grave todavía, es que esa petición se hace con
// una llamada SÍNCRONA (urllib.request.urlopen, o requests.get/post sin
// "await") desde DENTRO de una función "async def" — el SDK de MCP corre
// sobre asyncio/anyio, de un solo hilo de event loop. Un endpoint "tarpit"
// que acepta la conexión pero nunca responde (sin timeout configurado)
// congela ese hilo entero: todas las tareas y sesiones concurrentes del
// proceso quedan bloqueadas con una sola petición maliciosa.
//
// Motivado por CVE-2026-116686 (CVSS 6.5, CWE-918) en el SDK oficial de
// Python de MCP (paquete "mcp" en PyPI, versiones 1.10.0-1.29.1 y
// 2.0.0-2.1.1): validar un outputSchema no confiable con jsonschema.validate()
// sin un Registry/resolver que restrinja referencias externas. Parchado en
// 1.30.0/2.2.0 resolviendo referencias solo dentro del propio documento.
//
// Es un análisis ESTÁTICO por patrones de texto (no ejecuta nada) — mismo
// enfoque y mismas limitaciones que lib/ssrf.js y lib/redos.js. Límite
// conocido: encontrar el "cuerpo" de una función async de Python es
// aproximado (Python no usa llaves) — se usa una ventana de caracteres
// después de la firma "async def", no un parser real.

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

function contextSnippet(text, idx, len) {
  var start = Math.max(0, idx - 34);
  var end = Math.min(text.length, idx + len + 34);
  var prefix = start > 0 ? '…' : '';
  var suffix = end < text.length ? '…' : '';
  return prefix + text.slice(start, idx) + '[' + text.slice(idx, idx + len) + ']' + text.slice(idx + len, end) + suffix;
}

function findMatchingParen(text, openParenIndex) {
  var depth = 0;
  var inString = null;
  for (var i = openParenIndex; i < text.length; i++) {
    var ch = text[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// Llamadas de validación de JSON Schema (librería "jsonschema" de Python).
var JSONSCHEMA_CALL = /\bjsonschema\.validate\s*\(|\bDraft\d*Validator\s*\(|\bvalidator_for\s*\(/g;

// Señal de que el esquema que se está validando vino de una fuente no
// confiable: el outputSchema/inputSchema de una herramienta MCP, o la
// lista de herramientas de un servidor remoto.
var UNTRUSTED_SCHEMA_SIGNAL = /outputschema|output_schema|inputschema|input_schema|list_tools|tool\.schema|server_schema|remote_schema|external_schema/i;

// Mitigación real: un Registry/Resolver explícito que restringe la
// resolución de referencias externas (el arreglo que trae el parche de
// CVE-2026-116686: resolver solo dentro del propio documento).
var REGISTRY_GUARD = /\bregistry\s*=|\bRefResolver\s*\(|\bresolver\s*=|\bretrieve\s*=/;

function findUnsafeSchemaValidation(text) {
  var out = [];
  var re = new RegExp(JSONSCHEMA_CALL.source, JSONSCHEMA_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var before = text.slice(Math.max(0, m.index - 250), m.index);
    var openParenIdx = m.index + m[0].length - 1;
    var closeParenIdx = findMatchingParen(text, openParenIdx);
    var argsText = closeParenIdx === -1 ? '' : text.slice(openParenIdx + 1, closeParenIdx);
    var windowAfter = text.slice(m.index, Math.min(text.length, (closeParenIdx === -1 ? m.index + 200 : closeParenIdx) + 100));
    if (UNTRUSTED_SCHEMA_SIGNAL.test(before) && !REGISTRY_GUARD.test(argsText) && !REGISTRY_GUARD.test(windowAfter)) {
      out.push({ index: m.index, raw: m[0] + argsText.slice(0, 50) });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// Funciones async de Python (sin llaves — se usa una ventana de caracteres
// después de la firma como aproximación de su "cuerpo").
var ASYNC_DEF = /\basync\s+def\s+\w+\s*\([^)]*\)\s*:/g;
var BLOCKING_NETWORK_CALL = /\burllib\.request\.urlopen\s*\(|\brequests\.(?:get|post|put|delete|patch)\s*\(/g;
var OFFLOAD_SIGNAL = /asyncio\.to_thread\s*\(|run_in_executor\s*\(/;
var TIMEOUT_KW = /\btimeout\s*=/;

function findBlockingCallsInAsyncDef(text) {
  var out = [];
  var asyncRe = new RegExp(ASYNC_DEF.source, ASYNC_DEF.flags);
  var m;
  while ((m = asyncRe.exec(text))) {
    var windowEnd = Math.min(text.length, m.index + 700);
    var win = text.slice(m.index, windowEnd);
    var callRe = new RegExp(BLOCKING_NETWORK_CALL.source, BLOCKING_NETWORK_CALL.flags);
    var cm;
    while ((cm = callRe.exec(win))) {
      var openParenIdx = cm.index + cm[0].length - 1;
      var closeParenIdx = findMatchingParen(win, openParenIdx);
      var argsText = closeParenIdx === -1 ? '' : win.slice(openParenIdx + 1, closeParenIdx);
      var beforeCall = win.slice(Math.max(0, cm.index - 120), cm.index);
      if (!TIMEOUT_KW.test(argsText) && !OFFLOAD_SIGNAL.test(beforeCall)) {
        out.push({ index: m.index + cm.index, raw: cm[0] + argsText.slice(0, 40) });
      }
      if (cm.index === callRe.lastIndex) callRe.lastIndex++;
    }
    if (m.index === asyncRe.lastIndex) asyncRe.lastIndex++;
  }
  var seen = {};
  return out.filter(function (o) {
    if (seen[o.index]) return false;
    seen[o.index] = true;
    return true;
  });
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo
// informativo, no cambia la detección.
function checkOutputSchemaSsrfRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código del lado cliente que valida outputSchema/inputSchema de herramientas MCP) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var schemaSinRestriccion = findUnsafeSchemaValidation(text);
  if (schemaSinRestriccion.length > 0) {
    var ded1 = 55 + Math.min(20, (schemaSinRestriccion.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'Un outputSchema/inputSchema que vino de un servidor MCP (no confiable) se valida con jsonschema sin ningún Registry/Resolver que restrinja la resolución de referencias externas ($ref/$dynamicRef/$id) — un servidor malicioso puede forzar al cliente a hacer una petición SSRF hacia una URL arbitraria (http(s)://, incluso file://). El mismo patrón detrás de CVE-2026-116686 (CVSS 6.5) en el SDK oficial de Python de MCP',
      snippet: contextSnippet(text, schemaSinRestriccion[0].index, schemaSinRestriccion[0].raw.length)
    });
  }

  var bloqueantesSinTimeout = findBlockingCallsInAsyncDef(text);
  if (bloqueantesSinTimeout.length > 0) {
    var ded2 = 55 + Math.min(15, (bloqueantesSinTimeout.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'critical',
      label: 'Una llamada de red SÍNCRONA (urllib.request.urlopen/requests.get-post-put-delete) corre dentro de una función "async def", sin "timeout" configurado ni delegarse a un hilo aparte (asyncio.to_thread/run_in_executor) — un único endpoint que nunca responde ("tarpit") congela el event loop entero del proceso, con todas sus tareas y sesiones concurrentes. El vector de denegación de servicio detrás de CVE-2026-116686',
      snippet: contextSnippet(text, bloqueantesSinTimeout[0].index, bloqueantesSinTimeout[0].raw.length)
    });
  }

  if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'No se encontró ninguna validación de un esquema no confiable sin restringir referencias externas, ni ninguna llamada de red síncrona sin tope dentro de una función async.', snippet: null });
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + schemaSinRestriccion.length + ' validación(es) de esquema no confiable sin restringir referencias externas y ' + bloqueantesSinTimeout.length + ' llamada(s) de red síncrona(s) sin tope dentro de una función async.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkOutputSchemaSsrfRisk: checkOutputSchemaSsrfRisk,
  findUnsafeSchemaValidation: findUnsafeSchemaValidation,
  findBlockingCallsInAsyncDef: findBlockingCallsInAsyncDef,
  bucket: bucket
};
