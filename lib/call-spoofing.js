"use strict";
// Escudo de Suplantación de Llamada — detector de extracción de llamadas a
// herramientas desde TEXTO LIBRE en vez del campo estructurado de la API
// ("Repeat-After-Me").
// ================================================================================
// Problema real: las APIs de los modelos (Anthropic, OpenAI, etc.) devuelven una
// llamada a herramienta en un campo ESTRUCTURADO y dedicado de la respuesta
// (tool_calls / function_call / tool_use) — ese campo solo se llena cuando el
// modelo decidió de verdad invocar una herramienta a través del mecanismo nativo
// de function-calling. Varios frameworks de orquestación de agentes, en cambio,
// (también o en lugar de leer ese campo) escanean el TEXTO LIBRE de la respuesta
// (el contenido/mensaje) buscando un patrón que "parezca" una llamada a
// herramienta (una marca como TOOL_CALL:, un bloque ```json, una etiqueta
// <tool_call>) y, si lo encuentran, lo ejecutan como si fuera real.
//
// El problema: ese texto libre puede contener cualquier cosa que haya llegado al
// contexto del modelo — un documento cargado, una página web, el resultado de
// una herramienta anterior. Si ese contenido ya tiene algo con pinta de llamada
// a herramienta y el modelo simplemente lo "repite" (porque se le pidió resumir,
// citar o traducir ese contenido), el orquestador no tiene manera de distinguir
// un patrón repetido de una decisión real del modelo — ambos aparecen igual en
// el texto libre. Esto es el ataque "Repeat-After-Me", documentado en una
// investigación de GBHackers de octubre de 2026 contra 6 frameworks de agentes
// de uso extendido: LangGraph, Microsoft Agent Framework, Google ADK 2.0,
// AutoGen, AWS Strands y CrewAI — en los 6, la capa de orquestación confiaba en
// un parseo de texto/regex de la salida del modelo en vez de exigir la API de
// function-calling estructurada.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el código de orquestación
// del lado del AGENTE (no ejecuta nada) — mismo enfoque y mismas limitaciones
// que lib/sampling-hijack.js y lib/toxic-flows.js: no reemplaza un analizador de
// sintaxis (AST) real ni una auditoría de seguridad formal. Límite conocido: las
// marcas de "llamada a herramienta en texto libre" (TOOL_CALL, FUNCTION_CALL,
// <tool_call>, bloque ```json, etc.) y el "campo estructurado" (tool_calls,
// function_call, tool_use) se reconocen por nombres típicos — una convención muy
// distinta puede no detectarse.

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

// Marca de "esto parece una llamada a herramienta" dentro de texto libre: una
// palabra clave tipo TOOL_CALL/FUNCTION_CALL, una etiqueta <tool_call>/<tool_use>,
// o un bloque de código ```json (el formato más común para que un modelo
// "escriba" una llamada a herramienta como texto en vez de usar la API nativa).
var TEXTMARK_TOOLCALL = /\bTOOL_CALL\b|\bFUNCTION_CALL\b|<tool[_-]?call\b|<tool[_-]?use\b|```json/i;

// Una operación de parseo de texto (regex, split, JSON.parse/json.loads) — la
// señal de que el código de verdad intenta EXTRAER algo de ese texto libre, no
// solo que la palabra aparece suelta en un comentario o un string de ejemplo.
var TEXT_PARSE_CALL = /\bre\.(?:search|match|findall|finditer)\s*\(|\.match\s*\(|\.exec\s*\(|\.split\s*\(|\bjson\.loads\s*\(|\bJSON\.parse\s*\(/;

// Campo ESTRUCTURADO y dedicado de la API para una llamada a herramienta real —
// solo se llena cuando el modelo invocó la función nativa de function-calling,
// no por el contenido en texto libre.
var STRUCTURED_FIELD = /\.tool_calls\b|\.toolCalls\b|\.function_call\b|\.functionCall\b|\.tool_use\b|\.toolUse\b|\btool_calls\s*[:=]|\bfunction_call\s*[:=]/;

// Que ese texto parseado se use de verdad para disparar una herramienta — el
// vector real de ejecución, no solo detección de patrón.
var DISPATCH_SIGNAL = /\.\s*(?:callTool|executeTool|invokeTool|dispatchTool|runTool)\s*\(|\bexecute_tool\s*\(|\brun_tool\s*\(|\binvoke_tool\s*\(|\bdispatch_tool\s*\(|\btool_map\s*\[|\btools_by_name\s*\[|\bTOOLS_MAP\s*\[/;

function findTextToolCallScans(text) {
  var out = [];
  var re = new RegExp(TEXTMARK_TOOLCALL.source, TEXTMARK_TOOLCALL.flags + (TEXTMARK_TOOLCALL.flags.indexOf('g') === -1 ? 'g' : ''));
  var m;
  while ((m = re.exec(text))) {
    var windowStart = Math.max(0, m.index - 150);
    var windowEnd = Math.min(text.length, m.index + m[0].length + 150);
    var windowText = text.slice(windowStart, windowEnd);
    if (TEXT_PARSE_CALL.test(windowText)) {
      out.push({ index: m.index, len: m[0].length });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function checkCallSpoofingRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código de orquestación del lado del agente que interpreta la respuesta del modelo) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var scans = findTextToolCallScans(text);
  var hasStructured = STRUCTURED_FIELD.test(text);
  var hasDispatch = scans.length > 0 && DISPATCH_SIGNAL.test(text);

  if (scans.length > 0 && hasDispatch) {
    var ded1 = 55 + Math.min(20, (scans.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'El código ejecuta una herramienta (callTool/executeTool/tool_map[...]) a partir de un patrón encontrado en el TEXTO LIBRE de la respuesta del modelo (una marca como TOOL_CALL:, un bloque ```json, una etiqueta <tool_call>), en vez de leerla únicamente del campo estructurado y dedicado de la API (tool_calls/function_call/tool_use) — contenido que solo PARECE una llamada a herramienta, incrustado en un documento, una página web o el resultado de otra herramienta que el modelo simplemente "repite", puede terminar ejecutado como si el modelo realmente hubiera decidido invocarla (ataque "Repeat-After-Me", documentado en octubre de 2026 contra 6 frameworks de agentes: LangGraph, Microsoft Agent Framework, Google ADK 2.0, AutoGen, AWS Strands y CrewAI)',
      snippet: contextSnippet(text, scans[0].index, scans[0].len)
    });
  }

  if (scans.length > 0 && !hasStructured) {
    var ded2 = 30;
    deduction += ded2;
    findings.push({
      sev: 'warn',
      label: 'El código nunca lee el campo estructurado y dedicado de la API para llamadas a herramientas (tool_calls/function_call/tool_use) — depende únicamente de coincidencias de patrones sobre el texto libre de la respuesta para reconocer una llamada a herramienta, un mecanismo inherentemente más fácil de falsificar que el function-calling nativo del modelo',
      snippet: null
    });
  } else if (scans.length > 0 && hasStructured && !hasDispatch) {
    var ded3 = 25;
    deduction += ded3;
    findings.push({
      sev: 'warn',
      label: 'El código sí lee el campo estructurado de la API para llamadas a herramientas, pero también escanea el texto libre de la respuesta en busca de un patrón de llamada a herramienta (una posible ruta de respaldo) — sin un disparo de ejecución claramente conectado en este fragmento, pero vale la pena revisar por qué existe ese segundo camino: un atacante solo necesita evitar que se llene el campo estructurado para que el contenido en texto libre vuelva a ser la única señal',
      snippet: contextSnippet(text, scans[0].index, scans[0].len)
    });
  }

  if (findings.length === 0) {
    findings.push({
      sev: 'ok',
      label: scans.length === 0
        ? 'No se encontró ningún parseo de texto libre en busca de patrones de llamada a herramienta (TOOL_CALL/FUNCTION_CALL/<tool_call>/```json) en el código analizado.'
        : 'Se encontraron marcas de llamada a herramienta en texto libre, pero no acompañadas de un parseo real ni de un disparo de ejecución conectado a ellas.',
      snippet: null
    });
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + scans.length + ' coincidencia(s) de parseo de llamada a herramienta en texto libre (campo estructurado de la API: ' + (hasStructured ? 'sí se lee' : 'nunca se lee') + '; disparo de ejecución conectado: ' + (hasDispatch ? 'sí' : 'no') + ').',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkCallSpoofingRisk: checkCallSpoofingRisk,
  findTextToolCallScans: findTextToolCallScans,
  bucket: bucket
};
