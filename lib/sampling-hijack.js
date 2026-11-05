"use strict";
// Escudo de Secuestro de Sampling — detector de peticiones de sampling MCP
// completadas sin revisión humana (y de invocación encubierta de herramientas)
// ================================================================================
// Problema real: la función "sampling" de MCP deja que un SERVIDOR le pida al
// modelo del CLIENTE que genere una completion — el servidor no llama al modelo
// directamente, le pide al cliente que lo haga por él. La propia especificación
// de MCP dice que los clientes DEBERÍAN dejar que la persona revise y apruebe
// esa petición antes de cumplirla (qué contenido se le manda al modelo, y con
// qué modelo). Un cliente/host que cumple la petición de sampling de un
// servidor sin ningún paso de revisión humana deja que un servidor malicioso
// esconda instrucciones dentro de esa petición — el modelo las sigue sin que
// la persona vea nada raro.
//
// Documentado en una investigación de Unit42 (Palo Alto Networks) y reportado
// de nuevo el 16 de octubre de 2026: contra una app de tipo copiloto de código,
// un servidor MCP malicioso usó sampling para (a) robo de recursos — instruir
// al modelo a generar texto de más, gastando tokens/cómputo sin que la persona
// lo note; (b) secuestro de conversación — instrucciones que persisten y
// cambian el comportamiento del modelo en turnos futuros; y (c) invocación
// encubierta de herramientas, el vector más grave — el servidor instruye al
// modelo a llamar herramientas (como escribir un archivo) sin aprobación
// explícita de la persona.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO del lado
// cliente/host que maneja peticiones de sampling entrantes (no ejecuta nada) —
// mismo enfoque y mismas limitaciones que lib/toxic-flows.js y
// lib/missing-auth.js: no reemplaza un analizador de sintaxis (AST) real ni
// una auditoría de seguridad formal. Límite conocido: la "revisión humana" se
// reconoce por palabras clave típicas (confirm, requireApproval, humanReview,
// etc.) — un gate de aprobación con un nombre muy distinto puede no
// detectarse.

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

function findMatchingBrace(text, openBraceIndex) {
  var depth = 0;
  var inString = null;
  for (var i = openBraceIndex; i < text.length; i++) {
    var ch = text[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// Registro de un handler para peticiones de sampling entrantes del servidor:
// setRequestHandler(CreateMessageRequestSchema, ...) en el SDK oficial, o la
// forma equivalente por nombre de método literal 'sampling/createMessage'.
var SAMPLING_HANDLER = /\bsetRequestHandler\s*\(\s*(?:CreateMessageRequestSchema|['"]sampling\/createMessage['"])\s*,\s*(?:async\s*)?(?:function\s*\(|\([^)]*\)\s*=>|\w+\s*=>)\s*\{/g;

function findSamplingHandlers(text) {
  var out = [];
  var re = new RegExp(SAMPLING_HANDLER.source, SAMPLING_HANDLER.flags);
  var m;
  while ((m = re.exec(text))) {
    var openBraceIdx = m.index + m[0].length - 1;
    var closeBraceIdx = findMatchingBrace(text, openBraceIdx);
    if (closeBraceIdx !== -1) {
      out.push({ index: m.index, body: text.slice(openBraceIdx + 1, closeBraceIdx) });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// Señales de que, antes de cumplir la petición (llamar al modelo y devolver
// una respuesta), hay algún paso reconocible de revisión/aprobación humana —
// justo lo que la especificación de MCP recomienda para sampling.
var APPROVAL_SIGNAL = /\bconfirm\s*\(|\bwindow\.confirm\s*\(|\brequireApproval\b|\buserApproved\b|\bhumanReview\w*\b|\bhuman[_-]?in[_-]?the[_-]?loop\b|\bpendingApproval\b|\bawait\s+\w*[Aa]pprov\w*\s*\(|\bawait\s+\w*[Rr]evis\w*\s*\(/i;

// Invocación encubierta de herramientas: dentro del mismo handler de
// sampling, el código llama a una herramienta (callTool/executeTool) — el
// vector más grave documentado: el servidor instruye al modelo a disparar una
// herramienta a partir de la propia completion, sin que la persona lo apruebe.
var TOOL_DISPATCH_SIGNAL = /\.\s*callTool\s*\(|\.\s*executeTool\s*\(/;

// Ausencia de un tope de longitud/tokens en la petición cumplida — el vector
// de "robo de recursos": sin maxTokens/max_tokens, nada impide que la
// completion gastada sea mucho más larga que lo que la persona espera ver.
var MAX_TOKENS_CAP = /\bmax_tokens\b|\bmaxTokens\b/i;

function checkSamplingHijackRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código del lado cliente/host que maneja peticiones de sampling de un servidor MCP) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var handlers = findSamplingHandlers(text);
  var sinAprobacion = handlers.filter(function (h) { return !APPROVAL_SIGNAL.test(h.body); });
  var invocacionEncubierta = handlers.filter(function (h) { return TOOL_DISPATCH_SIGNAL.test(h.body) && !APPROVAL_SIGNAL.test(h.body); });
  var sinTope = handlers.filter(function (h) { return !MAX_TOKENS_CAP.test(h.body); });

  if (sinAprobacion.length > 0) {
    var ded1 = 55 + Math.min(20, (sinAprobacion.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'Una petición de sampling entrante (setRequestHandler sobre CreateMessageRequestSchema / "sampling/createMessage") se cumple sin ningún paso reconocible de revisión o aprobación humana antes de mandarle el contenido al modelo — exactamente lo que la especificación de MCP recomienda exigir, y la puerta que un servidor malicioso usa para esconder instrucciones que el modelo sigue sin que la persona note nada raro',
      snippet: contextSnippet(text, sinAprobacion[0].index, 60)
    });
  }

  if (invocacionEncubierta.length > 0) {
    var ded2 = 55 + Math.min(20, (invocacionEncubierta.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'critical',
      label: 'Dentro del mismo handler de sampling, el código dispara una herramienta (callTool/executeTool) sin ningún paso de aprobación — el vector más grave documentado: un servidor MCP puede instruir al modelo a invocar una herramienta (como escribir un archivo) a partir de una petición de sampling, sin que la persona lo apruebe explícitamente (invocación encubierta de herramientas)',
      snippet: null
    });
  }

  if (sinTope.length > 0 && handlers.length > 0) {
    var ded3 = 25 + Math.min(10, (sinTope.length - 1) * 5);
    deduction += ded3;
    findings.push({
      sev: 'warn',
      label: 'La petición de sampling se cumple sin ningún tope de longitud/tokens (maxTokens/max_tokens) — nada impide que la completion generada sea mucho más larga de lo esperado, el vector de "robo de recursos": gastar cómputo y créditos de más sin que la persona lo note',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (handlers.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ningún handler de peticiones de sampling entrantes (setRequestHandler sobre CreateMessageRequestSchema / "sampling/createMessage") en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron handlers de sampling, y todos tienen un paso reconocible de revisión humana antes de cumplir la petición, sin invocación encubierta de herramientas y con un tope de longitud/tokens configurado.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + handlers.length + ' handler(s) de sampling (' + sinAprobacion.length + ' sin revisión humana, ' + invocacionEncubierta.length + ' con invocación encubierta de herramientas, ' + sinTope.length + ' sin tope de longitud/tokens).',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkSamplingHijackRisk: checkSamplingHijackRisk,
  findSamplingHandlers: findSamplingHandlers,
  bucket: bucket
};
