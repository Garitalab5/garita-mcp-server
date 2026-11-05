"use strict";
// Escudo de Fuga Entre Clientes — detector de estado de servidor MCP
// compartido sin aislamiento por sesión/cliente
// ================================================================================
// Problema real: un servidor MCP que crea UNA sola instancia de McpServer/Server
// al arrancar, y la reutiliza para atender a TODOS los clientes que se conectan
// (en vez de crear una instancia nueva por sesión), puede terminar mezclando el
// estado de un cliente con el de otro: una respuesta armada para el cliente A
// puede llegar al cliente B. Lo mismo pasa, incluso con instancias separadas,
// si hay una variable mutable a nivel de módulo (let/var, no const) que un
// handler de petición escribe y que el callback de una herramienta registrada
// lee — dos peticiones concurrentes de clientes distintos terminan compartiendo
// ese mismo valor.
//
// Motivado por CVE-2026-25536 (CVSS 7.1), una falla real en el propio SDK
// oficial de TypeScript de MCP (v1.10.0 a v1.25.3): una sola instancia de
// McpServer emparejada con un StreamableHTTPServerTransport se reutilizaba
// entre clientes, sin aislar el estado de la respuesta por cliente — las
// respuestas podían cruzarse entre clientes distintos. Es también el patrón
// que el propio OWASP MCP Top 10 llama "Context Injection and Over Sharing".
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO que arma el
// transporte HTTP/SSE de un servidor MCP (no ejecuta nada) — mismo enfoque y
// mismas limitaciones que lib/dns-rebinding.js y lib/missing-auth.js: no
// reemplaza un analizador de sintaxis (AST) real ni una auditoría de seguridad
// formal. Límite conocido: identificar qué código cae "dentro" de un handler
// de ruta es aproximado (busca el handler y balancea sus llaves, no es un
// parser real) — una estructura muy atípica puede confundirlo.

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

function isInsideAnyRange(ranges, index) {
  for (var i = 0; i < ranges.length; i++) {
    if (index >= ranges[i].bodyStart && index <= ranges[i].bodyEnd) return true;
  }
  return false;
}

var MCP_SERVER_CTOR = /\bnew\s+(?:McpServer|Server)\s*\(/g;
var MCP_TRANSPORT_CTOR = /\bnew\s+(?:StreamableHTTPServerTransport|SSEServerTransport)\s*\(/g;
var CONNECT_CALL = /\.\s*connect\s*\(/;

// Handlers de ruta HTTP típicos (Express/Fastify-like): app.post('/mcp', (req,res) => {...}),
// router.post(...), etc. — donde normalmente vive la conexión por-cliente de MCP.
var ROUTE_HANDLER = /\b(?:app|router)\s*\.\s*(?:post|get|all|use)\s*\(\s*(?:['"][^'"]*['"]\s*,\s*)?(?:async\s*)?(?:function\s*\(|\([^)]*\)\s*=>|\w+\s*=>)\s*\{/g;

function findRouteHandlers(text) {
  var out = [];
  var re = new RegExp(ROUTE_HANDLER.source, ROUTE_HANDLER.flags);
  var m;
  while ((m = re.exec(text))) {
    var openBraceIdx = m.index + m[0].length - 1;
    var closeBraceIdx = findMatchingBrace(text, openBraceIdx);
    if (closeBraceIdx !== -1) {
      out.push({ index: m.index, bodyStart: openBraceIdx + 1, bodyEnd: closeBraceIdx, body: text.slice(openBraceIdx + 1, closeBraceIdx) });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// Instancias de McpServer/Server creadas FUERA de cualquier handler de ruta —
// es decir, una sola vez al arrancar, candidatas a quedar compartidas entre
// todos los clientes que se conecten después.
function findTopLevelServerDeclarations(text, handlerRanges) {
  var out = [];
  var re = new RegExp(MCP_SERVER_CTOR.source, MCP_SERVER_CTOR.flags);
  var m;
  while ((m = re.exec(text))) {
    if (!isInsideAnyRange(handlerRanges, m.index)) {
      var before = text.slice(Math.max(0, m.index - 60), m.index);
      var varMatch = /(?:const|let|var)\s+(\w+)\s*=\s*$/.exec(before);
      out.push({ index: m.index, varName: varMatch ? varMatch[1] : null, raw: m[0] });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// Dentro de cada handler de ruta: si crea su PROPIA instancia nueva de
// McpServer/Server, queda aislado (no se marca) aunque también exista una
// instancia compartida en otro lado. Si en cambio conecta un transporte nuevo
// contra la instancia COMPARTIDA (server.connect(transport) usando el nombre
// de la variable de nivel de módulo), ese handler reutiliza estado entre
// clientes.
function findHandlersReusingSharedServer(text, sharedServers) {
  var out = [];
  var handlers = findRouteHandlers(text);
  handlers.forEach(function (h) {
    var hasFreshServerInstance = new RegExp(MCP_SERVER_CTOR.source, MCP_SERVER_CTOR.flags).test(h.body);
    if (hasFreshServerInstance) return;
    var hasTransportAndConnect = new RegExp(MCP_TRANSPORT_CTOR.source, MCP_TRANSPORT_CTOR.flags).test(h.body) && CONNECT_CALL.test(h.body);
    if (!hasTransportAndConnect) return;
    sharedServers.forEach(function (s) {
      if (!s.varName) return;
      var usesSharedVar = new RegExp('\\b' + s.varName + '\\s*\\.\\s*connect\\s*\\(').test(h.body);
      if (usesSharedVar) {
        out.push({ index: h.index, raw: text.slice(h.index, h.index + 60) });
      }
    });
  });
  return out;
}

// Variable mutable (let/var, no const) declarada FUERA de cualquier handler
// de ruta, y referenciada dentro del callback de una herramienta registrada
// (registerTool/tool) — la misma clase de fuga de CVE-2026-25536, incluso sin
// reutilizar la instancia completa del servidor.
var MODULE_MUTABLE_STATE = /\b(?:let|var)\s+(\w+)\s*(?:=|;)/g;
var REGISTER_TOOL_CALL = /\.\s*(?:registerTool|tool)\s*\(/g;

function findSharedMutableStateInToolHandlers(text, handlerRanges) {
  var out = [];
  var declRe = new RegExp(MODULE_MUTABLE_STATE.source, MODULE_MUTABLE_STATE.flags);
  var m;
  var candidatos = [];
  while ((m = declRe.exec(text))) {
    if (!isInsideAnyRange(handlerRanges, m.index)) {
      candidatos.push({ name: m[1], index: m.index });
    }
    if (m.index === declRe.lastIndex) declRe.lastIndex++;
  }
  if (candidatos.length === 0) return out;

  var toolRe = new RegExp(REGISTER_TOOL_CALL.source, REGISTER_TOOL_CALL.flags);
  while ((m = toolRe.exec(text))) {
    var openParenIdx = m.index + m[0].length - 1;
    var win = text.slice(openParenIdx, Math.min(text.length, openParenIdx + 2000));
    candidatos.forEach(function (c) {
      var re2 = new RegExp('\\b' + c.name + '\\b');
      if (re2.test(win)) {
        out.push({ index: m.index, varName: c.name, raw: text.slice(m.index, m.index + 40) });
      }
    });
    if (m.index === toolRe.lastIndex) toolRe.lastIndex++;
  }
  var seen = {};
  return out.filter(function (o) {
    if (seen[o.varName]) return false;
    seen[o.varName] = true;
    return true;
  });
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección.
function checkCrossClientLeakRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente que arma el transporte HTTP/SSE de un servidor MCP) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var handlerRanges = findRouteHandlers(text);
  var sharedServers = findTopLevelServerDeclarations(text, handlerRanges);
  var handlersConReuso = findHandlersReusingSharedServer(text, sharedServers);

  if (handlersConReuso.length > 0) {
    var ded1 = 60 + Math.min(20, (handlersConReuso.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'Una sola instancia de McpServer/Server creada a nivel de módulo se conecta a un transporte HTTP/SSE nuevo dentro de un handler de petición, en vez de crear también una instancia nueva del servidor por cada cliente/sesión — las respuestas pueden terminar mezclándose entre clientes distintos. El mismo patrón detrás de CVE-2026-25536 (CVSS 7.1) en el propio SDK oficial de TypeScript de MCP',
      snippet: contextSnippet(text, handlersConReuso[0].index, handlersConReuso[0].raw.length)
    });
  }

  var estadoCompartido = findSharedMutableStateInToolHandlers(text, handlerRanges);
  if (estadoCompartido.length > 0) {
    var ded2 = 30 + Math.min(15, (estadoCompartido.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'warn',
      label: 'Una variable mutable declarada a nivel de módulo (let/var) se usa dentro del callback de una herramienta registrada en el servidor MCP (registerTool/tool) — si esa variable se escribe durante la petición de un cliente, una petición concurrente de otro cliente puede leer (o pisar) ese mismo valor, sin que haga falta reutilizar ninguna instancia completa de servidor',
      snippet: contextSnippet(text, estadoCompartido[0].index, estadoCompartido[0].raw.length)
    });
  }

  if (findings.length === 0) {
    if (sharedServers.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna instancia de McpServer/Server creada a nivel de módulo y reutilizada dentro de un handler de petición, ni estado mutable compartido referenciado dentro de una herramienta registrada.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontró una instancia de servidor MCP a nivel de módulo, pero cada handler de petición crea su propia instancia nueva al conectar un transporte — aislamiento por cliente presente.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + sharedServers.length + ' instancia(s) de servidor MCP a nivel de módulo (' + handlersConReuso.length + ' reutilizada(s) sin aislamiento por cliente dentro de un handler) y ' + estadoCompartido.length + ' variable(s) mutable(s) compartida(s) referenciada(s) dentro de una herramienta registrada.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkCrossClientLeakRisk: checkCrossClientLeakRisk,
  findRouteHandlers: findRouteHandlers,
  findTopLevelServerDeclarations: findTopLevelServerDeclarations,
  findHandlersReusingSharedServer: findHandlersReusingSharedServer,
  findSharedMutableStateInToolHandlers: findSharedMutableStateInToolHandlers,
  bucket: bucket
};
