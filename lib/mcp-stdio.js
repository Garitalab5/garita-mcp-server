"use strict";
// Escudo de Lanzamiento MCP (STDIO) — detector de inyección de comandos en el
// transporte "stdio" de un CLIENTE MCP
// ================================================================================
// Problema real, documentado en 2026 como una falla de DISEÑO en los SDKs
// oficiales de MCP (no un bug puntual de una implementación): cuando un
// cliente MCP se conecta a un servidor por "stdio" (en vez de HTTP/SSE), el
// SDK arma los parámetros de lanzamiento — típicamente un objeto con
// "command" (el binario a correr) y "args" (sus argumentos) — y el sistema
// operativo EJECUTA ese comando de inmediato al construir/conectar el
// transporte, ANTES de que exista ningún intercambio del protocolo MCP. Si
// una aplicación deja que ese "command"/"args" venga de una entrada externa
// (un usuario configurando "su propio servidor MCP", un campo de un
// formulario, una API de administración) sin restringirlo a una lista de
// lanzadores conocidos, cualquiera que controle ese campo ejecuta código
// arbitrario en el servidor — y, como señala la Cloud Security Alliance,
// "incluso cuando el comando malicioso falla en establecer una sesión MCP
// válida... el comando del sistema operativo YA SE EJECUTÓ". La validación
// de la sesión MCP llega demasiado tarde para servir de defensa.
//
// Es un problema arquitectónico confirmado en los cuatro SDKs oficiales
// (Python, TypeScript, Java, Rust) — no es exclusivo de un lenguaje. Casos
// reales explotados: CVE-2026-30623 (LiteLLM) — los endpoints de prueba
// `/mcp-rest/test/connection` y `/mcp-rest/test/tools/list`, además de
// `NewMCPServerRequest`/`UpdateMCPServerRequest`, pasaban el "command" que
// mandaba el propio usuario directo a `StdioServerParameters`, sin ninguna
// validación ni control de que el endpoint fuera solo para administradores;
// corregido con una lista blanca del NOMBRE BASE del comando
// (`{npx, uvx, python, python3, node, docker, deno}`, ampliable por variable
// de entorno), validada tanto al guardar la configuración como al lanzarla
// de verdad — porque validar solo al guardar y volver a cargar esa
// configuración después sin revalidar es, en los hechos, lo mismo que no
// validar nada ("brecha de rehidratación", ver REGLA 2 abajo). CVE-2026-22688
// (Tencent WeKnora, CVSS 9.9) es el mismo patrón: `stdio_config.command`/
// `args` sin sanitizar, expuestos en un endpoint `/test` sin control de
// acceso de administrador.
//
// Esta herramienta es distinta y complementaria a detect_command_injection_risk:
// esa cubre la inyección de comandos CLÁSICA (una shell del sistema
// interpretando metacaracteres como ; && | `` $()); esta cubre el contrato
// específico y más sutil de los SDKs de MCP, donde el riesgo existe aunque
// NO haya ninguna shell de por medio — alcanza con poder elegir el binario
// (o, como ve la REGLA 3 abajo, con poder elegir solo el CÓDIGO que un
// binario ya permitido va a ejecutar).
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO que arma la
// conexión del cliente MCP (no ejecuta nada) — mismo enfoque y mismas
// limitaciones que lib/command-injection.js, lib/ssrf.js y lib/traversal.js:
// no reemplaza un analizador de sintaxis (AST) real ni una auditoría de
// seguridad formal. Alcance documentado: reconoce los dos constructores más
// usados y mejor documentados (`StdioClientTransport` del SDK de TypeScript
// y `StdioServerParameters` del SDK de Python); los SDKs de Java y Rust usan
// nombres de clase propios que esta versión no reconoce todavía (límite
// conocido, no oculto).

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

// Construcción de los parámetros de lanzamiento de un transporte stdio de
// MCP — el punto exacto donde el SDK va a ejecutar "command" como un
// proceso del sistema operativo.
var SINK_STDIO = /new\s+StdioClientTransport\s*\(|StdioServerParameters\s*\(/g;

var COMMAND_FIELD = /\bcommand\s*[:=]\s*/;

// Misma lógica que isLiteralArg() en lib/command-injection.js y
// lib/sql-injection.js: un valor que arranca con comilla y cierra limpio,
// sin concatenación/interpolación/formateo después, se trata como fijo; si
// no se puede confirmar, se trata como dependiente de una entrada externa
// por precaución (mismo criterio conservador que el resto del catálogo).
// Devuelve el contenido ENTRE comillas si "argWindow" arranca con un string
// literal limpio (sin concatenación/interpolación/formateo después), o null
// si no se puede confirmar — nunca devuelve la ventana cruda completa, para
// no arrastrar basura de los argumentos que vienen después del valor.
function extractLiteralValue(argWindow) {
  var trimmed = argWindow.replace(/^\s+/, '');
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return null;
  var closeIdx = trimmed.indexOf(q, 1);
  if (closeIdx === -1) return null;
  var inner = trimmed.slice(1, closeIdx);
  if (q === '`' && /\$\{/.test(inner)) return null; // template literal con interpolación -> no es un literal fijo
  var after = trimmed.slice(closeIdx + 1, closeIdx + 24).replace(/^\s+/, '');
  if (after[0] === '+' || after[0] === '%') return null; // concatenación o formateo "%s"
  if (/^\.\s*format\s*\(/.test(after)) return null; // "cmd {}".format(x)
  return inner;
}

function isLiteralArg(argWindow) {
  return extractLiteralValue(argWindow) !== null;
}

// REGLA 1 / REGLA 2 — señal de que "command" (o su nombre base) ya se
// compara contra una lista explícita de lanzadores permitidos, al estilo
// del parche real de CVE-2026-30623 (allowlist de {npx, uvx, python,
// python3, node, docker, deno}, revisada por nombre base con basename()).
var VALIDACION_ALLOWLIST = /\b(?:ALLOWED|ALLOWLIST|WHITELIST)_?(?:MCP_?)?(?:STDIO_?)?(?:COMMANDS?|LAUNCHERS?|BINARIES)\b|\bcomandos?_permitidos\b|\blanzadores?_permitidos\b|(?:path\.basename|os\.path\.basename|basename)\s*\(\s*command\b[^)]*\)\s*(?:not\s+)?in\b|\bcommand\b\s*(?:not\s+)?in\s+(?:ALLOWED|allowed|new\s+Set|\[|\{)/i;

// REGLA 2 — señal de que "command"/"args" viene de una configuración ya
// guardada antes (recargada de una base de datos, un archivo, un objeto
// deserializado) en vez de construirse de nuevo en este mismo lugar — el
// escenario exacto donde una validación que solo corre al GUARDAR la
// configuración (y no al LANZARLA de verdad) deja de servir de nada.
var CARGA_CONFIG_GUARDADA = /\bJSON\.parse\s*\(|\.find\s*\(|\bawait\s+\w*(?:db|store|repo|config|dao)\w*\.(?:get|find|load|fetch)\s*\(|\bgetServerConfig\s*\(|\bstoredConfig\b|\bsavedConfig\b|\bexistingServer\b|\bserver_config\b|\bconfig\.load\s*\(/i;

// REGLA 3 — "command" es un intérprete que SÍ podría estar en cualquier
// lista blanca razonable (python, node, etc.) pero sus argumentos incluyen
// una bandera de ejecución directa de código con un valor que no es un
// literal fijo — la lista blanca por nombre de binario no alcanza si el
// atacante solo necesita elegir QUÉ CÓDIGO le hace correr a ese binario ya
// permitido.
var LANZADORES_INTERPRETE = ['python', 'python3', 'node', 'deno', 'ruby', 'perl', 'php'];
var FLAG_EJECUCION_CON_DINAMICO = /-{1,2}(?:c|e|eval)\b['"]?\s*,\s*(?!['"`])[A-Za-z_$][\w.$]*\b/;

// REGLA 4 — falsa sensación de seguridad propia de Garita: creer que, si el
// comando no resulta ser un servidor MCP válido, "el protocolo MCP va a
// fallar" y ahí termina el problema — pero el comando del sistema operativo
// ya corrió antes de llegar a esa validación (la propia advertencia de la
// Cloud Security Alliance sobre este diseño).
var RECLAMA_SESION_PROTEGE = /si\s+no\s+es\s+(?:un\s+)?servidor\s+(?:mcp\s+)?v[áa]lido|protocolo\s+mcp\s+(?:lo\s+)?(?:fallar[íi]a|falla|rechazar[íi]a)|handshake\s+(?:fallar[íi]a|falla)|the\s+(?:mcp\s+)?handshake\s+will\s+fail|if\s+it'?s\s+not\s+a\s+valid\s+(?:mcp\s+)?server|connection\s+will\s+(?:just\s+)?(?:fail|error)\s+out/i;

function findOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(SINK_STDIO.source, SINK_STDIO.flags);
  var m;
  while ((m = re.exec(text))) {
    var windowStart = m.index + m[0].length;
    var win = text.slice(windowStart, windowStart + 500);
    var fieldMatch = COMMAND_FIELD.exec(win);
    var literal, valueWindow, commandRaw;
    if (fieldMatch) {
      valueWindow = win.slice(fieldMatch.index + fieldMatch[0].length, fieldMatch.index + fieldMatch[0].length + 120);
      commandRaw = extractLiteralValue(valueWindow);
      literal = commandRaw !== null;
    } else {
      // No se encontró un campo "command" reconocible en la ventana — no se
      // puede confirmar que sea seguro, así que (mismo criterio conservador
      // que el resto del catálogo) se trata como dependiente de una entrada
      // externa en vez de ignorarlo en silencio.
      literal = false;
      commandRaw = null;
    }
    operaciones.push({ index: m.index, callText: m[0], window: win, literal: literal, commandRaw: commandRaw });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo
// informativo, no cambia la detección (los patrones ya cubren varios SDKs
// a la vez).
function checkMcpStdioLaunchRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código que arma la conexión stdio de un cliente MCP) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);
  var candidatas = operaciones.filter(function (o) { return !o.literal; });

  var allowlistEnElArchivo = VALIDACION_ALLOWLIST.test(text);

  var sinValidarCerca = candidatas.filter(function (o) {
    var contextStart = Math.max(0, o.index - 800);
    var contexto = text.slice(contextStart, o.index) + o.callText + o.window.slice(0, 150);
    return !VALIDACION_ALLOWLIST.test(contexto);
  });

  // De las que no tienen validación cerca, separar las que además muestran
  // señales de venir de una configuración ya guardada antes (REGLA 2,
  // "brecha de rehidratación") — esas usan un mensaje más específico,
  // porque son el caso donde SÍ existe una validación en el archivo, solo
  // que no se aplica en este camino de ejecución.
  var rehidratacion = sinValidarCerca.filter(function (o) {
    if (!allowlistEnElArchivo) return false;
    var contextStart = Math.max(0, o.index - 500);
    return CARGA_CONFIG_GUARDADA.test(text.slice(contextStart, o.index));
  });
  var sinNingunaValidacion = sinValidarCerca.filter(function (o) { return rehidratacion.indexOf(o) === -1; });

  if (sinNingunaValidacion.length > 0) {
    var ded1 = 60 + Math.min(20, (sinNingunaValidacion.length - 1) * 10);
    deduction += ded1;
    sinNingunaValidacion.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Parámetros de lanzamiento de un transporte stdio de MCP ("command") que dependen de una entrada externa, sin ninguna validación contra una lista de lanzadores permitidos — el sistema operativo ejecuta ese comando de inmediato, antes de que exista ninguna validación del protocolo MCP',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  if (rehidratacion.length > 0) {
    var ded2 = 65 + Math.min(20, (rehidratacion.length - 1) * 10);
    deduction += ded2;
    rehidratacion.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Posible brecha de "rehidratación": el archivo sí tiene una lista de lanzadores permitidos en algún lado, pero este lanzamiento parece venir de una configuración ya guardada/cargada antes (no se vuelve a validar al momento de lanzarla de verdad) — el mismo patrón detrás de CVE-2026-30623 antes de su parche, donde validar solo al guardar no bastaba',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var bypassBandera = operaciones.filter(function (o) {
    if (!o.literal || !o.commandRaw) return false;
    var base = o.commandRaw.split(/[\\/]/).pop();
    if (LANZADORES_INTERPRETE.indexOf(base.toLowerCase()) === -1) return false;
    return FLAG_EJECUCION_CON_DINAMICO.test(o.window);
  });
  if (bypassBandera.length > 0) {
    deduction += 60;
    bypassBandera.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'El comando está en una lista blanca razonable de lanzadores (' + o.commandRaw + '), pero eso no alcanza: sus argumentos incluyen una bandera de ejecución directa de código (-c/-e/--eval) con un valor que no es fijo — el atacante no necesita elegir el comando, solo el código que ese comando ya permitido va a ejecutar',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  if (sinValidarCerca.length > 0 && RECLAMA_SESION_PROTEGE.test(text)) {
    deduction += 35;
    findings.push({
      sev: 'critical',
      label: 'El código (o su comentario) sugiere que si el comando no resulta ser un servidor MCP válido "el protocolo fallaría" y ahí termina el problema — pero el comando del sistema operativo ya se ejecutó antes de llegar a esa validación; la sesión MCP invalidándose después no deshace nada',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna construcción de un transporte stdio de MCP (StdioClientTransport/StdioServerParameters) en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron construcciones de un transporte stdio de MCP, y todas usan un comando fijo (no depende de una entrada externa) o pasan por una validación contra una lista de lanzadores permitidos.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' construcción(es) de transporte stdio de MCP en el código, ' + candidatas.length + ' con un comando que depende de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkMcpStdioLaunchRisk: checkMcpStdioLaunchRisk,
  findOperaciones: findOperaciones,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
