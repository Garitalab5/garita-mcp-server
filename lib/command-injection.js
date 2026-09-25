"use strict";
// Detector de riesgo de inyección de comandos del sistema
// ================================================================================
// Problema real: una herramienta MCP que arma un comando de shell a partir de
// una entrada que le pasa el propio agente (un nombre de archivo, un argumento
// de búsqueda, un parámetro cualquiera) y lo ejecuta con una función que invoca
// una shell de verdad (system, exec, subprocess con shell=True) puede terminar
// ejecutando CUALQUIER comando que un atacante logre colar — encadenando con
// ";", "&&", "|", backticks o "$(...)" — aunque el desarrollador haya validado
// el "comando base" contra una lista de permitidos.
//
// Es la SEGUNDA categoría más grande de vulnerabilidades reales del censo de
// 9.695 servidores MCP escaneados en 2026 (bex.co, "MCP Vulnerability Census"):
// inyección de comandos fue el 9.6% de los 4.982 problemas encontrados (476
// casos) — solo detrás de acceso arbitrario a archivos. Casos reales
// documentados: CVE-2026-55581/55582/55580 (CVSS hasta 8.6) en mcp-shell, cuyo
// "modo seguro" solo validaba el PRIMER TOKEN del comando contra una lista
// blanca y por defecto ejecutaba todo con `/bin/bash -c`, dejando pasar
// cualquier cosa encadenada después del comando permitido; y CVE-2025-6514
// (CVSS 9.6, CRÍTICO) en mcp-remote, donde una URL de un servidor OAuth remoto
// sin validar terminaba ejecutándose como comando del sistema operativo.
//
// Esto es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada) — mismo enfoque y mismas limitaciones que
// lib/ssrf.js y lib/traversal.js: no reemplaza un analizador de sintaxis (AST)
// real ni una auditoría de seguridad formal. Una llamada como
// `subprocess.run([...], shell=False)` con una lista de argumentos (sin
// invocar una shell) no se marca como riesgo — ese es precisamente el patrón
// seguro que reemplaza a una shell interpretando el string.

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

// Funciones que SIEMPRE invocan una shell del sistema operativo (JS: exec/execSync;
// Python: os.system/os.popen; PHP: shell_exec/passthru/popen/exec/system; Ruby: exec/system).
var SIEMPRE_PELIGROSA = /\b(?:child_process\.)?(?:exec|execSync)\s*\(|\bos\.(?:system|popen)\s*\(|\b(?:shell_exec|passthru)\s*\(|\bpopen\s*\(|\bsystem\s*\(/gi;

// Funciones que solo invocan una shell CONDICIONALMENTE, según una opción
// explícita (spawn/execFile de Node con {shell:true}; subprocess.run/Popen/call
// de Python con shell=True) — sin esa opción, reciben un arreglo de argumentos
// y ejecutan el binario directamente (execve), sin pasar por ningún intérprete
// de shell, y por lo tanto no son vulnerables a inyección de comandos.
var CONDICIONAL_PELIGROSA = /\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\(|\b(?:child_process\.)?(?:execFile(?:Sync)?|spawn(?:Sync)?)\s*\(/gi;

var SHELL_TRUE = /\bshell\s*[:=]\s*(?:true|True)\b/;

// Señal de que el comando pasa por una función de escape reconocida, o por una
// lista de comandos permitidos (aunque, como muestra CVE-2026-55581, una lista
// permitida no basta por sí sola — ver la regla de metacaracteres más abajo).
var VALIDACION = /shlex\.quote\(|shlex\.split\(|escapeshellarg\(|escapeshellcmd\(|require\(['"]shell-quote['"]\)|from\s+['"]shlex['"]\s+import|\b(?:allowlist|whitelist|comandos?_permitidos|ALLOWED_COMMANDS|COMANDOS_PERMITIDOS)\b/i;

// Patrón "descargar y ejecutar": trae un script de una URL remota y lo manda
// directo a una shell, sin ninguna verificación de lo que ese script contiene
// en el momento de ejecutarse.
var DESCARGA_EJECUTA = /(?:curl|wget)\b[^\n;]{0,140}\|\s*(?:sudo\s+)?(?:bash|sh|zsh)\b/i;

// Heurística de que el código filtra metacaracteres de shell (;, &, |, `, $(),
// >, <) en algún punto — una clase de caracteres que los incluye, o el uso de
// una de las funciones de escape reconocidas.
var METACARACTERES_FILTRADOS = /\[[^\]]*[;&|`][^\]]*\]|shlex\.quote\(|escapeshellarg\(|escapeshellcmd\(/i;

function isLiteralArg(argWindow) {
  var trimmed = argWindow.replace(/^\s+/, '');
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return false; // no arranca con string -> variable/expresión (incluye prefijos f"/b"/r" de Python)
  var closeIdx = trimmed.indexOf(q, 1);
  if (closeIdx === -1) return false; // no se puede confirmar, se trata como variable por precaución
  var inner = trimmed.slice(1, closeIdx);
  if (q === '`' && /\$\{/.test(inner)) return false; // template literal con interpolación -> variable
  var after = trimmed.slice(closeIdx + 1, closeIdx + 24).replace(/^\s+/, '');
  if (after[0] === '+' || after[0] === '%') return false; // concatenación o formateo "%s" -> variable
  if (/^\.\s*format\s*\(/.test(after)) return false; // "cmd {}".format(x) -> variable
  return true; // literal limpio, no depende de entrada externa
}

function findOperaciones(text) {
  var operaciones = [];

  var reS = new RegExp(SIEMPRE_PELIGROSA.source, SIEMPRE_PELIGROSA.flags);
  var m;
  while ((m = reS.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 200);
    operaciones.push({ index: m.index, callText: m[0], argWindow: argWindow, literal: isLiteralArg(argWindow) });
    if (m.index === reS.lastIndex) reS.lastIndex++; // evita loop infinito con matches vacíos
  }

  var reC = new RegExp(CONDICIONAL_PELIGROSA.source, CONDICIONAL_PELIGROSA.flags);
  while ((m = reC.exec(text))) {
    var startArgC = m.index + m[0].length;
    var wideWindow = text.slice(startArgC, startArgC + 300);
    if (SHELL_TRUE.test(wideWindow)) {
      var argWindowC = wideWindow.slice(0, 200);
      operaciones.push({ index: m.index, callText: m[0], argWindow: argWindowC, literal: isLiteralArg(argWindowC) });
    }
    // Sin "shell: true"/"shell=True" cerca, es la forma segura (arreglo de
    // argumentos ejecutado directamente, sin intérprete de shell) — no se cuenta.
    if (m.index === reC.lastIndex) reC.lastIndex++;
  }

  operaciones.sort(function (a, b) { return a.index - b.index; });
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkCommandInjectionRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que ejecuta un comando del sistema) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);
  var candidatas = operaciones.filter(function (o) { return !o.literal; });

  var noValidadas = candidatas.filter(function (o) {
    var contextStart = Math.max(0, o.index - 600);
    var contexto = text.slice(contextStart, o.index) + o.callText + o.argWindow.slice(0, 100);
    return !VALIDACION.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    noValidadas.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Ejecución de un comando del sistema (invocando una shell) con un argumento que depende de una variable/entrada externa, sin ninguna validación o escape reconocible cerca',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var mDescarga = DESCARGA_EJECUTA.exec(text);
  if (mDescarga) {
    deduction += 55;
    findings.push({
      sev: 'critical',
      label: 'Patrón de "descargar y ejecutar" (curl/wget encadenado con una tubería directa a una shell) — corre cualquier script que el servidor remoto decida devolver en ese momento, sin ninguna verificación',
      snippet: contextSnippet(text, mDescarga.index, mDescarga[0].length)
    });
  }

  var sinFiltroMetacaracteres = candidatas.length > 0 && !METACARACTERES_FILTRADOS.test(text);
  if (sinFiltroMetacaracteres) {
    deduction += 25;
    findings.push({
      sev: 'warn',
      label: 'No se encontró ningún filtrado reconocible de metacaracteres de shell (;, &&, |, `, $(), >, <) — una lista de comandos permitidos que solo revisa el primer token deja pasar comandos encadenados después de ese token, el mismo patrón detrás de CVE-2026-55581/55582',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna ejecución de un comando del sistema con riesgo de inyección (ninguna llamada peligrosa, o las que hay usan la forma segura de lista de argumentos sin invocar una shell).', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron ejecuciones de comandos, pero todas usan un comando fijo (no depende de una entrada externa) o pasan por una validación/escape reconocible.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' ejecución(es) de comandos del sistema en el código, ' + candidatas.length + ' con un argumento que depende de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkCommandInjectionRisk: checkCommandInjectionRisk,
  findOperaciones: findOperaciones,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
