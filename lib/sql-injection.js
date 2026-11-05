"use strict";
// Detector de riesgo de inyección SQL
// ================================================================================
// Problema real: una herramienta MCP que arma una consulta SQL a partir de una
// entrada que le pasa el agente (un nombre de usuario, un filtro de búsqueda,
// un identificador cualquiera) y la ejecuta con una función que corre SQL crudo
// puede terminar ejecutando CUALQUIER sentencia que un atacante logre colar —
// leyendo tablas que no debería, modificando datos, o saltándose por completo
// una restricción de "solo lectura" que solo existe como texto en la
// descripción de la herramienta, no como un permiso real de la base de datos.
//
// Es una categoría real y documentada de vulnerabilidades en el censo de 9.695
// servidores MCP escaneados en 2026 (bex.co, "MCP Vulnerability Census"):
// inyección SQL fue el 4.2% de los 4.982 problemas encontrados (211 casos).
// Caso real de mayor perfil: Datadog Security Labs encontró inyección SQL en
// el propio servidor MCP de referencia de Postgres de Anthropic — su
// restricción de "solo lectura" estaba implementada ÚNICAMENTE como una
// instrucción de texto en la descripción de la herramienta (algo que un
// agente puede ignorar o que un ataque de inyección de prompt puede anular),
// no como un permiso real a nivel de base de datos. También documentado en
// CVE-2026-7206 (sqlite-mcp) y CVE-2025-66335 (Apache Doris MCP Server).
//
// Esta herramienta revisa dos cosas distintas: (1) el patrón clásico de
// inyección — una consulta armada por concatenación/interpolación de una
// entrada externa, en vez de parámetros preparados — y (2) el patrón
// específico del caso de Datadog: el código (o su documentación/comentarios)
// AFIRMA que la herramienta es de "solo lectura", pero no hay ninguna señal
// de que eso se aplique de verdad a nivel de base de datos.
//
// Esto es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada) — mismo enfoque y mismas limitaciones que
// lib/ssrf.js, lib/traversal.js y lib/command-injection.js: no reemplaza un
// analizador de sintaxis (AST) real ni una auditoría de seguridad formal.

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

// Funciones que ejecutan SQL crudo (JS: .query/.execute/.raw de drivers y ORMs
// comunes — pg, mysql2, knex, sequelize.query; Python: .execute/.executemany
// de DB-API, .exec_driver_sql de SQLAlchemy; PHP: mysqli_query, ->query/->exec de PDO).
var SINK_PELIGROSO = /\.(?:execute|executemany|query|raw|exec_driver_sql)\s*\(|\bmysqli_query\s*\(/gi;

// Señal de que el valor pasa por una función de escape reconocida antes de
// entrar a la consulta (en vez de, o además de, parámetros preparados).
// Nota: "prepare(" se exige invocado como método de un objeto conocido de
// base de datos (db/conn/connection/client/stmt), no como una función libre
// cualquiera — una función local sin relación llamada "prepare" (passthrough
// total) no debe contar como consulta preparada real.
var VALIDACION_SQL = /\.escape\(|escapeId\(|\b(?:db|conn|connection|client|stmt)\.prepare\(|mysql\.escape|connection\.escape|pg_escape|quote_ident|quote_literal/i;

// El código (o su comentario/docstring) afirma que la herramienta es de "solo
// lectura" / "solo consulta".
var RECLAMA_SOLO_LECTURA = /read[\s-]?only|solo\s+lectura|s[oó]lo\s+de\s+lectura|solo\s+consulta|only\s+select|lectura\s+[uú]nicamente/i;

// Señales de que esa restricción de "solo lectura" se aplica de verdad, a
// nivel de base de datos o de código — no solo como una frase en un comentario
// o en la descripción de la herramienta.
var ENFORCEMENT_REAL = /SET\s+TRANSACTION\s+READ\s+ONLY|readOnly\s*[:=]\s*true|default_transaction_read_only|REVOKE\s+(?:INSERT|UPDATE|DELETE)|toUpperCase\(\)\.startsWith\(\s*['"]SELECT['"]\)|\.startsWith\(\s*['"]SELECT['"]\)|ALLOWED_STATEMENTS|only_select|solo_consulta_permitida/i;

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
  if (/^\.\s*format\s*\(/.test(after)) return false; // "SELECT {}".format(x) -> variable
  return true; // literal limpio, no depende de entrada externa
}

function findOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(SINK_PELIGROSO.source, SINK_PELIGROSO.flags);
  var m;
  while ((m = re.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 220);
    operaciones.push({ index: m.index, callText: m[0], argWindow: argWindow, literal: isLiteralArg(argWindow) });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkSqlInjectionRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que ejecuta una consulta SQL) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);
  var candidatas = operaciones.filter(function (o) { return !o.literal; });

  var noValidadas = candidatas.filter(function (o) {
    var contextStart = Math.max(0, o.index - 600);
    var contexto = text.slice(contextStart, o.index) + o.callText + o.argWindow.slice(0, 100);
    return !VALIDACION_SQL.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    noValidadas.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Consulta SQL armada por concatenación/interpolación de una variable/entrada externa, en vez de un parámetro preparado, sin ninguna función de escape reconocible cerca',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  // ENFORCEMENT_REAL se busca en una ventana acotada alrededor de la
  // afirmación de "solo lectura" y alrededor de cada llamada a SINK_PELIGROSO
  // (mismo criterio de ventana de contexto que ya usa VALIDACION_SQL) — no en
  // el texto completo del archivo. Así, una señal de aplicación real sin
  // relación (ej. un objeto de UI { readOnly: true } en otra parte del
  // archivo) no apaga la regla.
  var reclamaMatch = RECLAMA_SOLO_LECTURA.exec(text);
  var reclamaSoloLectura = false;
  if (reclamaMatch) {
    var winStart = Math.max(0, reclamaMatch.index - 300);
    var winEnd = Math.min(text.length, reclamaMatch.index + reclamaMatch[0].length + 300);
    var enforcementCerca = ENFORCEMENT_REAL.test(text.slice(winStart, winEnd));
    if (!enforcementCerca) {
      enforcementCerca = operaciones.some(function (o) {
        var opStart = Math.max(0, o.index - 300);
        var opEnd = Math.min(text.length, o.index + o.callText.length + 300);
        return ENFORCEMENT_REAL.test(text.slice(opStart, opEnd));
      });
    }
    reclamaSoloLectura = !enforcementCerca;
  }
  if (reclamaSoloLectura) {
    deduction += 40;
    findings.push({
      sev: 'critical',
      label: 'El código (o su comentario/descripción) afirma que la herramienta es de "solo lectura", pero no se encontró ninguna señal de que eso se aplique de verdad a nivel de base de datos — el mismo patrón que Datadog Security Labs encontró en el servidor MCP de referencia de Postgres de Anthropic, donde la restricción vivía solo en el texto que lee el agente',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna ejecución de una consulta SQL cruda en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron consultas SQL, pero todas usan una consulta fija/parametrizada (no depende de una entrada externa concatenada) o pasan por una función de escape reconocible.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' consulta(s) SQL cruda(s) en el código, ' + candidatas.length + ' con un argumento que depende de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkSqlInjectionRisk: checkSqlInjectionRisk,
  findOperaciones: findOperaciones,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
