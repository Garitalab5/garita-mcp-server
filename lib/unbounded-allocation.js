"use strict";
// Escudo de Asignación sin Límite — detector de agotamiento de memoria/CPU
// ================================================================================
// Problema real: una herramienta/servidor que (a) lee el cuerpo completo de
// una petición o un archivo en memoria sin ningún tope de tamaño, o (b)
// reserva un array/buffer, o corre un bucle, cuyo tamaño/cantidad de
// vueltas viene directamente de un número que controla quien llama — sin
// nunca limitarlo — deja la puerta abierta a que un solo mensaje ("Content-
// Length: 50GB", o { "cantidad": 999999999999 }) agote toda la memoria o la
// CPU del proceso del agente (CWE-770, "Allocation of Resources Without
// Limits or Throttling"). A diferencia de detect_toxic_flow_risk o
// detect_ssrf_risk (que miran la LÓGICA de qué se hace con los datos), acá
// el problema es puramente de RECURSOS: ni siquiera hace falta que el dato
// sea "malicioso" en contenido, basta con que sea GRANDE o NUMEROSO.
//
// Motivado por CVE-2026-14539 (CVSS alto): un servidor MCP leía el cuerpo
// completo de la petición hacia memoria sin ningún límite de tamaño
// configurado, y por separado reservaba estructuras cuyo tamaño dependía
// directamente de un conteo provisto por quien llamaba, sin ningún tope —
// un solo request bastaba para agotar la memoria disponible del proceso.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO que lee
// cuerpos de petición, archivos, o reserva memoria/itera (no ejecuta nada,
// no mide uso real de memoria) — mismo enfoque y mismas limitaciones que
// lib/dynamic-code.js y lib/ssrf.js: no reemplaza un analizador de sintaxis
// (AST) real ni una auditoría de seguridad formal.

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

function splitTopLevelArgs(argsText) {
  var args = [];
  var depth = 0;
  var inString = null;
  var current = '';
  for (var i = 0; i < argsText.length; i++) {
    var ch = argsText[i];
    if (inString) {
      current += ch;
      if (ch === '\\') { i++; if (i < argsText.length) current += argsText[i]; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; current += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') { depth++; current += ch; continue; }
    if (ch === ')' || ch === ']' || ch === '}') { depth--; current += ch; continue; }
    if (ch === ',' && depth === 0) { args.push(current); current = ''; continue; }
    current += ch;
  }
  if (current.trim() !== '' || args.length > 0) args.push(current);
  return args;
}

function isLiteralArg(argWindow) {
  var trimmed = (argWindow || '').replace(/^\s+/, '');
  if (/^-?\d+(?:\.\d+)?$/.test(trimmed)) return true; // número fijo escrito por el desarrollador
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return false;
  var closeIdx = trimmed.indexOf(q, 1);
  return closeIdx !== -1;
}

// ---------- (a) lectura completa del cuerpo de la petición sin límite ----------

var BODY_PARSER_CALL = /\b(?:express|bodyParser)\.(?:json|raw|text|urlencoded)\s*\(/g;

function findBodyParserSinLimite(text) {
  var out = [];
  var re = new RegExp(BODY_PARSER_CALL.source, BODY_PARSER_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var openParenIdx = m.index + m[0].length - 1;
    var closeParenIdx = findMatchingParen(text, openParenIdx);
    var argsText = closeParenIdx === -1 ? '' : text.slice(openParenIdx + 1, closeParenIdx);
    if (!/\blimit\s*:/.test(argsText)) {
      out.push({ index: m.index, raw: m[0] + argsText + ')' });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// Acumulación manual de un stream ("req.on('data', chunk => { body += chunk })")
// sin ningún chequeo de tamaño total dentro del handler.
var STREAM_DATA_HANDLER = /\.on\s*\(\s*['"]data['"]\s*,/g;
var ACUMULACION = /\+=|\.push\s*\(|\.concat\s*\(/;
var TOPE_TAMANO = /\.length\s*[+>]|size\s*[+>]=?|MAX_(?:BODY|SIZE|LENGTH)\w*|maxSize|maxLength/i;

function findStreamSinLimite(text) {
  var out = [];
  var re = new RegExp(STREAM_DATA_HANDLER.source, STREAM_DATA_HANDLER.flags);
  var m;
  while ((m = re.exec(text))) {
    var windowEnd = Math.min(text.length, m.index + 350);
    var win = text.slice(m.index, windowEnd);
    if (ACUMULACION.test(win) && !TOPE_TAMANO.test(win)) {
      out.push({ index: m.index, raw: m[0] });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// Lectura completa de un archivo cuya ruta NO es un texto fijo (viene de un
// parámetro/entrada externa), sin ningún chequeo de tamaño (fs.statSync,
// ".size") antes de leerlo entero a memoria.
var FS_READ_CALL = /\bfs\.readFileSync\s*\(|\bfs\.readFile\s*\(/g;
var SIZE_CHECK_ANTES = /\.statSync\s*\(|fs\.stat\s*\(|\.size\s*[<>]=?\s*\d|\.size\s*[<>]=?\s*[A-Z_]+/i;

function findLecturaArchivoSinLimite(text) {
  var out = [];
  var re = new RegExp(FS_READ_CALL.source, FS_READ_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var openParenIdx = m.index + m[0].length - 1;
    var closeParenIdx = findMatchingParen(text, openParenIdx);
    var argsText = closeParenIdx === -1 ? '' : text.slice(openParenIdx + 1, closeParenIdx);
    var argsList = splitTopLevelArgs(argsText);
    var firstArg = argsList.length > 0 ? argsList[0].replace(/^\s+/, '') : '';
    if (!isLiteralArg(firstArg)) {
      var contextoAntes = text.slice(Math.max(0, m.index - 300), m.index);
      if (!SIZE_CHECK_ANTES.test(contextoAntes)) {
        out.push({ index: m.index, raw: m[0] + argsText.slice(0, 60) });
      }
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// ---------- (b) reservas/bucles con tamaño/cantidad sin tope ----------

var ALLOC_CALL = /\bnew\s+Array\s*\(|\bArray\s*\(|\bBuffer\.alloc(?:Unsafe)?\s*\(|\bbytearray\s*\(/g;
var CAP_CHECK = /Math\.min\s*\(|\bif\s*\([^)]{0,80}[<>]=?\s*\d|\bif\s*\([^)]{0,80}[<>]=?\s*[A-Z_][A-Z0-9_]*\b/i;

function findAllocSinTope(text) {
  var out = [];
  var re = new RegExp(ALLOC_CALL.source, ALLOC_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var openParenIdx = m.index + m[0].length - 1;
    var closeParenIdx = findMatchingParen(text, openParenIdx);
    var argsText = closeParenIdx === -1 ? '' : text.slice(openParenIdx + 1, closeParenIdx);
    var argsList = splitTopLevelArgs(argsText);
    var firstArg = argsList.length > 0 ? argsList[0].replace(/^\s+/, '') : '';
    if (firstArg && !isLiteralArg(firstArg)) {
      var contextoAntes = text.slice(Math.max(0, m.index - 250), m.index);
      var usaMathMinEnElMismoArgumento = /Math\.min\s*\(/.test(firstArg);
      if (!usaMathMinEnElMismoArgumento && !CAP_CHECK.test(contextoAntes)) {
        out.push({ index: m.index, raw: m[0] + argsText.slice(0, 40) });
      }
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// for (i = 0; i < N; i++) donde N es una variable (no una constante en
// MAYÚSCULAS ni un número fijo) y no hay ningún tope reconocible antes.
var FOR_LOOP_BOUND = /\bfor\s*\(\s*(?:let|var|const)?\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;/g;

function findBucleSinTope(text) {
  var out = [];
  var re = new RegExp(FOR_LOOP_BOUND.source, FOR_LOOP_BOUND.flags);
  var m;
  while ((m = re.exec(text))) {
    var boundName = m[1];
    var esConstanteObvia = /^[A-Z0-9_]+$/.test(boundName) || /^\d+$/.test(boundName);
    if (!esConstanteObvia) {
      var contextoAntes = text.slice(Math.max(0, m.index - 250), m.index);
      var tieneTope = new RegExp('Math\\.min\\s*\\(\\s*' + boundName + '\\b|\\b' + boundName + '\\b[^\\n;]{0,40}[<>]=?\\s*\\d|[<>]=?\\s*\\d[^\\n;]{0,40}\\b' + boundName + '\\b').test(contextoAntes);
      if (!tieneTope) {
        out.push({ index: m.index, raw: m[0], boundName: boundName });
      }
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkUnboundedAllocationRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente que lee un cuerpo/archivo o reserva memoria/itera) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var bodyParserSinLimite = findBodyParserSinLimite(text);
  var streamSinLimite = findStreamSinLimite(text);
  var lecturaArchivoSinLimite = findLecturaArchivoSinLimite(text);
  var lecturaSinLimite = bodyParserSinLimite.concat(streamSinLimite).concat(lecturaArchivoSinLimite);

  if (lecturaSinLimite.length > 0) {
    var ded1 = 55 + Math.min(20, (lecturaSinLimite.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'Se lee un cuerpo de petición o un archivo completo hacia memoria sin ningún tope de tamaño configurado (sin "limit" en express.json()/bodyParser, sin chequeo de tamaño en la acumulación manual de un stream, o sin fs.statSync() antes de leer un archivo con ruta no fija) — un solo mensaje/archivo grande puede agotar la memoria del proceso. El mismo patrón detrás de CVE-2026-14539 (CWE-770)',
      snippet: contextSnippet(text, lecturaSinLimite[0].index, Math.min(50, lecturaSinLimite[0].raw.length))
    });
  }

  var allocSinTope = findAllocSinTope(text);
  var bucleSinTope = findBucleSinTope(text);
  var reservaSinTope = allocSinTope.concat(bucleSinTope);

  if (reservaSinTope.length > 0) {
    var ded2 = 55 + Math.min(20, (reservaSinTope.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'critical',
      label: 'Se reserva un array/buffer, o se corre un bucle, cuyo tamaño/cantidad de vueltas viene directamente de una variable (no un número fijo que escribió el desarrollador) sin ningún tope (Math.min/comparación contra un máximo) antes — quien llame a la herramienta controla cuánta memoria o CPU se consume, sin límite. Variante documentada también en CVE-2026-14539 (CWE-770)',
      snippet: contextSnippet(text, reservaSinTope[0].index, Math.min(50, reservaSinTope[0].raw.length))
    });
  }

  if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'No se encontró ninguna lectura de cuerpo/archivo sin tope de tamaño, ni ninguna reserva de memoria o bucle sin límite dependiendo de una entrada externa.', snippet: null });
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + lecturaSinLimite.length + ' lectura(s) de cuerpo/archivo sin tope de tamaño y ' + reservaSinTope.length + ' reserva(s)/bucle(s) sin tope dependiendo de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkUnboundedAllocationRisk: checkUnboundedAllocationRisk,
  findBodyParserSinLimite: findBodyParserSinLimite,
  findStreamSinLimite: findStreamSinLimite,
  findLecturaArchivoSinLimite: findLecturaArchivoSinLimite,
  findAllocSinTope: findAllocSinTope,
  findBucleSinTope: findBucleSinTope,
  bucket: bucket
};
