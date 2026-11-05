"use strict";
// Escudo de Confusión de Audiencia OAuth — detector de validación de "aud" rota
// ================================================================================
// Problema real: un servidor que verifica un JWT/token OAuth pero cuya
// validación del claim "audience"/"aud" (el campo que dice PARA QUIÉN se
// emitió el token) está rota de una forma más sutil que "no existe en
// absoluto": existe en el código, pero (a) un bloque catch() silencia el
// error que lanza la librería cuando la audiencia no coincide y deja pasar
// la petición igual, (b) la comparación de audiencia SÍ falla, pero su rama
// de "no coincide" solo loguea una advertencia en vez de rechazar la
// petición (throw/return/res.status), o (c) todo el chequeo de audiencia
// está condicionado a una bandera de configuración (config.checkAudience,
// options.strictMode, etc.) que puede estar desactivada — en los tres casos
// el código "tiene" una validación de audiencia que un lector apurado
// asumiría que funciona, pero que en la práctica deja pasar un token emitido
// para OTRO servidor/cliente (confused deputy vía audiencia).
//
// Esto es DISTINTO del chequeo que ya hace detect_token_passthrough_risk: esa
// herramienta solo mira si la palabra "audience"/"aud" aparece en absoluto
// cerca de un jwt.verify()/jwt.decode() (una señal de warn, superficial).
// Esta herramienta mira el VERIFICADOR PROPIO del servidor con más
// profundidad — si la validación de audiencia que SÍ existe realmente
// bloquea la petición cuando no coincide, o si fue escrita de una forma que
// falla en modo abierto (fail-open).
//
// Motivado por CVE-2026-14541 (confusión de audiencia OAuth en MCP): la
// validación de audiencia del propio verificador de tokens del servidor
// aceptaba, bajo ciertas condiciones, un token que no estaba destinado a ese
// servidor — exactamente el patrón de "validación condicional/fail-open" que
// cubre esta herramienta, distinto del simple olvido total de validar "aud".
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO del
// verificador de tokens (no ejecuta nada) — mismo enfoque y mismas
// limitaciones que lib/token-passthrough.js y lib/missing-auth.js: no
// reemplaza un analizador de sintaxis (AST) real ni una auditoría de
// seguridad formal.

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

// Llamadas que verifican/decodifican un JWT — el verificador propio del
// servidor, no un reenvío (eso lo cubre lib/token-passthrough.js).
var JWT_CALL = /\bjwt\.(?:verify|decode)\s*\(/g;
var AUD_MENTION = /\baud(?:ience)?\b/gi;

// Señales de que, a partir de ese punto, se rechaza realmente la petición
// (en vez de solo registrar y seguir).
var ENFORCEMENT_SIGNAL = /\bthrow\b|\breturn\b|res\.(?:status|json)\s*\(|\bprocess\.exit\s*\(|\breject\s*\(/;

// Una bandera de configuración/feature-flag típica — si el chequeo de
// audiencia vive DENTRO de un if gateado por una de estas palabras, el
// chequeo puede estar simplemente apagado según la config.
var FLAG_CONDITION = /\bif\s*\([^()]*\b(?:config|options?|flag|enable\w*|strict\w*|debug|skip\w*|settings)\w*[^()]*\)\s*\{/gi;

function estaAnidadoEnFlag(text, matchIndex) {
  var windowStart = Math.max(0, matchIndex - 300);
  var before = text.slice(windowStart, matchIndex);
  var re = new RegExp(FLAG_CONDITION.source, FLAG_CONDITION.flags);
  var m, last = null;
  while ((m = re.exec(before))) {
    last = m;
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  if (!last) return false;
  var afterOpenBrace = before.slice(last.index + last[0].length);
  return !/\}/.test(afterOpenBrace); // esa llave no se cerró antes de llegar al chequeo de audiencia -> sigue anidado adentro
}

function bloqueSinEnforcement(text, openBraceIdx) {
  if (openBraceIdx === -1) return null; // no se encontró el bloque -> no se puede confirmar, no se marca por precaución de falso positivo
  var closeIdx = findMatchingBrace(text, openBraceIdx);
  if (closeIdx === -1) return null;
  var body = text.slice(openBraceIdx + 1, closeIdx);
  return !ENFORCEMENT_SIGNAL.test(body);
}

// Comparación de audiencia que SÍ falla explícitamente: "...aud... !== ..."
// o "... !== ...aud...". Busca el '{' del bloque "si no coincide" que le
// sigue (dentro de los próximos 60 caracteres) para revisar si ese bloque
// realmente rechaza la petición.
var AUD_MISMATCH = /\baud(?:ience)?\b[^\n;{}]{0,40}(?:!==|!=)|(?:!==|!=)[^\n;{}]{0,40}\baud(?:ience)?\b/gi;

function findFailOpenPorComparacion(text) {
  var out = [];
  var re = new RegExp(AUD_MISMATCH.source, AUD_MISMATCH.flags);
  var m;
  while ((m = re.exec(text))) {
    var afterEnd = m.index + m[0].length;
    var braceWindow = text.slice(afterEnd, afterEnd + 60);
    var braceRelIdx = braceWindow.indexOf('{');
    var openBraceIdx = braceRelIdx === -1 ? -1 : afterEnd + braceRelIdx;
    var sinEnforcement = bloqueSinEnforcement(text, openBraceIdx);
    var anidadoEnFlag = estaAnidadoEnFlag(text, m.index);
    if (sinEnforcement === true || anidadoEnFlag) {
      out.push({
        index: m.index,
        raw: m[0],
        tipo: anidadoEnFlag ? 'condicional' : 'warn_only'
      });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// try { ...jwt.verify con audience... } catch (e) { /* sin throw/return/res.status -> silencia el rechazo */ }
var TRY_OPEN = /\btry\s*\{/g;
var CATCH_OPEN = /\}\s*catch\s*(?:\([^)]*\))?\s*\{/;

function findFailOpenPorCatch(text) {
  var out = [];
  var re = new RegExp(TRY_OPEN.source, TRY_OPEN.flags);
  var m;
  while ((m = re.exec(text))) {
    var openBrace = m.index + m[0].length - 1;
    var closeBrace = findMatchingBrace(text, openBrace);
    if (closeBrace === -1) { if (m.index === re.lastIndex) re.lastIndex++; continue; }
    var tryBody = text.slice(openBrace + 1, closeBrace);
    var tieneJwt = new RegExp(JWT_CALL.source, JWT_CALL.flags).test(tryBody);
    var tieneAud = new RegExp(AUD_MENTION.source, AUD_MENTION.flags).test(tryBody);
    if (tieneJwt && tieneAud) {
      var afterTry = text.slice(closeBrace, Math.min(text.length, closeBrace + 60));
      var catchMatch = CATCH_OPEN.exec(afterTry);
      if (catchMatch) {
        var catchOpenBrace = closeBrace + catchMatch.index + catchMatch[0].length - 1;
        var sinEnforcement = bloqueSinEnforcement(text, catchOpenBrace);
        if (sinEnforcement === true) {
          out.push({ index: m.index, raw: 'try { … jwt.verify/decode con audience … } catch (e) { … }' });
        }
      }
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function findAusenciaTotal(text) {
  var out = [];
  var re = new RegExp(JWT_CALL.source, JWT_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var windowEnd = Math.min(text.length, m.index + 260);
    var win = text.slice(m.index, windowEnd);
    var cut = win.search(/;\s*\n\s*\n|\n\s*\n/);
    var scoped = cut === -1 ? win : win.slice(0, cut);
    if (!new RegExp(AUD_MENTION.source, AUD_MENTION.flags).test(scoped)) {
      out.push({ index: m.index, raw: m[0] });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkOAuthAudienceConfusionRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente del verificador de tokens OAuth/JWT del servidor) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var failOpenComparacion = findFailOpenPorComparacion(text);
  var failOpenCatch = findFailOpenPorCatch(text);
  var condicional = failOpenComparacion.filter(function (f) { return f.tipo === 'condicional'; });
  var warnOnly = failOpenComparacion.filter(function (f) { return f.tipo === 'warn_only'; });

  if (condicional.length > 0) {
    deduction += 55 + Math.min(20, (condicional.length - 1) * 10);
    findings.push({
      sev: 'critical',
      label: 'La validación del claim "audience"/"aud" está condicionada a una bandera de configuración (config/options/flag/strict/debug) — si esa bandera no está activa, el token se acepta sin validar para quién fue emitido. El mismo patrón de "validación condicional" detrás de CVE-2026-14541',
      snippet: contextSnippet(text, condicional[0].index, condicional[0].raw.length)
    });
  }

  if (warnOnly.length > 0) {
    deduction += 55 + Math.min(20, (warnOnly.length - 1) * 10);
    findings.push({
      sev: 'critical',
      label: 'La comparación de audiencia SÍ detecta que no coincide, pero su rama de "no coincide" no rechaza la petición (no hay throw/return/res.status) — solo registra la discrepancia y sigue, dejando pasar un token emitido para otro servidor (fail-open)',
      snippet: contextSnippet(text, warnOnly[0].index, warnOnly[0].raw.length)
    });
  }

  if (failOpenCatch.length > 0) {
    deduction += 55 + Math.min(20, (failOpenCatch.length - 1) * 10);
    findings.push({
      sev: 'critical',
      label: 'Un bloque catch() silencia el error que lanza la verificación de audiencia (jwt.verify con la opción "audience", o una comparación manual dentro del try) sin rechazar la petición — el token se termina aceptando igual aunque la librería ya haya detectado que la audiencia no coincide (fail-open vía catch)',
      snippet: null
    });
  }

  var ausenciaTotal = findAusenciaTotal(text);
  if (ausenciaTotal.length > 0 && condicional.length === 0 && warnOnly.length === 0 && failOpenCatch.length === 0) {
    deduction += 55 + Math.min(20, (ausenciaTotal.length - 1) * 10);
    findings.push({
      sev: 'critical',
      label: 'El verificador de tokens propio del servidor (jwt.verify/jwt.decode) no valida el claim "audience"/"aud" en ninguna parte cerca de la llamada — nada distingue un token emitido para este servidor de uno emitido para cualquier otro destinatario',
      snippet: contextSnippet(text, ausenciaTotal[0].index, ausenciaTotal[0].raw.length)
    });
  }

  if (findings.length === 0) {
    var huboVerificador = new RegExp(JWT_CALL.source, JWT_CALL.flags).test(text);
    if (!huboVerificador) {
      findings.push({ sev: 'ok', label: 'No se encontró ningún verificador de tokens (jwt.verify/jwt.decode) en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontró verificación de tokens con validación de audiencia presente, incondicional, y que rechaza correctamente la petición cuando no coincide.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + condicional.length + ' validación(es) de audiencia condicionada(s) a una bandera de configuración, ' + warnOnly.length + ' que no rechazan la petición al no coincidir, ' + failOpenCatch.length + ' silenciada(s) por un catch(), y ' + (condicional.length === 0 && warnOnly.length === 0 && failOpenCatch.length === 0 ? ausenciaTotal.length : 0) + ' verificador(es) sin ningún chequeo de audiencia.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkOAuthAudienceConfusionRisk: checkOAuthAudienceConfusionRisk,
  findFailOpenPorComparacion: findFailOpenPorComparacion,
  findFailOpenPorCatch: findFailOpenPorCatch,
  findAusenciaTotal: findAusenciaTotal,
  bucket: bucket
};
