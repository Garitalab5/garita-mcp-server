"use strict";
// Detector de riesgo de "token passthrough" (reenvío de tokens OAuth / confused deputy)
// ================================================================================
// Problema real: un servidor o middleware MCP recibe un token de autorización de
// quien lo llama y, en vez de validarlo y emitir uno propio, lo REENVÍA tal cual
// hacia otra API — o deja pasar la petición sin validar el token en absoluto. El
// resultado es el clásico "confused deputy": el servidor actúa con la autoridad
// de un token que nunca debió aceptar ni reenviar, o filtra credenciales de larga
// duración a quien haga la petición.
//
// La especificación oficial de MCP lo nombra como antipatrón explícitamente
// prohibido: un servidor "MUST NOT accept any tokens that were not explicitly
// issued for the MCP server" (modelcontextprotocol.io, Security Best Practices).
// No es hipotético — es el patrón exacto detrás de CVE-2026-48039 (Meta Ads MCP,
// CVSS 9.1 CRÍTICO): un middleware `dispatch()` llama a `call_next(request)` sin
// verificar el header de autorización, y el token de larga duración del operador
// termina filtrado en las URLs de las respuestas de error a quien haga la
// petición, sin autenticarse. El mismo patrón aparece en CVE-2025-6514
// (mcp-remote, CVSS 9.6) y CVE-2026-27826 (MCP Atlassian, CVSS 8.2).
//
// Esto es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta o middleware (no ejecuta nada) — mismo enfoque y mismas
// limitaciones que lib/ssrf.js, lib/traversal.js, lib/command-injection.js y
// lib/sql-injection.js: no reemplaza un analizador de sintaxis (AST) real ni una
// auditoría de seguridad formal.

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

// Llamadas que dejan pasar una petición dentro de un middleware (Express/Koa:
// next(); Starlette/FastAPI: call_next(request)).
var NEXT_CALL = /\b(?:next|call_next)\s*\(\s*(?:req(?:uest)?)?\s*\)/g;

// Señal de que hubo algún tipo de verificación de autorización/autenticación
// antes de dejar pasar la petición (no se exige que sea correcta, solo que
// exista una señal reconocible de que el código intentó comprobar algo).
var AUTH_CHECK = /\b(?:authoriz|authenticate|autentic|autoriz)\w*|\bverify\w*|\bvalidate\w*|\bunauthorized\b|\b401\b|\b403\b|\brequire_?auth\w*|\bcheck_?auth\w*|\bget_?user\w*/i;

// El header Authorization de la petición ENTRANTE, reenviado tal cual dentro de
// otra construcción de headers (por ejemplo, dentro de la config de una llamada
// saliente con fetch/axios/requests/httpx a otra API).
var DIRECT_FORWARD = /Authorization["'\]]*\s*[:=]\s*(?:req|request)\.headers(?:\.get\(\s*['"]authorization['"]\s*\)|\[['"]authorization['"]\]|\.authorization)/gi;

// El token entrante se guarda primero en una variable...
var HEADER_CAPTURE = /\b(?:const|let|var)\s+(\w+)\s*=\s*(?:req|request)\.headers(?:\.get\(\s*['"]authorization['"]\s*\)|\[['"]authorization['"]\]|\.authorization)|\b(\w+)\s*=\s*request\.headers(?:\.get\(\s*["']Authorization["']\s*(?:,\s*[^)]*)?\)|\[["']Authorization["']\])/g;

// ...y si aparece de nuevo como el Authorization de una llamada saliente sin que
// antes se haya reemitido/intercambiado el token, es el mismo patrón de reenvío.
var REEMISION = /\b(?:exchange_?token|mint_?token|issue_?token|refresh_?token|create_?token|generate_?token|jwt\.sign)\s*\(/i;

// jwt.verify()/jwt.decode() sin validar el claim "audience"/"aud" — el servidor
// acepta un token emitido para OTRO destinatario, la raíz técnica del "confused
// deputy": nada distingue un token válido para este servidor de uno válido para
// cualquier otro.
var JWT_CALL = /\bjwt\.(?:verify|decode)\s*\(/gi;
var AUDIENCE_CHECK = /audience|(?:^|[^a-zA-Z_])aud\s*[:=]/i;

// Un token colocado como parámetro de una URL en vez de en un header — queda
// expuesto en logs de acceso, historial del navegador y cabeceras Referer.
var TOKEN_IN_URL = /[?&](?:access_token|token|api_key|auth_token)=(?:\$\{|["']\s*\+|\{[a-zA-Z_])/gi;

function findOperaciones(text) {
  var ops = [];
  var seen = {};
  var m;

  var reNext = new RegExp(NEXT_CALL.source, NEXT_CALL.flags);
  while ((m = reNext.exec(text))) {
    var before = text.slice(Math.max(0, m.index - 400), m.index);
    if (/\breq(?:uest)?\b/i.test(before) && !AUTH_CHECK.test(before)) {
      var keyMw = 'mw:' + m.index;
      if (!seen[keyMw]) {
        seen[keyMw] = true;
        ops.push({ tipo: 'middleware', index: m.index, callText: m[0], snippet: contextSnippet(text, m.index, m[0].length) });
      }
    }
    if (m.index === reNext.lastIndex) reNext.lastIndex++;
  }

  var reDirect = new RegExp(DIRECT_FORWARD.source, DIRECT_FORWARD.flags);
  while ((m = reDirect.exec(text))) {
    var keyDf = 'df:' + m.index;
    if (!seen[keyDf]) {
      seen[keyDf] = true;
      ops.push({ tipo: 'reenvio', index: m.index, callText: m[0], snippet: contextSnippet(text, m.index, m[0].length) });
    }
    if (m.index === reDirect.lastIndex) reDirect.lastIndex++;
  }

  var reCapture = new RegExp(HEADER_CAPTURE.source, HEADER_CAPTURE.flags);
  var c;
  while ((c = reCapture.exec(text))) {
    var varName = c[1] || c[2];
    if (varName) {
      var afterStart = c.index + c[0].length;
      var windowEnd = Math.min(text.length, afterStart + 600);
      var win = text.slice(afterStart, windowEnd);
      // Alias directo: "const/let/var NUEVO_NOMBRE = NOMBRE_YA_RASTREADO;" — un
      // solo nivel de asignación directa entre identificadores (sin llamada de
      // función en el medio) alcanza para no perder el rastro del token cuando
      // se reasigna a otra variable antes de reenviarlo.
      var trackedNames = [varName];
      var aliasRe = new RegExp('\\b(?:const|let|var)\\s+(\\w+)\\s*=\\s*' + varName + '\\s*;');
      var aliasMatch = aliasRe.exec(win);
      if (aliasMatch && aliasMatch[1]) {
        trackedNames.push(aliasMatch[1]);
      }
      var namesPattern = trackedNames.join('|');
      var reuseRe = new RegExp(
        'Authorization["\'\\]]*\\s*[:=]\\s*(?:`Bearer\\s*\\$\\{\\s*(?:' + namesPattern + ')\\s*\\}`|(?:' + namesPattern + ')\\b|["\']Bearer["\']\\s*\\+\\s*(?:' + namesPattern + ')\\b)'
      );
      var reuseMatch = reuseRe.exec(win);
      if (reuseMatch) {
        var between = win.slice(0, reuseMatch.index);
        if (!REEMISION.test(between)) {
          var idx = afterStart + reuseMatch.index;
          var keyVf = 'vf:' + idx;
          if (!seen[keyVf]) {
            seen[keyVf] = true;
            ops.push({ tipo: 'reenvio', index: idx, callText: reuseMatch[0], snippet: contextSnippet(text, idx, reuseMatch[0].length) });
          }
        }
      }
    }
    if (c.index === reCapture.lastIndex) reCapture.lastIndex++;
  }

  ops.sort(function (a, b) { return a.index - b.index; });
  return ops;
}

// jwt.decode() (a diferencia de jwt.verify()) NUNCA valida firma ni ningún
// claim — la librería real ignora por completo cualquier opción que se le
// pase, incluida "audience". Si se usa sobre el token de la petición entrante
// y no hay también un jwt.verify() sobre ese mismo código, el token se está
// aceptando sin ninguna verificación real, sin importar qué opciones se le
// pasen a decode().
var JWT_DECODE_CALL = /\bjwt\.decode\s*\(/gi;
var JWT_VERIFY_CALL = /\bjwt\.verify\s*\(/i;

function findJwtDecodeSinVerify(text) {
  var out = [];
  if (JWT_VERIFY_CALL.test(text)) return out; // hay jwt.verify() en el código -> no marcamos decode() como crítico

  var capturedNames = [];
  var reCap = new RegExp(HEADER_CAPTURE.source, HEADER_CAPTURE.flags);
  var cm;
  while ((cm = reCap.exec(text))) {
    var vn = cm[1] || cm[2];
    if (vn) capturedNames.push(vn);
    if (cm.index === reCap.lastIndex) reCap.lastIndex++;
  }

  var re = new RegExp(JWT_DECODE_CALL.source, JWT_DECODE_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var argWindow = text.slice(m.index + m[0].length, m.index + m[0].length + 80);
    var esTokenEntrante = /(?:req|request)\.headers(?:\.get\(\s*['"]authorization['"]\s*\)|\[['"]authorization['"]\]|\.authorization)/i.test(argWindow) ||
      capturedNames.some(function (n) { return new RegExp('\\b' + n + '\\b').test(argWindow); });
    if (esTokenEntrante) {
      out.push({ index: m.index, callText: m[0], snippet: contextSnippet(text, m.index, m[0].length) });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function findJwtSinAudiencia(text) {
  var out = [];
  var re = new RegExp(JWT_CALL.source, JWT_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var windowEnd = Math.min(text.length, m.index + 220);
    var win = text.slice(m.index, windowEnd);
    var cut = win.search(/;\s*\n|\n\s*\n/);
    var scoped = cut === -1 ? win : win.slice(0, cut);
    if (!AUDIENCE_CHECK.test(scoped)) {
      out.push({ index: m.index, callText: m[0], snippet: contextSnippet(text, m.index, m[0].length) });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function findTokenEnUrl(text) {
  var out = [];
  var re = new RegExp(TOKEN_IN_URL.source, TOKEN_IN_URL.flags);
  var m;
  while ((m = re.exec(text))) {
    out.push({ index: m.index, callText: m[0], snippet: contextSnippet(text, m.index, m[0].length) });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkTokenPassthroughRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente del middleware/herramienta que maneja el token de autorización) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var ops = findOperaciones(text);
  var middlewareOps = ops.filter(function (o) { return o.tipo === 'middleware'; });
  var reenvioOps = ops.filter(function (o) { return o.tipo === 'reenvio'; });

  if (ops.length > 0) {
    var ded1 = 55 + Math.min(20, (ops.length - 1) * 10);
    deduction += ded1;
    if (middlewareOps.length > 0) {
      findings.push({
        sev: 'critical',
        label: 'El middleware deja pasar la petición (next()/call_next()) sin ninguna verificación de autorización reconocible antes — el mismo patrón detrás de CVE-2026-48039 (Meta Ads MCP, CVSS 9.1)',
        snippet: middlewareOps[0].snippet
      });
    }
    if (reenvioOps.length > 0) {
      findings.push({
        sev: 'critical',
        label: 'El token de autorización que llega en la petición entrante se reenvía tal cual hacia otra llamada saliente, sin revalidarlo ni reemitir uno propio (token passthrough / confused deputy) — la especificación de MCP prohíbe explícitamente aceptar o reenviar tokens no emitidos para este servidor',
        snippet: reenvioOps[0].snippet
      });
    }
  }

  var decodeIssues = findJwtDecodeSinVerify(text);
  if (decodeIssues.length > 0) {
    deduction += 55;
    findings.push({
      sev: 'critical',
      label: 'jwt.decode() usado sobre el token de la petición entrante sin que exista también un jwt.verify() en el código analizado — jwt.decode() NUNCA valida la firma ni ningún claim (incluida "audience"), aunque se le pase esa opción; el token se acepta sin ninguna verificación real',
      snippet: decodeIssues[0].snippet
    });
  }

  var jwtIssues = findJwtSinAudiencia(text);
  if (jwtIssues.length > 0) {
    deduction += 30;
    findings.push({
      sev: 'warn',
      label: 'Verificación de JWT (jwt.verify/jwt.decode) sin validar el claim "audience" (aud) — nada distingue un token emitido para este servidor de uno emitido para otro destinatario',
      snippet: jwtIssues[0].snippet
    });
  }

  var urlIssues = findTokenEnUrl(text);
  if (urlIssues.length > 0) {
    deduction += 25;
    findings.push({
      sev: 'warn',
      label: 'Un token se coloca como parámetro de una URL en vez de en un header — queda expuesto en logs de acceso, historial y cabeceras Referer',
      snippet: urlIssues[0].snippet
    });
  }

  if (findings.length === 0) {
    if (ops.length === 0 && decodeIssues.length === 0 && jwtIssues.length === 0 && urlIssues.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ningún reenvío de tokens sin validar, ni jwt.decode() sin verify(), ni verificación de JWT sin "audience", ni tokens expuestos en una URL.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + ops.length + ' señal(es) de reenvío de token sin validar, ' + decodeIssues.length + ' uso(s) de jwt.decode() sin verify(), ' + jwtIssues.length + ' verificación(es) de JWT sin "audience", y ' + urlIssues.length + ' token(s) expuesto(s) en una URL.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkTokenPassthroughRisk: checkTokenPassthroughRisk,
  findOperaciones: findOperaciones,
  findJwtSinAudiencia: findJwtSinAudiencia,
  findJwtDecodeSinVerify: findJwtDecodeSinVerify,
  findTokenEnUrl: findTokenEnUrl,
  bucket: bucket
};
