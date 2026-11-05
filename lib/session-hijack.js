"use strict";
// Escudo de Secuestro de Sesión — detector de sesiones validadas solo por ID
// ================================================================================
// Problema real: un servidor/herramienta que busca una sesión SOLO por el ID
// que trae la petición ("sessions[sessionId]", "sessionStore.get(sessionId)")
// y después confía en esa sesión sin comparar NINGÚN campo suyo (dueño,
// principal, cuenta) contra quien está haciendo la petición en este momento,
// es vulnerable a secuestro de sesión: quien consiga ese ID — adivinándolo,
// robándolo de un log, de una URL compartida, o interceptándolo — queda
// autenticado como el dueño real de la sesión, sin que el servidor note nada
// raro. Esto es distinto de "falta de autenticación" (detect_missing_auth_risk,
// CWE-306): ahí no se verifica NADA; aquí SÍ hay una sesión y SÍ se la busca,
// pero la búsqueda por ID no es, por sí sola, una prueba de que quien la
// presenta es su dueño legítimo (CWE-384, "Session Fixation" / secuestro de
// sesión por falta de vínculo con el principal).
//
// Motivado por CVE-2026-52869 (CVSS alto): un servidor MCP resolvía sesiones
// de un cliente SOLO por el identificador de sesión recibido en la petición,
// sin ningún vínculo adicional con el token/identidad de quien la presentaba
// — cualquiera que obtuviera (o adivinara) un ID de sesión válido heredaba
// por completo el contexto de otro cliente ya autenticado.
//
// Regla secundaria, documentada en la misma CVE: el ID de sesión generado con
// poca entropía (Math.random(), un contador, o solo Date.now()) es
// adivinable/predecible por fuerza bruta incluso si después SÍ se valida
// correctamente contra el dueño — la propia superficie de ataque (adivinar un
// ID válido) depende de qué tan aleatorio sea ese ID.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO que busca o
// genera sesiones (no ejecuta nada) — mismo enfoque y mismas limitaciones que
// lib/missing-auth.js y lib/token-passthrough.js: no reemplaza un analizador
// de sintaxis (AST) real ni una auditoría de seguridad formal. Límite
// conocido: si el vínculo de dueño/principal se verifica en una función
// aparte definida lejos de la búsqueda, o el nombre de esa función no usa
// ninguna palabra reconocible, puede no detectarse como vínculo real.

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

// Búsqueda de una sesión indexada/consultada SOLO por un identificador: un
// objeto/variable cuyo nombre contiene "session" (store, map, objeto, etc.)
// accedido con [id]/.get(id)/.findOne({...id...}) donde "id" es una variable
// (no un literal) cuyo nombre sugiere que es el identificador que trajo la
// petición (sessionId, session_id, sid, token).
var SESSION_LOOKUP = /\b(\w*[Ss]essions?\w*)\s*(?:\[\s*([\w.]+)\s*\]|\.\s*get\s*\(\s*([\w.]+)\s*\)|\.\s*findOne\s*\(\s*\{[^}]*?(\w*(?:[Ss]ession)?[Ii]d|sid|token)\s*:\s*([\w.]+)[^}]*?\}\s*\))/g;

// Señal de que, después de obtener la sesión, SÍ se compara algún campo de
// dueño/principal contra la identidad de quien hace la petición ahora mismo
// — no se exige que la comparación sea perfecta, solo que exista una señal
// reconocible de que el código intentó vincular la sesión a un dueño.
var BINDING_CHECK = /\b(?:userId|user_id|ownerId|owner_id|accountId|account_id|principal|owner)\b[^\n;]{0,50}(?:===|!==|==|!=)|(?:===|!==|==|!=)[^\n;]{0,50}\b(?:userId|user_id|ownerId|owner_id|accountId|account_id|principal|owner)\b/;

// El propio identificador es en realidad un token criptográficamente firmado
// y verificado (jwt.verify, HMAC con comparación en tiempo constante) — ahí
// la validez del token YA demuestra quién es el dueño, sin necesitar una
// comparación de campo aparte.
var TOKEN_FIRMADO_VERIFICADO = /\bjwt\.verify\s*\(|crypto\.timingSafeEqual\s*\(|\.compareSync\s*\(|constantTimeCompare\s*\(/i;

function findSessionLookups(text) {
  var out = [];
  var re = new RegExp(SESSION_LOOKUP.source, SESSION_LOOKUP.flags);
  var m;
  while ((m = re.exec(text))) {
    // "sessions[id] = {...}" es CREAR una sesión nueva (escritura), no leer
    // una existente para confiar en ella — no hace falta ningún vínculo de
    // dueño todavía en ese momento, así que no se cuenta como lookup riesgoso.
    var after = text.slice(re.lastIndex).replace(/^\s+/, '');
    var esEscritura = after[0] === '=' && after[1] !== '=';
    if (!esEscritura) {
      out.push({ index: m.index, raw: m[0] });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

function findSinVinculo(text) {
  var lookups = findSessionLookups(text);
  var out = [];
  lookups.forEach(function (l) {
    var windowStart = l.index + l.raw.length;
    var windowEnd = Math.min(text.length, windowStart + 500);
    var win = text.slice(windowStart, windowEnd);
    if (!BINDING_CHECK.test(win) && !TOKEN_FIRMADO_VERIFICADO.test(win)) {
      out.push({ index: l.index, raw: l.raw, snippet: contextSnippet(text, l.index, l.raw.length) });
    }
  });
  return out;
}

// Generación de un identificador de sesión con poca entropía: Math.random(),
// solo Date.now()/time.time() (sin ningún componente aleatorio criptográfico
// mezclado), o un contador incremental — todos predecibles/adivinables por
// fuerza bruta en un tiempo razonable.
var WEAK_ID_GEN = /\b(\w*(?:session|sid)\w*(?:Id|_id)?)\s*=\s*(?:Math\.random\s*\(\)(?:\.toString\([^)]*\))?|(?:["'`][^"'`]*["'`]\s*\+\s*)?Date\.now\s*\(\)(?:\.toString\(\))?(?:\s*\+\s*["'`][^"'`]*["'`])?|\+\+\w*[Cc]ount\w*|\w*[Cc]ount\w*\+\+|uuid\.v1\s*\(\)|time\.time\s*\(\))/gi;

// Mitigaciones reales: un generador criptográficamente seguro.
var STRONG_ID_GEN = /crypto\.randomBytes\s*\(|crypto\.randomUUID\s*\(|secrets\.token_hex\s*\(|secrets\.token_urlsafe\s*\(|uuid\.v4\s*\(|os\.urandom\s*\(/i;

function findWeakIdGen(text) {
  var out = [];
  var re = new RegExp(WEAK_ID_GEN.source, WEAK_ID_GEN.flags);
  var m;
  while ((m = re.exec(text))) {
    out.push({ index: m.index, raw: m[0], varName: m[1] });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkSessionHijackRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente que busca o genera sesiones) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var lookups = findSessionLookups(text);
  var sinVinculo = findSinVinculo(text);

  if (sinVinculo.length > 0) {
    var ded1 = 55 + Math.min(20, (sinVinculo.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'La sesión se busca SOLO por el identificador que trae la petición (sessions[id]/.get(id)/.findOne({id})), sin comparar después ningún campo de dueño/principal (userId/owner/accountId) contra quien hace la petición ahora — quien consiga ese ID (adivinándolo, robándolo de un log o interceptándolo) hereda la sesión de otro cliente por completo. El mismo patrón detrás de CVE-2026-52869',
      snippet: sinVinculo[0].snippet
    });
  }

  var weakGen = findWeakIdGen(text);
  var weakGenSinMitigar = weakGen.filter(function (g) {
    var contexto = text.slice(Math.max(0, g.index - 200), Math.min(text.length, g.index + 200));
    return !STRONG_ID_GEN.test(contexto);
  });
  if (weakGenSinMitigar.length > 0) {
    var ded2 = 45 + Math.min(20, (weakGenSinMitigar.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'critical',
      label: 'El identificador de sesión se genera con poca entropía (Math.random(), Date.now()/time.time() solo, o un contador incremental) en vez de un generador criptográficamente seguro (crypto.randomBytes/randomUUID, secrets.token_hex/token_urlsafe) — un ID así es adivinable/forzable por fuerza bruta, documentado como regla secundaria en CVE-2026-52869',
      snippet: contextSnippet(text, weakGenSinMitigar[0].index, weakGenSinMitigar[0].raw.length)
    });
  }

  if (findings.length === 0) {
    if (lookups.length === 0 && weakGen.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna búsqueda de sesión por ID sin vínculo de dueño, ni ninguna generación de ID de sesión con poca entropía.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron búsquedas/generaciones de sesión, pero todas verifican un vínculo con el dueño o usan un generador de IDs criptográficamente seguro.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + lookups.length + ' búsqueda(s) de sesión por ID (' + sinVinculo.length + ' sin vínculo de dueño confirmado) y ' + weakGen.length + ' generación(es) de ID de sesión (' + weakGenSinMitigar.length + ' con poca entropía sin mitigar).',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkSessionHijackRisk: checkSessionHijackRisk,
  findSessionLookups: findSessionLookups,
  findSinVinculo: findSinVinculo,
  findWeakIdGen: findWeakIdGen,
  bucket: bucket
};
