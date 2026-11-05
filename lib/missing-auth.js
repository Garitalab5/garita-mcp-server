"use strict";
// Centinela de Autenticación — detector de endpoints MCP sin verificación de autenticación
// ================================================================================
// Problema real: un servidor MCP que expone su transporte HTTP o SSE (el
// endpoint por el que un cliente MCP le habla por JSON-RPC — "/mcp", "/sse",
// "/messages") y despacha directamente la lógica de sus herramientas sin
// pasar antes por ninguna verificación de autenticación deja esas
// herramientas abiertas a CUALQUIER llamador que sepa la URL — sin login,
// sin llave de API, sin token. Esto es distinto de validar el header Origin
// (lib/dns-rebinding.js, herramienta 19): ahí el problema es DE DÓNDE viene
// la petición; aquí el problema es que no se verifica QUIÉN la hace, punto.
//
// No es un caso aislado — es el patrón MÁS repetido entre los CVEs de MCP de
// 2026, encontrado de forma independiente en servidores muy distintos:
//
//   - CVE-2026-44895 (CVSS 9.1, crítico) en @yoda.digital/gitlab-mcp-server:
//     el transporte SSE no verificaba autenticación en ningún code path
//     ("/sse", "/messages") y además respondía con
//     "Access-Control-Allow-Origin: *", permitiendo a cualquier llamador no
//     autenticado invocar las 86 herramientas de GitLab del servidor —
//     incluido borrar repositorios — usando el token de acceso personal
//     (PAT) del operador.
//   - CVE-2026-32211 en Azure MCP Server (Microsoft): exposición de
//     información por falta de autenticación.
//   - El mismo patrón (CWE-306) confirmado también en deepseek-mcp-server
//     (CVE-2026-55605), NetLicensing-MCP (CVE-2026-54446), obsidian-web-mcp
//     (CVE-2026-54618) y mcp-documentation-server (CVE-2026-54504) — todos
//     de 2026.
//
// Regla propia de Garita: cuando además de faltar la autenticación el
// código deja el CORS completamente abierto ("Access-Control-Allow-Origin:
// *", o un middleware cors() sin restringir origen), el riesgo es
// estrictamente peor — es exactamente la combinación que hizo explotable a
// CVE-2026-44895 desde cualquier página web, no solo desde otro proceso
// local.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO que arma el
// transporte HTTP/SSE del servidor MCP (no ejecuta nada, no abre ningún
// puerto) — mismo enfoque y mismas limitaciones que lib/dns-rebinding.js y
// lib/command-injection.js: no reemplaza un analizador de sintaxis (AST)
// real ni una auditoría de seguridad formal. Límite conocido: si la
// verificación de autenticación vive en un middleware definido lejos (en
// otro archivo) y aquí solo se ve el nombre de una función genérica sin
// palabras reconocibles ("mw1", "chequeo"), puede no reconocerse como
// autenticación real. Sub-caso del mismo límite: la ventana de contexto
// alrededor de cada sink es de ±800/400 caracteres — si el middleware de
// auth SÍ está en el mismo archivo pero registrado mucho más lejos de esa
// ventana (ej. al principio de un archivo largo, con cientos de líneas de
// código entre medio y el registro de la ruta), tampoco se reconoce.

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

// Configuración/arranque de un transporte HTTP o SSE de MCP, o el registro
// de sus rutas típicas ("/mcp", "/sse", "/messages") en Express, Flask o
// FastAPI — el punto exacto donde entra una petición JSON-RPC de un cliente.
// `app\s*\.\s*` (en vez de `app\.` pegado) tolera un salto de línea/espacios
// entre "app" y el punto, y entre el punto y el método (estilo de lint real:
// `app\n  .post('/mcp', ...)`). También se reconoce el patrón de
// express.Router `app.route('/mcp').post(handler)`, que no queda cubierto
// por las alternativas "app.<método>(" de arriba porque el método va
// encadenado después de `.route(...)`, no pegado a `app.`.
var SINK_TRANSPORTE = /new\s+StreamableHTTPServerTransport\s*\(|new\s+SSEServerTransport\s*\(|app\s*\.\s*(?:post|get|all|use)\s*\(\s*['"`]\/(?:mcp|sse|messages)['"`]|@app\.(?:route|post|get)\s*\(\s*['"`]\/(?:mcp|sse|messages)['"`]|app\.route\s*\(\s*['"`]\/(?:mcp|sse|messages)['"`]\s*\)\s*\.\s*(?:post|get|all|use)\s*\(/g;

// Señal real de autenticación: el código lee el header Authorization (o lo
// compara contra "Bearer"), compara una llave de API, llama a una función
// reconocible de autenticación/licencia, o usa un middleware conocido
// (passport, jwt.verify).
//
// OJO: a propósito NO incluye una alternativa genérica suelta del estilo
// `Authorization['"]?\s*[:=]` — eso confundía la LECTURA del header
// Authorization de la petición ENTRANTE (validación real) con la
// CONSTRUCCIÓN de un header Authorization para una llamada SALIENTE hacia
// otro servicio (ej. `{ Authorization: 'Bearer ' + process.env.UPSTREAM_TOKEN }`
// dentro de un fetch/HTTP a otra API) — el endpoint del propio servidor
// seguía sin autenticar a quien lo llama, pero el motor lo marcaba
// "Aceptable". Ese caso ahora se evalúa aparte, exigiendo que la ocurrencia
// de "Authorization"+separador esté precedida de cerca por `req.`/`request.`
// (ver hasLecturaAuthorizationEntrante más abajo).
var VALIDACION_AUTH = /(?:req|request)\.headers\.(?:get\(\s*['"]authorization['"]\s*\)|authorization|\[\s*['"]authorization['"]\s*\])|api[_-]?key\s*(?:===|!==|==|!=)|check(?:AndConsume|ApiKey|Auth|Token)\s*\(|authenticate\s*\(|requireAuth\s*\(|isAuthenticated\s*\(|jwt\.verify\s*\(|passport\.authenticate\s*\(|verify_?api_?key\s*\(|validar_?(?:llave|clave|token|auth)\s*\(/i;

// Dos patrones "ambiguos": la palabra "Bearer " y una ocurrencia suelta de
// "Authorization" seguida de ':' o '=' (una clave de objeto o una
// asignación). Ninguno de los dos alcanza por sí solo — ambos aparecen igual
// de naturalmente en una LECTURA/validación real del header ENTRANTE
// (`req.headers.authorization !== 'Bearer ' + KEY`) que en la CONSTRUCCIÓN
// de un objeto de headers para una petición SALIENTE hacia otro servicio
// (`{ Authorization: 'Bearer ' + process.env.UPSTREAM_TOKEN }` dentro de un
// fetch/HTTP a otra API) — en ese segundo caso el endpoint del propio
// servidor sigue sin autenticar a quien lo llama. Solo cuentan como señal de
// autenticación real si, mirando hacia atrás una ventana corta
// (~60 caracteres, sin cruzar '{'/'}'/';'/salto de línea), aparece
// `req.`/`request.` — es decir, si de verdad cuelgan de leer la petición
// entrante y no de armar un objeto de headers nuevo para llamar a otro
// servicio.
var PATRON_AMBIGUO_AUTH = /\bBearer\s|Authorization['"]?\s*[:=]/gi;
var REQ_JUSTO_ANTES = /(?:req|request)\.[^;{}\n]{0,60}$/i;

function hasLecturaAuthorizationEntrante(contexto) {
  var re = new RegExp(PATRON_AMBIGUO_AUTH.source, PATRON_AMBIGUO_AUTH.flags);
  var m;
  while ((m = re.exec(contexto))) {
    var before = contexto.slice(Math.max(0, m.index - 60), m.index);
    if (REQ_JUSTO_ANTES.test(before)) return true;
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return false;
}

// CORS completamente abierto: sin restricción de origen alguna. Combinado
// con falta de autenticación, es exactamente el patrón de CVE-2026-44895.
var CORS_ABIERTO = /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|\bcors\s*\(\s*\)|cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]/i;

function findOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(SINK_TRANSPORTE.source, SINK_TRANSPORTE.flags);
  var m;
  while ((m = re.exec(text))) {
    operaciones.push({ index: m.index, callText: m[0] });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkMissingAuthRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código que arma el transporte HTTP/SSE del servidor MCP, o registra sus rutas) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);

  var sinAuth = operaciones.filter(function (o) {
    var contextStart = Math.max(0, o.index - 800);
    var contextEnd = Math.min(text.length, o.index + o.callText.length + 400);
    var contexto = text.slice(contextStart, contextEnd);
    return !VALIDACION_AUTH.test(contexto) && !hasLecturaAuthorizationEntrante(contexto);
  });

  if (sinAuth.length > 0) {
    var ded1 = 55 + Math.min(20, (sinAuth.length - 1) * 10);
    deduction += ded1;
    sinAuth.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Transporte HTTP/SSE de MCP configurado sin ninguna verificación de autenticación reconocible antes de despachar la petición — cualquiera que sepa la URL puede invocar las herramientas del servidor sin llave de API ni token',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var corsAbierto = operaciones.length > 0 && sinAuth.length > 0 && CORS_ABIERTO.test(text);
  if (corsAbierto) {
    deduction += 40;
    findings.push({
      sev: 'critical',
      label: 'Además de faltar autenticación, el CORS está completamente abierto (Access-Control-Allow-Origin: "*" o cors() sin restringir origen) — esta combinación exacta es la que hizo explotable a CVE-2026-44895 desde cualquier página web, no solo desde otro proceso local',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna configuración de transporte HTTP/SSE de MCP (ni registro de sus rutas típicas) en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontró configuración de transporte HTTP/SSE de MCP, y todas las instancias verifican autenticación antes de despachar la petición.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' configuración(es)/ruta(s) de transporte HTTP/SSE de MCP en el código, ' + sinAuth.length + ' sin verificación de autenticación reconocible.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkMissingAuthRisk: checkMissingAuthRisk,
  findOperaciones: findOperaciones,
  bucket: bucket
};
