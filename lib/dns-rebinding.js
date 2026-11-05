"use strict";
// Escudo de Rebinding DNS — detector de falta de validación de Origen/Host
// ================================================================================
// Problema real: un servidor MCP que expone su transporte HTTP/SSE (el
// endpoint que un cliente MCP usa para hablarle por JSON-RPC) sin validar el
// header "Origin" (ni "Host") de cada petición entrante deja una puerta
// abierta a un ataque de "DNS rebinding": una página web maliciosa que el
// navegador de la víctima visita hace que el navegador termine hablándole
// directamente a ese servidor MCP — que suele correr en localhost o en la
// red interna del usuario — como si fuera un cliente MCP de confianza,
// porque el navegador SÍ manda las peticiones (las políticas de mismo origen
// del navegador no bloquean la petición en sí, solo la LECTURA de la
// respuesta desde JavaScript — y muchos ataques de este tipo ni siquiera
// necesitan leer la respuesta). Bindear el servidor solo a 127.0.0.1/
// localhost NO alcanza como protección: ese es exactamente el malentendido
// que hace posible el rebinding — el atacante registra un dominio que
// primero resuelve a su propio servidor y, después de que el navegador ya
// cargó la página, cambia el DNS para que ese mismo dominio resuelva a
// 127.0.0.1, dejando que el navegador siga tratándolo como "el mismo origen"
// del dominio del atacante mientras habla con el servidor local de la
// víctima. La única defensa real es validar el header Origin (y/o Host) de
// cada petición contra una lista explícita de orígenes permitidos.
//
// Motivada por un patrón repetido en 2026: no es un bug aislado, se encontró
// de forma independiente en al menos tres SDKs/implementaciones oficiales o
// muy usadas de MCP, en tres lenguajes distintos — CVE-2026-42559 (CVSS 8.8)
// en rmcp, el SDK oficial de Rust; CVE-2026-35568 en el SDK de Java; y
// CVE-2026-59971 en mysql-mcp-server (Python) — todas por la misma causa
// raíz: el transporte HTTP/SSE procesaba peticiones JSON-RPC sin validar de
// dónde venían.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de
// configuración del servidor/transporte (no ejecuta nada, no abre ningún
// puerto) — mismo enfoque y mismas limitaciones que lib/ssrf.js y
// lib/command-injection.js: no reemplaza un analizador de sintaxis (AST)
// real ni una auditoría de seguridad formal.

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

// Configuración/arranque de un transporte HTTP o SSE de MCP: el constructor
// oficial de las variantes más comunes (StreamableHTTPServerTransport,
// SSEServerTransport) y el registro típico de la ruta "/mcp" en Express,
// Flask o FastAPI — el punto exacto donde entra una petición JSON-RPC.
// `app\s*\.\s*` (en vez de `app\.` pegado) tolera un salto de línea/espacios
// entre "app" y el punto, y entre el punto y el método (estilo de lint real:
// `app\n  .post('/mcp', ...)`). También se reconoce el patrón de
// express.Router `app.route('/mcp').post(handler)`, que no queda cubierto
// por las alternativas "app.<método>(" de arriba porque el método va
// encadenado después de `.route(...)`, no pegado a `app.`.
var SINK_TRANSPORTE = /new\s+StreamableHTTPServerTransport\s*\(|new\s+SSEServerTransport\s*\(|app\s*\.\s*(?:post|all|use)\s*\(\s*['"`]\/mcp['"`]|@app\.(?:route|post)\s*\(\s*['"`]\/mcp['"`]|app\.route\s*\(\s*['"`]\/(?:mcp|sse|messages)['"`]\s*\)\s*\.\s*(?:post|get|all|use)\s*\(/g;

// Señal real de validación: el código compara el header Origin (o Host)
// contra una lista/constante de orígenes permitidos, o llama a una función
// reconocible con ese propósito.
var VALIDACION_ORIGEN = /(?:req|request)\.headers\.(?:get\(\s*['"]origin['"]\s*\)|origin)\s*(?:!==|===|==|!=|\bin\b)|\borigin\s+(?:not\s+)?in\s+(?:ALLOWED_ORIGINS|allowed_origins|allowlist)|valida(?:r|te)?_?(?:origen|origin)\s*\(|check_?origin\s*\(|verify_?origin\s*\(|isAllowedOrigin\s*\(|ALLOWED_ORIGINS\s*=|allowed_origins\s*=|allowedOrigins\s*[:=]/i;

// Malentendido documentado: creer que bindear solo a 127.0.0.1/localhost ya
// protege contra esto — es precisamente el escenario que el rebinding rompe.
var RECLAMA_LOCALHOST_SUFICIENTE = /(?:127\.0\.0\.1|localhost)[\s\S]{0,90}(?:seguro|protegid|only\s+accessible\s+locally|no\s+(?:es\s+)?(?:accesible|expuesto)\s+(?:desde\s+)?(?:afuera|externamente))|solo\s+(?:escucha|acepta\s+conexiones)\s+en\s+(?:localhost|127\.0\.0\.1)/i;

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
function checkDnsRebindingRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código que arma el transporte HTTP/SSE del servidor MCP) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);

  var sinValidar = operaciones.filter(function (o) {
    var contextStart = Math.max(0, o.index - 800);
    var contextEnd = Math.min(text.length, o.index + o.callText.length + 400);
    var contexto = text.slice(contextStart, contextEnd);
    return !VALIDACION_ORIGEN.test(contexto);
  });

  if (sinValidar.length > 0) {
    var ded1 = 55 + Math.min(20, (sinValidar.length - 1) * 10);
    deduction += ded1;
    sinValidar.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Transporte HTTP/SSE de MCP configurado sin ninguna validación reconocible del header Origin (ni Host) antes de procesar la petición — una página web maliciosa puede hacer que el navegador de la víctima hable con este servidor como si fuera un cliente MCP de confianza (rebinding DNS)',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var reclamaLocalhostComoDefensa = operaciones.length > 0 && sinValidar.length > 0 && RECLAMA_LOCALHOST_SUFICIENTE.test(text);
  if (reclamaLocalhostComoDefensa) {
    deduction += 40;
    findings.push({
      sev: 'critical',
      label: 'El código (o su comentario) sugiere que bindear el servidor solo a localhost/127.0.0.1 ya lo protege — pero eso NO evita el rebinding DNS: el atacante registra un dominio que primero resuelve a su propio servidor y luego cambia el DNS para que resuelva a 127.0.0.1, y el navegador sigue tratándolo como el mismo origen. La única defensa real es validar el header Origin.',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna configuración de transporte HTTP/SSE de MCP en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontró configuración de transporte HTTP/SSE de MCP, y todas las instancias validan el header Origin (o Host) antes de procesar la petición.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' configuración(es) de transporte HTTP/SSE de MCP en el código, ' + sinValidar.length + ' sin validación reconocible del header Origin.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkDnsRebindingRisk: checkDnsRebindingRisk,
  findOperaciones: findOperaciones,
  bucket: bucket
};
