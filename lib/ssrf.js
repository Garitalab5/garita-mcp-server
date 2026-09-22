"use strict";
// Detector de riesgo de SSRF (Server-Side Request Forgery) en herramientas MCP
// ================================================================================
// Problema real: una herramienta MCP que le hace una petición HTTP a una URL que
// le pasa el propio agente/usuario (ej. "traeme el contenido de esta URL", un
// webhook, un scraper) puede terminar usada para que el SERVIDOR pida, en su
// nombre, un recurso INTERNO que el atacante no podría alcanzar directamente:
// el endpoint de metadata de la nube (roba credenciales temporales de AWS/GCP/
// Azure), un panel de administración interno, o cualquier servicio en
// localhost/red privada — y la respuesta se la devuelve al atacante a través
// del propio agente.
//
// Documentado como una de las categorías más grandes de vulnerabilidades reales
// encontradas en un censo de 9.695 servidores MCP escaneados en 2026 (bex.co,
// "MCP Vulnerability Census"): SSRF fue el 8.5% de los 4.982 problemas
// encontrados (422 casos), dentro de un 60% de servidores con algún problema de
// seguridad. Solo el 8.5% de los servidores usa OAuth de verdad — el resto usa
// llaves estáticas o ninguna autenticación, lo que hace que estas fallas de
// validación de URL sean aún más explotables.
//
// Esto es un análisis ESTÁTICO por patrones sobre el CÓDIGO de una herramienta
// (no ejecuta nada) — mismo enfoque y mismas limitaciones que el resto del
// motor de Garita (ver lib/escudo.js, lib/config-poison.js): busca señales de
// texto, no reemplaza un analizador de sintaxis (AST) real ni una auditoría de
// seguridad formal. Pensado para código en JS/TS, Python, PHP y Java por igual
// (los patrones de llamada HTTP cubren los clientes más comunes de cada uno).

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

// Clientes HTTP más comunes en JS/TS, Python, PHP y Java.
var LLAMADA_HTTP = /\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|https?\.(?:get|request)|requests\.(?:get|post|put|delete|patch|head)|urlopen|curl_exec|file_get_contents|WebClient\.create)\s*\(/gi;

var VALIDACION = /\b(allowlist|whitelist|blocklist|blacklist|private[-_ ]?ip|is[-_]?private|is[-_]?internal|isInternalHost|ssrf|resolve\w{0,10}ip|dns\.lookup|ipaddress\.ip_address|is_reserved|is_loopback|is_link_local|allowed[-_ ]?hosts?|hostname\s*(===?|in)\s*\[?['"]|new\s+URL\([^)]*\)\.hostname|urlparse\([^)]*\)\.hostname|scheme\s*(===?|in)\s*\[?['"]https?|protocol\s*===?\s*['"]https?:?['"]|require\(['"](?:ssrf-req-filter|request-filtering-agent|ssrf-safe)['"]\)|from\s+['"](?:ssrf-req-filter|request-filtering-agent)['"]\s+import|import\s+[\w{}, ]*(?:ssrf-req-filter|request-filtering-agent))/i;

var ESQUEMA = /startsWith\(['"]https?:\/\/['"]\)|protocol\s*===?\s*['"]https?:?['"]|\.scheme\s*(===?|in)\s*\(?\[?['"]https?|urlparse\([^)]*\)\.scheme/i;

var TLS_DESACTIVADO = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[:=]\s*['"]?0|verify\s*=\s*False|--insecure\b|curl\s+[^\n]{0,20}-k\b/i;

var REDIRECT_SEGUIDO = /redirect\s*:\s*['"]follow['"]|allow_redirects\s*=\s*True|maxRedirects\s*:\s*[1-9]/i;
var REDIRECT_REVALIDADO = /onRedirect|beforeRedirect|redirect\w{0,10}(check|valid|verify)/i;

var IP_PRIVADA_O_METADATA = /\b(127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|::1)\b/i;

function isLiteralArg(argWindow) {
  var trimmed = argWindow.replace(/^\s+/, '');
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return false; // no arranca con string -> variable/expresión
  var closeIdx = trimmed.indexOf(q, 1);
  if (closeIdx === -1) return false; // no se puede confirmar, se trata como variable por precaución
  var inner = trimmed.slice(1, closeIdx);
  if (q === '`' && /\$\{/.test(inner)) return false; // template literal con interpolación -> variable
  var after = trimmed.slice(closeIdx + 1, closeIdx + 20).replace(/^\s+/, '');
  if (after[0] === '+') return false; // concatenación de string -> variable
  return true; // literal limpio, no depende de entrada externa
}

function findLlamadas(text) {
  var llamadas = [];
  var re = new RegExp(LLAMADA_HTTP.source, LLAMADA_HTTP.flags);
  var m;
  while ((m = re.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 160);
    llamadas.push({ index: m.index, callText: m[0], argWindow: argWindow, literal: isLiteralArg(argWindow) });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return llamadas;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkSsrfRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que hace la petición HTTP) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var llamadas = findLlamadas(text);
  var candidatas = llamadas.filter(function (l) { return !l.literal; });

  var noValidadas = candidatas.filter(function (l) {
    var contextStart = Math.max(0, l.index - 600);
    var contexto = text.slice(contextStart, l.index) + l.callText + l.argWindow.slice(0, 100);
    return !VALIDACION.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    noValidadas.slice(0, 3).forEach(function (l) {
      findings.push({
        sev: 'critical',
        label: 'Llamada HTTP con una URL que depende de una variable/entrada externa, sin ninguna validación reconocible cerca (lista permitida, chequeo de IP privada, o una librería conocida contra SSRF)',
        snippet: contextSnippet(text, l.index, l.callText.length)
      });
    });
  }

  // Referencia directa a una IP privada/loopback o a un endpoint de metadata de
  // la nube DENTRO del argumento de una llamada HTTP en sí (no en cualquier
  // parte del código — una función que la menciona para BLOQUEARLA, por
  // ejemplo, no cuenta acá).
  var conIpEnArgumento = llamadas.filter(function (l) {
    return IP_PRIVADA_O_METADATA.test(l.argWindow);
  });
  if (conIpEnArgumento.length > 0) {
    deduction += 55;
    var lIp = conIpEnArgumento[0];
    var mIpLocal = IP_PRIVADA_O_METADATA.exec(lIp.argWindow);
    findings.push({
      sev: 'critical',
      label: 'Referencia directa a una IP privada/loopback o a un endpoint de metadata de la nube (AWS/GCP/Azure) dentro de una llamada HTTP — el patrón exacto usado para robar credenciales temporales de la nube vía SSRF',
      snippet: contextSnippet(text, lIp.index + lIp.callText.length + mIpLocal.index, mIpLocal[0].length)
    });
  }

  if (candidatas.length > 0 && TLS_DESACTIVADO.test(text)) {
    var mTls = TLS_DESACTIVADO.exec(text);
    deduction += 40;
    findings.push({
      sev: 'critical',
      label: 'Verificación de certificado TLS desactivada junto con una petición a una URL externa — permite interceptar o redirigir la petición sin que el código lo note',
      snippet: contextSnippet(text, mTls.index, mTls[0].length)
    });
  }

  var conRedirectSinRevalidar = noValidadas.filter(function (l) {
    var ventana = l.callText + l.argWindow;
    return REDIRECT_SEGUIDO.test(ventana) && !REDIRECT_REVALIDADO.test(ventana);
  });
  if (conRedirectSinRevalidar.length > 0) {
    deduction += 15;
    var l0 = conRedirectSinRevalidar[0];
    findings.push({
      sev: 'warn',
      label: 'La petición sigue redirecciones automáticamente sin revalidar el destino final — un servidor externo controlado por el atacante puede redirigir hacia un recurso interno después de pasar la primera validación',
      snippet: contextSnippet(text, l0.index, l0.callText.length)
    });
  }

  if (candidatas.length > 0 && !ESQUEMA.test(text)) {
    deduction += 15;
    findings.push({
      sev: 'warn',
      label: 'No se encontró ninguna restricción de esquema (ej. exigir que la URL empiece con http:// o https://) — sin esto, aunque se valide la IP, esquemas como file:// o gopher:// pueden seguir siendo posibles',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (llamadas.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontraron llamadas HTTP en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron llamadas HTTP, pero todas usan una URL fija (no depende de una entrada externa) o pasan por una validación reconocible.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + llamadas.length + ' llamada(s) HTTP en el código, ' + candidatas.length + ' con una URL que depende de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkSsrfRisk: checkSsrfRisk,
  findLlamadas: findLlamadas,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
