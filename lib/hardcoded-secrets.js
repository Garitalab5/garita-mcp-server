"use strict";
// Detector de riesgo de secretos embebidos en texto plano (credenciales/API keys
// hardcodeadas en código fuente o en archivos de configuración de MCP)
// ================================================================================
// Problema real: cuando una API key, un token o una contraseña queda escrita
// tal cual en el código fuente o en un archivo de configuración (en vez de venir
// de una variable de entorno o un gestor de secretos), cualquiera que vea ese
// archivo — un compañero de equipo, un repositorio público, un historial de git,
// o un agente de IA al que se le da acceso de lectura — se queda con esa
// credencial. Es, probablemente, el hallazgo más básico que se espera de
// cualquier escáner de seguridad, y ninguna de las herramientas anteriores de
// Garita lo busca.
//
// Motivado por un reporte real de Hush Security (18 de septiembre de 2026), que
// escaneó ~82.000 archivos de configuración MCP públicos en GitHub: el 12% de
// los espacios de credenciales tenía un secreto literal embebido, el 53% de esos
// con acceso a nivel de toda la organización o base de datos, y el 80% de los
// que tenían política de expiración no expiraban nunca por defecto. El 55% de
// esos secretos no coincidía con ningún formato de token conocido (por eso este
// detector no se limita a buscar formatos específicos). También documentado por
// Trend Micro (48% de 19.402 servidores MCP con almacenamiento inseguro de
// secretos) y catalogado como MCP01 en el OWASP MCP Top 10.
//
// Esto es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO o la
// CONFIGURACIÓN de una herramienta (no ejecuta nada, no se conecta a ningún
// repositorio) — mismo enfoque y mismas limitaciones que el resto del catálogo:
// no reemplaza un escáner de secretos completo (tipo gitleaks/TruffleHog) ni
// revisa el historial de git.

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

// Formatos de credenciales reales y reconocibles de un vistazo (proveedores
// grandes que usan un prefijo fijo, o el encabezado de una llave privada PEM).
var KNOWN_FORMATS = /sk-(?:proj-)?[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

// Asignación de un valor literal (entre comillas) a una variable o llave con
// nombre de credencial — en JS, Python, o dentro de un bloque JSON de config
// (por ejemplo, el bloque "env" de un servidor en mcpServers, el patrón exacto
// que escaneó Hush Security).
// (Sin \b al inicio a propósito: en nombres compuestos como "META_ACCESS_TOKEN"
// o "DB_PASSWORD" el "_" cuenta como carácter de palabra para \b, así que un
// límite de palabra estricto nunca coincidiría justo antes de "TOKEN"/"PASSWORD".
// El "[:=]" inmediato después ya evita falsos positivos con palabras que solo
// contienen la palabra clave en el medio, como "TOKENIZER_MODEL".)
var CREDENTIAL_ASSIGNMENT = /(api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?key|private[_-]?key|client[_-]?secret|password|passwd|pwd|auth[_-]?token|token|credentials?)s?["']?\s*[:=]\s*["']([^"'\n]{8,200})["']/gi;

// Línea al estilo ".env" (NOMBRE_EN_MAYUSCULAS=valor) con un nombre de variable
// que indica una credencial.
var ENV_LINE = /^[ \t]*([A-Z][A-Z0-9_]{2,})[ \t]*=[ \t]*(?!\$\{)([^\s#][^\n]{4,200})$/gm;
var ENV_LINE_KEY_CREDENCIAL = /API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL/i;

// Un valor de entorno con un valor de reserva ("fallback") hardcodeado — si la
// variable de entorno no existe, el código sigue funcionando con el secreto
// literal en vez de fallar, lo que en la práctica vuelve inútil usar la
// variable de entorno para empezar.
var DEFAULT_FALLBACK = /(?:process\.env\.\w+|os\.environ(?:\.get\(\s*["']\w+["']|\[\s*["']\w+["']\s*\]))\s*(?:\|\|\s*|,\s*)["']([^"'\n]{8,200})["']/g;

// Valores que son placeholders/ejemplos reconocibles, no secretos reales.
var PLACEHOLDER = /^(?:x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,}|0{3,}|1{3,}|your[_-]?|my[_-]?|insert[_-]?|replace[_-]?|change[_-]?me\b|example|sample\b|test(?:ing)?\b|demo\b|placeholder\b|fake\b|dummy\b|redacted\b|todo\b|fixme\b|none\b|null\b|undefined\b|n\/a\b|not[_-]?set\b|tbd\b)/i;
var PLACEHOLDER_EXACT = { password: 1, secret: 1, token: 1, apikey: 1, api_key: 1, key: 1, credential: 1, credentials: 1, changeme: 1 };

function esPlaceholder(valor) {
  var v = valor.trim();
  if (v.length === 0) return true;
  if (PLACEHOLDER.test(v)) return true;
  if (PLACEHOLDER_EXACT[v.toLowerCase()]) return true;
  if (/^\$\{/.test(v)) return true; // interpolación/variable, no literal de verdad
  return false;
}

function findOperaciones(text) {
  var ops = [];
  var seen = {};
  var m;

  var reFormato = new RegExp(KNOWN_FORMATS.source, KNOWN_FORMATS.flags);
  while ((m = reFormato.exec(text))) {
    if (!/example/i.test(m[0])) {
      var keyF = 'f:' + m.index;
      if (!seen[keyF]) {
        seen[keyF] = true;
        ops.push({ tipo: 'formato_conocido', index: m.index, snippet: contextSnippet(text, m.index, m[0].length) });
      }
    }
    if (m.index === reFormato.lastIndex) reFormato.lastIndex++;
  }

  var reAsig = new RegExp(CREDENTIAL_ASSIGNMENT.source, CREDENTIAL_ASSIGNMENT.flags);
  while ((m = reAsig.exec(text))) {
    if (!esPlaceholder(m[2])) {
      var keyA = 'a:' + m.index;
      if (!seen[keyA]) {
        seen[keyA] = true;
        ops.push({ tipo: 'asignacion_literal', index: m.index, snippet: contextSnippet(text, m.index, m[0].length) });
      }
    }
    if (m.index === reAsig.lastIndex) reAsig.lastIndex++;
  }

  var reEnv = new RegExp(ENV_LINE.source, ENV_LINE.flags);
  while ((m = reEnv.exec(text))) {
    if (ENV_LINE_KEY_CREDENCIAL.test(m[1]) && !esPlaceholder(m[2])) {
      var keyE = 'e:' + m.index;
      if (!seen[keyE]) {
        seen[keyE] = true;
        ops.push({ tipo: 'linea_env', index: m.index, snippet: contextSnippet(text, m.index, m[0].length) });
      }
    }
    if (m.index === reEnv.lastIndex) reEnv.lastIndex++;
  }

  ops.sort(function (a, b) { return a.index - b.index; });
  return ops;
}

function findFallbackHardcodeado(text) {
  var out = [];
  var re = new RegExp(DEFAULT_FALLBACK.source, DEFAULT_FALLBACK.flags);
  var m;
  while ((m = re.exec(text))) {
    if (!esPlaceholder(m[1])) {
      out.push({ index: m.index, snippet: contextSnippet(text, m.index, m[0].length) });
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes/formatos a la
// vez: JS, Python, JSON de configuración, y archivos ".env").
function checkHardcodedSecretsRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente o archivo de configuración a revisar) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var ops = findOperaciones(text);
  if (ops.length > 0) {
    deduction += 55 + Math.min(20, (ops.length - 1) * 10);
    var tiposVistos = {};
    ops.forEach(function (o) {
      if (tiposVistos[o.tipo]) return;
      tiposVistos[o.tipo] = true;
      var label;
      if (o.tipo === 'formato_conocido') {
        label = 'Se encontró una cadena con el formato reconocible de una credencial real (llave de API, token, o llave privada) escrita tal cual en el texto';
      } else if (o.tipo === 'asignacion_literal') {
        label = 'Una variable o llave de configuración con nombre de credencial (api_key, secret, token, password…) tiene un valor literal escrito en el propio código, en vez de venir de una variable de entorno o un gestor de secretos';
      } else {
        label = 'Una línea al estilo ".env" asigna un valor literal a una variable de entorno cuyo nombre indica una credencial';
      }
      findings.push({ sev: 'critical', label: label, snippet: o.snippet });
    });
  }

  var fallbacks = findFallbackHardcodeado(text);
  if (fallbacks.length > 0) {
    deduction += 30;
    findings.push({
      sev: 'warn',
      label: 'Una variable de entorno tiene un valor de reserva ("fallback") con un secreto literal hardcodeado — si la variable de entorno no está definida, el código sigue funcionando igual con la credencial embebida, lo que anula el propósito de usar una variable de entorno',
      snippet: fallbacks[0].snippet
    });
  }

  if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'No se encontró ninguna credencial con formato reconocible, ninguna asignación literal a una variable/llave de nombre de credencial, ni un valor de reserva hardcodeado.', snippet: null });
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + ops.length + ' secreto(s) embebido(s) en texto plano, y ' + fallbacks.length + ' valor(es) de reserva hardcodeado(s).',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkHardcodedSecretsRisk: checkHardcodedSecretsRisk,
  findOperaciones: findOperaciones,
  findFallbackHardcodeado: findFallbackHardcodeado,
  esPlaceholder: esPlaceholder,
  bucket: bucket
};
