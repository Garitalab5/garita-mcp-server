"use strict";
// Escudo de Dependencia Frágil — detector de llamadas a servicios externos sin
// timeout ni reintento (punto único de falla)
// ================================================================================
// Problema real: una herramienta MCP que llama a un servicio externo (una
// API, otro microservicio, una base de datos remota) sin configurar un
// TIMEOUT deja esa llamada esperando indefinidamente si el servicio externo
// se cuelga o deja de responder — el agente que invocó la herramienta queda
// bloqueado, sin ningún límite de tiempo que le devuelva el control. Si
// además no hay ninguna lógica de REINTENTO (retry/backoff), una falla
// transitoria y corta del servicio externo (una caída de red de pocos
// segundos, un 503 momentáneo) se propaga directo como una falla total de la
// herramienta, sin que nada intente recuperarse sola.
//
// Motivado por el apagón de control aéreo de EE. UU. del 13 de noviembre de
// 2026: una falla de telecomunicaciones en un solo punto de los centros de
// control de ruta de la FAA (sin un mecanismo de respaldo que absorbiera la
// caída) obligó a detener TODOS los despegues del país durante horas, con
// más de 440 vuelos cancelados y 9.000 demorados solo en las primeras horas
// (fuente: FAA / cobertura de Infobae, Canal26, CNN en Español, 13-14 de
// noviembre de 2026 — las autoridades descartaron un ciberataque; la causa
// fue una falla técnica de telecomunicaciones). El mismo patrón de diseño —
// una dependencia crítica única, sin timeout ni plan de respaldo — es
// exactamente lo que esta herramienta busca en el código de un servidor o
// agente MCP: no hace falta un ataque para que un solo punto de falla tumbe
// todo el sistema, basta con que nadie haya puesto un límite de tiempo ni
// un reintento.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO que hace
// llamadas salientes a servicios externos (fetch/axios/http.request en
// JavaScript, requests/urllib en Python) — no ejecuta nada, no mide latencia
// real. Mismo enfoque y mismas limitaciones que lib/missing-auth.js y
// lib/unbounded-allocation.js: no reemplaza un analizador de sintaxis (AST)
// real. Límite conocido: si el timeout o el reintento se configuran en un
// cliente HTTP compartido definido lejos de la llamada (ej. una instancia de
// axios con `timeout` ya en su configuración base, creada en otro archivo),
// esta herramienta no lo ve y puede marcar la llamada como desprotegida
// cuando en realidad no lo está — por eso conviene revisar manualmente
// cualquier hallazgo antes de darlo por definitivo.

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

// Llamada saliente a un servicio externo: fetch, axios (incluidas sus formas
// con método: axios.get/post/put/delete/patch, y axios(config)), el cliente
// http/https nativo de Node, y los clientes más comunes de Python
// (requests.*, urllib.request.urlopen).
var SINK_LLAMADA_EXTERNA = /\bfetch\s*\(|axios\s*(?:\.\s*(?:get|post|put|delete|patch|request)\s*)?\(|https?\s*\.\s*request\s*\(|\brequests\s*\.\s*(?:get|post|put|delete|patch)\s*\(|urllib\.request\.urlopen\s*\(/g;

// Señal de timeout/deadline configurado en o cerca de la llamada: una opción
// `timeout`, un AbortController/AbortSignal.timeout (fetch moderno), o un
// parámetro `signal` pasado al fetch.
var SENAL_TIMEOUT = /\btimeout\s*[:=]|AbortSignal\s*\.\s*timeout\s*\(|new\s+AbortController\s*\(|signal\s*:\s*\w/i;

// Señal de reintento/backoff: una librería reconocida (p-retry, async-retry,
// tenacity, backoff, retry), o la palabra "retry"/"reintent"/"backoff" cerca
// de la llamada (ej. un bucle `for (let intento = 0; intento < 3; intento++)`
// envolviendo la llamada, o un comentario/variable que lo nombre).
var SENAL_REINTENTO = /\bretry\s*\(|p-?retry|async-?retry|tenacity|backoff|reintent/i;

function findOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(SINK_LLAMADA_EXTERNA.source, SINK_LLAMADA_EXTERNA.flags);
  var m;
  while ((m = re.exec(text))) {
    operaciones.push({ index: m.index, callText: m[0] });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkSinglePointOfFailureRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código que hace llamadas a servicios externos — fetch/axios/http.request/requests) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);

  var sinTimeout = [];
  var conTimeoutSinReintento = [];

  operaciones.forEach(function (o) {
    var ventanaStart = Math.max(0, o.index - 200);
    var ventanaEnd = Math.min(text.length, o.index + o.callText.length + 600);
    var contexto = text.slice(ventanaStart, ventanaEnd);
    var tieneTimeout = SENAL_TIMEOUT.test(contexto);
    var tieneReintento = SENAL_REINTENTO.test(contexto);
    if (!tieneTimeout) {
      sinTimeout.push(o);
    } else if (!tieneReintento) {
      conTimeoutSinReintento.push(o);
    }
  });

  if (sinTimeout.length > 0) {
    var ded1 = 50 + Math.min(25, (sinTimeout.length - 1) * 10);
    deduction += ded1;
    sinTimeout.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Llamada a un servicio externo sin ningún timeout/deadline configurado cerca — si ese servicio se cuelga o deja de responder, esta llamada puede quedar esperando indefinidamente y bloquear al agente que invocó la herramienta (punto único de falla, sin límite de tiempo)',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  if (conTimeoutSinReintento.length > 0) {
    var ded2 = 15 + Math.min(15, (conTimeoutSinReintento.length - 1) * 5);
    deduction += ded2;
    conTimeoutSinReintento.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'warn',
        label: 'Llamada a un servicio externo con timeout configurado, pero sin ninguna lógica de reintento/backoff visible cerca — una falla transitoria y corta del servicio (una caída de red de segundos, un 503 momentáneo) se propaga directo como una falla total de la herramienta',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontraron llamadas a servicios externos (fetch/axios/http.request/requests) en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron llamadas a servicios externos, y todas tienen timeout configurado junto con alguna lógica de reintento/backoff reconocible.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' llamada(s) a servicio(s) externo(s), ' + sinTimeout.length + ' sin timeout configurado y ' +
      conTimeoutSinReintento.length + ' con timeout pero sin reintento/backoff.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkSinglePointOfFailureRisk: checkSinglePointOfFailureRisk,
  findOperaciones: findOperaciones,
  bucket: bucket
};
