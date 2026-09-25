"use strict";
// Detector de riesgo de path traversal / acceso arbitrario a archivos
// ================================================================================
// Problema real: una herramienta MCP que lee, escribe o borra un archivo a
// partir de una ruta que le pasa el propio agente (abrir un documento, guardar
// un adjunto, exportar un reporte) puede terminar usada para escapar del
// directorio que se pensaba permitido — con "../../../etc/passwd" o con una
// ruta absoluta directa — y leer, sobrescribir o borrar CUALQUIER archivo al
// que el proceso del servidor tenga acceso.
//
// Es la categoría MÁS GRANDE de vulnerabilidades reales encontradas en el
// censo de 9.695 servidores MCP escaneados en 2026 (bex.co, "MCP
// Vulnerability Census"): acceso arbitrario a archivos fue el 17.7% de los
// 4.982 problemas encontrados (880 casos) — más grande que denegación de
// servicio, inyección de comandos, o SSRF. Caso real documentado:
// CVE-2026-40576 (CVSS 9.4, crítico) en un servidor MCP de Excel — su función
// de rutas permitía tanto rutas absolutas ("/etc/passwd") como secuencias de
// escape ("../../../") sin resolverlas contra el directorio permitido, y como
// el servidor no pedía autenticación, cualquiera en la red podía leer o
// sobrescribir archivos arbitrarios del sistema a través de sus 25 herramientas.
//
// Esto es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada) — mismo enfoque y mismas limitaciones que
// lib/ssrf.js y el resto del motor de Garita: no reemplaza un analizador de
// sintaxis (AST) real ni una auditoría de seguridad formal.

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

// Operaciones de archivo más comunes en JS/TS, Python, PHP y frameworks web.
var OPERACION_ARCHIVO = /\b(?:fs\.(?:readFile(?:Sync)?|writeFile(?:Sync)?|appendFile(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|rmdir(?:Sync)?|createReadStream|createWriteStream|open(?:Sync)?|readdir(?:Sync)?)|fs\.promises\.(?:readFile|writeFile|unlink|rm)|open|shutil\.(?:copy2?|move|rmtree)|os\.(?:remove|unlink|rename)|send_file|sendFile|res\.download|res\.sendFile)\s*\(/gi;

// Señal de que se valida específicamente contra secuencias de escape ("..")
// o se reconstruye la ruta de forma segura (resolver + comparar contra una
// base, normalizar, o quedarse solo con el nombre de archivo sin directorio).
var VALIDACION_ESCAPE = /(?:includes|indexOf|startsWith|replace|split|test|match)\([^)]*\.\.[^)]*\)|path\.resolve\([^)]*\)[\s\S]{0,150}startsWith|os\.path\.realpath\([^)]*\)[\s\S]{0,150}startswith|path\.normalize\(|realpath\(|\.basename\(|secure_filename\(|require\(['"](?:sanitize-filename|path-is-inside|is-path-inside|resolve-path)['"]\)|from\s+['"](?:werkzeug\.utils|pathvalidate)['"]\s+import/i;

// Rechazo explícito de rutas absolutas (otra forma común y válida de cerrar
// el escape, sin necesariamente revisar "..").
var RECHAZA_ABSOLUTA = /path\.isAbsolute\([^)]*\)[^;\n]{0,60}(?:throw|reject|error)|os\.path\.isabs\([^)]*\)[^;\n]{0,60}(?:raise|error)|startsWith\(\s*['"][/\\]['"]\s*\)[^;\n]{0,60}(?:throw|reject|error)/i;

// Rutas sensibles del sistema referenciadas directamente — un indicio fuerte
// de que el snippet es una prueba de concepto de la falla, o código malicioso.
var RUTA_SENSIBLE = /(?:\/etc\/passwd|\/etc\/shadow|\.ssh[/\\]id_rsa|\.aws[/\\]credentials|\.env\b|[A-Za-z]:\\+Windows\\+System32|\/etc\/hosts|\.git[/\\]config)/i;

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

function findOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(OPERACION_ARCHIVO.source, OPERACION_ARCHIVO.flags);
  var m;
  while ((m = re.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 160);
    operaciones.push({ index: m.index, callText: m[0], argWindow: argWindow, literal: isLiteralArg(argWindow) });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkPathTraversalRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que lee/escribe/borra un archivo) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);
  var candidatas = operaciones.filter(function (o) { return !o.literal; });

  var noValidadas = candidatas.filter(function (o) {
    var contextStart = Math.max(0, o.index - 600);
    var contexto = text.slice(contextStart, o.index) + o.callText + o.argWindow.slice(0, 100);
    return !VALIDACION_ESCAPE.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    noValidadas.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Operación de archivo con una ruta que depende de una variable/entrada externa, sin ninguna validación reconocible contra secuencias de escape ("../") cerca',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var conRutaSensible = operaciones.filter(function (o) { return RUTA_SENSIBLE.test(o.argWindow); });
  if (conRutaSensible.length > 0) {
    deduction += 55;
    var oSens = conRutaSensible[0];
    var mSens = RUTA_SENSIBLE.exec(oSens.argWindow);
    findings.push({
      sev: 'critical',
      label: 'Referencia directa a una ruta sensible del sistema (credenciales, llaves SSH, archivo de configuración) dentro de una operación de archivo — el patrón usado para robar secretos vía path traversal',
      snippet: contextSnippet(text, oSens.index + oSens.callText.length + mSens.index, mSens[0].length)
    });
  }

  var sinRechazoAbsoluta = candidatas.length > 0 && !RECHAZA_ABSOLUTA.test(text);
  if (sinRechazoAbsoluta) {
    deduction += 15;
    findings.push({
      sev: 'warn',
      label: 'No se encontró ningún rechazo explícito de rutas absolutas (ej. lanzar un error si la ruta empieza con "/" o ya es absoluta) — sin esto, aunque se filtren las secuencias "../", una ruta absoluta directa puede seguir escapando del directorio permitido',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontraron operaciones de archivo en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron operaciones de archivo, pero todas usan una ruta fija (no depende de una entrada externa) o pasan por una validación reconocible contra secuencias de escape.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' operación(es) de archivo en el código, ' + candidatas.length + ' con una ruta que depende de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkPathTraversalRisk: checkPathTraversalRisk,
  findOperaciones: findOperaciones,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
