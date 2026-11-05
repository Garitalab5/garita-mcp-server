"use strict";
// Escudo de Código Dinámico — detector de ejecución de código no confiable
// ================================================================================
// Problema real: una herramienta/agente que evalúa código en tiempo de
// ejecución (eval(), el constructor Function(), exec() de Python, o el módulo
// "vm" de Node: vm.runInContext/runInNewContext/runInThisContext) a partir de
// un texto que NO escribió el desarrollador — sino que viene de la respuesta
// de un modelo, de un documento recuperado (RAG), o de un parámetro de
// herramienta — le da a quien controle ese texto ejecución arbitraria de
// código (RCE) dentro del propio proceso del agente. Es una clase de
// vulnerabilidad (CWE-95, "Eval Injection") distinta de la inyección de
// comandos del sistema operativo que ya cubre detect_command_injection_risk
// (CWE-78): ahí se invoca una SHELL externa; acá se evalúa código directamente
// dentro del intérprete/motor JS que corre el propio agente, sin pasar por
// ningún proceso hijo.
//
// Motivada por CVE-2026-26030 (CVSS 9.8, publicado ~feb 2026) en Microsoft
// Semantic Kernel (SDK de Python, InMemoryVectorStore < 1.39.4): el filtro
// del vector store interpolaba un campo controlado por el atacante —
// contenido recuperado de un documento indexado, es decir, data envenenada
// de un pipeline RAG — directamente en una expresión que terminaba pasando
// por eval(), dando RCE completo en el proceso del agente a partir de datos
// RECUPERADOS, no de una entrada directa del usuario. Es el mismo patrón que
// motivó detect_memory_poisoning y detect_toxic_flow_risk: el dato peligroso
// no llega por la entrada "obvia", sino por un canal que el desarrollador
// asumió que era solo texto pasivo.
//
// Incluye también, como sink independiente, el patrón clásico de "eval
// implícito" vía setTimeout()/setInterval() llamado con un STRING como primer
// argumento en vez de una función — JS lo evalúa igual que un eval() directo,
// un vector documentado desde hace años pero que sigue apareciendo en código
// generado apurado.
//
// Regla propia de Garita (mismo espíritu que las reglas de "falsa sensación
// de seguridad" en detect_sql_injection_risk y detect_ssti_risk): usar la
// librería vm2 para "sandboxear" un eval no es una mitigación real — vm2 fue
// oficialmente DEPRECADA en 2023 después de varias fugas de sandbox críticas
// y documentadas (CVE-2023-32314, CVE-2023-37903, CVE-2023-37466), con los
// propios mantenedores recomendando migrar a isolated-vm. Reconocemos
// isolated-vm (aislamiento real a nivel de V8 Isolate, proceso separado) como
// mitigación real, igual que SandboxedEnvironment de Jinja2 en detect_ssti_risk.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada) — mismo enfoque y mismas limitaciones que
// lib/ssti.js, lib/sql-injection.js y lib/command-injection.js: no reemplaza
// un analizador de sintaxis (AST) real ni una auditoría de seguridad formal.

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

// Sinks que evalúan directamente su argumento como CÓDIGO: eval() (JS y
// Python comparten el nombre), el constructor Function()/new Function() de
// JS, exec() de Python, las tres variantes del módulo "vm" de Node que
// ejecutan un string como código en un contexto dado, y vm.Script(...) (la
// API de dos pasos de Node: el constructor YA compila/ejecuta el string como
// código, aunque el .runInContext()/.runInNewContext() venga encadenado
// después).
var SINK_DIRECTO = /\beval\s*\(|\bFunction\s*\(|\bexec\s*\(|\bvm\.runInContext\s*\(|\bvm\.runInNewContext\s*\(|\bvm\.runInThisContext\s*\(|\bvm\.Script\s*\(/g;

// Referencia INDIRECTA a eval: `(0, eval)`, ya sea invocada ahí mismo
// (`(0, eval)(x)`) o asignada a una variable para usarla después
// (`var indirectEval = (0, eval); indirectEval(x)`). Este truco evade
// SINK_DIRECTO porque no aparece "eval(" pegado. No hay forma de saber con
// qué se va a invocar después mirando solo el texto, así que se trata
// siempre como sink dinámico no confiable (no se aplica isLiteralArg).
var SINK_EVAL_INDIRECTO = /\(\s*0\s*,\s*eval\s*\)/g;

// setTimeout()/setInterval() llamado con un STRING como primer argumento
// (detectable porque lo que sigue al paréntesis de apertura es directamente
// una comilla) es "eval implícito" — JS compila y ejecuta ese string igual
// que un eval() directo. Con una referencia a función (setTimeout(miFn, 100))
// no hay comilla justo después del paréntesis, así que el patrón no dispara.
var SINK_TIMER_STRING = /\bset(?:Timeout|Interval)\s*\(\s*(?=['"`])/g;

// isolated-vm: aislamiento real a nivel de V8 Isolate (proceso separado de
// memoria) — se reconoce como mitigación genuina, igual que weights_only=True
// en detect_insecure_deserialization_risk o SandboxedEnvironment en detect_ssti_risk.
var SANDBOX_REAL = /isolated-vm|require\(['"]isolated-vm['"]\)|new\s+ivm\.Isolate\s*\(/i;

// vm2: "sandbox" ampliamente usado en el pasado, pero oficialmente deprecado
// desde 2023 tras múltiples fugas de sandbox críticas (CVE-2023-32314,
// CVE-2023-37903, CVE-2023-37466) — no detiene RCE de forma confiable.
// Separado en dos patrones: el import (evidencia de que "VM"/"NodeVM" es
// REALMENTE el de la librería vm2) y el uso (new VM(...)/new NodeVM(...)).
// Los dos deben co-ocurrir para atribuirle a vm2 el hallazgo de "falsa
// mitigación" — si el código solo tiene una clase o símbolo propio llamado
// "VM" (ej. `class VM {...}`) sin ningún `require('vm2')`/`from 'vm2'`
// cerca, no hay base para asumir que se trata de la librería vm2.
var VM2_IMPORT = /require\(['"]vm2['"]\)|from\s+['"]vm2['"]/;
var VM2_USO_SANDBOX = /new\s+VM\s*\(|new\s+NodeVM\s*\(/;

function isLiteralArg(argWindow) {
  var trimmed = argWindow.replace(/^\s+/, '');
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return false; // no arranca con string -> variable/expresión (incluye prefijos f"/r" de Python)
  var closeIdx = trimmed.indexOf(q, 1);
  if (closeIdx === -1) return false; // no se puede confirmar, se trata como variable por precaución
  var inner = trimmed.slice(1, closeIdx);
  if (q === '`' && /\$\{/.test(inner)) return false; // template literal con interpolación -> variable
  var after = trimmed.slice(closeIdx + 1, closeIdx + 24).replace(/^\s+/, '');
  if (after[0] === '+' || after[0] === '%') return false; // concatenación o formateo "%s" -> variable
  if (/^\.\s*format\s*\(/.test(after)) return false; // "codigo {}".format(x) -> variable
  return true; // literal limpio que escribió el desarrollador, no depende de entrada externa
}

// Encuentra el índice del paréntesis de cierre que hace juego con el de
// apertura en `openParenIndex` (que debe apuntar exactamente a un '('),
// llevando cuenta de la profundidad de paréntesis y de si el recorrido está
// dentro de un string/template literal (para no contar un '(' o ')' que
// aparece dentro de un string como si fuera parte de la estructura de la
// llamada). Devuelve -1 si el código está truncado/malformado y no hay
// cierre.
function findMatchingParen(text, openParenIndex) {
  var depth = 0;
  var inString = null; // '"', "'", '`', o null si no estamos en un string
  for (var i = openParenIndex; i < text.length; i++) {
    var ch = text[i];
    if (inString) {
      if (ch === '\\') { i++; continue; } // salta el carácter escapado
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Separa en argumentos de nivel superior el texto entre paréntesis de una
// llamada (`a, b, c` — sin incluir los paréntesis), respetando comillas y
// paréntesis/corchetes/llaves anidados, para no cortar en una coma que está
// dentro de un string o de una llamada/objeto anidado.
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

function findOperaciones(text) {
  var operaciones = [];

  var reD = new RegExp(SINK_DIRECTO.source, SINK_DIRECTO.flags);
  var m;
  while ((m = reD.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 220);
    var literal;
    if (/^Function\s*\(/.test(m[0])) {
      // Function()/new Function(): lo que el motor REALMENTE ejecuta como
      // código es el ÚLTIMO argumento (el cuerpo de la función) — con 3+
      // argumentos (nombres de parámetros + cuerpo), mirar solo el primero
      // deja pasar un cuerpo dinámico disfrazado detrás de nombres de
      // parámetros literales.
      var openParenIdx = m.index + m[0].length - 1;
      var closeParenIdx = findMatchingParen(text, openParenIdx);
      if (closeParenIdx !== -1) {
        var argsList = splitTopLevelArgs(text.slice(openParenIdx + 1, closeParenIdx));
        literal = argsList.length > 0 ? isLiteralArg(argsList[argsList.length - 1]) : isLiteralArg(argWindow);
      } else {
        literal = isLiteralArg(argWindow); // no se pudo determinar el cierre -> fallback al criterio anterior
      }
    } else {
      literal = isLiteralArg(argWindow);
    }
    operaciones.push({ index: m.index, callText: m[0], argWindow: argWindow, literal: literal });
    if (m.index === reD.lastIndex) reD.lastIndex++; // evita loop infinito con matches vacíos
  }

  var reI = new RegExp(SINK_EVAL_INDIRECTO.source, SINK_EVAL_INDIRECTO.flags);
  while ((m = reI.exec(text))) {
    var startArgI = m.index + m[0].length;
    var argWindowI = text.slice(startArgI, startArgI + 220);
    operaciones.push({ index: m.index, callText: m[0], argWindow: argWindowI, literal: false });
    if (m.index === reI.lastIndex) reI.lastIndex++;
  }

  var reT = new RegExp(SINK_TIMER_STRING.source, SINK_TIMER_STRING.flags);
  while ((m = reT.exec(text))) {
    var startArgT = m.index + m[0].length;
    var argWindowT = text.slice(startArgT, startArgT + 220);
    operaciones.push({ index: m.index, callText: text.slice(m.index, startArgT), argWindow: argWindowT, literal: isLiteralArg(argWindowT) });
    if (m.index === reT.lastIndex) reT.lastIndex++;
  }

  operaciones.sort(function (a, b) { return a.index - b.index; });
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkDynamicCodeRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que evalúa código dinámicamente) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);
  var candidatas = operaciones.filter(function (o) { return !o.literal; });

  var noValidadas = candidatas.filter(function (o) {
    var contextStart = Math.max(0, o.index - 600);
    var contexto = text.slice(contextStart, o.index) + o.callText + o.argWindow.slice(0, 100);
    return !SANDBOX_REAL.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    noValidadas.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Ejecución de código dinámico (eval/Function/exec/vm.runInContext o similar) con un argumento que depende de una variable/entrada externa — respuesta de un modelo, documento recuperado o parámetro de herramienta — en vez de un texto fijo que escribió el desarrollador, sin un aislamiento real (isolated-vm) reconocible cerca',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var reclamaVm2ComoDefensa = candidatas.length > 0 && VM2_IMPORT.test(text) && VM2_USO_SANDBOX.test(text) && !SANDBOX_REAL.test(text);
  if (reclamaVm2ComoDefensa) {
    deduction += 40;
    findings.push({
      sev: 'critical',
      label: 'El código usa vm2 para "sandbozear" la ejecución dinámica — pero vm2 está oficialmente deprecado desde 2023 tras varias fugas de sandbox críticas y documentadas (CVE-2023-32314, CVE-2023-37903, CVE-2023-37466); no es una mitigación confiable contra RCE',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna ejecución de código dinámico (eval/Function/exec/vm.runInContext/setTimeout con string) en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron ejecuciones de código dinámico, pero todas usan un texto fijo que escribió el desarrollador, o pasan por un aislamiento real (isolated-vm).', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' ejecución(es) de código dinámico en el código, ' + candidatas.length + ' con el código a evaluar dependiendo de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkDynamicCodeRisk: checkDynamicCodeRisk,
  findOperaciones: findOperaciones,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
