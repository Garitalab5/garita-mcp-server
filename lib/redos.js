"use strict";
// Escudo Anti-ReDoS — detector de expresiones regulares vulnerables a
// backtracking catastrófico (Regular Expression Denial of Service)
// ================================================================================
// Problema real: una herramienta/agente que valida o parsea texto con una
// expresión regular que tiene "cuantificadores anidados" (ej. (a+)+, (\s*\w+)*,
// ([a-zA-Z]+)*) o alternancia con ramas superpuestas seguida de un cuantificador
// (ej. (a|a)*) puede quedar atascado procesando un solo string de entrada
// durante segundos, minutos o para siempre — el motor de regex de JS/Python
// prueba exponencialmente muchas formas de agrupar la misma entrada antes de
// fallar. Si ese patrón se aplica sobre una entrada que no tiene ningún tope
// de longitud y que viene de quien llama a la herramienta (un parámetro, el
// cuerpo de una petición, una respuesta de otro servicio), un solo mensaje
// cuidadosamente armado (ej. "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!") basta
// para colgar el proceso del agente entero — una denegación de servicio (CWE-1333)
// sin necesidad de ninguna otra vulnerabilidad.
//
// Motivado por CVE-2026-0621 (CVSS 7.5, ReDoS en una expresión regular de
// validación usada por un servidor/herramienta MCP ampliamente desplegado): el
// patrón vulnerable vivía en una sola función de validación de formato,
// alcanzable sin autenticación, y un único request bastaba para saturar el
// hilo de ese proceso. La misma CVE documenta también el patrón hermano: un
// regex compilado dinámicamente (RegExp(x)/re.compile(x) con x NO literal) a
// partir de una fuente no controlada por el desarrollador — ahí quien llama a
// la herramienta no solo elige la ENTRADA a validar, sino el PROPIO PATRÓN,
// pudiendo inyectar directamente una forma catastrófica, o cambiar por
// completo qué cuenta como válido.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada, no mide tiempos reales de backtracking) —
// mismo enfoque y mismas limitaciones que lib/ssti.js, lib/dynamic-code.js y
// lib/sql-injection.js: no reemplaza un analizador de sintaxis (AST) real, un
// motor de verificación de regex (ej. "safe-regex") corriendo de verdad, ni
// una auditoría de seguridad formal.

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

// Literal de regex de JavaScript: /patrón/flags. Exige que lo que precede a
// la barra de apertura no sea algo que indique que en realidad es un
// operador de división (identificador, número, ')' o ']' justo antes) —
// nunca se puede distinguir el 100% de los casos solo con texto, mismo
// criterio conservador que el resto del motor.
var REGEX_LITERAL = /(^|[=(:,;!&|?\n{}[]\s*)\/((?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+)\/([a-z]*)/g;

// RegExp(x) / new RegExp(x) de JavaScript, y re.compile(x) de Python — los
// dos constructores que compilan un patrón a partir de un STRING en vez de
// un literal de regex, así que "x" puede ser un texto fijo o una variable.
var REGEXP_CTOR = /\b(?:new\s+RegExp|RegExp|re\.compile)\s*\(/g;

// Mitigaciones reconocidas: un tope de longitud sobre la entrada antes de
// aplicarle el regex (igual de espíritu que los topes de lib/vulnerabilidades.js
// y lib/toxic-flows.js), o una librería/motor que corre el regex con un
// tiempo límite real en vez del motor de backtracking nativo.
var MITIGACION_TOPE_LONGITUD = /\.length\s*[<>]=?\s*\d+|\.slice\(\s*0\s*,\s*\d+\s*\)|\.substring\(\s*0\s*,\s*\d+\s*\)|\.slice\(\s*0\s*,\s*[A-Z_][A-Z0-9_]*\s*\)|\bMAX_(?:LEN|LENGTH|INPUT)\w*\b|\bmaxLength\b/i;
var MITIGACION_TIMEOUT_O_LIBRERIA = /\bre2\b|require\(['"]re2['"]\)|from\s+['"]re2['"]|safe-regex2?|\brecheck\b|require\(['"]safe-regex2?['"]\)|new\s+Worker\s*\(|\bworker_threads\b|\btimeout\s*:\s*\d+|vm\.(?:runInContext|runInNewContext|runInThisContext)\s*\([^)]{0,200}timeout/i;

function isLiteralStringArg(argWindow) {
  var trimmed = argWindow.replace(/^\s+/, '');
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return false; // no arranca con string -> variable/expresión
  var closeIdx = trimmed.indexOf(q, 1);
  if (closeIdx === -1) return false; // no se puede confirmar, se trata como variable por precaución
  var inner = trimmed.slice(1, closeIdx);
  if (q === '`' && /\$\{/.test(inner)) return false; // template literal con interpolación -> variable
  var after = trimmed.slice(closeIdx + 1, closeIdx + 24).replace(/^\s+/, '');
  if (after[0] === '+' || after[0] === '%') return false; // concatenación o formateo -> variable
  if (/^\.\s*format\s*\(/.test(after)) return false; // "patron {}".format(x) -> variable
  return true;
}

// Busca un grupo "(...)" que contenga un cuantificador (+, *, o {n,} sin tope
// superior) o una alternancia ("|") en su interior, y cuyo paréntesis de
// cierre esté inmediatamente seguido por otro cuantificador — la forma
// clásica de "cuantificador anidado" que dispara backtracking exponencial
// (ej. (a+)+, (\s*\w+)*, ([a-zA-Z]+)*, (a|a)*). Un grupo cuantificado que
// solo repite texto fijo sin cuantificador/alternancia interior (ej. (abc)+)
// NO es catastrófico por sí mismo y no se marca.
function hasCatastrophicShape(pattern) {
  if (typeof pattern !== 'string') return false;
  for (var i = 0; i < pattern.length; i++) {
    if (pattern[i] !== '(') continue;
    var depth = 1;
    var j = i + 1;
    var inner = '';
    var inClass = false;
    for (; j < pattern.length && depth > 0; j++) {
      var ch = pattern[j];
      if (ch === '\\') { inner += ch + (pattern[j + 1] || ''); j++; continue; }
      if (ch === '[') inClass = true;
      if (ch === ']') inClass = false;
      if (!inClass) {
        if (ch === '(') { depth++; inner += ch; continue; }
        else if (ch === ')') { depth--; if (depth === 0) break; inner += ch; continue; }
      }
      inner += ch;
    }
    if (depth !== 0) continue; // no cierra -> patrón truncado/malformado, no se puede evaluar esta porción
    var closeIdx = j;
    var afterClose = pattern.slice(closeIdx + 1, closeIdx + 4);
    var tieneCuantificadorAfuera = /^[+*]|^\{\d*,\}?/.test(afterClose);
    if (!tieneCuantificadorAfuera) continue;
    var innerSinEscapes = inner.replace(/\\./g, '');
    var innerTieneCuantificador = /[+*]|\{\d*,\}/.test(innerSinEscapes);
    var innerTieneAlternancia = /\|/.test(innerSinEscapes);
    if (innerTieneCuantificador || innerTieneAlternancia) return true;
  }
  return false;
}

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

function findMatchingParen(text, openParenIndex) {
  var depth = 0;
  var inString = null;
  for (var i = openParenIndex; i < text.length; i++) {
    var ch = text[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === inString) inString = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = ch; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

// Busca si, en una ventana de texto después de definir un regex (literal o
// por constructor), ese regex se aplica contra algo — y si ese "algo" es un
// texto fijo (sin riesgo real) o una variable/expresión (entrada externa
// potencial). Cubre las dos formas más comunes en JS: NOMBRE.test(arg) /
// NOMBRE.exec(arg) (el regex llama al método), y algo.match(NOMBRE) /
// algo.matchAll(NOMBRE) (el regex se pasa como argumento de .match()).
function buscarAplicacion(text, varName, afterIndex) {
  var windowEnd = Math.min(text.length, afterIndex + 800);
  var win = text.slice(afterIndex, windowEnd);
  var namePattern = varName ? varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : null;

  if (namePattern) {
    var reA = new RegExp('\\b' + namePattern + '\\s*\\.\\s*(?:test|exec)\\s*\\(');
    var mA = reA.exec(win);
    if (mA) {
      var argStart = mA.index + mA[0].length;
      var argWindow = win.slice(argStart, argStart + 160);
      return { aplicado: true, literal: isLiteralStringArg(argWindow) };
    }
    var reB = new RegExp('\\.\\s*match(?:All)?\\s*\\(\\s*' + namePattern + '\\s*\\)');
    if (reB.test(win)) {
      return { aplicado: true, literal: false };
    }
  }

  // Aplicación inmediata sin nombre (el literal se usa de una, ej. /pat/.test(x)).
  var reC = /^\s*\.\s*(?:test|exec)\s*\(/;
  var mC = reC.exec(win);
  if (mC) {
    var argStart2 = mC.index + mC[0].length;
    var argWindow2 = win.slice(argStart2, argStart2 + 160);
    return { aplicado: true, literal: isLiteralStringArg(argWindow2) };
  }

  return { aplicado: false, literal: null };
}

// Recorre todo el texto en busca de: (a) literales de regex de JS con su
// variable asignada si la tiene, (b) RegExp()/new RegExp() con su argumento
// (literal o dinámico), y (c) re.compile() de Python con su argumento. Para
// re.match()/re.search()/re.fullmatch() de Python (que reciben el patrón y
// el sujeto como dos argumentos de la misma llamada, no method-chaining) se
// evalúa la aplicación directamente ahí mismo.
function findDefiniciones(text) {
  var definiciones = [];

  var reLit = new RegExp(REGEX_LITERAL.source, REGEX_LITERAL.flags);
  var m;
  while ((m = reLit.exec(text))) {
    var patIndex = m.index + m[1].length + 1;
    var pattern = m[2];
    var varMatch = /(?:const|let|var)\s+(\w+)\s*=\s*$/.exec(text.slice(Math.max(0, m.index - 60), m.index + m[1].length));
    var varName = varMatch ? varMatch[1] : null;
    definiciones.push({ kind: 'literal', index: patIndex, pattern: pattern, varName: varName, raw: '/' + pattern + '/' + m[3] });
    if (m.index === reLit.lastIndex) reLit.lastIndex++;
  }

  var reCtor = new RegExp(REGEXP_CTOR.source, REGEXP_CTOR.flags);
  while ((m = reCtor.exec(text))) {
    var openParenIdx = m.index + m[0].length - 1;
    var closeParenIdx = findMatchingParen(text, openParenIdx);
    if (closeParenIdx === -1) { if (m.index === reCtor.lastIndex) reCtor.lastIndex++; continue; }
    var argsList = splitTopLevelArgs(text.slice(openParenIdx + 1, closeParenIdx));
    var firstArg = argsList.length > 0 ? argsList[0] : '';
    var esPython = /re\.compile\s*\($/.test(m[0]);
    var literalFirstArg = isLiteralStringArg(firstArg.replace(/^\s+/, ''));

    if (!literalFirstArg) {
      definiciones.push({ kind: 'dinamico', index: m.index, pattern: null, varName: null, raw: m[0], esPython: esPython });
      if (m.index === reCtor.lastIndex) reCtor.lastIndex++;
      continue;
    }

    var innerLit = firstArg.replace(/^\s+['"`]/, '').replace(/['"`]\s*$/, '');
    var varMatch2 = /(?:const|let|var)\s+(\w+)\s*=\s*$/.exec(text.slice(Math.max(0, m.index - 60), m.index));
    var varMatch2Py = /(\w+)\s*=\s*$/.exec(text.slice(Math.max(0, m.index - 40), m.index));
    var varName2 = varMatch2 ? varMatch2[1] : (esPython && varMatch2Py ? varMatch2Py[1] : null);
    definiciones.push({ kind: 'literal', index: m.index, pattern: innerLit, varName: varName2, raw: m[0] + firstArg + ')', esPython: esPython });
    if (m.index === reCtor.lastIndex) reCtor.lastIndex++;
  }

  return definiciones;
}

// re.match(patron, sujeto) / re.search(patron, sujeto) / re.fullmatch(patron, sujeto)
// de Python: a diferencia de re.compile(), acá el patrón y el sujeto llegan
// juntos como los dos primeros argumentos de la misma llamada.
var RE_APPLY_PY = /\bre\.(?:match|search|fullmatch)\s*\(/g;

function findAplicacionesPython(text) {
  var out = [];
  var re = new RegExp(RE_APPLY_PY.source, RE_APPLY_PY.flags);
  var m;
  while ((m = re.exec(text))) {
    var openParenIdx = m.index + m[0].length - 1;
    var closeParenIdx = findMatchingParen(text, openParenIdx);
    if (closeParenIdx !== -1) {
      var argsList = splitTopLevelArgs(text.slice(openParenIdx + 1, closeParenIdx));
      if (argsList.length >= 2) {
        var patronArg = argsList[0].replace(/^\s+/, '');
        var sujetoArg = argsList[1].replace(/^\s+/, '');
        var patronLiteral = isLiteralStringArg(patronArg);
        var pattern = patronLiteral ? patronArg.replace(/^['"`]/, '').replace(/['"`]$/, '') : null;
        out.push({
          index: m.index,
          pattern: pattern,
          patronEsVariable: !patronLiteral,
          sujetoEsLiteral: isLiteralStringArg(sujetoArg),
          raw: text.slice(m.index, closeParenIdx + 1)
        });
      }
    }
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkRedosRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que compila o aplica una expresión regular) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var definiciones = findDefiniciones(text);
  var regexDinamico = definiciones.filter(function (d) { return d.kind === 'dinamico'; });
  var regexLiteral = definiciones.filter(function (d) { return d.kind === 'literal' && d.pattern !== null; });

  var evilAplicadoSinMitigar = [];
  var evilSinConfirmarAplicacion = [];

  regexLiteral.forEach(function (d) {
    if (!hasCatastrophicShape(d.pattern)) return;
    // El propio literal evil queda envuelto directamente en el constructor de
    // un motor seguro (ej. "new RE2(/(a+)+/)") -> el motor nativo de
    // backtracking nunca llega a correr sobre este patrón, mitigado de raíz.
    var inmediatoAntes = text.slice(Math.max(0, d.index - 40), d.index);
    if (/\bRE2\s*\(\s*\/?\s*$/.test(inmediatoAntes)) return;
    var aplicacion = buscarAplicacion(text, d.varName, d.index);
    var ventanaContexto = text.slice(Math.max(0, d.index - 300), Math.min(text.length, d.index + 900));
    var mitigado = MITIGACION_TOPE_LONGITUD.test(ventanaContexto) || MITIGACION_TIMEOUT_O_LIBRERIA.test(ventanaContexto);
    if (aplicacion.aplicado && !aplicacion.literal && !mitigado) {
      evilAplicadoSinMitigar.push(d);
    } else if (!aplicacion.aplicado) {
      evilSinConfirmarAplicacion.push(d);
    }
    // aplicado && literal, o aplicado && mitigado -> no se marca (sin exposición real confirmada).
  });

  // Variante Python de "aplicado": re.match(patron_fijo_catastrófico, sujeto_variable).
  var aplicacionesPy = findAplicacionesPython(text);
  aplicacionesPy.forEach(function (a) {
    if (!a.pattern || !hasCatastrophicShape(a.pattern)) return;
    var ventanaContexto = text.slice(Math.max(0, a.index - 300), a.index);
    var mitigado = MITIGACION_TOPE_LONGITUD.test(ventanaContexto) || MITIGACION_TIMEOUT_O_LIBRERIA.test(ventanaContexto);
    if (!a.sujetoEsLiteral && !mitigado) {
      evilAplicadoSinMitigar.push({ index: a.index, pattern: a.pattern, raw: a.raw });
    }
  });

  if (evilAplicadoSinMitigar.length > 0) {
    var ded1 = 55 + Math.min(20, (evilAplicadoSinMitigar.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'Expresión regular con forma de "cuantificador anidado" (backtracking catastrófico, ej. (a+)+, (\\s*\\w+)*, (a|a)*) aplicada contra una entrada que no es un texto fijo — ni un tope de longitud ni un motor con timeout/librería segura (re2, safe-regex, recheck) reconocibles cerca — el mismo patrón detrás de CVE-2026-0621 (CVSS 7.5): un solo string cuidadosamente armado puede colgar el proceso del agente entero (ReDoS, CWE-1333)',
      snippet: contextSnippet(text, evilAplicadoSinMitigar[0].index, Math.min(40, (evilAplicadoSinMitigar[0].raw || evilAplicadoSinMitigar[0].pattern || '').length))
    });
  }

  if (regexDinamico.length > 0) {
    var ded2 = 55 + Math.min(20, (regexDinamico.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'critical',
      label: 'Un regex se compila (RegExp()/new RegExp()/re.compile()) a partir de una fuente que NO es un texto fijo que escribió el desarrollador, sino una variable — quien llame a la herramienta no solo elige la entrada a validar, sino el PROPIO PATRÓN, pudiendo inyectar directamente una forma catastrófica (ReDoS) o cambiar por completo la lógica de validación; variante documentada también en CVE-2026-0621',
      snippet: contextSnippet(text, regexDinamico[0].index, regexDinamico[0].raw.length)
    });
  }

  if (evilAplicadoSinMitigar.length === 0 && evilSinConfirmarAplicacion.length > 0) {
    deduction += 25;
    findings.push({
      sev: 'warn',
      label: 'Se definió una expresión regular con forma de cuantificador anidado (potencialmente catastrófica), pero en este fragmento no se pudo confirmar dónde o contra qué entrada se aplica — conviene revisar manualmente que nunca reciba un texto externo sin tope de longitud',
      snippet: contextSnippet(text, evilSinConfirmarAplicacion[0].index, Math.min(40, evilSinConfirmarAplicacion[0].pattern.length))
    });
  }

  if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'No se encontró ninguna expresión regular con forma de cuantificador anidado aplicada sin mitigar contra una entrada variable, ni ningún regex compilado dinámicamente a partir de una fuente no literal.', snippet: null });
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + regexLiteral.length + ' expresión(es) regular(es) literal(es) analizada(s) (' + evilAplicadoSinMitigar.length + ' con forma catastrófica aplicada sin mitigar) y ' + regexDinamico.length + ' regex compilado(s) dinámicamente a partir de una fuente no literal.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkRedosRisk: checkRedosRisk,
  hasCatastrophicShape: hasCatastrophicShape,
  findDefiniciones: findDefiniciones,
  findAplicacionesPython: findAplicacionesPython,
  bucket: bucket
};
