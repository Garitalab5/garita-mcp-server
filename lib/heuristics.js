"use strict";
// Motor de reglas de Garita MCP, portado tal cual del Artifact publicado
// (garita-mcp.html, Versión 4 — después de las 3 rondas de ataques) para
// que un agente de IA pueda llamarlo directamente como una tool MCP, en
// vez de que una persona pegue JSON en un navegador.
//
// Esto es el MISMO motor, no una reimplementación desde cero: mismos
// regexes, mismos pesos, mismas tres correcciones de seguridad (Infinity,
// el tope de 200,000 nodos, y los caracteres invisibles). Si algún día se
// corrige algo en garita-mcp.html, hay que replicarlo aquí también — no
// comparten código en tiempo de ejecución.

const DESTRUCTIVE_VERBS = /\b(borr\w*|elimin\w*|delet\w*|remov\w*|drop\s+table|wip\w*|format\w*|pag(?!in)\w*|transf\w*|withdraw\w*|retir\w*|ejecut\w*|execut\w*|eval|shell|sudo|revoc\w*|revoke\w*|cancel\w*.{0,25}(suscrip\w*|subscription)|env[ií]\w*\s+(dinero|cripto|crypto|fondos)|send\s+(money|crypto)|wire\s+transfer)\b/i;
const CODE_FIELD_NAMES = /^(command|cmd|script|query|sql|code|shell|payload|exec)$/i;

// OJO (ronda 5, 2026-09): la lista original aquí solo cubría 4 caracteres
// (zero-width space/joiner/non-joiner y BOM) — mucho más angosta que la
// lista ya endurecida en lib/escudo.js tras sus propias rondas de ataques
// (guion suave, separadores de línea/párrafo, marcas de dirección de texto
// incluido el RTL override, selectores de variación, rellenos de Hangul,
// etc.). Un caracter fuera de esa lista corta (ej. el guion suave U+00AD)
// partía un verbo peligroso ("bo" + U+00AD + "rra") sin que se detectara.
//
// OJO (ronda 7, 2026-10): ni los caracteres crudos NI los escapes \u
// literales en el código fuente sobreviven de forma confiable un
// round-trip de guardado/copiado (U+2028/U+2029 son separadores de línea
// reales que rompen la sintaxis de un literal de regex de JavaScript, y
// un escape \u puede quedar auto-decodificado a su caracter real por el
// camino) — esto ya rompió este mismo motor más de una vez. La lista se
// construye ahora a partir de pares de codepoints NUMÉRICOS con
// String.fromCodePoint, sin un solo backslash ni caracter invisible
// pegado directamente en este archivo.
var INVISIBLE_CODEPOINTS = [
  [0x00AD, 0x00AD],
  [0x061C, 0x061C],
  [0x115F, 0x1160],
  [0x180E, 0x180E],
  [0x200B, 0x200F],
  [0x2028, 0x2029],
  [0x202A, 0x202E],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0x3164, 0x3164],
  [0xFE00, 0xFE0F],
  [0xFEFF, 0xFEFF],
  [0xFFA0, 0xFFA0],
  [0xE0000, 0xE007F]
];
function buildInvisiblesRegex() {
  var parts = INVISIBLE_CODEPOINTS.map(function (par) {
    var a = String.fromCodePoint(par[0]);
    var b = String.fromCodePoint(par[1]);
    return par[0] === par[1] ? a : (a + '-' + b);
  });
  return new RegExp('[' + parts.join('') + ']', 'gu');
}
var INVISIBLES = buildInvisiblesRegex();

function stripInvisibles(str) {
  return String(str).replace(INVISIBLES, '');
}

// OJO (ronda 6, 2026-09): DESTRUCTIVE_VERBS y CODE_FIELD_NAMES son regexes
// sobre texto Latino puro — no tenían ninguna normalización de homoglifos,
// así que una sola letra cirílica/griega visualmente idéntica dentro del
// verbo ("bоrra" con "о" cirílica U+043E) partía la coincidencia del regex
// sin que stripInvisibles hiciera nada (el caracter SÍ es visible, solo es
// de otro alfabeto). lib/escudo.js ya tiene una regla ("homoglifo") para
// detectar mezcla de alfabetos, pero acá hace falta algo distinto: no solo
// detectar la mezcla, sino NORMALIZAR el texto para que el regex de verbos
// destructivos lo siga reconociendo. Mapeo mínimo de los homoglifos
// cirílico/griego más comunes (mayúscula y minúscula) a su equivalente
// Latino visualmente idéntico.
var HOMOGLYPH_MAP = {
  // Cirílico
  'а': 'a', 'А': 'A', // а А
  'е': 'e', 'Е': 'E', // е Е
  'о': 'o', 'О': 'O', // о О
  'р': 'p', 'Р': 'P', // р Р
  'с': 'c', 'С': 'C', // с С
  'у': 'y', 'У': 'Y', // у У
  'х': 'x', 'Х': 'X', // х Х
  // Griego
  'α': 'a', 'Α': 'A', // α Α
  'ο': 'o', 'Ο': 'O', // ο Ο
  'ρ': 'p', 'Ρ': 'P', // ρ Ρ
  'ε': 'e', 'Ε': 'E'  // ε Ε
};
var HOMOGLYPH_RE = new RegExp('[' + Object.keys(HOMOGLYPH_MAP).join('') + ']', 'g');

function normalizarHomoglifos(texto) {
  return String(texto).replace(HOMOGLYPH_RE, function (ch) { return HOMOGLYPH_MAP[ch]; });
}

function fmt(n) {
  try { return Number(n).toLocaleString('es-CO', { maximumFractionDigits: 2 }); }
  catch (e) { return String(n); }
}

function maxOf(numbers) {
  var max = -Infinity;
  for (var i = 0; i < numbers.length; i++) {
    if (numbers[i] > max) max = numbers[i];
  }
  return numbers.length ? max : 0;
}

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

// ---------- Auditor de servidor MCP ----------

function analyzeTool(tool, idx) {
  var findings = [];
  var deduction = 0;
  var ann = tool && tool.annotations;
  var desc = ((tool && tool.description) || '').trim();
  var name = (tool && tool.name) || ('herramienta_' + (idx + 1));

  if (!ann) {
    deduction += 6;
    findings.push({ sev: 'warn', text: 'Sin objeto "annotations" MCP (readOnlyHint / destructiveHint / idempotentHint / openWorldHint) — no hay señales declaradas de riesgo.' });
  } else {
    if (ann.destructiveHint === true) {
      deduction += 10;
      findings.push({ sev: 'critical', text: 'Marcada explícitamente como destructiveHint: true.' });
    }
    if (ann.openWorldHint === true && ann.readOnlyHint !== true) {
      deduction += 6;
      findings.push({ sev: 'warn', text: 'openWorldHint: true — interactúa con sistemas externos impredecibles y no es de solo lectura.' });
    }
  }
  // OJO (ronda 5, 2026-09): esta revisión solo se activaba cuando NO había
  // ningún destructiveHint declarado. Eso dejaba un hueco real: un servidor
  // podía declarar destructiveHint: false (mintiendo) — o incluso un valor
  // que no fuera exactamente el booleano true, ej. el string "true" — sobre
  // una herramienta con una descripción claramente destructiva, y ni la
  // deducción de "declarado true" (arriba, exige === true) ni esta de acá
  // (exigía === undefined) se disparaban: la herramienta salía con puntaje
  // limpio. Ahora se revisa el texto SIEMPRE que no esté declarado
  // exactamente destructiveHint: true, y si además el servidor declaró
  // false de forma explícita (una contradicción activa entre lo que dice
  // el texto y lo que declara la anotación — más sospechoso que simplemente
  // no declarar nada), se penaliza más fuerte.
  var descNameNorm = normalizarHomoglifos(stripInvisibles(desc + ' ' + name));
  if (ann && ann.destructiveHint === false && DESTRUCTIVE_VERBS.test(descNameNorm)) {
    deduction += 22;
    findings.push({ sev: 'critical', text: 'La descripción sugiere una acción irreversible, pero la anotación declara destructiveHint: false — contradicción activa entre el texto y lo que el servidor afirma de sí mismo.' });
  } else if ((!ann || ann.destructiveHint !== true) && DESTRUCTIVE_VERBS.test(descNameNorm)) {
    deduction += 14;
    findings.push({ sev: 'critical', text: 'La descripción sugiere una acción irreversible, pero no declara destructiveHint: true de forma válida — el agente no puede saberlo de antemano.' });
  }
  if (!desc || desc.length < 8) {
    deduction += 8;
    findings.push({ sev: 'warn', text: 'Sin descripción útil — un agente puede invocarla sin entender su efecto.' });
  }
  var props = (tool && tool.inputSchema && tool.inputSchema.properties) || {};
  Object.keys(props).forEach(function (key) {
    if (CODE_FIELD_NAMES.test(normalizarHomoglifos(key))) {
      deduction += 10;
      findings.push({ sev: 'critical', text: 'El campo "' + key + '" acepta código o comandos libres — superficie de inyección.' });
    }
  });
  if (findings.length === 0) {
    findings.push({ sev: 'ok', text: 'Sin señales de riesgo: anotada, descrita y sin campos de comando libre.' });
  }
  return { name: name, deduction: deduction, findings: findings };
}

function analyzeServer(serverInfo, toolCount) {
  var findings = [];
  var deduction = 0;
  serverInfo = serverInfo || {};
  if (serverInfo.requiresAuth === false) {
    deduction += 20;
    findings.push({ sev: 'critical', text: 'El servidor declara explícitamente que NO requiere autenticación — cualquiera que lo alcance puede listar y llamar sus herramientas.' });
  } else if (serverInfo.requiresAuth === undefined) {
    deduction += 5;
    findings.push({ sev: 'warn', text: 'No se declara si el servidor requiere autenticación — trátalo como no confiable hasta confirmarlo.' });
  }
  if (toolCount > 15) {
    deduction += 5;
    findings.push({ sev: 'warn', text: 'Superficie amplia: ' + toolCount + ' herramientas expuestas. Expón solo las necesarias por agente (menor privilegio).' });
  }
  return { deduction: deduction, findings: findings };
}

// manifest: objeto ya parseado (no texto) — el llamador (agente) manda JSON real,
// no un blob de texto para pegar en un textarea.
function auditManifest(manifest) {
  var data = manifest;
  var tools = Array.isArray(data) ? data : ((data && data.tools) || (data && data.name ? [data] : []));
  var serverInfo = Array.isArray(data) ? {} : ((data && (data.serverInfo || data.server)) || {});

  if (!tools || !tools.length) {
    return { error: 'No se encontró un arreglo "tools" con al menos una herramienta en el manifiesto.' };
  }

  var toolResults = tools.map(analyzeTool);
  var serverResult = analyzeServer(serverInfo, tools.length);

  var maxDed = maxOf(toolResults.map(function (t) { return t.deduction; }));
  var avgDed = toolResults.reduce(function (s, t) { return s + t.deduction; }, 0) / toolResults.length;
  var totalDeduction = serverResult.deduction + maxDed * 0.6 + avgDed * 0.4;
  var score = Math.max(0, Math.min(100, Math.round(100 - totalDeduction)));
  var b = bucket(score);

  return {
    score: score,
    verdict: b.label,
    severity: b.sev,
    server: {
      name: serverInfo.name || 'sin nombre',
      findings: serverResult.findings
    },
    tools: toolResults.map(function (t) {
      var tb = bucket(100 - t.deduction * 1.4);
      return { name: t.name, verdict: tb.label, severity: tb.sev, findings: t.findings };
    })
  };
}

// ---------- Simulador de aprobación ----------

// OJO (ronda 6, 2026-09): un monto en formato es-CO/europeo escrito como
// string ("1.500.000", punto = separador de miles) se leía en formato US
// (punto = decimal), tomando solo el primer grupo ("1.500" -> 1.5) y
// perdiendo por completo el resto de los dígitos — un monto de metro y
// medio de millón se colaba por debajo de cualquier umbral razonable.
// Ahora se prueban AMBAS interpretaciones posibles cuando el string tiene
// el patrón de puntos de miles sin ninguna coma (para no reinterpretar un
// monto normal en formato US con decimales, ej. "4200.50", que sí trae
// coma en su variante de miles "4,200.50") y se devuelven todos los
// candidatos — el llamador se queda con el máximo, nunca con el mínimo:
// esto es una herramienta de seguridad, más vale retener de más que dejar
// pasar un monto real por una interpretación optimista del formato.
var THOUSANDS_DOT_PATTERN = /\d{1,3}(\.\d{3})+(?!\d)/;

function parseAmountsFromString(str) {
  var candidates = [];

  // Interpretación US: las comas son separador de miles, el punto es decimal.
  var usText = str.replace(/,/g, '');
  var mUS = usText.match(/-?\d+(\.\d+)?([eE][+-]?\d+)?/);
  if (mUS) {
    var nUS = parseFloat(mUS[0]);
    if (!isNaN(nUS)) candidates.push(nUS);
  }

  // Interpretación es-CO/europea: los puntos son separador de miles, no hay
  // coma decimal en juego. Solo se intenta cuando el string realmente tiene
  // la forma de un monto agrupado de a tres dígitos por punto y ninguna
  // coma (si hay coma, es casi seguro formato US con miles-coma).
  if (str.indexOf(',') === -1 && THOUSANDS_DOT_PATTERN.test(str)) {
    var esText = str.replace(/\./g, '');
    var mES = esText.match(/-?\d+([eE][+-]?\d+)?/);
    if (mES) {
      var nES = parseFloat(mES[0]);
      if (!isNaN(nES)) candidates.push(nES);
    }
  }

  return candidates;
}

function findMaxNumber(root) {
  var max = null;
  var stack = [root];
  var guard = 0;
  var truncated = false;
  while (stack.length) {
    if (++guard > 200000) { truncated = true; break; }
    var v = stack.pop();
    if (typeof v === 'number' && !isNaN(v)) {
      if (max === null || v > max) max = v;
    } else if (typeof v === 'string') {
      // OJO (ronda 5, 2026-09): el regex original no reconocía notación
      // científica dentro de un string ("4e3", "1e400") — solo capturaba
      // la parte de dígitos antes de la "e", así que un monto de 4.000
      // escrito como el string "4e3" se leía como "4" y se colaba por
      // debajo del umbral sin retenerse. Ahora el regex incluye el
      // sufijo de exponente opcional ([eE][+-]?\d+) para que parseFloat
      // reciba el número completo, igual que ya pasa con un número JSON
      // crudo (1e400 -> Infinity, ya cubierto desde la ronda 3).
      //
      // OJO (ronda 6, 2026-09): parseAmountsFromString además interpreta el
      // string en DOS formatos posibles (US y es-CO/europeo) cuando hay
      // ambigüedad, y se queda con el máximo — nunca hay que infravalorar
      // un monto en una herramienta de seguridad. Ver el comentario de esa
      // función.
      var candidates = parseAmountsFromString(v);
      for (var ci = 0; ci < candidates.length; ci++) {
        if (max === null || candidates[ci] > max) max = candidates[ci];
      }
    } else if (Array.isArray(v)) {
      for (var i = 0; i < v.length; i++) stack.push(v[i]);
    } else if (v && typeof v === 'object') {
      var keys = Object.keys(v);
      for (var j = 0; j < keys.length; j++) stack.push(v[keys[j]]);
    }
  }
  return { value: max, truncated: truncated };
}

var DEFAULT_RULES = { destructive: true, verbs: true, openWorld: true, amount: true, code: true };

// action: { tool, description, arguments, annotations } ya parseado.
// rules/threshold: política de retención, igual que los checkboxes de la UI.
function simulateApproval(action, rules, threshold) {
  action = action || {};
  rules = Object.assign({}, DEFAULT_RULES, rules || {});
  threshold = typeof threshold === 'number' && !isNaN(threshold) ? threshold : 500;

  var ann = action.annotations || {};
  var text = normalizarHomoglifos(stripInvisibles((action.tool || '') + ' ' + (action.description || ''))).toLowerCase();
  var triggered = [];

  if (rules.destructive && ann.destructiveHint === true) {
    triggered.push('Anotada como destructiveHint: true.');
  }
  if (rules.verbs && DESTRUCTIVE_VERBS.test(text)) {
    triggered.push('El nombre o descripción contiene un verbo de acción irreversible.');
  }
  if (rules.openWorld && ann.openWorldHint === true && ann.readOnlyHint !== true) {
    triggered.push('openWorldHint: true sin ser de solo lectura.');
  }
  var maxAmount = null;
  if (rules.amount) {
    var amountScan = findMaxNumber(action.arguments);
    maxAmount = amountScan.value;
    if (maxAmount !== null && maxAmount > threshold) {
      triggered.push('Se detectó un monto de ' + fmt(maxAmount) + ' en los argumentos, por encima del umbral de ' + fmt(threshold) + '.');
    }
    if (amountScan.truncated) {
      triggered.push('Los argumentos son demasiado grandes o complejos para verificar el monto por completo — se retiene por precaución.');
    }
  }
  if (rules.code) {
    var props = action.arguments || {};
    Object.keys(props).forEach(function (key) {
      if (CODE_FIELD_NAMES.test(normalizarHomoglifos(key))) triggered.push('El argumento "' + key + '" contiene código o comandos libres.');
    });
  }

  var held = triggered.length > 0;
  // JSON.stringify convierte Infinity/-Infinity en null silenciosamente —
  // eso volvería a esconder justo el caso que se corrigió (un monto
  // "infinito" detectado) en la respuesta que recibe el agente. Se
  // representa como texto en la salida; la detección interna ya usó el
  // valor numérico real.
  var maxAmountOut = maxAmount;
  if (typeof maxAmount === 'number' && !isFinite(maxAmount)) {
    maxAmountOut = maxAmount > 0 ? 'Infinity' : '-Infinity';
  }
  return {
    verdict: held ? 'retenido' : 'auto_aprobado',
    held: held,
    tool: action.tool || action.name || 'acción sin nombre',
    reasons: triggered,
    maxAmountDetected: maxAmountOut
  };
}

module.exports = { auditManifest, simulateApproval, DESTRUCTIVE_VERBS, CODE_FIELD_NAMES, stripInvisibles, findMaxNumber, normalizarHomoglifos, parseAmountsFromString };
