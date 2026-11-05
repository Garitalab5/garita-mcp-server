"use strict";
// Garita Escudo — motor de detección (versión servidor)
// =======================================================
// Puerto directo del motor probado en garita-tools/garita-escudo/tool.html
// (Versión 4, cuatro rondas de ataques adversariales sin evasiones
// pendientes salvo las dos documentadas: parafraseo sin palabras clave, y
// versalitas fonéticas Unicode). Las expresiones regulares, el orden de
// las pasadas de limpieza/decodificación y la fórmula de puntaje son
// IDÉNTICOS al motor del navegador — solo se quitó lo específico de HTML
// (escapeHtml, <mark>, render() al DOM) porque aquí el resultado es JSON
// para que lo lea un agente, no una persona mirando una página.
//
// No modificar las reglas ni el orden de las pasadas sin volver a correr
// las pruebas de regresión de las 4 rondas — cada regla existe por una
// evasión real encontrada y corregida en su momento.

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

function maxOf(numbers) {
  var max = -Infinity;
  for (var i = 0; i < numbers.length; i++) { if (numbers[i] > max) max = numbers[i]; }
  return numbers.length ? max : 0;
}

// Caracteres invisibles/de control sin uso legítimo en una descripción de
// herramienta (zero-width, guion suave, separadores, marcas/controles de
// dirección de texto —incluido el "RTL override" tipo Trojan Source—,
// selectores de variación, y el bloque "Tags" U+E0000-E007F usado para
// esteganografía / "ASCII smuggling").
// Construido a partir de pares de codepoints numericos (nunca escapes \\u
// ni caracteres crudos pegados en el codigo fuente) para que U+2028/U+2029
// (separadores de linea/parrafo reales) no puedan romper la sintaxis de
// este archivo al guardarlo o copiarlo.
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
function stripInvisibles(str) { return String(str).replace(INVISIBLES, ''); }

// Marcas diacríticas combinantes ("zalgo") que rompen la coincidencia
// literal de las reglas de texto letra por letra. NFKC (aplicado antes)
// ya compone cualquier acento legítimo del español/inglés, así que
// cualquier marca combinante que sobrevive después de NFKC no es una
// letra acentuada real en este contexto — es señal de evasión, segura de
// quitar de la copia de texto usada para el análisis.
var COMBINING_MARKS = /[̀-ͯ᪰-᫿᷀-᷿⃐-⃿︠-︯]/gu;
function stripCombiningMarks(str) { return String(str).replace(COMBINING_MARKS, ''); }

// OJO (ronda 6, 2026-09): el chequeo original disparaba el hallazgo crítico
// de "zalgo" con que UNA SOLA marca combinante sobreviviera en todo el
// texto tras NFKC. Eso es un falso positivo real: ortografía académica
// legítima de yoruba/vietnamita (y otras lenguas tonales) usa un caracter
// ya precompuesto MÁS una marca de tono combinante adicional encima — una
// sola marca residual, no apilada. Un ataque zalgo real apila 2+ marcas
// sobre el MISMO caracter base para saturar la coincidencia visual/textual.
// Se exige ahora una corrida de 2+ marcas combinantes CONSECUTIVAS antes de
// tratarlo como señal de evasión; el texto se sigue limpiando de marcas
// sueltas de todas formas (no cuentan para el hallazgo, pero no deben
// quedar en el texto que se analiza semánticamente).
var ZALGO_RUN = /[̀-ͯ᪰-᫿᷀-᷿⃐-⃿︠-︯]{2,}/;

// El bloque Unicode "Tags" no solo se esconde — cada caracter
// E0020-E007E es el ASCII 20-7E desplazado, así que una instrucción
// entera puede viajar invisible ahí dentro. Se decodifica y se suma al
// análisis semántico, no basta con quitarlo.
function decodeUnicodeTags(str) {
  var out = '';
  var found = false;
  for (var i = 0; i < str.length; i++) {
    var cp = str.codePointAt(i);
    if (cp > 0xFFFF) i++;
    if (cp >= 0xE0020 && cp <= 0xE007E) {
      out += String.fromCharCode(cp - 0xE0000);
      found = true;
    }
  }
  return found ? out : '';
}

// Entidades HTML numéricas (&#78; o &#x4E;) pueden deletrear una frase
// entera sin ningún caracter ASCII crudo. Se decodifican antes de
// analizar — solo numéricas y un puñado de nombradas de uso legítimo
// común (no cuentan para la señal de "contiene entidades").
function decodeHtmlEntitiesOnce(str) {
  var hadNumeric = false;
  var out = String(str)
    .replace(/&#x([0-9a-fA-F]+);/g, function (_, hex) { hadNumeric = true; return String.fromCodePoint(parseInt(hex, 16)); })
    .replace(/&#(\d+);/g, function (_, dec) { hadNumeric = true; return String.fromCodePoint(parseInt(dec, 10)); })
    .replace(/&(amp|lt|gt|quot|apos|nbsp);/g, function (_, ent) {
      return { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' }[ent];
    });
  return { text: out, hadNumeric: hadNumeric };
}

// Entidades codificadas EN CAPAS (cada caracter de "&#73;" vuelto a
// escribir como sus propias entidades) necesitan decodificarse hasta que
// ya no cambie nada, con un tope bajo de pasadas.
function decodeHtmlEntities(str) {
  var current = String(str);
  var hadNumericAny = false;
  for (var i = 0; i < 6; i++) {
    var pass = decodeHtmlEntitiesOnce(current);
    if (pass.hadNumeric) hadNumericAny = true;
    if (pass.text === current) break;
    current = pass.text;
  }
  return { text: current, hadNumeric: hadNumericAny };
}

// ---------- reglas de detección ----------
// Cada regla busca una señal semántica distinta. No son literales: se
// basan en patrones documentados en casos reales (Invariant Labs/Cursor,
// GitHub, Docker/WhatsApp MCP, benchmark MCPTox).
var RULES = [
  {
    id: 'ocultamiento', sev: 'critical', deduction: 55,
    label: 'Instrucción para ocultar la acción al usuario',
    regex: /\b(no\s+(le\s+)?(informes?|avises?|muestres?|digas?|notifiques?|reveles?)\s+(a\s+)?(el|al)?\s*usuario|sin\s+que\s+el\s+usuario\s+se\s+entere|no\s+lo\s+menciones|do\s+not\s+(tell|notify|inform|show|reveal|surface)\s+(the\s+)?user|without\s+(telling|notifying|informing)\s+the\s+user|keep\s+this\s+(secret|hidden)|mant[eé]nlo\s+en\s+secreto)\b/i
  },
  {
    id: 'etiqueta_oculta', sev: 'critical', deduction: 35,
    label: 'Bloque de pseudo-instrucción o comentario oculto dentro del texto',
    regex: /<\s*(important|system|instructions?|hidden|admin|override|root|directive)\b[^>]{0,60}>|<!--[\s\S]{0,400}?-->/i
  },
  {
    id: 'manipulacion_cruzada', sev: 'critical', deduction: 45,
    label: 'Instrucción para alterar el comportamiento de OTRA herramienta',
    regex: /\b(cuando\s+(se\s+)?(invoque|llame|ejecute|use)\b[\s\S]{0,220}\b(cambia|redirige|reemplaza|sustituye|agrega|incluye)|(cambia|redirige|reemplaza|sustituye|agrega|incluye)\b[\s\S]{0,220}\bcuando\s+(se\s+)?(invoque|llame|ejecute|use)\b|when\s+[\w.\-]+\s+is\s+(invoked|called)\b[\s\S]{0,220}\b(change|redirect|replace|append|include)|(change|redirect|replace|append|include)\b[\s\S]{0,220}\bwhen\s+[\w.\-]+\s+is\s+(invoked|called)\b)/i
  },
  {
    id: 'redireccion', sev: 'critical', deduction: 40,
    label: 'Instrucción de reenviar, copiar o redirigir datos a un destino distinto',
    regex: /\b(reenv[ií]a\w*|env[ií]a\s+(tambi[eé]n|una\s+copia)|copia\s+oculta|cc\s+a|bcc|forward(?:s|ed|ing)?\s+a\s+copy|send\s+a\s+copy)\b/i
  },
  {
    id: 'lenguaje_autoridad', sev: 'warn', deduction: 12,
    label: 'Lenguaje de autoridad/urgencia poco habitual en una descripción de herramienta',
    regex: /\b(IMPORTANTE|CR[IÍ]TICO|URGENTE|OBLIGATORIO|ATENCI[OÓ]N|IMPORTANT|CRITICAL|WARNING|MANDATORY|REQUIRED)\b/
  },
  {
    id: 'homoglifo', sev: 'critical', deduction: 35,
    label: 'Letras de otro alfabeto (cirílico/griego) mezcladas dentro de una misma palabra — típico de suplantación visual (homoglifos)',
    regex: /[a-zA-Z]+[Ͱ-ϿЀ-ӿ]+[a-zA-ZͰ-ϿЀ-ӿ]*|[Ͱ-ϿЀ-ӿ]+[a-zA-Z]+[a-zA-ZͰ-ϿЀ-ӿ]*/
  },
  {
    id: 'meta_decodificar', sev: 'critical', deduction: 40,
    label: 'Instrucción que pide decodificar/interpretar un texto codificado y luego seguirlo — un patrón casi siempre malicioso en una descripción de herramienta',
    regex: /\b(decodific\w*|descifr\w*|interpret\w*|decode\w*|decrypt\w*)\b[\s\S]{0,60}\b(base ?64|hex(adecimal)?|rot13|y\s+(sigue|ejecuta|aplica)|and\s+(follow|execute|run|apply))\b|\b(sigue|ejecuta|aplica|follow|execute)\b[\s\S]{0,60}\b(decodific\w*|descifr\w*|decode\w*|decrypt\w*)\b/i
  },
  {
    // Patrón documentado como "MCP Tool Rug-Pull" (catalogado como
    // ATR-2026-00581, OWASP Agentic ASI02/ASI05, MITRE ATLAS
    // AML.T0053/T0051/T0104, 2026-09): una herramienta se ve benigna al
    // aprobarse, pero su propia descripción incluye una instrucción que se
    // activa DESPUÉS ("cuando ya se aprobó", "en la próxima ejecución") y
    // en ese momento diferido pide algo peligroso (leer llaves SSH/
    // credenciales, o un comando de exfiltración tipo cat|base64|wget). Se
    // exige AMBAS partes (gatillo diferido + indicador peligroso concreto)
    // para no marcar el lenguaje normal de "después de que autorices el
    // acceso, usaremos tu token" que sí es legítimo en muchas integraciones
    // reales (OAuth) — ver la prueba de falso positivo en test-escudo.js.
    id: 'gatillo_diferido', sev: 'critical', deduction: 45,
    label: 'Instrucción que se activa después de la aprobación o en una ejecución futura, combinada con acceso a credenciales o un comando de exfiltración ("rug-pull")',
    // OJO (ronda 5, 2026-09): dos huecos reales encontrados y corregidos.
    // (1) Frases-gatillo en español no cubiertas: "en ejecuciones futuras"
    // (orden sustantivo-adjetivo, distinto de "en las próximas ejecuciones")
    // y "la próxima vez que...". (2) El indicador de peligro solo cubría
    // una tubería directa a wget/curl/nc, o rutas específicas de SSH/AWS/
    // git — un comando curl/wget con flags de subida (-d/--data/-F/-T/
    // --upload-file/-X POST) SIN tubería, o scp/rsync hacia un host
    // remoto, exfiltraban cualquier archivo (ej. /etc/passwd, .env) sin
    // disparar la regla. Ver las pruebas de ronda 5 en test-escudo.js.
    //
    // OJO (ronda 6, 2026-09): un tercer hueco — el indicador de peligro no
    // cubría reverse shells (bash vía /dev/tcp/, netcat con -e) ni
    // exfiltración por DNS (nslookup/dig con sustitución de comando), así
    // que un "gatillo diferido" combinado con cualquiera de esos tres no se
    // detectaba. Ver las pruebas de ronda 6 en test-escudo.js.
    regex: /\b(despu[eé]s\s+de\s+(que\s+)?(el\s+usuario\s+)?aprob\w*|en\s+(la|las)\s+pr[oó]xima(s)?\s+ejecuci[oó]n(es)?|en\s+ejecuci[oó]n(es)?\s+futuras?|la\s+pr[oó]xima\s+vez\s+que\b|una\s+vez\s+(que\s+)?(esta\s+herramienta\s+)?(sea|est[eé])\s+(confiabl|confiad)\w*|ahora\s+que\s+(esta\s+herramienta|esto)\s+(es|est[aá])\s+(confiabl|confiad)\w*|after\s+(the\s+)?(user\s+)?approv\w*|on\s+(subsequent|next|future)\s+(runs?|executions?|loads?)|once\s+(this\s+tool\s+is|it'?s)\s+trusted|now\s+that\s+(this\s+tool\s+is|it'?s)\s+trusted)\b[\s\S]{0,150}(~\/\.ssh|\.ssh\/|id_rsa|id_ed25519|authorized_keys|\.aws\/credentials|\.git-credentials|clave\s+privada|llave\s+ssh|clave\s+ssh|\|\s*(wget|curl|nc\b)|base ?64[\s\S]{0,25}(wget|curl)|(wget|curl)[\s\S]{0,25}base ?64|(curl|wget)[\s\S]{0,40}(-{1,2}data(-raw|-binary)?\b|-F\b|--form\b|-T\b|--upload-file\b|--post-data\b|--post-file\b|-X\s*POST)|\bscp\b[\s\S]{0,80}@[\w.\-]+:|\brsync\b[\s\S]{0,80}@[\w.\-]+:|\/dev\/tcp\/[\w.\-]+\/\d+|\bnc\s+-e\b|\bncat\b[\s\S]{0,20}-e\b|\bnslookup\b|\bdig\b[\s\S]{0,60}\$\()|(~\/\.ssh|\.ssh\/|id_rsa|id_ed25519|authorized_keys|\.aws\/credentials|\.git-credentials|clave\s+privada|llave\s+ssh|clave\s+ssh|\|\s*(wget|curl|nc\b)|base ?64[\s\S]{0,25}(wget|curl)|(wget|curl)[\s\S]{0,25}base ?64|(curl|wget)[\s\S]{0,40}(-{1,2}data(-raw|-binary)?\b|-F\b|--form\b|-T\b|--upload-file\b|--post-data\b|--post-file\b|-X\s*POST)|\bscp\b[\s\S]{0,80}@[\w.\-]+:|\brsync\b[\s\S]{0,80}@[\w.\-]+:|\/dev\/tcp\/[\w.\-]+\/\d+|\bnc\s+-e\b|\bncat\b[\s\S]{0,20}-e\b|\bnslookup\b|\bdig\b[\s\S]{0,60}\$\()[\s\S]{0,150}\b(despu[eé]s\s+de\s+(que\s+)?(el\s+usuario\s+)?aprob\w*|en\s+(la|las)\s+pr[oó]xima(s)?\s+ejecuci[oó]n(es)?|en\s+ejecuci[oó]n(es)?\s+futuras?|la\s+pr[oó]xima\s+vez\s+que\b|una\s+vez\s+(que\s+)?(esta\s+herramienta\s+)?(sea|est[eé])\s+(confiabl|confiad)\w*|ahora\s+que\s+(esta\s+herramienta|esto)\s+(es|est[aá])\s+(confiabl|confiad)\w*|after\s+(the\s+)?(user\s+)?approv\w*|on\s+(subsequent|next|future)\s+(runs?|executions?|loads?)|once\s+(this\s+tool\s+is|it'?s)\s+trusted|now\s+that\s+(this\s+tool\s+is|it'?s)\s+trusted)\b/i
  }
];

function contextSnippet(text, idx, len) {
  var start = Math.max(0, idx - 34);
  var end = Math.min(text.length, idx + len + 34);
  var prefix = start > 0 ? '…' : '';
  var suffix = end < text.length ? '…' : '';
  return prefix + text.slice(start, idx) + '[' + text.slice(idx, idx + len) + ']' + text.slice(idx + len, end) + suffix;
}

function invisibleSnippet(rawText) {
  var idx = rawText.search(INVISIBLES);
  if (idx === -1) return null;
  var start = Math.max(0, idx - 24);
  var visible = rawText.slice(start, Math.min(rawText.length, idx + 24)).replace(INVISIBLES, '·');
  var markedIdx = idx - start;
  return (start > 0 ? '…' : '') + visible.slice(0, markedIdx) + '[·]' + visible.slice(markedIdx + 1) + '…';
}

function analyzeText(name, rawText, opts) {
  opts = opts || {};
  var findings = [];
  var deduction = 0;
  var firedIds = [];

  var entityDecoded = decodeHtmlEntities(String(rawText || ''));
  if (entityDecoded.hadNumeric) {
    deduction += 15;
    findings.push({ sev: 'warn', label: 'Contiene entidades HTML numéricas (&#…;) — una forma inusual de escribir texto en una descripción de herramienta, se decodificó antes de analizar.', snippet: null });
  }

  var text = entityDecoded.text.normalize('NFKC');

  var stripped = stripInvisibles(text);
  if (stripped.length !== text.length) {
    var count = text.length - stripped.length;
    deduction += 30;
    findings.push({ sev: 'critical', label: 'Caracteres invisibles dentro del texto (' + count + ')', snippet: invisibleSnippet(text) });
  }

  var deZalga = stripCombiningMarks(stripped);
  if (deZalga.length !== stripped.length) {
    if (ZALGO_RUN.test(stripped)) {
      deduction += 30;
      findings.push({ sev: 'critical', label: 'Marcas diacríticas combinantes fuera de lo normal ("zalgo") que rompen la coincidencia de palabras clave, encontradas y quitadas antes de analizar', snippet: null });
    }
    stripped = deZalga;
  }

  var tagDecoded = decodeUnicodeTags(text);
  var semanticText = tagDecoded ? (stripped + '\n' + tagDecoded) : stripped;
  if (tagDecoded) {
    findings.push({
      sev: 'critical',
      label: 'Texto escondido con esteganografía Unicode (bloque "Tags") — se decodificó y también se analiza',
      snippet: contextSnippet(semanticText, semanticText.indexOf(tagDecoded), Math.min(tagDecoded.length, 120))
    });
    deduction += 30;
  }

  var scriptCounts = { latin: 0, other: 0 };
  var otherRun = 0, maxOtherRun = 0;
  for (var si = 0; si < semanticText.length; si++) {
    var cc = semanticText.charCodeAt(si);
    var isLatinLetter = (cc >= 65 && cc <= 90) || (cc >= 97 && cc <= 122);
    var isOtherLetter = (cc >= 0x370 && cc <= 0x3FF) || (cc >= 0x400 && cc <= 0x4FF);
    if (isLatinLetter) { scriptCounts.latin++; otherRun = 0; }
    else if (isOtherLetter) { scriptCounts.other++; otherRun++; if (otherRun > maxOtherRun) maxOtherRun = otherRun; }
    else { otherRun = 0; }
  }
  if (scriptCounts.other >= 2 && maxOtherRun >= 2 && scriptCounts.latin > scriptCounts.other * 3) {
    deduction += 35;
    findings.push({ sev: 'critical', label: 'Palabra(s) completas escritas con letras de otro alfabeto (cirílico/griego) dentro de un texto mayormente en español/inglés — suplantación visual (homoglifos)', snippet: null });
  }

  RULES.forEach(function (rule) {
    var m = rule.regex.exec(semanticText);
    if (m) {
      deduction += rule.deduction;
      firedIds.push(rule.id);
      findings.push({ sev: rule.sev, label: rule.label, snippet: contextSnippet(semanticText, m.index, m[0].length) });
    }
  });

  if (opts.schemaTruncated) {
    deduction += 25;
    findings.push({ sev: 'warn', label: 'El esquema de entrada (inputSchema) es demasiado grande o profundo para revisarlo por completo — se retiene por precaución, puede haber texto sin analizar.', snippet: null });
  }

  if (!text.trim()) {
    findings.push({ sev: 'warn', label: 'Sin texto para analizar.', snippet: null });
  } else if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'Sin señales de instrucciones ocultas en el texto.', snippet: null });
  }

  return { name: name, deduction: deduction, findings: findings, firedIds: firedIds, normalizedText: semanticText };
}

// Recorrido iterativo (no recursivo) que junta todas las "description"
// de un inputSchema sin importar cuán anidado esté. Falla de forma
// segura (truncated: true) en vez de dar un puntaje limpio falso cuando
// el esquema es demasiado grande para revisarlo por completo.
function collectNestedDescriptions(node) {
  var found = [];
  var stack = [node];
  var guard = 0;
  var truncated = false;
  while (stack.length) {
    if (++guard > 200000) { truncated = true; break; }
    var v = stack.pop();
    if (Array.isArray(v)) {
      for (var i = 0; i < v.length; i++) stack.push(v[i]);
    } else if (v && typeof v === 'object') {
      var keys = Object.keys(v);
      for (var j = 0; j < keys.length; j++) {
        var k = keys[j];
        if (k === 'description' && typeof v[k] === 'string') found.push(v[k]);
        else stack.push(v[k]);
      }
    }
  }
  return { found: found, truncated: truncated };
}

function collectToolText(tool) {
  var parts = [tool && tool.name, tool && tool.description];
  var schemaTruncated = false;
  if (tool && tool.inputSchema) {
    var nested = collectNestedDescriptions(tool.inputSchema);
    parts = parts.concat(nested.found);
    schemaTruncated = nested.truncated;
  }
  return {
    text: parts.filter(function (p) { return typeof p === 'string'; }).join('\n'),
    truncated: schemaTruncated
  };
}

// tools[] puede traer strings sueltos en vez de objetos {name, description}
// (manifiesto malformado a propósito). Se envuelve como si fuera su
// descripción para que el texto se revise de todas formas.
function normalizeToolEntry(rawTool) {
  if (typeof rawTool === 'string') return { description: rawTool };
  return rawTool;
}

// ---------- punto de entrada ----------
// input: { manifest?: object|array, text?: string }
// - manifest: { serverInfo, tools: [...] } (igual que el Auditor de Garita
//   MCP), o un arreglo de herramientas, o una sola herramienta {name,description}.
// - text: descripción suelta de una sola herramienta (modo texto plano).
// Al menos uno de los dos debe venir con contenido.
function auditToolDescriptions(input) {
  input = input || {};
  var tools;

  if (input.manifest !== undefined && input.manifest !== null) {
    var data = input.manifest;
    tools = Array.isArray(data) ? data : (data.tools || (data.name || data.description ? [data] : []));
    if (!tools.length) {
      throw new Error('El manifiesto no tiene un arreglo "tools", ni es una herramienta suelta con "name"/"description".');
    }
  } else if (typeof input.text === 'string' && input.text.trim()) {
    tools = [{ name: 'texto analizado', description: input.text }];
  } else {
    throw new Error('Debes enviar "manifest" (objeto/arreglo) o "text" (descripción suelta) con contenido.');
  }

  var results = tools.map(function (rawTool, idx) {
    var tool = normalizeToolEntry(rawTool);
    var name = (tool && tool.name) || ('herramienta_' + (idx + 1));
    var ct = collectToolText(tool);
    return analyzeText(name, ct.text, { schemaTruncated: ct.truncated });
  });

  // Un patrón malicioso puede venir repartido entre dos o más herramientas
  // del mismo manifiesto sin que ninguna por sí sola lo contenga completo.
  var firedAnywhere = {};
  results.forEach(function (r) { (r.firedIds || []).forEach(function (id) { firedAnywhere[id] = true; }); });
  var combinedText = results.map(function (r) { return r.normalizedText; }).join('\n');
  var crossFindings = [];
  var crossDeduction = 0;
  RULES.forEach(function (rule) {
    if (firedAnywhere[rule.id]) return;
    var m = rule.regex.exec(combinedText);
    if (m) {
      crossDeduction += rule.deduction;
      crossFindings.push({
        sev: rule.sev,
        label: 'Patrón repartido entre varias herramientas: ' + rule.label,
        snippet: contextSnippet(combinedText, m.index, m[0].length)
      });
    }
  });

  var maxDed = maxOf(results.map(function (r) { return r.deduction; }));
  var avgDed = results.reduce(function (s, r) { return s + r.deduction; }, 0) / results.length;
  var totalDeduction = maxDed * 0.7 + avgDed * 0.3 + crossDeduction;
  var score = Math.max(0, Math.min(100, Math.round(100 - totalDeduction)));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Puntaje del peor caso entre las ' + results.length + ' herramienta(s) analizadas, ponderado con el promedio' +
      (crossFindings.length ? ' e incluye un patrón detectado solo al combinar varias herramientas.' : '.'),
    hallazgosCombinados: crossFindings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; }),
    herramientas: results.map(function (r) {
      var tb = bucket(100 - r.deduction * 1.1);
      return {
        nombre: r.name,
        veredicto: tb.label,
        hallazgos: r.findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
      };
    })
  };
}

module.exports = {
  auditToolDescriptions: auditToolDescriptions,
  analyzeText: analyzeText,
  RULES: RULES,
  bucket: bucket,
  collectToolText: collectToolText,
  normalizeToolEntry: normalizeToolEntry
};
