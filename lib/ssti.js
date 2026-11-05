"use strict";
// Detector de inyección en plantillas (SSTI — Server-Side Template Injection)
// ================================================================================
// Problema real: una herramienta que compila una plantilla (Jinja2, EJS,
// Handlebars, Pug, Mustache, lodash, un PromptTemplate de LangChain) a partir
// de un string no confiable — en vez de usar ese string como DATO que se
// inserta en una plantilla fija — deja que un atacante escriba directamente
// en el lenguaje de expresiones del motor de plantillas. Eso no es lo mismo
// que HTML/XSS: la mayoría de estos motores permiten llamar métodos y
// recorrer atributos de objetos de Python/JS desde dentro de la plantilla
// (el gadget clásico en Jinja2 es algo como
// {{ ''.__class__.__mro__[1].__subclasses__() }}), así que una plantilla
// controlada por el atacante puede terminar en ejecución arbitraria de código
// (RCE) en el proceso del servidor — un análisis (command injection, inyección
// SQL) distinto y anterior a cualquiera de las 16 herramientas de Garita.
//
// Motivada por una serie de avisos reales de 2026 en herramientas de IA/
// agentes específicamente: CVE-2026-33154 (CVSS 8.1) en Dynaconf, una
// librería de configuración muy usada por apps de IA/agentes (RCE por
// evaluación insegura de plantillas en su resolver @jinja); GHSA-cfr2-mp74-3763
// en Agenta-AI (plataforma de evaluación de LLMs): "SSTI vía plantillas Jinja2
// de evaluador personalizado permite RCE"; y GHSA-6qv9-48xg-fc7f en
// LangChain — el framework de agentes más usado — "Template Injection via
// Attribute Access in Prompt Templates". Este último caso es el más
// relevante para Garita: un PromptTemplate armado con un string que no
// escribió el desarrollador (viene de una entrada del agente, de un usuario,
// o de otra herramienta) es exactamente el mismo patrón.
//
// Distingue, igual que detect_sql_injection_risk e isLiteralArg, una
// plantilla FIJA (un string literal que escribió el desarrollador — sin
// riesgo, aunque tenga variables adentro para RELLENAR) de una plantilla
// armada dinámicamente a partir de una variable/concatenación/entrada
// externa (la fuente misma del texto de la plantilla es controlable).
//
// Regla propia de Garita (mismo espíritu que el hallazgo de Datadog sobre
// "solo lectura" en detect_sql_injection_risk): el código afirma estar
// protegido porque "escapa la salida" (autoescape=True, html.escape,
// MarkupSafe) — pero eso NO evita SSTI. El escape de salida actúa sobre el
// HTML ya renderizado; la ejecución de código ocurre antes, al COMPILAR la
// plantilla, así que "escapar la salida" no es una defensa contra esto en
// absoluto — es una falsa sensación de seguridad.
//
// Es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada) — mismo enfoque y mismas limitaciones que
// lib/sql-injection.js, lib/command-injection.js y lib/ssrf.js: no reemplaza
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

// Funciones cuyo primer argumento (o el argumento nombrado "template"/
// "template_string") es tratado como el TEXTO/FUENTE de la plantilla, no
// como un dato que se rellena en una plantilla ya fija.
//   Python/Jinja2: render_template_string(), Template(...) (constructor),
//     Environment().from_string() — el patrón exacto de CVE-2026-33154/Dynaconf
//   LangChain: PromptTemplate(template=...), .from_template(...) — el patrón
//     exacto de GHSA-6qv9-48xg-fc7f
//   Node: ejs.compile()/ejs.render(), Handlebars.compile(), pug.compile()/
//     pug.render(), Mustache.render(), lodash _.template()
// PromptTemplate(...) se maneja aparte, en findPromptTemplateOperaciones —
// ver el comentario ahí sobre por qué no puede vivir en esta misma regex.
var SINK_PELIGROSO = /render_template_string\s*\(|\bTemplate\s*\(|from_string\s*\(|\.from_template\s*\(|ejs\.(?:compile|render)\s*\(|Handlebars\.compile\s*\(|pug\.(?:compile|render)\s*\(|Mustache\.render\s*\(|_\.template\s*\(/g;

var PROMPT_TEMPLATE_CALL = /PromptTemplate\s*\(/g;
var TEMPLATE_KWARG = /template\s*=/;
// Cuántos caracteres después de "PromptTemplate(" se buscan para encontrar
// "template=" — suficiente para cubrir otros argumentos con nombre antes
// (input_variables=[...], partial_variables={...}) sin tener que abarcar
// todo el archivo.
var PROMPT_TEMPLATE_WINDOW = 300;

// Uso de un entorno "sandboxeado" de Jinja2 — reduce el riesgo (no lo elimina
// del todo; se conocen fugas documentadas del sandbox de Jinja2 en el pasado,
// así que se trata como mitigación real pero parcial, mismo criterio que
// weights_only=True en detect_insecure_deserialization_risk) — se reconoce
// como señal de que ya se tomó una precaución real.
var SANDBOXED = /SandboxedEnvironment/;

// El código o sus comentarios afirman estar protegidos porque "escapan la
// salida" — una defensa real contra XSS, pero irrelevante contra SSTI (la
// ejecución ocurre al COMPILAR la plantilla, no al mostrarla).
var RECLAMA_ESCAPE_SUFICIENTE = /autoescape\s*=\s*True|escapes?\s+(?:the\s+)?output|escapa\s+la\s+salida|html\.escape\s*\(|markupsafe|Markup\s*\(/i;

function isLiteralArg(argWindow) {
  var trimmed = argWindow.replace(/^\s+/, '');
  var q = trimmed[0];
  if (q !== '"' && q !== "'" && q !== '`') return false; // no arranca con string -> variable/expresión (incluye prefijos f"/r" de Python)
  var closeIdx = trimmed.indexOf(q, 1);
  if (closeIdx === -1) return false; // no se puede confirmar, se trata como variable por precaución
  var inner = trimmed.slice(1, closeIdx);
  if (q === '`' && /\$\{/.test(inner)) return false; // template literal de JS con interpolación -> variable
  var after = trimmed.slice(closeIdx + 1, closeIdx + 24).replace(/^\s+/, '');
  if (after[0] === '+' || after[0] === '%') return false; // concatenación o formateo "%s" -> variable
  if (/^\.\s*format\s*\(/.test(after)) return false; // "Hola {}".format(x) -> variable
  // Concatenación IMPLÍCITA de literales adyacentes de Python (dos strings
  // pegados sin ningún operador entre medio, ej. "Hola " f"{tool_input}...":
  // Python los concatena solo en tiempo de compilación) — si después del
  // primer literal (saltando espacios/saltos de línea) sigue otra comilla,
  // o un prefijo f"/r"/rb" seguido de comilla, alguna de esas partes puede
  // seguir dependiendo de una entrada externa, así que ya no cuenta como un
  // literal fijo y cerrado.
  if (/^["'`]/.test(after) || /^(?:f|r|rb|fr|rf|b)["'`]/i.test(after)) return false;
  return true; // literal limpio que escribió el desarrollador, no depende de entrada externa
}

// PromptTemplate(...) necesita un enfoque en dos pasos, distinto del resto
// de los sumideros: el argumento "template=" casi nunca es el primero
// (típicamente va después de input_variables=[...] u otros kwargs), así que
// no se puede usar un solo regex con "[^)]*template\s*=" — ese "[^)]*" se
// corta en el primer ")" que encuentre, y una llamada a función ANTES de
// "template=" (ej. PromptTemplate(input_variables=extract_vars(x),
// template=x)) cierra ")" en "extract_vars(x)" y el match nunca llega a
// "template=". En vez de eso: primero se encuentra "PromptTemplate(" suelto,
// y después se busca "template=" en una ventana de caracteres razonable
// después de esa posición — sin exigir que esté dentro del mismo match ni
// que no haya paréntesis intermedios.
function findPromptTemplateOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(PROMPT_TEMPLATE_CALL.source, PROMPT_TEMPLATE_CALL.flags);
  var m;
  while ((m = re.exec(text))) {
    var startWindow = m.index + m[0].length;
    var window = text.slice(startWindow, startWindow + PROMPT_TEMPLATE_WINDOW);
    var tm = TEMPLATE_KWARG.exec(window);
    if (tm) {
      var startArg = startWindow + tm.index + tm[0].length;
      var argWindow = text.slice(startArg, startArg + 220);
      // callText es un prefijo real del texto (no un literal armado a mano)
      // para que quede como substring exacto de "text" empezando en
      // o.index — se recorta a un largo razonable para el snippet, aunque
      // "template=" haya aparecido lejos dentro de la ventana de búsqueda.
      var callText = m[0] + window.slice(0, Math.min(tm.index + tm[0].length, 120));
      operaciones.push({
        index: m.index,
        callText: callText,
        argWindow: argWindow,
        literal: isLiteralArg(argWindow)
      });
    }
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  return operaciones;
}

function findOperaciones(text) {
  var operaciones = [];
  var re = new RegExp(SINK_PELIGROSO.source, SINK_PELIGROSO.flags);
  var m;
  while ((m = re.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 220);
    operaciones.push({ index: m.index, callText: m[0], argWindow: argWindow, literal: isLiteralArg(argWindow) });
    if (m.index === re.lastIndex) re.lastIndex++; // evita loop infinito con matches vacíos
  }
  operaciones = operaciones.concat(findPromptTemplateOperaciones(text));
  operaciones.sort(function (a, b) { return a.index - b.index; });
  return operaciones;
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkSsTemplateInjectionRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que compila una plantilla) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);
  var candidatas = operaciones.filter(function (o) { return !o.literal; });

  var noValidadas = candidatas.filter(function (o) {
    var contextStart = Math.max(0, o.index - 600);
    var contexto = text.slice(contextStart, o.index) + o.callText + o.argWindow.slice(0, 100);
    return !SANDBOXED.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    noValidadas.slice(0, 3).forEach(function (o) {
      findings.push({
        sev: 'critical',
        label: 'Plantilla compilada a partir de una variable/entrada externa (no un texto fijo que escribió el desarrollador), sin usar un entorno sandboxeado — un atacante que controle ese texto puede escribir directamente en el lenguaje de expresiones del motor y terminar ejecutando código en el servidor',
        snippet: contextSnippet(text, o.index, o.callText.length)
      });
    });
  }

  var reclamaEscapeComoDefensa = candidatas.length > 0 && RECLAMA_ESCAPE_SUFICIENTE.test(text) && !SANDBOXED.test(text);
  if (reclamaEscapeComoDefensa) {
    deduction += 40;
    findings.push({
      sev: 'critical',
      label: 'El código (o su comentario) sugiere que "escapar la salida" (autoescape, html.escape, MarkupSafe) alcanza como protección — pero eso solo evita XSS en el HTML ya renderizado; en una inyección en plantillas la ejecución ocurre ANTES, al compilar la plantilla, así que escapar la salida no evita nada acá',
      snippet: null
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna compilación de plantilla a partir de una fuente dinámica en el código analizado.', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron compilaciones de plantilla, pero todas usan un texto fijo que escribió el desarrollador, o pasan por un entorno sandboxeado.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' compilación(es) de plantilla en el código, ' + candidatas.length + ' con la fuente de la plantilla dependiendo de una entrada externa.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkSsTemplateInjectionRisk: checkSsTemplateInjectionRisk,
  findOperaciones: findOperaciones,
  isLiteralArg: isLiteralArg,
  bucket: bucket
};
