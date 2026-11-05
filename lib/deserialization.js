"use strict";
// Detector de riesgo de deserialización insegura (carga de datos serializados
// que puede terminar ejecutando código arbitrario al momento de "leerlos")
// ================================================================================
// Problema real: funciones como pickle.load() en Python, torch.load() (usada
// para cargar modelos de IA), o yaml.load() sin un cargador seguro, no solo
// "leen datos" — pueden reconstruir objetos arbitrarios de Python, y un objeto
// puede definir un método __reduce__ que, al reconstruirse, ejecuta cualquier
// código que el atacante haya empaquetado ahí. No hace falta ninguna otra falla:
// basta con que la función reciba bytes que vienen de afuera (un archivo
// subido, una respuesta de red, un argumento de una herramienta MCP).
//
// Motivado por fallas reales y recientes de 2025: CVE-2025-45146 (CVSS 9.8,
// CRÍTICO) en ModelCache, una librería de caché para agentes/LLM — llamaba a
// torch.load() sobre bytes de un modelo que llegaban sin validar, permitiendo
// ejecución remota de código vía un payload de pickle con __reduce__. Y
// CVE-2025-32434 (CVSS 9.3), que mostró que incluso la mitigación
// RECOMENDADA por PyTorch (weights_only=True) no bloqueaba la ejecución de
// código en versiones de torch anteriores a la 2.6.0 — es decir, ni siquiera
// la defensa "oficial" alcanza sola, así que este detector la trata como una
// señal que REDUCE el riesgo, no como algo que lo elimina.
//
// Esto es un análisis ESTÁTICO por patrones de texto sobre el CÓDIGO de una
// herramienta (no ejecuta nada) — mismo enfoque y mismas limitaciones que el
// resto del catálogo: no reemplaza un analizador de sintaxis (AST) real ni
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

// Funciones que SIEMPRE reconstruyen objetos arbitrarios a partir de bytes —
// no existe una variante "segura" con un parámetro que las vuelva inofensivas.
var SIEMPRE_PELIGROSA = /\bpickle\.(?:load|loads)\s*\(|\bc[Pp]ickle\.(?:load|loads)\s*\(|\b_pickle\.(?:load|loads)\s*\(|\bmarshal\.loads\s*\(|\bdill\.loads\s*\(|\bjoblib\.load\s*\(|\bunserialize\s*\(/gi;

// Funciones que reconstruyen objetos arbitrarios SOLO si no se usa la opción
// que las vuelve seguras — yaml.load() con un Loader seguro, o torch.load()
// con weights_only=True, se comportan distinto y no deserializan código.
var CONDICIONAL_PELIGROSA = /\byaml\.load\s*\(|\btorch\.load\s*\(/gi;

var YAML_SAFE_LOADER = /Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)\b/;
var TORCH_WEIGHTS_ONLY = /weights_only\s*=\s*True\b/;

// Señal de que el código ya toma alguna precaución reconocible: una subclase
// de Unpickler que restringe find_class (el patrón estándar de "pickle
// seguro" en Python), o una verificación de firma/checksum antes de cargar.
var VALIDACION = /RestrictedUnpickler|find_class|verify_signature|verificar_firma|\bhmac\.compare_digest\(|\bchecksum\b|\bsha256\s*\(.*\)\s*==|allow_pickle\s*=\s*False/i;

// Palabras que indican que los bytes a deserializar vienen de una fuente
// externa (no un archivo local fijo que el propio desarrollador empaquetó).
var FUENTE_NO_CONFIABLE = /\brequest\b|\breq\.|\bflask\b|\bupload\w*\b|\.recv\s*\(|\bsocket\b|urlopen\s*\(|\bdownload\w*\b|response\.content|\btool_input\b|\bargumento\b|\bmcp\b|\bremote\b|\.body\b|\bPOST\b|network/i;

// Un método __reduce__/__reduce_ex__ que, al reconstruirse, ejecuta un
// comando del sistema — la firma clásica de un payload malicioso de pickle
// (herramientas de red-team, o código de verdad comprometido). Incluye,
// además de la forma directa "os.system(...)", las formas indirectas que
// llegan al mismo sumidero sin escribir el substring literal "os.system":
// getattr(os, 'system')/getattr(os, 'popen') (busca el atributo en runtime,
// evade cualquier detector que solo busque "os.system") y __import__('os')
// (importa el módulo sin la palabra "os." pegada a nada).
var REDUCE_GADGET = /def\s+__reduce(?:_ex)?__\s*\([^)]*\)\s*:[\s\S]{0,300}?(?:os\.system|os\.popen|subprocess\.\w+|eval\s*\(|exec\s*\(|getattr\s*\(\s*os\s*,\s*["']system["']|getattr\s*\(\s*os\s*,\s*["']popen["']|__import__\s*\(\s*["']os["']\s*\))/;

function findOperaciones(text) {
  var ops = [];

  var reS = new RegExp(SIEMPRE_PELIGROSA.source, SIEMPRE_PELIGROSA.flags);
  var m;
  while ((m = reS.exec(text))) {
    ops.push({ index: m.index, callText: m[0], tipo: 'siempre' });
    if (m.index === reS.lastIndex) reS.lastIndex++;
  }

  var reC = new RegExp(CONDICIONAL_PELIGROSA.source, CONDICIONAL_PELIGROSA.flags);
  while ((m = reC.exec(text))) {
    var startArg = m.index + m[0].length;
    var argWindow = text.slice(startArg, startArg + 200);
    var esYaml = /^yaml\.load/i.test(m[0]);
    var esSeguro = esYaml ? YAML_SAFE_LOADER.test(argWindow) : TORCH_WEIGHTS_ONLY.test(argWindow);
    if (!esSeguro) {
      ops.push({ index: m.index, callText: m[0], tipo: 'condicional' });
    }
    if (m.index === reC.lastIndex) reC.lastIndex++;
  }

  ops.sort(function (a, b) { return a.index - b.index; });
  return ops;
}

// Quita el texto de comentarios (Python "# ..." y JS "// ..." / "/* ... */")
// antes de buscar una señal de validación cerca de una llamada peligrosa —
// un comentario que solo PROMETE una validación ("TODO: verificar checksum
// antes de cargar esto, pendiente") no debe contar como si el código
// realmente la hiciera. Limpieza simple línea por línea, no un parser real:
// no distingue un "#"/"//" dentro de un string literal de uno que abre un
// comentario de verdad, pero alcanza para este propósito.
function stripComments(text) {
  var sinLineComments = text.split('\n').map(function (line) {
    var idx = line.search(/#|\/\//);
    return idx === -1 ? line : line.slice(0, idx);
  }).join('\n');
  return sinLineComments.replace(/\/\*[\s\S]*?\*\//g, '');
}

function findReduceGadget(text) {
  var m = REDUCE_GADGET.exec(text);
  if (!m) return null;
  return { index: m.index, snippet: contextSnippet(text, m.index, Math.min(m[0].length, 60)) };
}

// input: { codigo: string, lenguaje?: string } — "lenguaje" es solo informativo,
// no cambia la detección (los patrones ya cubren varios lenguajes a la vez).
function checkInsecureDeserializationRisk(input) {
  input = input || {};
  var codigo = input.codigo;
  if (typeof codigo !== 'string' || !codigo.trim()) {
    throw new Error('Debes enviar "codigo" (el código fuente de la herramienta que deserializa datos) con contenido.');
  }
  var text = codigo;
  var findings = [];
  var deduction = 0;

  var operaciones = findOperaciones(text);

  var noValidadas = operaciones.filter(function (o) {
    var contextStart = Math.max(0, o.index - 400);
    var contexto = stripComments(text.slice(contextStart, o.index) + o.callText);
    return !VALIDACION.test(contexto);
  });

  if (noValidadas.length > 0) {
    var ded1 = 55 + Math.min(20, (noValidadas.length - 1) * 10);
    deduction += ded1;
    var vistoSiempre = false, vistoCondicional = false;
    noValidadas.forEach(function (o) {
      var contextStart = Math.max(0, o.index - 400);
      var contexto = text.slice(contextStart, o.index);
      var deFuenteNoConfiable = FUENTE_NO_CONFIABLE.test(contexto);
      if (o.tipo === 'siempre' && !vistoSiempre) {
        vistoSiempre = true;
        findings.push({
          sev: 'critical',
          label: 'Llamada a una función que reconstruye objetos arbitrarios a partir de bytes (' + o.callText.replace(/\($/, '') + ') — no tiene una variante "segura" con un parámetro; si los bytes vienen de afuera, un atacante puede ejecutar código con solo lograr que se "carguen"' + (deFuenteNoConfiable ? ' (el contexto sugiere que los datos vienen de una fuente externa: petición, subida de archivo, red)' : ''),
          snippet: contextSnippet(text, o.index, o.callText.length)
        });
      } else if (o.tipo === 'condicional' && !vistoCondicional) {
        vistoCondicional = true;
        var esYaml = /^yaml\.load/i.test(o.callText);
        findings.push({
          sev: 'critical',
          label: esYaml
            ? 'yaml.load() sin especificar un Loader seguro (Loader=yaml.SafeLoader, o usar yaml.safe_load()) puede reconstruir cualquier objeto de Python a partir del YAML, no solo datos'
            : 'torch.load() sin weights_only=True puede ejecutar código arbitrario al cargar un archivo de modelo — la propia mitigación recomendada por PyTorch (CVE-2025-32434 mostró que ni siquiera weights_only=True bastaba en versiones anteriores a la 2.6.0, así que además conviene mantener PyTorch actualizado)',
          snippet: contextSnippet(text, o.index, o.callText.length)
        });
      }
    });
  }

  var gadget = findReduceGadget(text);
  if (gadget) {
    deduction += 55;
    findings.push({
      sev: 'critical',
      label: 'Se encontró un método __reduce__/__reduce_ex__ que, al reconstruirse durante una deserialización, ejecuta un comando del sistema — la firma clásica de un payload malicioso de pickle',
      snippet: gadget.snippet
    });
  }

  if (findings.length === 0) {
    if (operaciones.length === 0) {
      findings.push({ sev: 'ok', label: 'No se encontró ninguna llamada de deserialización insegura (pickle, torch.load, yaml.load sin Loader seguro, y equivalentes).', snippet: null });
    } else {
      findings.push({ sev: 'ok', label: 'Se encontraron llamadas de deserialización, pero todas usan la forma segura (yaml.safe_load/Loader seguro, torch.load con weights_only=True) o pasan por una validación reconocible.', snippet: null });
    }
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Se encontraron ' + operaciones.length + ' llamada(s) de deserialización potencialmente insegura, ' + noValidadas.length + ' sin ninguna validación reconocible cerca.',
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkInsecureDeserializationRisk: checkInsecureDeserializationRisk,
  findOperaciones: findOperaciones,
  findReduceGadget: findReduceGadget,
  bucket: bucket
};
