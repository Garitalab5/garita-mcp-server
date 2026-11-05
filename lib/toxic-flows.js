"use strict";
// Garita — Detector de Flujos Tóxicos (tool #16, 2026-09)
// =========================================================
// A diferencia de las herramientas 9-15 (que analizan CÓDIGO FUENTE de una
// sola función en busca de un sumidero peligroso), esta analiza un
// MANIFIESTO de servidor MCP completo — igual que audit_mcp_server,
// detect_poisoned_tool_descriptions y detect_tool_rug_pull — pero en vez
// de mirar el texto de una herramienta a la vez, mira la COMBINACIÓN de
// capacidades de TODO el conjunto de herramientas expuesto.
//
// El problema real que ataca es el "confused deputy" / "lethal trifecta":
// un servidor (o el conjunto de herramientas de un agente) que junta (a)
// una herramienta que lee datos privados o contenido no confiable, con
// (b) una herramienta que puede sacar datos hacia afuera (correo, HTTP,
// crear un comentario/issue público, subir un adjunto), sin ningún paso
// de aprobación real entre medio. Cada herramienta puede estar descrita
// con total honestidad y cada token puede estar bien alcanzado — el
// problema es la COMBINACIÓN, no un fallo dentro de una sola herramienta.
// Motivado por CVE-2026-77255 (mcp-atlassian), EchoLeak/CVE-2025-32711
// (Microsoft 365 Copilot) y el caso del servidor MCP de GitHub reportado
// por Invariant Labs ("Toxic Flow Analysis").
//
// Convención de "gatillo real vs. afirmación de texto" (misma lección de
// detect_sql_injection_risk con el hallazgo de Datadog sobre "solo
// lectura" declarado en texto pero no exigido por permisos reales): un
// campo de aprobación EXIGIDO en el esquema de entrada (required) cuenta
// como mitigación real; una herramienta separada de "pedir aprobación" en
// el mismo manifiesto NO cuenta — nada obliga al agente a llamarla antes.

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

// snake_case / kebab-case no tiene límite de palabra (\b) entre "_"/"-" y
// la letra siguiente porque "_" cuenta como caracter de palabra en JS
// (mismo tipo de bug ya encontrado y corregido en herramientas previas,
// ej. META_ACCESS_TOKEN en detect_hardcoded_secrets_risk) — normalizar
// antes de aplicar cualquier \b evita repetir ese error.
// camelCase (ej. "readLocalCredentialsFile") tampoco tiene separador
// alguno entre palabras — sin esto, un nombre de herramienta así queda
// como una sola palabra pegada ("readlocalcredentialsfile") y ningún
// sustantivo compuesto de las listas de abajo puede reconocerse adentro
// (\b nunca coincide en medio de una cadena de solo letras). Se inserta un
// espacio en cada transición minúscula→MAYÚSCULA ANTES de bajar todo a
// minúsculas, para no perder la transición.
function normalize(str) {
  return String(str || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/[_\-]+/g, ' ');
}

function toolText(tool) {
  var name = normalize(tool && tool.name);
  var desc = normalize(tool && tool.description);
  return (name + ' ' + desc).trim();
}

// Verbos de lectura/consulta. Se omite el \b de cierre en las formas en
// inglés a propósito, para que "reads"/"reading"/"queries" también
// disparen sin tener que listar cada conjugación — el \b de apertura ya
// evita falsos positivos tipo "spread" (no hay límite entre "p" y "r").
// Variantes en portugués (ler/lê/lendo, obter/acessar/baixar): "ler" y "lê"
// son cortas y "lê" termina en vocal acentuada, así que un \b de cierre
// normal sería el mismo bug de siempre (\b no coincide de forma confiable
// después de un carácter que JS no trata como "de palabra") — se usa un
// lookahead que solo exige que no siga otra letra ASCII.
var INGESTION_VERBOS = /\b(read|get|fetch|load|quer(?:y|ies|ying)|list|scan|search|download|import|retriev|obtain|access|leer|lee\b|leyendo|obtener|obtiene\b|consultar|consulta\b|listar|lista\b|buscar|busca\b|descargar|descarga\b|importar|importa\b|recuperar|recupera\b|acceder|accede\b|escanear|escanea\b|ler(?![a-zA-Z])|l[eê](?![a-zA-Z])|lendo|obter(?![a-zA-Z])|obt[eé]m(?![a-zA-Z])|acessar|acessa\b|baixar|baixa\b)/i;

// Sustantivos que marcan la fuente como datos PRIVADOS/sensibles (la
// mitad "datos privados" de la trifecta letal). Incluye variantes en
// portugués (arquivo/ficheiro, credenciais, senha, banco de dados, chave).
var PRIVADO_SUSTANTIVOS = /\b(files?|archivos?|arquivos?|ficheiros?|secrets?|secretos?|credentials?|credenciales?|credencial|credenciais|tokens?|api ?keys?|llaves?|chaves?|contrase[ñn]as?|passwords?|senhas?|database|base de datos|banco de dados|repositorio privado|private repo|variable(?:s)? de entorno|environment variable|ssh key|llave ssh|private key|clave privada|internal|interno|interna|calendario|calendar|datos de clientes?|customer data|local file|archivo local)\b/i;

// Sustantivos que marcan la fuente como contenido NO CONFIABLE / que un
// atacante externo puede influenciar (la otra mitad de la trifecta).
var NO_CONFIABLE_SUSTANTIVOS = /\b(emails?|correo electr[oó]nico|correos?|inbox|bandeja de entrada|web ?page|p[aá]gina web|urls?|enlaces?|links?|attachments?|adjuntos?|issues?|tickets?|comments?|comentarios?|pull request|external|externo|externa|p[uú]blico|public|internet|untrusted|no confiable)\b/i;

// Verbos de egreso (mandar datos hacia afuera). Mismo criterio: sin \b de
// cierre en inglés para cubrir conjugaciones sin listarlas todas.
var EGRESO_VERBOS = /\b(send|post|publish|upload|share|notify|forward|repl(?:y|ies|ying)|webhook|enviar|env[ií]a\b|enviando|publicar|publica\b|publicando|subir|sube\b|subiendo|compartir|comparte\b|compartiendo|notificar|notifica\b|notificando|reenviar|reenv[ií]a\b|reenviando|responder|responde\b|respondiendo)/i;

// "crear" solo cuenta como egreso si va acompañado de un sustantivo de
// salida (comentario/issue/publicación) cerca — "crear una tarea interna"
// no es lo mismo que "crear un comentario público en un issue".
var CREAR_EGRESO = /\b(create|creates|creating|crear|crea|creando)\b[\s\S]{0,25}\b(comments?|comentarios?|issues?|tickets?|posts?|publicaci[oó]n|pull request|\bpr\b)\b/i;

// Nombre de campo que, si el esquema de entrada lo EXIGE (required), es
// una mitigación real (no solo una afirmación en la descripción, que un
// agente podría ignorar) — pausa la herramienta hasta que algo externo
// confirme la acción.
var GATE_FIELD = /confirm|aprob|approv|human[_ ]?review|revisi[oó]n[_ ]?humana/i;

function isGated(tool) {
  var schema = tool && tool.inputSchema;
  if (!schema || typeof schema !== 'object') return false;
  var required = Array.isArray(schema.required) ? schema.required : [];
  return required.some(function (name) { return typeof name === 'string' && GATE_FIELD.test(name); });
}

function classify(tool, idx) {
  var text = toolText(tool);
  var ingestion = INGESTION_VERBOS.test(text);
  var privado = ingestion && PRIVADO_SUSTANTIVOS.test(text);
  var noConfiable = ingestion && NO_CONFIABLE_SUSTANTIVOS.test(text);
  var egreso = EGRESO_VERBOS.test(text) || CREAR_EGRESO.test(text);
  return {
    nombre: (tool && tool.name) || ('herramienta_' + (idx + 1)),
    privado: privado,
    noConfiable: noConfiable,
    egreso: egreso,
    gated: isGated(tool)
  };
}

function checkToxicFlowRisk(input) {
  input = input || {};
  if (input.manifest === undefined || input.manifest === null) {
    throw new Error('Falta el manifiesto.');
  }
  var data = input.manifest;
  var tools = Array.isArray(data) ? data : (data.tools || (data.name || data.description ? [data] : []));
  if (!tools.length) {
    throw new Error('El manifiesto no tiene un arreglo "tools", ni es una herramienta suelta con "name"/"description".');
  }

  var classified = tools.map(function (rawTool, idx) {
    var tool = typeof rawTool === 'string' ? { description: rawTool } : rawTool;
    return classify(tool, idx);
  });

  var privados = classified.filter(function (c) { return c.privado; });
  var noConfiables = classified.filter(function (c) { return c.noConfiable; });
  var ingestionRiesgosa = classified.filter(function (c) { return c.privado || c.noConfiable; });
  var egresosSinGatillo = classified.filter(function (c) { return c.egreso && !c.gated; });
  var egresosConGatillo = classified.filter(function (c) { return c.egreso && c.gated; });

  var findings = [];
  var score = 100;

  if (ingestionRiesgosa.length && egresosSinGatillo.length) {
    var ejemploIngestion = ingestionRiesgosa[0];
    var ejemploEgreso = egresosSinGatillo[0];
    var deduccion = 55 + Math.min(20, (egresosSinGatillo.length - 1) * 10);
    score -= deduccion;
    findings.push({
      sev: 'critical',
      label: 'Flujo tóxico: capacidad de lectura + capacidad de salida sin aprobación exigida en el esquema',
      snippet:
        '"' + ejemploIngestion.nombre + '" (lee ' +
        (ejemploIngestion.privado && ejemploIngestion.noConfiable ? 'datos privados y contenido no confiable' : (ejemploIngestion.privado ? 'datos privados/sensibles' : 'contenido externo no confiable')) +
        ') + "' + ejemploEgreso.nombre + '" (puede enviar/publicar datos hacia afuera, sin un campo de confirmación exigido en su esquema)' +
        (egresosSinGatillo.length > 1 ? ' — y ' + (egresosSinGatillo.length - 1) + ' herramienta(s) de salida más en la misma condición' : '')
    });
  }

  if (privados.length && noConfiables.length && egresosSinGatillo.length) {
    score -= 20;
    findings.push({
      sev: 'critical',
      label: 'Trifecta letal completa: datos privados + contenido no confiable + canal de salida, las tres en el mismo servidor',
      snippet:
        '"' + privados[0].nombre + '" (datos privados) + "' + noConfiables[0].nombre + '" (contenido no confiable, posible vector de inyección de instrucciones) + "' +
        egresosSinGatillo[0].nombre + '" (canal de salida) — mismo patrón que el caso EchoLeak (CVE-2025-32711) y el reportado por Invariant Labs en un servidor MCP de GitHub.'
    });
  }

  score = Math.max(0, Math.min(100, score));
  var b = bucket(score);

  var resumen;
  if (!findings.length) {
    if (!ingestionRiesgosa.length) {
      resumen = 'No se detectaron herramientas que lean datos privados o contenido externo no confiable — sin ese lado de la combinación, no puede formarse un flujo tóxico.';
    } else if (!classified.some(function (c) { return c.egreso; })) {
      resumen = 'No se detectaron herramientas con capacidad de enviar/publicar datos hacia afuera — sin un canal de salida, la lectura de datos privados o no confiables no puede convertirse en una fuga.';
    } else if (egresosConGatillo.length && !egresosSinGatillo.length) {
      resumen = 'Hay lectura de datos sensibles y también herramientas de salida, pero toda(s) exige(n) un campo de confirmación real en su esquema de entrada (required) — no se puede llamarlas a ciegas sin ese paso.';
    } else {
      resumen = 'No se encontró una combinación de lectura riesgosa y salida sin aprobación en este manifiesto.';
    }
  } else {
    resumen = 'Se encontraron ' + findings.length + ' flujo(s) tóxico(s) / combinación(es) de capacidades peligrosa(s): ' + b.label.toLowerCase() + ' (' + score + '/100).';
  }

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: resumen,
    hallazgos: findings.map(function (f) {
      return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet };
    })
  };
}

module.exports = {
  checkToxicFlowRisk: checkToxicFlowRisk,
  classify: classify,
  isGated: isGated,
  normalize: normalize
};
