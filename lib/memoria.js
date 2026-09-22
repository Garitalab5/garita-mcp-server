"use strict";
// Detector de Envenenamiento de Memoria — motor de detección
// ============================================================
// Problema real: un agente con memoria persistente (notas, resúmenes de
// conversación, hechos guardados sobre el usuario) puede terminar
// guardando una instrucción maliciosa plantada por un tercero — un
// documento, una página web, la salida de otra herramienta, o incluso un
// resumen automático de una conversación vieja — y esa instrucción se
// activa recién SEMANAS después, en una sesión sin relación con el
// ataque original. Documentado en el método MINJA (NeurIPS 2025, más de
// 95% de éxito contra agentes en producción) y en un ataque real contra
// Gemini (investigador Johann Rehberger, 2025) usando frases-gatillo
// condicionales ("si el usuario dice que sí...") que activaban una
// "memoria falsa" plantada de antemano.
//
// Esto es distinto de Garita Escudo (lib/escudo.js), que revisa
// descripciones de HERRAMIENTAS. Acá se revisa CONTENIDO que va HACIA
// (o ya está DENTRO de) la memoria de largo plazo del agente — notas,
// hechos guardados, resúmenes — antes o después de guardarse.
//
// Principio de diseño (igual que en escudo.js): reglas compuestas para
// no marcar el uso normal del producto. Un usuario real pidiéndole al
// agente "acordate que prefiero el café con leche" es exactamente lo que
// este tipo de herramienta debe permitir — así que la fuente declarada
// del texto ("fuente") pesa en el puntaje, salvo en los patrones que NO
// tienen ninguna razón legítima de existir sin importar quién los
// escriba (combinación de persistencia + secreto, suplantación de
// autoridad del sistema, exfiltración programada a futuro).

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

var FUENTES_VALIDAS = ['usuario_directo', 'documento_o_web', 'resumen_automatico', 'salida_de_herramienta', 'desconocida'];

function contextSnippet(text, idx, len) {
  var start = Math.max(0, idx - 34);
  var end = Math.min(text.length, idx + len + 34);
  var prefix = start > 0 ? '…' : '';
  var suffix = end < text.length ? '…' : '';
  return prefix + text.slice(start, idx) + '[' + text.slice(idx, idx + len) + ']' + text.slice(idx + len, end) + suffix;
}

// ---------- reglas de detección ----------
// "pesoDirecto" es el multiplicador aplicado a la deducción cuando
// fuente === 'usuario_directo' (1 = igual de grave venga de quien venga,
// menor que 1 = se atenúa porque el propio usuario pidiéndoselo es uso
// normal del producto).
var RULES = [
  {
    id: 'persistencia_mas_secreto', sev: 'critical', deduction: 55, pesoDirecto: 1,
    label: 'Combinación de "recordar esto para siempre" + "no lo menciones" — casi nunca es legítima venga de donde venga',
    // Requiere AMBAS partes cerca una de otra: una frase de persistencia
    // (recuérdalo para siempre / en todas las conversaciones futuras) Y
    // una frase de secreto (no se lo digas al usuario / no lo menciones).
    regexPersistencia: /\b(recuerd\w*\s+esto\s+para\s+siempre|guard\w*\s+esto\s+para\s+siempre|en\s+todas\s+las\s+conversaciones\s+futuras|de\s+ahora\s+en\s+adelante\s+siempre|para\s+siempre\s+a\s+partir\s+de\s+ahora|remember\s+this\s+forever|in\s+all\s+future\s+conversations|from\s+now\s+on\s+always|permanently\s+remember)\b/i,
    regexSecreto: /\bno\s+(le\s+)?(se\s+(lo|la|los|las)\s+)?(digas?|menciones?|informes?|reveles?|cuentes?)\s+(esto\s+)?(a\s+)?(el|al)?\s*usuario\b|sin\s+dec[ií]rselo\s+a\s+nadie|no\s+lo\s+menciones|mant[eé]n(lo)?\s+en\s+secreto|don'?t\s+(tell|mention|reveal|inform)\s+(this\s+to\s+)?(the\s+)?user\b|without\s+telling\s+(anyone|the\s+user)|keep\s+this\s+(secret|hidden)\b/i
  },
  {
    id: 'gatillo_condicional', sev: 'critical', deduction: 40, pesoDirecto: 0.5,
    label: 'Instrucción condicional del tipo "si el usuario dice X, hacé Y" — patrón documentado del ataque de memoria falsa en Gemini (Rehberger, 2025)',
    // OJO: sin \b de cierre — varias ramas terminan en una vocal acentuada
    // (ejecutá, actuá) y el \b por defecto de JS no ve límite de palabra
    // entre una vocal con tilde y un espacio (trata la tilde como "no
    // palabra" en ambos lados), así que un \b final ahí nunca coincide.
    regex: /\b(si\s+(el\s+)?usuario\s+(dice|escribe|menciona|pregunta|responde)\b[\s\S]{0,150}\b(entonces\s+)?(hac[eé]|respond[eé]|actu[aá]|ejecut[aá]|ol\.?vid[aá])|cuando\s+alguien\s+(pregunte|diga|escriba|mencione)\b[\s\S]{0,150}\b(respond[eé]|hac[eé]|actu[aá])|if\s+(the\s+)?user\s+(says?|writes?|mentions?|asks?|responds?)\b[\s\S]{0,150}\bthen\b[\s\S]{0,60}\b(do|respond|act|execute|reply)|when\s+(someone|the\s+user)\s+(asks?|says?|mentions?)\b[\s\S]{0,150}\b(respond|do|act|reply))/i
  },
  {
    id: 'suplantacion_autoridad', sev: 'critical', deduction: 55, pesoDirecto: 1,
    label: 'Se hace pasar por una instrucción del sistema o pide ignorar instrucciones anteriores',
    regex: /\b(esto\s+es\s+una\s+instrucci[oó]n\s+(del\s+)?sistema|instrucci[oó]n(es)?\s+(actualizad|nuev)\w*\s+del\s+sistema|tus\s+(reglas|instrucciones)\s+han\s+cambiado|ignora\s+(las\s+)?instrucciones\s+anteriores|olvida\s+(las\s+)?instrucciones\s+anteriores|this\s+is\s+a\s+system\s+instruction|your\s+(rules|instructions)\s+have\s+(been\s+)?(updated|changed)|ignore\s+(all\s+)?(previous|prior)\s+instructions|disregard\s+(all\s+)?(previous|prior)\s+(instructions|guidance))\b/i
  },
  {
    id: 'exfiltracion_en_recuperacion', sev: 'critical', deduction: 55, pesoDirecto: 1,
    label: 'Instrucción para enviar/compartir datos a un tercero la próxima vez que se recupere esta memoria',
    regex: /\b(la\s+pr[oó]xima\s+vez\s+que\s+(tengas|ten[eé]s)\s+acceso\b[\s\S]{0,150}\b(env[ií]a|compart[ií]|copia|manda)|(env[ií]a|compart[ií]|copia|manda)\b[\s\S]{0,150}\bla\s+pr[oó]xima\s+vez\s+que\s+(tengas|ten[eé]s)\s+acceso|next\s+time\s+you\s+(have|get)\s+access\b[\s\S]{0,150}\b(send|share|copy|forward)|(send|share|copy|forward)\b[\s\S]{0,150}\bnext\s+time\s+you\s+(have|get)\s+access)\b/i
  },
  {
    id: 'direccionamiento_directo_ia', sev: 'warn', deduction: 25, pesoDirecto: 0.1,
    label: 'El texto se dirige directamente al asistente de IA por su nombre/rol como si le estuviera dando una orden — inusual en contenido de terceros (documento, web, resumen, salida de herramienta)',
    // Sin \b de cierre por la misma razón que en "gatillo_condicional":
    // "record[aá]" puede terminar en tilde y el \b por defecto no lo ve
    // como límite de palabra frente a un espacio.
    regex: /\b(claude|asistente(\s+de\s+ia)?|ia\b|assistant|ai\b)\s*[,:]\s*(record[aá]|ten[eé]\s+en\s+cuenta|hac[eé]|ejecut[aá]|a\s+partir\s+de\s+ahora|remember|keep\s+in\s+mind|from\s+now\s+on|do\s+this|note\s+that)/i
  },
  {
    id: 'formato_falso_sistema', sev: 'critical', deduction: 30, pesoDirecto: 1,
    label: 'Bloque con formato de etiqueta de sistema (<system>, [INSTRUCTION], ### SYSTEM) escondido dentro del contenido — intenta parecer una instrucción con autoridad',
    regex: /<\s*(system|instructions?|admin|override|directive)\b[^>]{0,60}>|\[\s*(system|instruction|admin|override)\s*\]|#{2,3}\s*(SYSTEM|INSTRUCTION)\b/i
  },
  {
    id: 'instruccion_futura_generica', sev: 'warn', deduction: 15, pesoDirecto: 0.2,
    label: 'Instrucción de comportamiento para futuras interacciones — leve por sí sola, se suma si aparece junto a otras señales',
    regex: /\b(para\s+(futuras|pr[oó]ximas)\s+interacciones|en\s+tus\s+pr[oó]ximas\s+respuestas|ten\s+en\s+cuenta\s+para\s+despu[eé]s|for\s+future\s+interactions|in\s+your\s+next\s+responses|keep\s+this\s+in\s+mind\s+for\s+next\s+time)\b/i
  }
];

function analyzeMemoryText(texto, fuente) {
  var text = String(texto || '');
  var findings = [];
  var deduction = 0;
  var firedIds = [];

  RULES.forEach(function (rule) {
    var peso = (fuente === 'usuario_directo') ? rule.pesoDirecto : 1;

    if (rule.regexPersistencia && rule.regexSecreto) {
      var mp = rule.regexPersistencia.exec(text);
      var ms = rule.regexSecreto.exec(text);
      if (mp && ms) {
        var ded = Math.round(rule.deduction * peso);
        deduction += ded;
        firedIds.push(rule.id);
        findings.push({ sev: rule.sev, label: rule.label, snippet: contextSnippet(text, mp.index, mp[0].length) });
      }
      return;
    }

    var m = rule.regex.exec(text);
    if (m) {
      var ded2 = Math.round(rule.deduction * peso);
      if (ded2 <= 0) return; // atenuado a cero por la fuente (ej. usuario directo dirigiéndose al asistente)
      deduction += ded2;
      firedIds.push(rule.id);
      findings.push({ sev: rule.sev, label: rule.label, snippet: contextSnippet(text, m.index, m[0].length) });
    }
  });

  if (!text.trim()) {
    findings.push({ sev: 'warn', label: 'Sin texto para analizar.', snippet: null });
  } else if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'Sin señales de envenenamiento de memoria en el texto.', snippet: null });
  }

  return { deduction: deduction, findings: findings, firedIds: firedIds };
}

// ---------- punto de entrada ----------
// input: { texto: string, fuente?: 'usuario_directo'|'documento_o_web'|
//          'resumen_automatico'|'salida_de_herramienta'|'desconocida' }
function checkMemoryPoisoning(input) {
  input = input || {};
  var texto = input.texto;
  if (typeof texto !== 'string' || !texto.trim()) {
    throw new Error('Debes enviar "texto" (el contenido que se va a guardar o ya está guardado en memoria) con contenido.');
  }
  var fuente = FUENTES_VALIDAS.indexOf(input.fuente) !== -1 ? input.fuente : 'desconocida';

  var result = analyzeMemoryText(texto, fuente);
  var score = Math.max(0, Math.min(100, 100 - result.deduction));
  var b = bucket(score);

  var fuenteEtiquetas = {
    usuario_directo: 'el propio usuario, en la conversación actual',
    documento_o_web: 'un documento o página web',
    resumen_automatico: 'un resumen automático de una conversación anterior',
    salida_de_herramienta: 'la salida de otra herramienta (API, búsqueda, archivo)',
    desconocida: 'sin especificar (se trata como no confiable por precaución)'
  };

  return {
    puntaje: score,
    veredicto: b.label,
    fuente: fuente,
    resumen: 'Texto evaluado como proveniente de: ' + fuenteEtiquetas[fuente] + '.',
    hallazgos: result.findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkMemoryPoisoning: checkMemoryPoisoning,
  analyzeMemoryText: analyzeMemoryText,
  RULES: RULES,
  FUENTES_VALIDAS: FUENTES_VALIDAS,
  bucket: bucket
};
