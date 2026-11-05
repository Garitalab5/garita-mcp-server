"use strict";
// Escudo de Agencia Excesiva — detector de herramientas con permiso
// para ejecutar una acción irreversible/de alto valor sin confirmación
// exigida ni tope de magnitud
// ================================================================================
// A diferencia de las herramientas 9-18/28 (que analizan CÓDIGO FUENTE) y
// de detect_toxic_flow_risk (que mira la COMBINACIÓN de capacidades entre
// varias herramientas), esta analiza el MANIFIESTO de un servidor MCP —
// igual que audit_mcp_server, detect_poisoned_tool_descriptions y
// detect_tool_rug_pull — pero mira una sola herramienta a la vez en busca
// de "agencia excesiva" (OWASP LLM06 / GenAI Top 10): una herramienta cuyo
// nombre o descripción indica una acción irreversible o de alto valor
// (transferir, retirar, pagar, borrar, eliminar, apagar) sin ningún campo
// de confirmación EXIGIDO en su esquema de entrada (required), y/o sin
// ningún tope máximo (maximum/exclusiveMaximum) en un campo de
// monto/cantidad — nada impide que una sola llamada mueva una cantidad
// arbitrariamente grande, ni que se ejecute sin que nada ni nadie la
// revise antes.
//
// Motivada directamente por el hackeo de Binance de octubre de 2026 (6.300
// millones de dólares, el mayor robo cripto de la historia): según el
// relato preliminar de la propia Binance y el análisis de TRM Labs, un
// solo dispositivo/credencial comprometido (una laptop de un ingeniero)
// alcanzó un sistema con autoridad para firmar/autorizar retiros, y pudo
// ordenarlos sin ninguna aprobación independiente ni tope por operación —
// exactamente el patrón de diseño que esta herramienta busca en el
// esquema de ENTRADA de una herramienta MCP, antes de que un incidente así
// ocurra con un agente de IA de por medio. Es la misma categoría (OWASP
// LLM06 "Excessive Agency") que había quedado pendiente de construir en
// un lote anterior.
//
// Convención de "gatillo real vs. afirmación de texto" (misma lección ya
// aplicada en detect_sql_injection_risk y detect_toxic_flow_risk): un
// campo EXIGIDO en el esquema de entrada (required) cuenta como mitigación
// real; una descripción que solo PROMETE pedir aprobación no cuenta —
// nada obliga al agente a respetarla.
//
// Es un análisis de PATRONES DE TEXTO sobre el manifiesto (no ejecuta
// nada, no es un parser de JSON Schema completo). Límite conocido: la
// lista de verbos/sustantivos de acción "irreversible o de alto valor" es
// una muestra representativa, no exhaustiva — una acción destructiva con
// un nombre muy atípico puede no reconocerse.

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

// Mismo normalizador que detect_toxic_flow_risk: separa camelCase y
// convierte snake_case/kebab-case en espacios antes de aplicar \b, para
// que un nombre de herramienta como "transferFunds" o "borrar_cuenta" se
// reconozca igual que "transfer funds"/"borrar cuenta".
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

// Verbos/frases de acción irreversible o de alto valor: movimiento de
// dinero (transferir, retirar, pagar, enviar/mover fondos) y operaciones
// destructivas de infraestructura (borrar, eliminar, formatear, apagar,
// revocar, purgar) — el tipo de acción que, una vez ejecutada, no se puede
// deshacer con una simple llamada posterior.
var DESTRUCTIVA_ALTO_VALOR = /\b(transfer|transferir|transfiere|withdraw|retirar|retira|wire transfer|pay|pagar|paga|send funds|enviar fondos|envia fondos|move funds|mover fondos|mueve fondos|approve payment|aprobar pago|execute trade|ejecutar operacion|delete|borrar|borra|eliminar|elimina|drop table|drop database|format|formatear|formatea|wipe|purge|purgar|purga|revoke|revocar|revoca|shutdown|apagar|apaga)\b/i;

// Mismo campo de confirmación EXIGIDO que detect_toxic_flow_risk reconoce
// como mitigación real (confirm/aprob/approv/human review/revisión
// humana) — no una herramienta separada de "pedir aprobación": nada obliga
// al agente a llamarla antes.
var GATE_FIELD = /confirm|aprob|approv|human[_ ]?review|revisi[oó]n[_ ]?humana/i;

function isGated(tool) {
  var schema = tool && tool.inputSchema;
  if (!schema || typeof schema !== 'object') return false;
  var required = Array.isArray(schema.required) ? schema.required : [];
  return required.some(function (name) { return typeof name === 'string' && GATE_FIELD.test(name); });
}

// Campos de monto/cantidad (amount/cantidad/monto/importe/valor/value) sin
// ningún tope máximo (maximum/exclusiveMaximum) declarado en su propio
// esquema — nada limita cuánto se puede mover en una sola llamada.
var AMOUNT_FIELD_NAME = /amount|cantidad|monto|importe|valor|value/i;

function findUnboundedAmountFields(tool) {
  var schema = tool && tool.inputSchema;
  if (!schema || typeof schema !== 'object' || !schema.properties || typeof schema.properties !== 'object') return [];
  var out = [];
  Object.keys(schema.properties).forEach(function (key) {
    if (!AMOUNT_FIELD_NAME.test(key)) return;
    var prop = schema.properties[key];
    var hasCap = prop && typeof prop === 'object' && (typeof prop.maximum === 'number' || typeof prop.exclusiveMaximum === 'number');
    if (!hasCap) out.push(key);
  });
  return out;
}

function classify(tool, idx) {
  var text = toolText(tool);
  var esDestructiva = DESTRUCTIVA_ALTO_VALOR.test(text);
  return {
    nombre: (tool && tool.name) || ('herramienta_' + (idx + 1)),
    esDestructiva: esDestructiva,
    gated: isGated(tool),
    camposSinTope: esDestructiva ? findUnboundedAmountFields(tool) : []
  };
}

function checkExcessiveAgencyRisk(input) {
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

  var destructivas = classified.filter(function (c) { return c.esDestructiva; });
  var destructivasSinGatillo = destructivas.filter(function (c) { return !c.gated; });
  var destructivasSinTope = destructivas.filter(function (c) { return c.camposSinTope.length > 0; });

  var findings = [];
  var deduction = 0;

  if (destructivasSinGatillo.length > 0) {
    var ded1 = 55 + Math.min(20, (destructivasSinGatillo.length - 1) * 10);
    deduction += ded1;
    findings.push({
      sev: 'critical',
      label: 'Agencia excesiva: la herramienta "' + destructivasSinGatillo[0].nombre + '" puede ejecutar una acción irreversible o de alto valor (transferir, retirar, pagar, borrar...) sin ningún campo de confirmación exigido (required) en su esquema de entrada' +
        (destructivasSinGatillo.length > 1 ? ' — y ' + (destructivasSinGatillo.length - 1) + ' herramienta(s) más en la misma condición' : '') +
        '. El mismo patrón de diseño señalado tras el hackeo de Binance de octubre 2026 (6.300 millones de dólares): un solo dispositivo/credencial comprometido pudo autorizar retiros sin ninguna aprobación independiente (OWASP LLM06 "Excessive Agency")',
      snippet: null
    });
  }

  if (destructivasSinTope.length > 0) {
    var ded2 = 30 + Math.min(15, (destructivasSinTope.length - 1) * 10);
    deduction += ded2;
    findings.push({
      sev: 'warn',
      label: 'Sin tope de magnitud: el campo "' + destructivasSinTope[0].camposSinTope[0] + '" de la herramienta "' + destructivasSinTope[0].nombre + '" (una acción irreversible o de alto valor) no tiene ningún límite máximo (maximum/exclusiveMaximum) declarado en su esquema — nada impide que una sola llamada mueva una cantidad arbitrariamente grande',
      snippet: null
    });
  }

  var resumen;
  if (findings.length === 0) {
    if (destructivas.length === 0) {
      resumen = 'No se encontraron herramientas que ejecuten una acción irreversible o de alto valor (transferir, retirar, pagar, borrar, etc.) en este manifiesto.';
    } else {
      resumen = 'Se encontraron herramientas que ejecutan una acción irreversible o de alto valor, pero todas exigen un campo de confirmación real y, cuando manejan un monto, tienen un tope máximo definido en su esquema.';
    }
    findings.push({ sev: 'ok', label: resumen, snippet: null });
  } else {
    resumen = 'Se encontraron ' + destructivas.length + ' herramienta(s) con una acción irreversible o de alto valor (' + destructivasSinGatillo.length + ' sin confirmación exigida, ' + destructivasSinTope.length + ' sin tope de magnitud en un campo de monto).';
  }

  var score = Math.max(0, Math.min(100, 100 - deduction));
  var b = bucket(score);

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: resumen,
    hallazgos: findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
  };
}

module.exports = {
  checkExcessiveAgencyRisk: checkExcessiveAgencyRisk,
  classify: classify,
  isGated: isGated,
  findUnboundedAmountFields: findUnboundedAmountFields,
  normalize: normalize
};
