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

function stripInvisibles(str) {
  return String(str).replace(/[​‌‍⁠﻿]/g, '');
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
  if ((!ann || ann.destructiveHint === undefined) && DESTRUCTIVE_VERBS.test(stripInvisibles(desc + ' ' + name))) {
    deduction += 14;
    findings.push({ sev: 'critical', text: 'La descripción sugiere una acción irreversible, pero no declara destructiveHint — el agente no puede saberlo de antemano.' });
  }
  if (!desc || desc.length < 8) {
    deduction += 8;
    findings.push({ sev: 'warn', text: 'Sin descripción útil — un agente puede invocarla sin entender su efecto.' });
  }
  var props = (tool && tool.inputSchema && tool.inputSchema.properties) || {};
  Object.keys(props).forEach(function (key) {
    if (CODE_FIELD_NAMES.test(key)) {
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
      var m = v.replace(/,/g, '').match(/-?\d+(\.\d+)?/);
      if (m) {
        var n = parseFloat(m[0]);
        if (!isNaN(n) && (max === null || n > max)) max = n;
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
  var text = stripInvisibles((action.tool || '') + ' ' + (action.description || '')).toLowerCase();
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
      if (CODE_FIELD_NAMES.test(key)) triggered.push('El argumento "' + key + '" contiene código o comandos libres.');
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

module.exports = { auditManifest, simulateApproval, DESTRUCTIVE_VERBS, CODE_FIELD_NAMES, stripInvisibles, findMaxNumber };
