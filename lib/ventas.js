"use strict";
// Asistente de Ventas — chat público de garitalabs.dev
// ================================================================================
// A diferencia de Vigía (lib/vigia.js), este asistente NO tiene acceso a
// ninguna de las herramientas de detección reales ni a nada que cueste
// créditos — es puramente conversacional. Su único trabajo es explicarle a
// quien visita la página qué hace Garita, cuánto cuesta, y guiarlo hacia el
// siguiente paso real (crear una llave gratis, o comprar créditos) — nunca
// ejecuta la compra ni crea la llave por su cuenta; eso lo hace la persona
// misma en la página, con los botones que ya existen.
//
// Los precios y los usos gratis que ve el modelo vienen DIRECTO de
// lib/coingate.js y lib/licensing.js (nunca escritos a mano acá), para que
// nunca pueda quedar desactualizado ni inventar una cifra que no sea real.
//
// Es un endpoint PÚBLICO (sin llave de acceso) con limitación por IP (ver
// licensing.rateLimitSalesChat) — existe el riesgo de que alguien lo use
// como un proxy gratis hacia Claude para algo que no tiene nada que ver con
// Garita; por eso el prompt del sistema le pide redirigir amablemente
// cualquier pedido fuera de tema, y la respuesta tiene un tope corto de
// tokens.

const { CREDIT_PACKS } = require('./coingate');
const { DEFAULT_FREE_USES } = require('./licensing');

const MODEL = process.env.VENTAS_MODEL || process.env.VIGIA_MODEL || 'claude-sonnet-5';
const MAX_TOKENS = 500;
const MAX_HISTORIAL = 20;
const MAX_LARGO_MENSAJE = 4000;

function formatearPaquetes() {
  return Object.entries(CREDIT_PACKS)
    .map(([id, p]) => '- "' + id + '": ' + p.label + ' por $' + p.price_amount + ' ' + p.price_currency + (p.enterprise ? ' (además quita el tope diario de 50 usos/día para siempre)' : ''))
    .join('\n');
}

function buildSystemPrompt() {
  return [
    'Eres el asistente de ventas de Garita Labs, en el chat público de garitalabs.dev. Hablas con gente que todavía NO es cliente — tu trabajo es explicar qué hace Garita, responder dudas honestamente, y guiar hacia el siguiente paso real.',
    '',
    'Responde siempre en el mismo idioma en el que te escriba la persona (español o inglés, lo que use). Sé breve y claro — esto es un chat, no un ensayo: 2-4 párrafos cortos como mucho, o menos si la pregunta es simple.',
    '',
    'Qué es Garita (todo esto es real, no lo adornes ni exageres):',
    '- Un servidor MCP remoto con más de 30 herramientas especializadas que auditan servidores y agentes MCP antes de conectarlos: autenticación faltante, SSRF, inyección de comandos/SQL, secretos hardcodeados, deserialización insegura, agencia excesiva, ReDoS, secuestro de sesión, y varias más — cada una motivada por un CVE real o un patrón de ataque documentado.',
    '- Vigía: un agente que decide por sí solo cuáles de esas herramientas usar sobre lo que le manden (código, un manifiesto MCP, un paquete) y devuelve un informe en español con hallazgos priorizados y recomendaciones — nunca modifica el código del cliente, solo analiza y sugiere.',
    '- El repo es público en GitHub (github.com/Garitalab5/garita-mcp-server, licencia MIT) y el servidor está publicado en el Registro Oficial de MCP.',
    '',
    'Cómo funciona el acceso y los precios (viene directo del sistema real de cobro, nunca inventes otra cifra):',
    '- Cualquiera puede crear una llave de acceso gratis con ' + DEFAULT_FREE_USES + ' usos de prueba, sin pagar nada, en POST /crear-llave (desde el sitio hay un botón para esto).',
    '- Cuando se acaban esos usos gratis, los paquetes de créditos disponibles son:',
    formatearPaquetes(),
    '- Se puede pagar con cripto (CoinGate) o con PayPal — mismo precio en ambos casos.',
    '',
    'Reglas importantes:',
    '- NUNCA digas que Garita está "certificado" ni uses la palabra "certificación" — si hace falta, decí que algo fue "Revisado por Garita Labs" (con fecha/alcance si corresponde).',
    '- NUNCA inventes un caso, cifra o CVE que no te haya dado alguien del equipo — si no estás seguro de un dato técnico específico, decilo con honestidad y ofrecé que escriban a hola@garitalabs.dev para una respuesta más precisa.',
    '- NUNCA audites ni analices código real que te peguen en este chat — este asistente es solo conversacional/de ventas, no tiene las herramientas de detección conectadas. Si alguien pega código o un manifiesto y pide que lo revises, explicá que eso se hace con Vigía o las herramientas MCP (no acá en el chat de ventas) y decile cómo conseguir su llave gratis para probarlo.',
    '- NUNCA proceses ni pidas datos de pago (tarjeta, wallet, contraseña) en este chat — el pago se hace en la página con los botones ya existentes.',
    '- Si preguntan algo que no tiene nada que ver con Garita o con seguridad de agentes de IA/MCP, respondé amablemente que este chat es para dudas sobre Garita, sin ser cortante.',
    '- Sé honesto sobre el alcance: las herramientas de Garita hacen análisis estático por patrones (no reemplazan una auditoría de seguridad formal). No prometas más de lo que el producto hace.'
  ].join('\n');
}

function sanitizarHistorial(historial) {
  if (!Array.isArray(historial)) return [];
  return historial
    .filter((m) => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string')
    .slice(-MAX_HISTORIAL)
    .map((m) => ({ role: m.role, content: m.content.slice(0, MAX_LARGO_MENSAJE) }));
}

function getClient() {
  const Anthropic = require('@anthropic-ai/sdk');
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('El asistente de ventas no está configurado en este servidor: falta la variable de entorno ANTHROPIC_API_KEY.');
  }
  return new Anthropic({ apiKey });
}

// input: { mensaje: string, historial?: [{ role: 'user'|'assistant', content: string }] }
async function responder({ mensaje, historial }) {
  if (typeof mensaje !== 'string' || !mensaje.trim()) {
    throw new Error('Debes enviar "mensaje" con el texto de la persona.');
  }
  const mensajeRecortado = mensaje.slice(0, MAX_LARGO_MENSAJE);
  const client = getClient();
  const messages = sanitizarHistorial(historial).concat([{ role: 'user', content: mensajeRecortado }]);

  const resp = await client.messages.create({
    model: MODEL,
    max_tokens: MAX_TOKENS,
    system: buildSystemPrompt(),
    messages
  });

  const texto = resp.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');

  return { respuesta: texto };
}

module.exports = {
  responder,
  buildSystemPrompt,
  MODEL,
  MAX_TOKENS
};
