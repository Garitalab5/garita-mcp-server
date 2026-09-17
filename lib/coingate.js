"use strict";
// Garita MCP — integración con CoinGate (paquetes de créditos prepagados)
// ==========================================================================
// Referencia: https://developer.coingate.com/reference/create-order y
// https://developer.coingate.com/reference/payment-callback (consultada el
// 2026-09-16). Dos ambientes con cuentas y llaves SEPARADAS:
//   - Pruebas (sandbox):  https://api-sandbox.coingate.com/v2  (sandbox.coingate.com)
//   - Real (live):        https://api.coingate.com/v2          (coingate.com)
// Autenticación: header "Authorization: Token <API_TOKEN>" (OJO: la palabra
// literal "Token", no "Bearer" — son cosas distintas en la API de CoinGate).

const COINGATE_ENV = (process.env.COINGATE_ENV || 'sandbox').toLowerCase();
const COINGATE_BASE_URL = COINGATE_ENV === 'live'
  ? 'https://api.coingate.com/v2'
  : 'https://api-sandbox.coingate.com/v2';
const COINGATE_API_TOKEN = process.env.COINGATE_API_TOKEN;

// Paquetes de créditos disponibles. 1 crédito = 1 llamada a una herramienta
// (audit_mcp_server o simulate_approval) una vez que se acaban los usos
// gratis. Precios en USD; CoinGate cobra su comisión (1%) sobre esto, no se
// resta aquí — el precio que paga el cliente es el que se define abajo.
const CREDIT_PACKS = {
  basico: { credits: 50, price_amount: 5, price_currency: 'USD', label: '50 usos' },
  pro: { credits: 300, price_amount: 25, price_currency: 'USD', label: '300 usos' },
  // Paquete empresarial: además de los créditos, quita el tope diario de
  // 50 llamadas/día PARA SIEMPRE en esa llave (ver licensing.grantEnterprise).
  // Pensado para un cliente cuyos agentes de IA llaman las herramientas en
  // volumen alto y constante, donde el tope diario pensado para frenar
  // abusos se volvería una limitación real del negocio.
  empresarial: { credits: 5000, price_amount: 300, price_currency: 'USD', label: '5.000 usos + sin tope diario', enterprise: true }
};

async function createOrder({ orderId, token, pack, publicBaseUrl }) {
  if (!COINGATE_API_TOKEN) {
    throw new Error('Falta configurar COINGATE_API_TOKEN en las variables de entorno.');
  }
  const packConfig = CREDIT_PACKS[pack];
  if (!packConfig) {
    throw new Error('Paquete de créditos desconocido: "' + pack + '". Opciones: ' + Object.keys(CREDIT_PACKS).join(', '));
  }

  const body = {
    order_id: orderId,
    price_amount: packConfig.price_amount,
    price_currency: packConfig.price_currency,
    title: 'Garita Labs — paquete de créditos (' + packConfig.label + ')',
    description: 'Paquete de ' + packConfig.credits + ' créditos para el servidor de Garita MCP.',
    token: token,
    callback_url: publicBaseUrl + '/coingate/webhook'
  };

  const res = await fetch(COINGATE_BASE_URL + '/orders', {
    method: 'POST',
    headers: {
      Authorization: 'Token ' + COINGATE_API_TOKEN,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error('CoinGate rechazó la orden (' + res.status + '): ' + JSON.stringify(data));
  }
  return { packConfig, payment_url: data.payment_url, coingateOrderId: data.id };
}

// Respaldo manual: CoinGate reintenta avisar el webhook automáticamente
// hasta 40 veces a lo largo de varios días si nuestro servidor no responde
// a tiempo (ver https://developer.coingate.com/reference/api-callbacks,
// consultada el 2026-09-16), así que un pago casi nunca debería quedar sin
// acreditarse solo. Aun así, esto sirve para revisar el estado real de una
// orden en el momento (por ejemplo si un cliente escribe preguntando "ya
// pagué, por qué no me llegaron los créditos") sin tener que esperar el
// próximo reintento.
async function getOrder(coingateOrderId) {
  if (!COINGATE_API_TOKEN) {
    throw new Error('Falta configurar COINGATE_API_TOKEN en las variables de entorno.');
  }
  const res = await fetch(COINGATE_BASE_URL + '/orders/' + coingateOrderId, {
    headers: { Authorization: 'Token ' + COINGATE_API_TOKEN }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error('CoinGate rechazó la consulta de la orden (' + res.status + '): ' + JSON.stringify(data));
  }
  return data; // incluye .status: 'pending' | 'confirming' | 'paid' | 'invalid' | 'canceled' | 'refunded' | 'expired'
}

module.exports = { COINGATE_ENV, COINGATE_BASE_URL, CREDIT_PACKS, createOrder, getOrder };
