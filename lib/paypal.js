// lib/paypal.js — integración con la API REST de PayPal (Orders v2) para
// comprar créditos de Garita Labs con PayPal, como alternativa a CoinGate
// (lib/coingate.js). Mismo patrón: credenciales SIEMPRE por variables de
// entorno (PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_ENV), nunca
// escritas en el código ni en el sitio web.
//
// Flujo (lo que PayPal llama el "Standard flow" con experience_context,
// vigente en su documentación oficial a 2026 — sin usar su SDK de
// JavaScript, todo desde el servidor):
//   1. getAccessToken()  — OAuth2 client_credentials contra /v1/oauth2/token.
//   2. createOrder()     — POST /v2/checkout/orders. Devuelve un link con
//      rel "payer-action" (o "approve" como respaldo en respuestas más
//      simples) al que se redirige al comprador.
//   3. El comprador aprueba el pago en paypal.com y PayPal lo manda de
//      vuelta a `return_url` con ?token=ORDER_ID&PayerID=...
//   4. captureOrder(orderId) — POST /v2/checkout/orders/{id}/capture.
//      Si devuelve status "COMPLETED", el pago ya es real y se puede
//      acreditar (ver creditOrderIfPaid en server.js, reutilizado tal cual
//      de CoinGate — esa función ya es agnóstica del proveedor de pago).

const PAYPAL_ENV = (process.env.PAYPAL_ENV || 'sandbox').toLowerCase();
const PAYPAL_BASE_URL = PAYPAL_ENV === 'live'
  ? 'https://api-m.paypal.com'
  : 'https://api-m.sandbox.paypal.com';
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

// Mismos paquetes/precios que CoinGate (lib/coingate.js es la única fuente
// de verdad de precios: un crédito cuesta lo mismo pagues como pagues).
const { CREDIT_PACKS } = require('./coingate');

// Cache simple del token de acceso en memoria del proceso — PayPal los da
// con ~9 horas de vida (expires_in en segundos); pedir uno nuevo en cada
// llamada sería lento e innecesario. Se renueva solo si falta menos de 30s.
let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < cachedTokenExpiresAt - 30000) {
    return cachedToken;
  }
  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    throw new Error('Falta configurar PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET en las variables de entorno.');
  }

  const basicAuth = Buffer.from(PAYPAL_CLIENT_ID + ':' + PAYPAL_CLIENT_SECRET).toString('base64');
  const resp = await fetch(PAYPAL_BASE_URL + '/v1/oauth2/token', {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + basicAuth,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: 'grant_type=client_credentials'
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || !data.access_token) {
    throw new Error('No se pudo autenticar con PayPal (' + resp.status + '): ' + (data.error_description || data.error || 'respuesta inesperada'));
  }
  cachedToken = data.access_token;
  cachedTokenExpiresAt = now + (Number(data.expires_in) || 0) * 1000;
  return cachedToken;
}

// Crea una orden de pago en PayPal para un paquete de créditos y devuelve
// el link al que hay que mandar al comprador para que apruebe el pago.
async function createOrder({ pack, returnUrl, cancelUrl }) {
  const packConfig = CREDIT_PACKS[pack];
  if (!packConfig) {
    throw new Error('Paquete de créditos desconocido: "' + pack + '". Opciones: ' + Object.keys(CREDIT_PACKS).join(', '));
  }
  if (!returnUrl || !cancelUrl) {
    throw new Error('Faltan returnUrl/cancelUrl para crear la orden en PayPal.');
  }

  const token = await getAccessToken();
  const resp = await fetch(PAYPAL_BASE_URL + '/v2/checkout/orders', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      intent: 'CAPTURE',
      purchase_units: [{
        description: 'Garita Labs — paquete ' + pack + ' (' + packConfig.label + ')',
        amount: {
          currency_code: packConfig.price_currency,
          value: String(packConfig.price_amount)
        }
      }],
      payment_source: {
        paypal: {
          experience_context: {
            payment_method_preference: 'IMMEDIATE_PAYMENT_REQUIRED',
            brand_name: 'Garita Labs',
            locale: 'es-CO',
            landing_page: 'LOGIN',
            shipping_preference: 'NO_SHIPPING',
            user_action: 'PAY_NOW',
            return_url: returnUrl,
            cancel_url: cancelUrl
          }
        }
      }
    })
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || !data.id) {
    throw new Error('No se pudo crear la orden en PayPal (' + resp.status + '): ' + (data.message || JSON.stringify(data.details || data)));
  }

  const links = data.links || [];
  const approveLink = links.find(l => l.rel === 'payer-action') || links.find(l => l.rel === 'approve');
  if (!approveLink) {
    throw new Error('PayPal no devolvió un link de aprobación para la orden ' + data.id + '.');
  }

  return { packConfig, payment_url: approveLink.href, paypalOrderId: data.id };
}

// Captura (cobra de verdad) una orden ya aprobada por el comprador. Si
// PayPal responde algo distinto de 201/200 con status "COMPLETED", el pago
// todavía no es real (puede estar pendiente, o el comprador nunca llegó a
// aprobar) y no hay que acreditar nada.
async function captureOrder(paypalOrderId) {
  if (!paypalOrderId) throw new Error('Falta el ID de la orden de PayPal a capturar.');
  const token = await getAccessToken();
  const resp = await fetch(PAYPAL_BASE_URL + '/v2/checkout/orders/' + encodeURIComponent(paypalOrderId) + '/capture', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type': 'application/json'
    }
  });
  const data = await resp.json().catch(() => ({}));
  // PayPal devuelve 422 ORDER_ALREADY_CAPTURED si se llama dos veces — no es
  // un error real para nuestro flujo (idempotente: el llamador decide qué
  // hacer mirando data.status / data.name).
  if (!resp.ok && data.name !== 'UNPROCESSABLE_ENTITY') {
    throw new Error('No se pudo capturar el pago en PayPal (' + resp.status + '): ' + (data.message || JSON.stringify(data.details || data)));
  }
  return data; // data.status === 'COMPLETED' es la señal de pago real confirmado
}

module.exports = { PAYPAL_ENV, PAYPAL_BASE_URL, CREDIT_PACKS, getAccessToken, createOrder, captureOrder };
