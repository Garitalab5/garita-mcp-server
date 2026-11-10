// test-paypal.js — pruebas de lib/paypal.js con fetch simulado (no llama a
// PayPal de verdad: esta sandbox de desarrollo no tiene salida de red hacia
// api-m.sandbox.paypal.com). Verifica construcción de la petición, lectura
// de la respuesta y manejo de errores — la verificación en vivo contra
// PayPal real se hace una vez desplegado, con las credenciales de Sandbox.
'use strict';

const assert = require('assert');

let fallas = 0;
function check(nombre, cond, detalle) {
  if (cond) {
    console.log('OK   -', nombre);
  } else {
    fallas++;
    console.log('FALLO -', nombre, detalle ? '(' + detalle + ')' : '');
  }
}

function mockFetchSecuencia(respuestas) {
  let i = 0;
  const llamadas = [];
  global.fetch = async (url, opts) => {
    llamadas.push({ url, opts });
    const r = respuestas[Math.min(i, respuestas.length - 1)];
    i++;
    if (typeof r === 'function') return r(url, opts);
    return {
      ok: r.ok !== false,
      status: r.status || (r.ok === false ? 400 : 200),
      json: async () => r.body
    };
  };
  return llamadas;
}

async function main() {
  process.env.PAYPAL_CLIENT_ID = 'test_client_id';
  process.env.PAYPAL_CLIENT_SECRET = 'test_secret';
  process.env.PAYPAL_ENV = 'sandbox';

  // ---- getAccessToken: construye bien la petición y cachea el token ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    const llamadas = mockFetchSecuencia([
      { body: { access_token: 'ACCESS123', expires_in: 32400, token_type: 'Bearer' } }
    ]);
    const token = await paypal.getAccessToken();
    check('getAccessToken devuelve el access_token', token === 'ACCESS123', token);
    check('getAccessToken usa /v1/oauth2/token en sandbox', llamadas[0].url === 'https://api-m.sandbox.paypal.com/v1/oauth2/token');
    check('getAccessToken manda Basic auth', /^Basic /.test(llamadas[0].opts.headers['Authorization']));
    check('getAccessToken manda grant_type=client_credentials', llamadas[0].opts.body === 'grant_type=client_credentials');

    // Segunda llamada: no debería pedir un token nuevo (debería usar la caché)
    const llamadas2 = mockFetchSecuencia([{ body: { access_token: 'OTRO', expires_in: 32400 } }]);
    const token2 = await paypal.getAccessToken();
    check('getAccessToken reutiliza el token en caché', token2 === 'ACCESS123' && llamadas2.length === 0, token2);
  }

  // ---- getAccessToken: sin credenciales configuradas, falla claro ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    delete process.env.PAYPAL_CLIENT_ID;
    const paypal = require('./lib/paypal');
    mockFetchSecuencia([]);
    let lanzo = false;
    try { await paypal.getAccessToken(); } catch (e) { lanzo = /PAYPAL_CLIENT_ID/.test(e.message); }
    check('getAccessToken sin credenciales lanza error claro', lanzo);
    process.env.PAYPAL_CLIENT_ID = 'test_client_id';
  }

  // ---- createOrder: construye el body correcto y lee el link payer-action ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    const llamadas = mockFetchSecuencia([
      { body: { access_token: 'TOK', expires_in: 32400 } },
      {
        body: {
          id: 'ORDER-1',
          status: 'PAYER_ACTION_REQUIRED',
          links: [
            { rel: 'self', href: 'https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER-1' },
            { rel: 'payer-action', href: 'https://www.sandbox.paypal.com/checkoutnow?token=ORDER-1' }
          ]
        }
      }
    ]);
    const result = await paypal.createOrder({ pack: 'basico', returnUrl: 'https://garitalabs.dev/paypal/retorno', cancelUrl: 'https://garitalabs.dev/paypal/cancelado' });
    check('createOrder devuelve el payment_url del link payer-action', result.payment_url === 'https://www.sandbox.paypal.com/checkoutnow?token=ORDER-1', result.payment_url);
    check('createOrder devuelve el paypalOrderId', result.paypalOrderId === 'ORDER-1');
    check('createOrder devuelve el packConfig del paquete pedido', result.packConfig.credits === 50 && result.packConfig.price_amount === 5);

    const bodyEnviado = JSON.parse(llamadas[1].opts.body);
    check('createOrder llama a POST /v2/checkout/orders', llamadas[1].url === 'https://api-m.sandbox.paypal.com/v2/checkout/orders');
    check('createOrder manda el monto correcto en USD', bodyEnviado.purchase_units[0].amount.value === '5' && bodyEnviado.purchase_units[0].amount.currency_code === 'USD');
    check('createOrder manda return_url y cancel_url dentro de experience_context', bodyEnviado.payment_source.paypal.experience_context.return_url === 'https://garitalabs.dev/paypal/retorno' && bodyEnviado.payment_source.paypal.experience_context.cancel_url === 'https://garitalabs.dev/paypal/cancelado');
    check('createOrder pide pago inmediato (no esperar a que el comprador elija fondear después)', bodyEnviado.payment_source.paypal.experience_context.payment_method_preference === 'IMMEDIATE_PAYMENT_REQUIRED');
  }

  // ---- createOrder: paquete desconocido falla ANTES de llamar a PayPal ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    const llamadas = mockFetchSecuencia([]);
    let lanzo = false;
    try {
      await paypal.createOrder({ pack: 'no-existe', returnUrl: 'https://x/r', cancelUrl: 'https://x/c' });
    } catch (e) { lanzo = /Paquete de créditos desconocido/.test(e.message); }
    check('createOrder con paquete inválido lanza error claro sin llamar a PayPal', lanzo && llamadas.length === 0);
  }

  // ---- createOrder: falta returnUrl/cancelUrl ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    mockFetchSecuencia([]);
    let lanzo = false;
    try { await paypal.createOrder({ pack: 'basico' }); } catch (e) { lanzo = /returnUrl/.test(e.message); }
    check('createOrder sin returnUrl/cancelUrl lanza error claro', lanzo);
  }

  // ---- createOrder: PayPal responde error (ej. credenciales live inválidas) ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    mockFetchSecuencia([
      { body: { access_token: 'TOK', expires_in: 32400 } },
      { ok: false, status: 401, body: { message: 'Client Authentication failed' } }
    ]);
    let lanzo = false;
    try { await paypal.createOrder({ pack: 'pro', returnUrl: 'https://x/r', cancelUrl: 'https://x/c' }); } catch (e) { lanzo = /Client Authentication failed/.test(e.message); }
    check('createOrder propaga el mensaje de error real de PayPal', lanzo);
  }

  // ---- captureOrder: pago completado ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    const llamadas = mockFetchSecuencia([
      { body: { access_token: 'TOK', expires_in: 32400 } },
      { body: { id: 'ORDER-1', status: 'COMPLETED' } }
    ]);
    const data = await paypal.captureOrder('ORDER-1');
    check('captureOrder llama a POST .../ORDER-1/capture', llamadas[1].url === 'https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER-1/capture');
    check('captureOrder devuelve status COMPLETED', data.status === 'COMPLETED');
  }

  // ---- captureOrder: ya estaba capturada antes (doble clic / recarga de la página de retorno) ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    mockFetchSecuencia([
      { body: { access_token: 'TOK', expires_in: 32400 } },
      { ok: false, status: 422, body: { name: 'UNPROCESSABLE_ENTITY', details: [{ issue: 'ORDER_ALREADY_CAPTURED' }] } }
    ]);
    let lanzo = false;
    let data = null;
    try { data = await paypal.captureOrder('ORDER-1'); } catch (e) { lanzo = true; }
    check('captureOrder NO lanza error cuando la orden ya estaba capturada (idempotente)', !lanzo && data && data.name === 'UNPROCESSABLE_ENTITY');
  }

  // ---- captureOrder: falla real de PayPal (ej. 500) sí debe lanzar ----
  {
    delete require.cache[require.resolve('./lib/paypal')];
    const paypal = require('./lib/paypal');
    mockFetchSecuencia([
      { body: { access_token: 'TOK', expires_in: 32400 } },
      { ok: false, status: 500, body: { message: 'Internal Server Error' } }
    ]);
    let lanzo = false;
    try { await paypal.captureOrder('ORDER-1'); } catch (e) { lanzo = /Internal Server Error/.test(e.message); }
    check('captureOrder lanza error en una falla real de PayPal (no 422)', lanzo);
  }

  console.log('\n' + (fallas === 0 ? 'Todas las pruebas de lib/paypal.js pasaron.' : fallas + ' prueba(s) fallaron.'));
  process.exit(fallas === 0 ? 0 : 1);
}

main().catch(err => { console.error('Error inesperado corriendo las pruebas:', err); process.exit(1); });
