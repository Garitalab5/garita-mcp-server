"use strict";
// Prueba de integración de GET /verificar-pago (el respaldo manual para
// cuando un pago tarda en confirmarse), SIN llamar a la API real de
// CoinGate: se intercepta fetch() global para simular sus respuestas antes
// de arrancar el servidor. No requiere credenciales reales.

const assert = require('assert');

process.env.COINGATE_API_TOKEN = 'token_de_prueba_falso';
process.env.COINGATE_ENV = 'sandbox';
process.env.PORT = '4501';

// Mapa de "estado actual" por id de orden falsa de CoinGate, para poder
// simular que un pago pasa de "confirming" a "paid" entre dos consultas.
const fakeCoingateOrders = new Map();
let nextFakeId = 1000;

const realFetch = global.fetch;
global.fetch = async (url, opts) => {
  const u = String(url);
  if (u.includes('api-sandbox.coingate.com/v2/orders') && (!opts || opts.method === 'POST' || opts.method === undefined) && opts && opts.method === 'POST') {
    const id = 'cg_' + (nextFakeId++);
    fakeCoingateOrders.set(id, 'confirming'); // arranca "aún no confirmado", como un pago real recién hecho
    return {
      ok: true,
      status: 200,
      json: async () => ({ id, payment_url: 'https://sandbox.coingate.com/pay/' + id })
    };
  }
  if (u.includes('api-sandbox.coingate.com/v2/orders/')) {
    const id = u.split('/orders/')[1];
    const status = fakeCoingateOrders.get(id) || 'pending';
    return { ok: true, status: 200, json: async () => ({ id, status }) };
  }
  // Cualquier otra llamada (Upstash está en modo memoria, no debería llamar
  // a fetch real tampoco) — si algo más llama a fetch, que falle ruidoso.
  throw new Error('fetch() real llamado inesperadamente a: ' + u);
};

const BASE_URL = 'http://localhost:4501';

(async () => {
  // Requerir server.js DESPUÉS de fijar env vars y el fetch falso, para que
  // lib/coingate.js lea COINGATE_API_TOKEN/COINGATE_ENV ya correctos.
  require('./server.js');
  await new Promise((r) => setTimeout(r, 300)); // dar tiempo a que arranque

  console.log('1) Crear una llave y comprar un paquete de créditos...');
  const keyRes = await realFetch(BASE_URL + '/crear-llave', { method: 'POST' });
  const { apiKey } = await keyRes.json();
  const buyRes = await realFetch(BASE_URL + '/comprar-creditos', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey, pack: 'basico' })
  });
  const buyData = await buyRes.json();
  assert.ok(buyData.orderId, 'la respuesta debe incluir un orderId');
  assert.ok(buyData.payment_url, 'la respuesta debe incluir un payment_url');
  console.log('   OK — orden', buyData.orderId, 'creada, link:', buyData.payment_url);

  console.log('2) Consultar el pago mientras SIGUE confirmando (no debe acreditar todavía)...');
  const check1 = await realFetch(BASE_URL + '/verificar-pago?orderId=' + buyData.orderId);
  const check1Data = await check1.json();
  assert.strictEqual(check1Data.estado, 'confirming');
  const keyCheck1 = await (await realFetch(BASE_URL + '/consultar-llave?apiKey=' + apiKey)).json();
  assert.strictEqual(keyCheck1.creditos, 0, 'no debería haber créditos todavía');
  console.log('   OK —', check1Data.mensaje);

  console.log('3) Simular que la red ya confirmó el pago (cambia a "paid" del lado de CoinGate)...');
  // Encuentra el id falso de CoinGate asociado a esta orden y le cambia el estado.
  const lastFakeId = 'cg_' + (nextFakeId - 1);
  fakeCoingateOrders.set(lastFakeId, 'paid');

  console.log('4) Volver a consultar /verificar-pago — ahora debe acreditar en el momento...');
  const check2 = await realFetch(BASE_URL + '/verificar-pago?orderId=' + buyData.orderId);
  const check2Data = await check2.json();
  assert.strictEqual(check2Data.estado, 'paid');
  const keyCheck2 = await (await realFetch(BASE_URL + '/consultar-llave?apiKey=' + apiKey)).json();
  assert.strictEqual(keyCheck2.creditos, 50, 'debería tener los 50 créditos del paquete "basico"');
  console.log('   OK —', check2Data.mensaje, '— créditos:', keyCheck2.creditos);

  console.log('5) Consultar una TERCERA vez — no debe volver a llamar a CoinGate ni duplicar créditos...');
  fakeCoingateOrders.delete(lastFakeId); // si esto se llegara a leer, el "|| pending" lo delataría igual
  const check3 = await realFetch(BASE_URL + '/verificar-pago?orderId=' + buyData.orderId);
  const check3Data = await check3.json();
  assert.strictEqual(check3Data.estado, 'paid');
  assert.match(check3Data.mensaje, /Ya estaba acreditada/);
  const keyCheck3 = await (await realFetch(BASE_URL + '/consultar-llave?apiKey=' + apiKey)).json();
  assert.strictEqual(keyCheck3.creditos, 50, 'no debería haber duplicado créditos');
  console.log('   OK — idempotente, sigue en', keyCheck3.creditos, 'créditos');

  console.log('6) Orden inexistente debe dar 404...');
  const check4 = await realFetch(BASE_URL + '/verificar-pago?orderId=garita_no_existe');
  assert.strictEqual(check4.status, 404);
  console.log('   OK — 404 como se esperaba');

  console.log('7) Comprar el paquete "empresarial" y confirmarlo — debe sumar créditos Y quitar el tope diario...');
  const buyEntRes = await realFetch(BASE_URL + '/comprar-creditos', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apiKey, pack: 'empresarial' })
  });
  const buyEntData = await buyEntRes.json();
  assert.strictEqual(buyEntData.empresarial, true, 'la respuesta de /comprar-creditos debe marcar empresarial: true');
  const lastFakeIdEnt = 'cg_' + (nextFakeId - 1);
  fakeCoingateOrders.set(lastFakeIdEnt, 'paid');
  const checkEnt = await realFetch(BASE_URL + '/verificar-pago?orderId=' + buyEntData.orderId);
  const checkEntData = await checkEnt.json();
  assert.strictEqual(checkEntData.estado, 'paid');
  const keyCheckEnt = await (await realFetch(BASE_URL + '/consultar-llave?apiKey=' + apiKey)).json();
  assert.strictEqual(keyCheckEnt.creditos, 50 + 5000, 'debe sumar los 5000 créditos del paquete empresarial a los 50 que ya tenía');
  assert.strictEqual(keyCheckEnt.empresarial, true, '/consultar-llave debe reportar empresarial: true tras la compra');
  assert.strictEqual(keyCheckEnt.topeDiario, null, '/consultar-llave debe reportar topeDiario: null para una llave empresarial');
  console.log('   OK — créditos:', keyCheckEnt.creditos, '— empresarial:', keyCheckEnt.empresarial, '— topeDiario:', keyCheckEnt.topeDiario);

  console.log('\nTodas las pruebas de /verificar-pago pasaron sin excepciones no capturadas.');
  process.exit(0);
})().catch((e) => {
  console.error('FALLÓ:', e);
  process.exit(1);
});
