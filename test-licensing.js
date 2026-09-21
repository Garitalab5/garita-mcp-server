"use strict";
// Prueba de extremo a extremo del ciclo de vida completo de una llave,
// SIN llamar a la API real de CoinGate (simula lo que haría el webhook una
// vez que CoinGate confirma un pago), usando el almacén en memoria.

const assert = require('assert');
const licensing = require('./lib/licensing');

// Réplica exacta de la validación que hace la ruta POST /coingate/webhook
// en server.js, para probar la lógica sin levantar un servidor HTTP.
async function simulateWebhook({ orderId, status, receivedToken }) {
  const order = await licensing.getOrderRecord(orderId);
  if (!order) return { ok: false, reason: 'orden desconocida' };
  if (receivedToken !== order.token) return { ok: false, reason: 'token inválido' };
  if (order.processed) return { ok: true, reason: 'ya procesada (idempotente)' };
  if (status === 'paid') {
    await licensing.topUpCredits(order.apiKey, order.credits);
    await licensing.markOrderProcessed(orderId, order);
    return { ok: true, reason: 'acreditado' };
  }
  return { ok: true, reason: 'estado no es "paid", nada que hacer' };
}

(async () => {
  console.log('1) Crear llave nueva...');
  const { apiKey, record } = await licensing.createKey();
  assert.strictEqual(record.freeUsesRemaining, licensing.DEFAULT_FREE_USES);
  assert.strictEqual(record.credits, 0);
  console.log('   OK — llave', apiKey, 'con', record.freeUsesRemaining, 'usos gratis');

  console.log('2) Consumir todos los usos gratis...');
  for (let i = 0; i < licensing.DEFAULT_FREE_USES; i++) {
    const check = await licensing.checkAndConsume(apiKey);
    assert.strictEqual(check.allowed, true, 'debería permitir uso gratis #' + (i + 1));
  }
  console.log('   OK —', licensing.DEFAULT_FREE_USES, 'usos gratis consumidos sin problema');

  console.log('3) El siguiente uso debe ser rechazado (sin créditos)...');
  const blocked = await licensing.checkAndConsume(apiKey);
  assert.strictEqual(blocked.allowed, false);
  console.log('   OK — rechazado con motivo:', blocked.reason);

  console.log('4) Simular una orden de CoinGate creada por /comprar-creditos...');
  const orderId = 'garita_test_' + Date.now();
  const token = licensing.randomOrderToken();
  await licensing.createOrderRecord(orderId, { apiKey, credits: 50, token });
  console.log('   OK — orden', orderId, 'registrada, esperando pago');

  console.log('5) Webhook con token INCORRECTO no debe acreditar...');
  const badWebhook = await simulateWebhook({ orderId, status: 'paid', receivedToken: 'token-falso' });
  assert.strictEqual(badWebhook.ok, false);
  const stillBlocked = await licensing.checkAndConsume(apiKey);
  assert.strictEqual(stillBlocked.allowed, false, 'no debería haberse acreditado con token falso');
  console.log('   OK — rechazado, sigue sin créditos:', badWebhook.reason);

  console.log('6) Webhook con status "pending" (no pagado aún) no debe acreditar...');
  await simulateWebhook({ orderId, status: 'pending', receivedToken: token });
  const stillBlocked2 = await licensing.checkAndConsume(apiKey);
  assert.strictEqual(stillBlocked2.allowed, false, 'no debería haberse acreditado con status pending');
  console.log('   OK — sigue sin créditos mientras no esté "paid"');

  console.log('7) Webhook real (status "paid", token correcto)...');
  const goodWebhook = await simulateWebhook({ orderId, status: 'paid', receivedToken: token });
  assert.strictEqual(goodWebhook.ok, true);
  const recordAfter = await licensing.getKeyRecord(apiKey);
  assert.strictEqual(recordAfter.credits, 50, 'debería tener 50 créditos acreditados');
  console.log('   OK — acreditados 50 créditos. Balance:', recordAfter.credits);

  console.log('8) Ahora sí debe permitir uso, descontando de los créditos...');
  const afterTopUp = await licensing.checkAndConsume(apiKey);
  assert.strictEqual(afterTopUp.allowed, true);
  assert.strictEqual(afterTopUp.remaining.creditos, 49);
  console.log('   OK — permitido, quedan', afterTopUp.remaining.creditos, 'créditos');

  console.log('9) Reenviar el MISMO webhook de pago (CoinGate reintenta a veces) — no debe duplicar el crédito...');
  const replay = await simulateWebhook({ orderId, status: 'paid', receivedToken: token });
  const recordAfterReplay = await licensing.getKeyRecord(apiKey);
  assert.strictEqual(recordAfterReplay.credits, 49, 'no debería haber acreditado una segunda vez');
  console.log('   OK — idempotente, sigue en', recordAfterReplay.credits, 'créditos. (' + replay.reason + ')');

  console.log('10) Llave inexistente debe ser rechazada...');
  const noKey = await licensing.checkAndConsume('gar_no_existe');
  assert.strictEqual(noKey.allowed, false);
  console.log('   OK —', noKey.reason);

  console.log('11) checkAndConsume sin llave (undefined) debe ser rechazado sin lanzar excepción...');
  const noKeyAtAll = await licensing.checkAndConsume(undefined);
  assert.strictEqual(noKeyAtAll.allowed, false);
  console.log('   OK —', noKeyAtAll.reason);

  console.log('12) Tope diario: con muchos créditos, igual debe bloquear al llegar a ' + licensing.DAILY_CALL_LIMIT + ' usos hoy...');
  const { apiKey: apiKey2 } = await licensing.createKey();
  await licensing.topUpCredits(apiKey2, 1000); // de sobra para no toparse con "sin créditos" antes del tope diario
  let allowedToday = 0;
  let blockedByDailyCap = false;
  for (let i = 0; i < licensing.DAILY_CALL_LIMIT + 5; i++) {
    const check = await licensing.checkAndConsume(apiKey2);
    if (check.allowed) {
      allowedToday++;
    } else {
      blockedByDailyCap = /tope de/.test(check.reason);
      assert.strictEqual(blockedByDailyCap, true, 'debería bloquear por tope diario, no por falta de créditos: ' + check.reason);
      break;
    }
  }
  assert.strictEqual(allowedToday, licensing.DAILY_CALL_LIMIT, 'debería haber permitido exactamente ' + licensing.DAILY_CALL_LIMIT + ' usos antes de bloquear');
  assert.strictEqual(blockedByDailyCap, true);
  const recordAfterDailyCap = await licensing.getKeyRecord(apiKey2);
  // apiKey2 nace con sus propios 5 usos gratis (de createKey), así que de
  // los 50 usos del tope diario, los primeros 5 salen de ahí y solo los
  // 45 restantes descuentan créditos.
  const creditosEsperados = 1000 - (licensing.DAILY_CALL_LIMIT - licensing.DEFAULT_FREE_USES);
  assert.strictEqual(recordAfterDailyCap.credits, creditosEsperados, 'los créditos gastados deben coincidir exactamente con los usos permitidos, descontando los usos gratis de la llave (el bloqueo no debe haber descontado de más)');
  console.log('   OK — permitidos', allowedToday, 'usos (5 gratis + 45 créditos), bloqueado el', (allowedToday + 1) + 'º por tope diario, con', recordAfterDailyCap.credits, 'créditos intactos de sobra');

  console.log('13) Los intentos bloqueados por el tope diario NO deben seguir gastando créditos...');
  const beforeExtra = (await licensing.getKeyRecord(apiKey2)).credits;
  await licensing.checkAndConsume(apiKey2);
  await licensing.checkAndConsume(apiKey2);
  const afterExtra = (await licensing.getKeyRecord(apiKey2)).credits;
  assert.strictEqual(afterExtra, beforeExtra, 'los créditos no deberían cambiar mientras siga bloqueado por el tope diario');
  console.log('   OK — créditos siguen en', afterExtra, 'tras más intentos bloqueados');

  console.log('14) Los usos gratis nunca se renuevan (confirmando el comportamiento de la llave original)...');
  const originalRecord = await licensing.getKeyRecord(apiKey);
  assert.strictEqual(originalRecord.freeUsesRemaining, 0, 'los usos gratis ya consumidos en la prueba 2 no deberían haber vuelto');
  console.log('   OK — usos gratis siguen en 0, no se repusieron solos');

  console.log('15) Paquete empresarial: grantEnterprise debe sumar créditos Y marcar unlimitedDaily...');
  const { apiKey: apiKey3 } = await licensing.createKey();
  const enterpriseRecord = await licensing.grantEnterprise(apiKey3, 5000);
  assert.strictEqual(enterpriseRecord.unlimitedDaily, true);
  assert.strictEqual(enterpriseRecord.credits, 5000);
  console.log('   OK — llave', apiKey3, 'ahora con', enterpriseRecord.credits, 'créditos y unlimitedDaily = true');

  console.log('16) Una llave empresarial NO debe bloquearse por el tope diario, aunque pase de ' + licensing.DAILY_CALL_LIMIT + ' usos en un día...');
  let allowedPastCap = 0;
  for (let i = 0; i < licensing.DAILY_CALL_LIMIT + 20; i++) {
    const check = await licensing.checkAndConsume(apiKey3);
    assert.strictEqual(check.allowed, true, 'una llave empresarial no debería bloquearse nunca por tope diario (fallo en el intento #' + (i + 1) + '): ' + (check.reason || ''));
    assert.strictEqual(check.remaining.topeDiario, null, 'topeDiario debe reportarse como null (sin tope) para una llave empresarial');
    allowedPastCap++;
  }
  assert.strictEqual(allowedPastCap, licensing.DAILY_CALL_LIMIT + 20, 'debería haber permitido TODOS los usos, muy por encima del tope diario normal');
  const recordAfterEnterprise = await licensing.getKeyRecord(apiKey3);
  // 5 usos gratis (de createKey) + (DAILY_CALL_LIMIT + 20) usos, todos pagados con créditos salvo los 5 gratis.
  const creditosGastadosEsperados = licensing.DAILY_CALL_LIMIT + 20 - licensing.DEFAULT_FREE_USES;
  assert.strictEqual(recordAfterEnterprise.credits, 5000 - creditosGastadosEsperados, 'los créditos deben seguir descontándose normalmente aunque no haya tope diario');
  console.log('   OK — permitidos', allowedPastCap, 'usos en un solo día sin bloquear, créditos descontados normalmente (quedan ' + recordAfterEnterprise.credits + ')');

  console.log('17) Una llave normal (no empresarial) sigue topada en ' + licensing.DAILY_CALL_LIMIT + ' como antes (no se rompió nada)...');
  const { apiKey: apiKey4 } = await licensing.createKey();
  await licensing.topUpCredits(apiKey4, 1000);
  let allowedNormal = 0;
  let blockedNormal = false;
  for (let i = 0; i < licensing.DAILY_CALL_LIMIT + 5; i++) {
    const check = await licensing.checkAndConsume(apiKey4);
    if (check.allowed) {
      allowedNormal++;
    } else {
      blockedNormal = true;
      break;
    }
  }
  assert.strictEqual(allowedNormal, licensing.DAILY_CALL_LIMIT, 'una llave normal (sin comprar el paquete empresarial) debe seguir topada igual que siempre');
  assert.strictEqual(blockedNormal, true);
  console.log('   OK — llave normal sigue topada en', allowedNormal, '— el paquete empresarial no afecta a las demás llaves');

  console.log('18) refundUse devuelve un uso gratis consumido (para cuando falla un servicio externo, ej. check_known_vulnerabilities)...');
  const { apiKey: apiKey5 } = await licensing.createKey();
  // Nota: en el almacén de respaldo EN MEMORIA (sin Redis configurado, solo
  // para pruebas locales) getKeyRecord devuelve el mismo objeto por
  // referencia, no una copia — así que hay que guardar el NÚMERO (no el
  // objeto) antes de consumir, o la "foto de antes" se mutaría junto con el
  // registro real. Con Upstash de verdad esto no pasa (cada GET deserializa
  // su propia copia desde JSON).
  const freeUsesAlCrear = (await licensing.getKeyRecord(apiKey5)).freeUsesRemaining;
  const consumed = await licensing.checkAndConsume(apiKey5);
  assert.strictEqual(consumed.allowed, true);
  assert.strictEqual(consumed.consumedFrom, 'gratis');
  const midRefund = await licensing.getKeyRecord(apiKey5);
  assert.strictEqual(midRefund.freeUsesRemaining, freeUsesAlCrear - 1);
  const usoHoyAntes = await licensing.getDailyUsage(apiKey5);
  await licensing.refundUse(apiKey5, consumed.consumedFrom);
  const afterRefund = await licensing.getKeyRecord(apiKey5);
  assert.strictEqual(afterRefund.freeUsesRemaining, freeUsesAlCrear, 'el uso gratis debe quedar como si nunca se hubiera consumido');
  const usoHoyDespues = await licensing.getDailyUsage(apiKey5);
  assert.strictEqual(usoHoyDespues, usoHoyAntes - 1, 'el conteo diario también debe revertirse');
  console.log('   OK — uso gratis y conteo diario revertidos correctamente');

  console.log('19) refundUse devuelve un crédito consumido (no un uso gratis)...');
  const { apiKey: apiKey6 } = await licensing.createKey();
  await licensing.topUpCredits(apiKey6, 3);
  // agotar los 5 usos gratis primero para forzar que el próximo consumo salga de créditos
  for (let i = 0; i < licensing.DEFAULT_FREE_USES; i++) await licensing.checkAndConsume(apiKey6);
  const consumedCredit = await licensing.checkAndConsume(apiKey6);
  assert.strictEqual(consumedCredit.allowed, true);
  assert.strictEqual(consumedCredit.consumedFrom, 'creditos');
  const midCredit = await licensing.getKeyRecord(apiKey6);
  assert.strictEqual(midCredit.credits, 2);
  await licensing.refundUse(apiKey6, consumedCredit.consumedFrom);
  const afterCredit = await licensing.getKeyRecord(apiKey6);
  assert.strictEqual(afterCredit.credits, 3, 'el crédito debe quedar como si nunca se hubiera consumido');
  console.log('   OK — crédito revertido correctamente, sin tocar los usos gratis');

  console.log('\nTodas las pruebas de licencias pasaron sin excepciones no capturadas.');
})().catch((e) => {
  console.error('FALLÓ:', e);
  process.exit(1);
});
