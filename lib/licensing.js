"use strict";
// Garita MCP — sistema de licencias (llave de acceso + usos gratis + créditos)
// ==============================================================================
// Cada cliente tiene una "llave de acceso" (apiKey) que manda en el header
// Authorization al conectarse al servidor MCP. Por llave se guarda:
//   - freeUsesRemaining: usos gratis que le quedan (arranca en DEFAULT_FREE_USES)
//   - credits: créditos comprados (1 crédito = 1 llamada a una herramienta)
// Cada vez que se llama una herramienta (audit_mcp_server / simulate_approval)
// se descuenta primero de los usos gratis, y cuando esos se acaban, de los
// créditos. Cuando ya no queda nada de ninguno, se niega la llamada con un
// mensaje que explica cómo comprar más créditos.
//
// Los 5 usos gratis son de UNA SOLA VEZ por llave — nunca se renuevan (no
// hay ningún código en este archivo que reponga freeUsesRemaining después
// de creada la llave). Aparte de eso hay un TOPE DIARIO (DAILY_CALL_LIMIT,
// independiente de los créditos que tenga la llave): protege contra un
// agente con un error en bucle que queme de golpe todos sus créditos
// comprados en minutos, o contra un abuso concentrado en un solo día. El
// tope diario se resetea solo cada día (contador con expiración en Redis,
// sin ningún trabajo programado que lo reinicie a mano).
//
// Persistencia: Upstash Redis (REST, plan gratis) — se eligió por ser la
// forma más simple de tener una base de datos de verdad sin mantener un
// servidor de base de datos aparte, con un API por HTTP (no necesita
// librerías de conexión ni manejo de sockets) que funciona bien incluso
// con un servicio que "duerme" como el plan gratis de Render.
//
// MODO DE RESPALDO EN MEMORIA: si no están configuradas las variables de
// entorno de Upstash, este módulo cae a un Map en memoria — sirve para
// probar el servidor localmente, pero NUNCA debe usarse en producción: se
// pierde todo (llaves, créditos, usos) cada vez que el proceso se reinicia.
// Se imprime una advertencia bien visible al arrancar si pasa esto.

const crypto = require('crypto');

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;
const USING_MEMORY_FALLBACK = !UPSTASH_URL || !UPSTASH_TOKEN;

if (USING_MEMORY_FALLBACK) {
  // eslint-disable-next-line no-console
  console.warn(
    '\n[garita-licensing] ADVERTENCIA: UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN no están configuradas.\n' +
    '[garita-licensing] Usando un almacén EN MEMORIA — las llaves, usos gratis y créditos se van a\n' +
    '[garita-licensing] perder cada vez que el servidor se reinicie o se duerma. Esto es solo para\n' +
    '[garita-licensing] pruebas locales. Configura Upstash antes de cobrarle a un cliente real (ver README).\n'
  );
}

const memoryStore = new Map();

// ---------- capa de almacenamiento (Upstash REST o memoria) ----------

async function redisGet(key) {
  if (USING_MEMORY_FALLBACK) {
    return memoryStore.has(key) ? memoryStore.get(key) : null;
  }
  const res = await fetch(UPSTASH_URL + '/get/' + encodeURIComponent(key), {
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN }
  });
  if (!res.ok) throw new Error('Upstash GET falló: ' + res.status);
  const data = await res.json();
  return data.result === null || data.result === undefined ? null : JSON.parse(data.result);
}

async function redisSet(key, value) {
  if (USING_MEMORY_FALLBACK) {
    memoryStore.set(key, value);
    return;
  }
  const res = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(['SET', key, JSON.stringify(value)])
  });
  if (!res.ok) throw new Error('Upstash SET falló: ' + res.status);
}

async function redisIncrWithExpiry(key, expirySeconds) {
  if (USING_MEMORY_FALLBACK) {
    const current = (memoryStore.get(key) || 0) + 1;
    memoryStore.set(key, current);
    return current;
  }
  const res = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(['INCR', key])
  });
  if (!res.ok) throw new Error('Upstash INCR falló: ' + res.status);
  const data = await res.json();
  const count = Number(data.result);
  if (count === 1) {
    // Primera vez que se usa esta llave de contador: ponerle expiración.
    await fetch(UPSTASH_URL, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify(['EXPIRE', key, String(expirySeconds)])
    });
  }
  return count;
}

async function redisDecr(key) {
  if (USING_MEMORY_FALLBACK) {
    const current = (memoryStore.get(key) || 0) - 1;
    memoryStore.set(key, current);
    return current;
  }
  const res = await fetch(UPSTASH_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + UPSTASH_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(['DECR', key])
  });
  if (!res.ok) throw new Error('Upstash DECR falló: ' + res.status);
  const data = await res.json();
  return Number(data.result);
}

// ---------- configuración ----------

const DEFAULT_FREE_USES = 5;
// Tope de llamadas por día por llave, SIN IMPORTAR cuántos créditos tenga
// comprados — ver la nota grande arriba. Fácil de ajustar: es solo esta
// constante. No aplica a /crear-llave ni /comprar-creditos, solo a las
// llamadas reales a las herramientas (audit_mcp_server / simulate_approval).
const DAILY_CALL_LIMIT = 50;
const KEY_PREFIX = 'garita:key:';
const DAILY_PREFIX = 'garita:daily:';
const DAILY_WINDOW_SECONDS = 26 * 60 * 60; // 26h de margen para que nunca expire justo antes de medianoche
const ORDER_PREFIX = 'garita:order:';
const RATE_LIMIT_PREFIX = 'garita:ratelimit:crear-llave:';
const RATE_LIMIT_MAX_PER_DAY = 5;
const RATE_LIMIT_WINDOW_SECONDS = 24 * 60 * 60;

function todayKey(apiKey) {
  return DAILY_PREFIX + apiKey + ':' + new Date().toISOString().slice(0, 10);
}

function randomApiKey() {
  return 'gar_' + crypto.randomBytes(20).toString('base64url');
}

function randomOrderToken() {
  return crypto.randomBytes(16).toString('hex');
}

// ---------- llaves de acceso ----------

async function getKeyRecord(apiKey) {
  if (!apiKey) return null;
  return redisGet(KEY_PREFIX + apiKey);
}

async function createKey() {
  const apiKey = randomApiKey();
  const record = {
    freeUsesRemaining: DEFAULT_FREE_USES,
    credits: 0,
    createdAt: new Date().toISOString()
  };
  await redisSet(KEY_PREFIX + apiKey, record);
  return { apiKey, record };
}

// Límite simple para que no sea trivial crear cientos de llaves nuevas solo
// para siempre tener "usos gratis" frescos. No es una defensa fuerte (no
// hay verificación de identidad en un self-serve así), pero sube el costo
// de abusar del truco más allá de lo que vale la pena para alguien casual.
async function rateLimitCreateKey(ip) {
  const key = RATE_LIMIT_PREFIX + (ip || 'desconocida') + ':' + new Date().toISOString().slice(0, 10);
  const count = await redisIncrWithExpiry(key, RATE_LIMIT_WINDOW_SECONDS);
  return count <= RATE_LIMIT_MAX_PER_DAY;
}

// Descuenta un uso: primero revisa el tope diario (aparte de los
// créditos), luego descuenta de los usos gratis, y cuando esos se acaban,
// de los créditos. Devuelve { allowed, reason?, remaining? }.
async function checkAndConsume(apiKey) {
  if (!apiKey) {
    return { allowed: false, reason: 'Falta la llave de acceso (header Authorization). Pide una gratis en POST /crear-llave.' };
  }
  const record = await getKeyRecord(apiKey);
  if (!record) {
    return { allowed: false, reason: 'Llave de acceso no reconocida. Pide una nueva en POST /crear-llave.' };
  }

  // Tope diario primero — salvo que la llave sea "empresarial"
  // (record.unlimitedDaily), que queda exenta para siempre desde que se le
  // otorga (ver grantEnterprise más abajo). Se incrementa "en optimista"
  // (asumiendo que la llamada se va a permitir) y se revierte con DECR en
  // cualquier camino donde al final NO se consuma nada real — así el
  // contador solo refleja llamadas que de verdad gastaron un uso gratis o
  // un crédito. Para una llave empresarial se sigue llevando la cuenta
  // (útil para /consultar-llave), solo que nunca bloquea por eso.
  const dailyKey = todayKey(apiKey);
  const dailyCount = await redisIncrWithExpiry(dailyKey, DAILY_WINDOW_SECONDS);
  const topeDiario = record.unlimitedDaily ? null : DAILY_CALL_LIMIT;
  if (!record.unlimitedDaily && dailyCount > DAILY_CALL_LIMIT) {
    await redisDecr(dailyKey);
    return {
      allowed: false,
      reason: 'Se alcanzó el tope de ' + DAILY_CALL_LIMIT + ' usos por día para esta llave (aparte de los créditos disponibles). Vuelve mañana, usa otra llave, o pásate al paquete empresarial (sin tope diario) en POST /comprar-creditos.',
      remaining: { usosGratis: record.freeUsesRemaining, creditos: record.credits, usosHoy: DAILY_CALL_LIMIT, topeDiario: DAILY_CALL_LIMIT }
    };
  }

  if (record.freeUsesRemaining > 0) {
    record.freeUsesRemaining -= 1;
    await redisSet(KEY_PREFIX + apiKey, record);
    return { allowed: true, consumedFrom: 'gratis', remaining: { usosGratis: record.freeUsesRemaining, creditos: record.credits, usosHoy: dailyCount, topeDiario } };
  }
  if (record.credits > 0) {
    record.credits -= 1;
    await redisSet(KEY_PREFIX + apiKey, record);
    return { allowed: true, consumedFrom: 'creditos', remaining: { usosGratis: record.freeUsesRemaining, creditos: record.credits, usosHoy: dailyCount, topeDiario } };
  }

  // No había usos gratis ni créditos: esta llamada no consumió nada real,
  // así que se revierte el conteo diario optimista de arriba.
  await redisDecr(dailyKey);
  return {
    allowed: false,
    reason: 'Se acabaron los usos gratis y los créditos de esta llave. Compra más en POST /comprar-creditos.',
    remaining: { usosGratis: 0, creditos: 0, usosHoy: dailyCount - 1, topeDiario }
  };
}

// Revierte un uso ya consumido por checkAndConsume — pensado para cuando la
// herramienta llamada depende de un servicio externo (ej. OSV.dev en
// check_known_vulnerabilities) y ese servicio falla: el cliente no recibió
// ningún resultado real, así que no debería perder un uso gratis/crédito por
// una falla que no es culpa suya. `consumedFrom` es el campo que devolvió
// checkAndConsume ('gratis' | 'creditos'). No es atómico con el consumo
// original (misma limitación que el resto de este archivo, sin
// transacciones de Upstash) pero es correcto en el caso normal sin carreras
// concurrentes sobre la misma llave.
async function refundUse(apiKey, consumedFrom) {
  if (!apiKey || (consumedFrom !== 'gratis' && consumedFrom !== 'creditos')) return;
  const record = await getKeyRecord(apiKey);
  if (!record) return; // la llave pudo haberse borrado entre medio — no hay nada que devolver
  if (consumedFrom === 'gratis') {
    record.freeUsesRemaining = (record.freeUsesRemaining || 0) + 1;
  } else {
    record.credits = (record.credits || 0) + 1;
  }
  await redisSet(KEY_PREFIX + apiKey, record);
  // También se revierte el conteo optimista del tope diario, igual que en
  // el camino de "no había nada que consumir" dentro de checkAndConsume.
  await redisDecr(todayKey(apiKey));
}

async function getDailyUsage(apiKey) {
  const count = await redisGet(todayKey(apiKey));
  return count || 0;
}

async function topUpCredits(apiKey, amount) {
  const record = await getKeyRecord(apiKey);
  if (!record) throw new Error('No se puede acreditar: la llave "' + apiKey + '" no existe.');
  record.credits = (record.credits || 0) + amount;
  await redisSet(KEY_PREFIX + apiKey, record);
  return record;
}

// Acredita un paquete empresarial: suma los créditos del paquete Y marca la
// llave con unlimitedDaily = true PARA SIEMPRE (no hay código en este
// archivo que vuelva a poner eso en false — una vez empresarial, la llave
// queda exenta del tope diario de por vida, aunque después se le acaben los
// créditos y tenga que comprar más).
async function grantEnterprise(apiKey, credits) {
  const record = await getKeyRecord(apiKey);
  if (!record) throw new Error('No se puede acreditar: la llave "' + apiKey + '" no existe.');
  record.credits = (record.credits || 0) + credits;
  record.unlimitedDaily = true;
  await redisSet(KEY_PREFIX + apiKey, record);
  return record;
}

// ---------- órdenes de pago (CoinGate) ----------

async function createOrderRecord(orderId, data) {
  await redisSet(ORDER_PREFIX + orderId, Object.assign({ status: 'pending', processed: false }, data));
}

async function getOrderRecord(orderId) {
  return redisGet(ORDER_PREFIX + orderId);
}

async function markOrderProcessed(orderId, record) {
  record.processed = true;
  record.status = 'paid';
  await redisSet(ORDER_PREFIX + orderId, record);
}

module.exports = {
  DEFAULT_FREE_USES,
  DAILY_CALL_LIMIT,
  USING_MEMORY_FALLBACK,
  randomOrderToken,
  getKeyRecord,
  createKey,
  rateLimitCreateKey,
  checkAndConsume,
  refundUse,
  getDailyUsage,
  topUpCredits,
  grantEnterprise,
  createOrderRecord,
  getOrderRecord,
  markOrderProcessed
};
