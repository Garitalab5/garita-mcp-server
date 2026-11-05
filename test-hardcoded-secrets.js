"use strict";
// Pruebas para lib/hardcoded-secrets.js — el motor de detect_hardcoded_secrets_risk.
//
// Correr con: node test-hardcoded-secrets.js

const assert = require('assert');
const { checkHardcodedSecretsRisk } = require('./lib/hardcoded-secrets');

let pass = 0;
let fail = 0;

function test(name, fn) {
  try {
    fn();
    pass++;
    console.log('OK   - ' + name);
  } catch (err) {
    fail++;
    console.log('FAIL - ' + name);
    console.log('       ' + (err && err.stack ? err.stack : err));
  }
}

// ---------- Casos positivos (deben marcar riesgo) ----------

test('API key de OpenAI con formato reconocible en el código -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const client = new OpenAI({ apiKey: 'sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789' });`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('llave de acceso de AWS (AKIA...) embebida -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `def conectar():\n    aws_access_key_id = "AKIAABCD1234EFGH5678"\n    return boto3.client('s3', aws_access_key_id=aws_access_key_id)`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('bloque "env" de configuración MCP con secreto literal (patrón Hush Security) -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `{
  "mcpServers": {
    "meta-ads": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "META_ACCESS_TOKEN": "EAAGm0PX4ZCpsBAqZCZC7z9x8y7w6v5u4t3s2r1q0p"
      }
    }
  }
}`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('línea .env con contraseña de base de datos literal -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `DATABASE_URL=postgres://admin:hunter2produccion@db.ejemplo.com:5432/app\nDB_PASSWORD=hunter2produccionSecreta`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('llave privada PEM pegada en el código -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const key = \`-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\`;`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación: secreto embebido + fallback hardcodeado -> puntaje peor que cualquiera de los dos solos', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const apiKey = 'sk-abcdefghijklmnopqrstuvwxyz012345';\nconst dbPass = process.env.DB_PASSWORD || 'produccionSecreta123';`
  });
  const solo1 = checkHardcodedSecretsRisk({ codigo: `const apiKey = 'sk-abcdefghijklmnopqrstuvwxyz012345';` });
  assert.ok(r.puntaje < solo1.puntaje, 'r.puntaje=' + r.puntaje + ' solo1.puntaje=' + solo1.puntaje);
});

test('valor de reserva con secreto hardcodeado (sin formato conocido) en process.env.X || "..." (solo) -> riesgo moderado', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const token = process.env.INTERNAL_TOKEN || 'p7f2k9x1z8w3v6q0j5h4n2m1c9b8a7s6';`
  });
  assert.strictEqual(r.veredicto, 'Riesgo moderado');
});

test('llave de Stripe en vivo (sk_live_..., formato con guion bajo) embebida -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const stripeKey = "sk_live_AbCdEfGhIjKlMnOpQrStUvWx";`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('llave de Stripe de prueba (sk_test_...) embebida -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const stripeKey = "sk_test_AbCdEfGhIjKlMnOpQrStUvWx";`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('variable con nombre "_KEY" a secas (sin prefijo api/secret/access/private) con valor literal -> alto riesgo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const STRIPE_KEY = "hunter2secretoproduccion123";`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('llave leída desde una variable de entorno (uso normal) -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('config MCP con referencia a variable de entorno (${...}) -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `{ "mcpServers": { "meta-ads": { "env": { "META_ACCESS_TOKEN": "\${META_ACCESS_TOKEN}" } } } }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('placeholder de ejemplo ("your-api-key-here") -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `apiKey = "your-api-key-here"\npassword = "changeme"`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('llave de ejemplo oficial de AWS (contiene "EXAMPLE") en la documentación -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `// Ejemplo de la documentación de AWS:\naws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('os.environ.get con nombre de variable, sin valor de reserva -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `token = os.environ.get('GITHUB_TOKEN')`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('variable "monkey" (contiene "key" como substring al final, sin ser una credencial) -> aceptable, no falso positivo', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const monkey = "just a random string of chars here";`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('process.env.NODE_ENV || "production" (default benigno común, no es una credencial) -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const env = process.env.NODE_ENV || 'production';`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('process.env.AWS_REGION || "us-east-1" (default benigno común, no es una credencial) -> aceptable', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `const region = process.env.AWS_REGION || 'us-east-1';`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna credencial en el texto -> aceptable, puntaje 100', () => {
  const r = checkHardcodedSecretsRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código vacío -> lanza error', () => {
  assert.throws(() => checkHardcodedSecretsRisk({ codigo: '   ' }));
});

test('sin campo "codigo" -> lanza error', () => {
  assert.throws(() => checkHardcodedSecretsRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
