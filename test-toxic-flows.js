"use strict";
// Pruebas para lib/toxic-flows.js — el motor de detect_toxic_flow_risk.
//
// Correr con: node test-toxic-flows.js

const assert = require('assert');
const { checkToxicFlowRisk, classify } = require('./lib/toxic-flows');

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

test('patrón mcp-atlassian (CVE-2026-77255): leer archivo local + subir adjunto sin aprobación -> alto riesgo', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_local_file', description: 'Lee el contenido de un archivo local del sistema, incluidas variables de configuración.' },
        { name: 'update_issue', description: 'Sube un adjunto a un ticket de Jira usando el archivo indicado.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.strictEqual(r.hallazgos.length, 1);
  assert.ok(!r.resumen.includes('trifecta'), 'no debería ser trifecta completa (falta contenido no confiable)');
});

test('patrón EchoLeak (CVE-2025-32711): correo no confiable + calendario privado + renderizado automático -> trifecta completa', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_email', description: 'Lee el contenido de un correo electrónico recibido en la bandeja de entrada.' },
        { name: 'get_internal_calendar', description: 'Obtiene el calendario interno privado del usuario.' },
        { name: 'render_link_preview', description: 'Publica una vista previa enviando el enlace a un servicio externo de renderizado.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.strictEqual(r.hallazgos.length, 2);
  assert.ok(r.resumen.toLowerCase().includes('flujo'), 'debe mencionar la cantidad de combinaciones');
});

test('patrón Invariant Labs / GitHub MCP: issue público + repo privado + crear comentario -> trifecta completa', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'get_public_issue', description: 'Busca el contenido de un issue público en un repositorio de GitHub.' },
        { name: 'search_private_repo', description: 'Busca contenido dentro de un repositorio privado del usuario.' },
        { name: 'create_comment', description: 'Crea un comentario en el issue indicado.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.strictEqual(r.hallazgos.length, 2);
});

test('una sola herramienta que lee un archivo local Y lo sube -> igual se marca (combinación dentro de la misma herramienta)', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'backup_local_file', description: 'Lee un archivo local y lo sube automáticamente a un servicio de respaldo en la nube.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.strictEqual(r.hallazgos.length, 1);
});

test('varias herramientas de salida sin aprobación -> puntaje peor que con solo una', () => {
  const unaSola = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_credentials_file', description: 'Lee el archivo local de credenciales.' },
        { name: 'send_email', description: 'Envía un correo electrónico con el contenido indicado.' }
      ]
    }
  });
  const tres = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_credentials_file', description: 'Lee el archivo local de credenciales.' },
        { name: 'send_email', description: 'Envía un correo electrónico con el contenido indicado.' },
        { name: 'post_to_webhook', description: 'Publica el contenido en un webhook externo.' },
        { name: 'share_via_link', description: 'Comparte el archivo generando un enlace público.' }
      ]
    }
  });
  assert.ok(tres.puntaje < unaSola.puntaje, 'más herramientas de salida sin aprobar debe dar peor puntaje: ' + tres.puntaje + ' vs ' + unaSola.puntaje);
});

test('descripciones en portugués (Lê / arquivo local / credenciais + envia a webhook) -> se reconoce igual que en español/inglés', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'ler_arquivo_credenciais', description: 'Lê o conteúdo de um arquivo local, incluindo credenciais e senha do banco de dados.' },
        { name: 'enviar_dados', description: 'Envia os dados para um webhook externo.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.strictEqual(r.hallazgos.length, 1);
});

test('nombre de herramienta camelCase sin separadores (readLocalCredentialsFile) -> se reconoce el sustantivo compuesto', () => {
  const c = classify({ name: 'readLocalCredentialsFile', description: '' }, 0);
  assert.strictEqual(c.privado, true);
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('solo herramientas de lectura, sin ninguna de salida -> aceptable', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_local_file', description: 'Lee un archivo local del sistema.' },
        { name: 'query_database', description: 'Consulta la base de datos de clientes.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos.length, 0);
});

test('solo herramientas de salida, sin ninguna de lectura de datos privados/no confiables -> aceptable', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'send_email', description: 'Envía un correo electrónico con el texto indicado por el usuario.' },
        { name: 'post_status_update', description: 'Publica una actualización de estado dada por el usuario.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos.length, 0);
});

test('herramienta de salida con campo de aprobación EXIGIDO en el esquema (required) -> no se marca', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_credentials_file', description: 'Lee el archivo local de credenciales.' },
        {
          name: 'send_email',
          description: 'Envía un correo electrónico con el contenido indicado.',
          inputSchema: {
            properties: { destinatario: { type: 'string' }, aprobado_por: { type: 'string' } },
            required: ['destinatario', 'aprobado_por']
          }
        }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos.length, 0);
  assert.ok(r.resumen.includes('confirmación'), 'debe explicar que hay una mitigación real declarada');
});

test('campo de aprobación presente en el esquema pero NO exigido (no está en "required") -> se sigue marcando', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'read_credentials_file', description: 'Lee el archivo local de credenciales.' },
        {
          name: 'send_email',
          description: 'Envía un correo electrónico con el contenido indicado.',
          inputSchema: {
            properties: { destinatario: { type: 'string' }, aprobado_por: { type: 'string' } },
            required: ['destinatario']
          }
        }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.strictEqual(r.hallazgos.length, 1);
});

test('list_comments / get_comments (solo lectura de comentarios) no se clasifica como herramienta de salida', () => {
  const c = classify({ name: 'list_comments', description: 'Lista los comentarios existentes en un issue.' }, 0);
  assert.strictEqual(c.egreso, false);
  assert.strictEqual(c.noConfiable, true, 'leer comentarios sí cuenta como contenido no confiable');
});

test('herramienta ajena al tema (clima) no se clasifica en ninguna categoría', () => {
  const r = checkToxicFlowRisk({
    manifest: {
      tools: [
        { name: 'get_weather', description: 'Obtiene el pronóstico del clima para una ciudad dada.' }
      ]
    }
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos.length, 0);
});

test('herramienta suelta como string (sin objeto {name,description}) no rompe el análisis', () => {
  const r = checkToxicFlowRisk({ manifest: ['Obtiene el pronóstico del clima para una ciudad dada.'] });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

// ---------- Casos de entrada inválida ----------

test('sin manifiesto -> lanza error', () => {
  assert.throws(() => checkToxicFlowRisk({}), /manifiesto/i);
});

test('manifiesto con arreglo "tools" vacío -> lanza error', () => {
  assert.throws(() => checkToxicFlowRisk({ manifest: { tools: [] } }), /manifiesto/i);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
process.exit(fail > 0 ? 1 : 0);
