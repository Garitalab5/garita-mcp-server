"use strict";
// Garita MCP — servidor remoto
// ==============================
// Expone el mismo motor de garita-mcp.html (Versión 4, ya probado en 3
// rondas de ataques) como dos "tools" MCP que un agente de IA puede llamar
// directamente, sin que una persona tenga que abrir un navegador.
//
// Desde la ronda de cobro (2026-09): cada llamada a una herramienta exige
// una llave de acceso (header Authorization) con usos gratis o créditos
// disponibles. Ver lib/licensing.js (usos/créditos) y lib/coingate.js
// (compra de paquetes de créditos). El servidor sigue siendo stateless
// entre llamadas MCP — todo el estado de licencias vive en Upstash Redis,
// no en este proceso.

const crypto = require('crypto');
const express = require('express');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const { auditManifest, simulateApproval } = require('./lib/heuristics');
const escudo = require('./lib/escudo');
const { checkKnownVulnerabilities, ECOSISTEMAS_CONOCIDOS } = require('./lib/vulnerabilidades');
const { detectToolRugPull } = require('./lib/rugpull');
const { detectPoisonedConfigFiles } = require('./lib/config-poison');
const { checkPackageAuthenticity, ECOSISTEMAS_SOPORTADOS: ECOSISTEMAS_SLOPSQUATTING } = require('./lib/slopsquatting');
const licensing = require('./lib/licensing');
const coingate = require('./lib/coingate');

function extractApiKey(req) {
  const header = req.headers['authorization'] || '';
  // Acepta tanto "Bearer <llave>" como la llave sola en el header, para que
  // sea más difícil de usar mal desde un cliente MCP que no deje elegir el
  // prefijo exacto.
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return (m ? m[1] : header.trim()) || null;
}

function licenseErrorResult(check) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({
        error: true,
        message: check.reason,
        comoConseguirLlave: 'POST /crear-llave (gratis, da usos de prueba)',
        comoComprarCreditos: 'POST /comprar-creditos con { "apiKey": "...", "pack": "basico" | "pro" | "empresarial" }'
      }, null, 2)
    }]
  };
}

function buildServer(apiKey) {
  const server = new McpServer({ name: 'garita-mcp', version: '1.0.0' }, { capabilities: {} });

  server.registerTool(
    'audit_mcp_server',
    {
      title: 'Auditar servidor MCP',
      description:
        'Audita el manifiesto de un servidor MCP (serverInfo + tools[]) y devuelve un puntaje de confianza de 0 a 100, ' +
        'basado en autenticación no declarada, verbos de acción irreversible sin anotar (destructiveHint), agencia excesiva ' +
        '(openWorldHint) y campos que aceptan código libre. Úsalo antes de conectarte a un servidor MCP nuevo o desconocido. ' +
        'Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        manifest: z
          .record(z.string(), z.any())
          .describe('El manifiesto del servidor MCP como objeto JSON: { serverInfo, tools: [...] }.')
      }
    },
    async ({ manifest }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      const result = auditManifest(manifest);
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'simulate_approval',
    {
      title: 'Simular aprobación de una acción',
      description:
        'Evalúa si una acción que un agente quiere ejecutar debería quedar retenida para revisión humana o auto-aprobarse, ' +
        'según una política de retención (destructiveHint, verbos irreversibles, openWorldHint, monto por encima de un umbral, ' +
        'argumentos de código libre). Úsalo como el último paso antes de que un agente ejecute una acción potencialmente riesgosa. ' +
        'Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        action: z
          .record(z.string(), z.any())
          .describe('La acción propuesta: { tool, description, arguments, annotations }.'),
        rules: z
          .object({
            destructive: z.boolean().optional(),
            verbs: z.boolean().optional(),
            openWorld: z.boolean().optional(),
            amount: z.boolean().optional(),
            code: z.boolean().optional()
          })
          .optional()
          .describe('Qué reglas de la política están activas. Por defecto, todas activas.'),
        threshold: z.number().optional().describe('Umbral de monto que dispara retención. Por defecto 500.')
      }
    },
    async ({ action, rules, threshold }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      const result = simulateApproval(action, rules, threshold);
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'detect_poisoned_tool_descriptions',
    {
      title: 'Detectar instrucciones escondidas en descripciones de herramientas (Garita Escudo)',
      description:
        'Analiza la(s) descripción(es) de una o más herramientas MCP en busca de instrucciones ocultas o inyectadas ' +
        '("tool poisoning" / inyección de prompt): caracteres invisibles, esteganografía Unicode, homoglifos ' +
        '(letras de otro alfabeto mezcladas), entidades HTML en capas, bloques de pseudo-instrucción escondidos ' +
        '(<IMPORTANT>, comentarios), instrucciones para ocultar la acción al usuario, para manipular OTRA herramienta, ' +
        'para redirigir/copiar datos a otro destino, o para decodificar y seguir un texto codificado. Devuelve un ' +
        'puntaje de 0 a 100 y el detalle de cada señal encontrada, con el fragmento de texto donde apareció. ' +
        'Es un chequeo distinto y complementario a audit_mcp_server (que revisa el esquema/anotaciones del manifiesto, ' +
        'no el contenido semántico del texto) — úsalo antes de confiar en la descripción de una herramienta MCP nueva ' +
        'o desconocida. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        manifest: z
          .record(z.string(), z.any())
          .optional()
          .describe('Manifiesto MCP { serverInfo, tools: [...] }, un arreglo de herramientas, o una sola herramienta { name, description }.'),
        text: z
          .string()
          .optional()
          .describe('Alternativa a "manifest": una descripción de herramienta suelta, en texto plano.')
      }
    },
    async ({ manifest, text }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = escudo.auditToolDescriptions({ manifest, text });
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: err.message }, null, 2) }]
        };
      }
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'check_known_vulnerabilities',
    {
      title: 'Verificar vulnerabilidades conocidas de un paquete',
      description:
        'Revisa si un paquete de software (de npm, PyPI, Go, crates.io, Maven, RubyGems, y otros ecosistemas soportados por OSV.dev) ' +
        'tiene vulnerabilidades ya conocidas y publicadas (CVEs y equivalentes), consultando la base de datos abierta OSV.dev ' +
        '(agrega GitHub Advisory Database, PyPA, Go, npm, RustSec, entre otras). Devuelve cada vulnerabilidad encontrada con su ' +
        'identificador, CVE oficial si existe, severidad, fecha de publicación y un link. Úsalo antes de confiar en un paquete ' +
        'del que depende un servidor MCP o cualquier otro componente — un paquete puede pasar la auditoría del manifiesto y la ' +
        'detección de descripciones envenenadas y aun así tener una falla de seguridad ya conocida en su propio código. ' +
        'Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        ecosistema: z
          .string()
          .describe('Ecosistema del paquete. Comunes: ' + ECOSISTEMAS_CONOCIDOS.join(', ') + '. Se envía tal cual a OSV.dev.'),
        nombre: z.string().describe('Nombre exacto del paquete tal como aparece en su registro (ej. "left-pad" en npm).'),
        version: z
          .string()
          .optional()
          .describe('Versión exacta a revisar. Si se omite, busca vulnerabilidades conocidas en cualquier versión del paquete.')
      }
    },
    async ({ ecosistema, nombre, version }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = await checkKnownVulnerabilities({ ecosistema, nombre, version });
      } catch (err) {
        // A diferencia de las otras herramientas, esta depende de un
        // servicio externo (OSV.dev) — si falla, el cliente no recibió
        // ningún resultado real, así que se le devuelve el uso/crédito que
        // ya se había descontado arriba (no es justo cobrarle por una
        // falla de un tercero o de la red, fuera de su control).
        await licensing.refundUse(apiKey, check.consumedFrom);
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: err.message, _nota: 'No se descontó ningún uso/crédito por este intento.' }, null, 2) }]
        };
      }
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'detect_tool_rug_pull',
    {
      title: 'Detectar redefinición de herramientas tras la aprobación (rug-pull)',
      description:
        'Compara dos versiones del manifiesto de un mismo servidor MCP — la que aprobaste/revisaste antes ("anterior") y la de ahora ("actual") — ' +
        'y avisa si el texto de alguna herramienta ya aprobada cambió desde entonces. Detecta el patrón conocido como "MCP Tool Rug-Pull": una ' +
        'herramienta se ve benigna al aprobarse, pero su descripción se redefine DESPUÉS (en una actualización, en la siguiente carga) para meter ' +
        'una instrucción peligrosa. detect_poisoned_tool_descriptions revisa un manifiesto en un solo momento; esta herramienta revisa si algo ' +
        'cambió desde la última vez — úsalas juntas. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        anterior: z
          .record(z.string(), z.any())
          .describe('El manifiesto que aprobaste/revisaste la vez anterior: { serverInfo, tools: [...] } (mismo formato que audit_mcp_server).'),
        actual: z
          .record(z.string(), z.any())
          .describe('El manifiesto actual del mismo servidor, para comparar contra "anterior".')
      }
    },
    async ({ anterior, actual }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = detectToolRugPull({ anterior, actual });
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: err.message }, null, 2) }]
        };
      }
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'detect_poisoned_config_files',
    {
      title: 'Detectar archivos de configuración/instrucciones envenenados',
      description:
        'Analiza archivos de configuración/instrucciones que un agente de código carga y confía DE INMEDIATO, sin ningún paso de ' +
        'aprobación (AGENTS.md, CLAUDE.md, .cursorrules, archivos de "skills", y similares), en busca de instrucciones ocultas o ' +
        'peligrosas. Reutiliza el mismo motor de detect_poisoned_tool_descriptions (Garita Escudo) — caracteres invisibles, ' +
        'esteganografía Unicode, homoglifos, entidades HTML en capas, bloques de pseudo-instrucción escondidos, instrucciones de ' +
        'ocultar la acción al usuario, de manipular OTRA herramienta, de redirigir datos, de decodificar y seguir texto codificado, ' +
        'y el gatillo diferido tipo "rug-pull" — pero AJUSTADO a este género de archivo: el lenguaje de autoridad (IMPORTANTE, ' +
        'CRÍTICO) no se penaliza aquí porque es normal y esperado en un archivo de instrucciones, y se agrega una regla nueva, ' +
        '"filtración de credenciales", que no necesita ningún gatillo temporal — una instrucción de leer y exponer el contenido de ' +
        'un archivo de credenciales/secretos se marca de inmediato, porque a diferencia de una herramienta MCP, un archivo de ' +
        'instrucciones se confía sin pedir aprobación a nadie. Motivada por un caso real (2026): un archivo de reglas envenenado ' +
        'exfiltró credenciales de AWS/Kubernetes/Terraform en menos de 2 minutos en una prueba controlada. Acepta uno o varios ' +
        'archivos a la vez. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        archivos: z
          .array(z.object({
            ruta: z.string().optional().describe('Nombre/ruta del archivo, solo para identificarlo en el reporte (ej. "AGENTS.md", ".cursor/rules").'),
            contenido: z.string().describe('Contenido completo del archivo, en texto plano.')
          }))
          .optional()
          .describe('Uno o más archivos a revisar a la vez: [{ ruta, contenido }, ...].'),
        contenido: z
          .string()
          .optional()
          .describe('Alternativa a "archivos": el contenido de un solo archivo suelto, en texto plano.'),
        ruta: z
          .string()
          .optional()
          .describe('Solo junto con "contenido": el nombre/ruta de ese archivo suelto.')
      }
    },
    async ({ archivos, contenido, ruta }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = detectPoisonedConfigFiles({ archivos, contenido, ruta });
      } catch (err) {
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: err.message }, null, 2) }]
        };
      }
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'check_package_authenticity',
    {
      title: 'Verificar autenticidad de un paquete (typosquatting / "slopsquatting")',
      description:
        'Revisa si un paquete (por ahora solo npm) tiene señales de ser un impostor recién publicado en vez de un paquete ' +
        'legítimo: nombre casi idéntico a uno de los paquetes más populares combinado con poco historial propio ' +
        '(typosquatting clásico), publicado hace muy poco con un número de versión inicial ya "maduro" como 35.x.y en vez ' +
        'de 0.x/1.x (el patrón documentado en campañas reales de 2026 de "slopsquatting": nombres diseñados para parecerse ' +
        'a los que un asistente de IA alucina al sugerir una dependencia), un script que se ejecuta solo al instalar ' +
        '(postinstall/preinstall) en un paquete reciente, o ausencia total de repositorio/homepage/README. Si el paquete NO ' +
        'existe en el registro, avisa que puede ser una alucinación del agente y del riesgo de que alguien lo registre ' +
        'después con malware. Distinto y complementario a check_known_vulnerabilities: esa herramienta busca CVEs ya ' +
        'publicados en un paquete probablemente legítimo; esta busca señales de que el paquete en sí es falso, aunque no ' +
        'tenga ningún CVE todavía. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        ecosistema: z
          .string()
          .describe('Ecosistema del paquete. Por ahora solo se soporta: ' + ECOSISTEMAS_SLOPSQUATTING.join(', ') + '.'),
        nombre: z.string().describe('Nombre exacto del paquete tal como aparece en su registro (ej. "left-pad" en npm, o "@scope/paquete" para uno con alcance).')
      }
    },
    async ({ ecosistema, nombre }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = await checkPackageAuthenticity({ ecosistema, nombre });
      } catch (err) {
        // Igual que check_known_vulnerabilities: si el registro de npm no
        // respondió, el cliente no recibió ningún resultado real, así que
        // se le devuelve el uso/crédito.
        await licensing.refundUse(apiKey, check.consumedFrom);
        return {
          isError: true,
          content: [{ type: 'text', text: JSON.stringify({ error: true, message: err.message, _nota: 'No se descontó ningún uso/crédito por este intento.' }, null, 2) }]
        };
      }
      result._licencia = check.remaining;
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  return server;
}

const app = express();
app.set('trust proxy', true); // Render está detrás de un proxy; necesario para obtener la IP real del cliente.
// 2 MB es de sobra para un manifiesto MCP o una acción real, y sigue siendo
// una defensa adicional (además del tope de 200,000 nodos dentro del motor)
// contra un payload inflado a propósito para agotar el análisis.
app.use(express.json({ limit: '2mb' }));

function publicBaseUrl(req) {
  return process.env.PUBLIC_BASE_URL || (req.protocol + '://' + req.get('host'));
}

app.get('/', (req, res) => {
  res.type('text/plain').send(
    'Garita MCP server — remote MCP endpoint en POST /mcp (requiere llave de acceso en el header Authorization).\n\n' +
    'Herramientas MCP disponibles: audit_mcp_server, simulate_approval, detect_poisoned_tool_descriptions (Garita Escudo), check_known_vulnerabilities, detect_tool_rug_pull, detect_poisoned_config_files, check_package_authenticity.\n\n' +
    'Endpoints:\n' +
    '  POST /crear-llave              — consigue una llave de acceso gratis (' + licensing.DEFAULT_FREE_USES + ' usos de prueba)\n' +
    '  GET  /consultar-llave?apiKey=  — consulta cuántos usos gratis/créditos le quedan a una llave\n' +
    '  POST /comprar-creditos         — { apiKey, pack: "basico"|"pro"|"empresarial" } → devuelve un link de pago CoinGate\n' +
    '                                    ("empresarial" además quita el tope diario de 50 usos/día para siempre en esa llave)\n' +
    '  GET  /verificar-pago?orderId=  — revisa a mano si un pago ya se confirmó (respaldo, normalmente no hace falta)\n' +
    '  POST /coingate/webhook         — (uso interno de CoinGate, no lo llames a mano)\n' +
    '  POST /mcp                      — endpoint MCP, ver README para conectarlo desde un agente\n'
  );
});

// ---------- llaves de acceso ----------

app.post('/crear-llave', async (req, res) => {
  try {
    const ip = req.ip || 'desconocida';
    const okRate = await licensing.rateLimitCreateKey(ip);
    if (!okRate) {
      return res.status(429).json({ error: true, message: 'Demasiadas llaves nuevas creadas desde esta dirección hoy. Intenta de nuevo mañana, o compra créditos para una llave existente.' });
    }
    const { apiKey, record } = await licensing.createKey();
    res.json({
      apiKey,
      usosGratis: record.freeUsesRemaining,
      mensaje: 'Guarda esta llave — no se puede recuperar después. Mándala en el header "Authorization: Bearer ' + apiKey + '" al conectar el servidor MCP.'
    });
  } catch (err) {
    console.error('Error en /crear-llave:', err);
    res.status(500).json({ error: true, message: 'No se pudo crear la llave.' });
  }
});

app.get('/consultar-llave', async (req, res) => {
  try {
    const apiKey = String(req.query.apiKey || '');
    const record = await licensing.getKeyRecord(apiKey);
    if (!record) return res.status(404).json({ error: true, message: 'Llave no encontrada.' });
    const usosHoy = await licensing.getDailyUsage(apiKey);
    res.json({
      usosGratis: record.freeUsesRemaining,
      creditos: record.credits,
      usosHoy,
      topeDiario: record.unlimitedDaily ? null : licensing.DAILY_CALL_LIMIT,
      empresarial: !!record.unlimitedDaily,
      creadaEl: record.createdAt
    });
  } catch (err) {
    console.error('Error en /consultar-llave:', err);
    res.status(500).json({ error: true, message: 'No se pudo consultar la llave.' });
  }
});

// ---------- compra de créditos (CoinGate) ----------

app.post('/comprar-creditos', async (req, res) => {
  try {
    const apiKey = String((req.body && req.body.apiKey) || '');
    const pack = String((req.body && req.body.pack) || '');
    const record = await licensing.getKeyRecord(apiKey);
    if (!record) return res.status(404).json({ error: true, message: 'Llave no encontrada. Crea una primero en POST /crear-llave.' });
    if (!coingate.CREDIT_PACKS[pack]) {
      return res.status(400).json({ error: true, message: 'Paquete inválido. Opciones: ' + Object.keys(coingate.CREDIT_PACKS).join(', ') });
    }

    const orderId = 'garita_' + crypto.randomUUID();
    const token = licensing.randomOrderToken();
    const { packConfig, payment_url, coingateOrderId } = await coingate.createOrder({
      orderId, token, pack, publicBaseUrl: publicBaseUrl(req)
    });
    await licensing.createOrderRecord(orderId, {
      apiKey,
      credits: packConfig.credits,
      token,
      coingateOrderId,
      enterprise: !!packConfig.enterprise
    });

    res.json({
      payment_url,
      orderId,
      paquete: packConfig.label,
      creditos: packConfig.credits,
      empresarial: !!packConfig.enterprise,
      precio: packConfig.price_amount + ' ' + packConfig.price_currency,
      nota: 'Guarda el "orderId" — con él puedes consultar el estado del pago en GET /verificar-pago?orderId=... si tarda en confirmarse (normal en pagos con cripto: puede tomar desde minutos hasta más, según la red).'
    });
  } catch (err) {
    console.error('Error en /comprar-creditos:', err);
    res.status(500).json({ error: true, message: 'No se pudo crear la orden de pago: ' + err.message });
  }
});

// Acredita una orden si su estado es "paid" y todavía no se había
// procesado. Idempotente (se puede llamar de más sin duplicar créditos).
// Compartida entre el webhook automático y la consulta manual de abajo.
async function creditOrderIfPaid(orderId, order, status) {
  if (order.processed) return { credited: false, alreadyProcessed: true };
  if (status !== 'paid') return { credited: false, alreadyProcessed: false };
  if (order.enterprise) {
    await licensing.grantEnterprise(order.apiKey, order.credits);
  } else {
    await licensing.topUpCredits(order.apiKey, order.credits);
  }
  await licensing.markOrderProcessed(orderId, order);
  return { credited: true, alreadyProcessed: false };
}

app.post('/coingate/webhook', async (req, res) => {
  // Siempre responder rápido con 200 una vez leído el cuerpo — CoinGate
  // reintenta hasta 40 veces a lo largo de varios días si no recibe un 200,
  // así que no hace falta ser estrictos aquí, pero tampoco queremos
  // convertir un error nuestro en reintentos innecesarios.
  try {
    const body = req.body || {};
    const orderId = String(body.order_id || '');
    const status = String(body.status || '');
    const receivedToken = String(body.token || '');

    const order = await licensing.getOrderRecord(orderId);
    if (!order) {
      console.warn('Webhook de CoinGate para una orden desconocida:', orderId);
      return res.status(200).send('ok');
    }
    if (receivedToken !== order.token) {
      // Firma inválida: no confiar en esta notificación. No es un 4xx para
      // evitar dar pistas de por qué falló, pero tampoco se acredita nada.
      console.warn('Webhook de CoinGate con token inválido para la orden:', orderId);
      return res.status(200).send('ok');
    }
    await creditOrderIfPaid(orderId, order, status);
    res.status(200).send('ok');
  } catch (err) {
    console.error('Error en /coingate/webhook:', err);
    res.status(200).send('ok'); // ver comentario arriba: siempre 200 para evitar reintentos en cascada
  }
});

// Respaldo manual para cuando un pago tarda en confirmarse (normal con
// cripto) o alguien quiere revisar sin esperar el próximo reintento del
// webhook: le pregunta a CoinGate el estado REAL de la orden en este
// momento, y si ya está pagada, la acredita en el momento — sin esperar a
// que llegue el webhook. Es seguro llamarlo las veces que sea (idempotente).
app.get('/verificar-pago', async (req, res) => {
  try {
    const orderId = String(req.query.orderId || '');
    const order = await licensing.getOrderRecord(orderId);
    if (!order) return res.status(404).json({ error: true, message: 'Orden no encontrada.' });

    if (order.processed) {
      return res.json({ estado: 'paid', mensaje: 'Ya estaba acreditada.', creditos: order.credits });
    }

    const liveOrder = await coingate.getOrder(order.coingateOrderId);
    const result = await creditOrderIfPaid(orderId, order, liveOrder.status);

    if (result.credited) {
      return res.json({ estado: 'paid', mensaje: '¡Pago confirmado! Se acreditaron los créditos ahora mismo.', creditos: order.credits });
    }
    res.json({
      estado: liveOrder.status,
      mensaje: liveOrder.status === 'confirming'
        ? 'El pago ya llegó pero la red de la criptomoneda todavía no lo confirma del todo — es normal, puede tardar. Vuelve a consultar en un rato.'
        : 'Todavía no hay un pago confirmado para esta orden.'
    });
  } catch (err) {
    console.error('Error en /verificar-pago:', err);
    res.status(500).json({ error: true, message: 'No se pudo consultar el estado del pago: ' + err.message });
  }
});

// ---------- endpoint MCP ----------

// Servidor stateless: una conexión nueva por request, sin sesiones que
// mantener vivas entre llamadas — más simple y más barato de hostear
// (encaja bien con planes gratuitos que duermen el servicio por inactividad).
app.post('/mcp', async (req, res) => {
  try {
    const apiKey = extractApiKey(req);
    const server = buildServer(apiKey);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
    res.on('close', () => {
      transport.close();
      server.close();
    });
  } catch (err) {
    console.error('Error manejando solicitud MCP:', err);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
    }
  }
});

app.get('/mcp', (req, res) => {
  res.writeHead(405).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
});
app.delete('/mcp', (req, res) => {
  res.writeHead(405).end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Garita MCP server escuchando en el puerto ' + PORT);
  if (licensing.USING_MEMORY_FALLBACK) {
    console.log('(Modo de licencias EN MEMORIA — ver advertencia arriba. No usar así en producción.)');
  }
});

process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
