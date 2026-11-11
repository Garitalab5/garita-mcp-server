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
const { checkMemoryPoisoning, FUENTES_VALIDAS: FUENTES_MEMORIA } = require('./lib/memoria');
const { checkSsrfRisk } = require('./lib/ssrf');
const { checkPathTraversalRisk } = require('./lib/traversal');
const { checkCommandInjectionRisk } = require('./lib/command-injection');
const { checkSqlInjectionRisk } = require('./lib/sql-injection');
const { checkTokenPassthroughRisk } = require('./lib/token-passthrough');
const { checkHardcodedSecretsRisk } = require('./lib/hardcoded-secrets');
const { checkInsecureDeserializationRisk } = require('./lib/deserialization');
const { checkToxicFlowRisk } = require('./lib/toxic-flows');
const { checkSsTemplateInjectionRisk } = require('./lib/ssti');
const { checkDynamicCodeRisk } = require('./lib/dynamic-code');
const { checkDnsRebindingRisk } = require('./lib/dns-rebinding');
const { checkMissingAuthRisk } = require('./lib/missing-auth');
const { checkMcpStdioLaunchRisk } = require('./lib/mcp-stdio');
const { checkRedosRisk } = require('./lib/redos');
const { checkSessionHijackRisk } = require('./lib/session-hijack');
const { checkOAuthAudienceConfusionRisk } = require('./lib/oauth-audience');
const { checkUnboundedAllocationRisk } = require('./lib/unbounded-allocation');
const { checkCrossClientLeakRisk } = require('./lib/cross-client-leak');
const { checkSamplingHijackRisk } = require('./lib/sampling-hijack');
const { checkOutputSchemaSsrfRisk } = require('./lib/output-schema-ssrf');
const { checkExcessiveAgencyRisk } = require('./lib/excessive-agency');
const { checkCallSpoofingRisk } = require('./lib/call-spoofing');
const licensing = require('./lib/licensing');
const coingate = require('./lib/coingate');
const paypal = require('./lib/paypal');
const vigia = require('./lib/vigia');

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

  server.registerTool(
    'detect_memory_poisoning',
    {
      title: 'Detectar envenenamiento de memoria persistente',
      description:
        'Revisa un texto que un agente con memoria de largo plazo va a guardar (o que ya guardó) en busca de instrucciones ' +
        'plantadas para activarse recién en una sesión futura, sin relación con la conversación donde se coló el texto. ' +
        'Distinto de detect_poisoned_tool_descriptions (Garita Escudo): ese revisa la descripción de una HERRAMIENTA; este ' +
        'revisa CONTENIDO que va hacia la memoria — una nota, un hecho guardado, un resumen automático de una conversación ' +
        'vieja, o texto traído por otra herramienta (documento, página web, salida de una API). Detecta: instrucciones ' +
        'condicionales tipo "si el usuario dice que sí, entonces..." (el método documentado del ataque real contra Gemini, ' +
        'investigador Rehberger 2025, y el método MINJA de NeurIPS 2025 con más de 95% de éxito contra agentes en ' +
        'producción), la combinación de "recordá esto para siempre" + "no se lo menciones al usuario" (casi nunca legítima ' +
        'venga de donde venga), texto que se hace pasar por una instrucción del sistema o pide ignorar instrucciones ' +
        'anteriores, instrucciones de enviar datos a un tercero la próxima vez que se recupere la memoria, etiquetas falsas ' +
        'de sistema escondidas en el contenido, y texto que se dirige directamente al asistente por su nombre dentro de ' +
        'contenido que debería ser pasivo (un documento, una página web). El campo "fuente" importa: un usuario pidiéndole ' +
        'directamente al agente que recuerde algo es el uso normal del producto y se pondera distinto a lo mismo encontrado ' +
        'dentro de un documento, un resumen automático o la salida de otra herramienta. Requiere una llave de acceso válida ' +
        '(usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        texto: z.string().describe('El contenido que se va a guardar (o que ya está guardado) en la memoria de largo plazo del agente.'),
        fuente: z
          .string()
          .optional()
          .describe('De dónde viene el texto: ' + FUENTES_MEMORIA.join(', ') + '. Si no se especifica, se trata como no confiable por precaución.')
      }
    },
    async ({ texto, fuente }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkMemoryPoisoning({ texto, fuente });
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
    'detect_ssrf_risk',
    {
      title: 'Detectar riesgo de SSRF (Server-Side Request Forgery) en una herramienta',
      description:
        'Analiza el código fuente de una herramienta MCP que hace una petición HTTP a una URL (traer una página, ' +
        'llamar un webhook, un scraper) en busca de señales de riesgo de SSRF: una llamada HTTP (fetch, axios, ' +
        'requests, urlopen, curl_exec, y equivalentes) cuya URL depende de una variable/entrada externa sin ninguna ' +
        'validación reconocible cerca (lista de hosts permitidos, chequeo de IP privada, o una librería conocida ' +
        'contra SSRF), una referencia directa a una IP privada/loopback o a un endpoint de metadata de la nube ' +
        '(AWS/GCP/Azure — el patrón real usado para robar credenciales temporales de la nube) dentro de la propia ' +
        'llamada, verificación de certificado TLS desactivada junto con una petición externa, seguir redirecciones ' +
        'automáticamente sin revalidar el destino final, y ausencia de restricción de esquema (http/https) aunque ' +
        'sí se valide la IP. Motivada por un censo real de 2026 sobre 9.695 servidores MCP escaneados: SSRF fue el ' +
        '8.5% de los 4.982 problemas encontrados, dentro de un 60% de servidores con algún problema de seguridad. ' +
        'Es un análisis estático por patrones de texto (no ejecuta el código) — mismo enfoque que ' +
        'detect_poisoned_tool_descriptions. Requiere una llave de acceso válida (usos gratis o créditos) — ver ' +
        'POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que hace la petición HTTP, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkSsrfRisk({ codigo, lenguaje });
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
    'detect_path_traversal_risk',
    {
      title: 'Detectar riesgo de path traversal / acceso arbitrario a archivos',
      description:
        'Analiza el código fuente de una herramienta MCP que lee, escribe o borra un archivo a partir de una ruta que le ' +
        'pasa el agente (abrir un documento, guardar un adjunto, exportar un reporte) en busca de señales de riesgo de ' +
        'path traversal: una operación de archivo (fs.readFile, fs.writeFile, open, shutil, send_file, y equivalentes) ' +
        'cuya ruta depende de una variable/entrada externa sin ninguna validación reconocible contra secuencias de ' +
        'escape ("../") cerca, una referencia directa a una ruta sensible del sistema (/etc/passwd, una llave SSH, un ' +
        'archivo de credenciales) dentro de la propia operación, y ausencia de rechazo explícito de rutas absolutas ' +
        '(aunque sí se filtren las secuencias "../", una ruta absoluta directa puede seguir escapando del directorio ' +
        'permitido). Motivada por ser la categoría MÁS GRANDE de vulnerabilidades reales encontradas en un censo de 2026 ' +
        'sobre 9.695 servidores MCP escaneados: acceso arbitrario a archivos fue el 17.7% de los 4.982 problemas ' +
        'encontrados (880 casos) — más grande que denegación de servicio, inyección de comandos o SSRF. Caso real: ' +
        'CVE-2026-40576 (CVSS 9.4, crítico) en un servidor MCP de Excel, donde su función de rutas permitía tanto rutas ' +
        'absolutas como secuencias "../" sin resolverlas contra el directorio permitido. Es un análisis estático por ' +
        'patrones de texto (no ejecuta el código) — mismo enfoque que detect_ssrf_risk. Requiere una llave de acceso ' +
        'válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que lee, escribe o borra un archivo, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkPathTraversalRisk({ codigo, lenguaje });
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
    'detect_command_injection_risk',
    {
      title: 'Detectar riesgo de inyección de comandos del sistema',
      description:
        'Analiza el código fuente de una herramienta MCP que ejecuta un comando del sistema operativo a partir de ' +
        'una entrada que le pasa el agente (un nombre de archivo, un argumento de búsqueda, un parámetro cualquiera) ' +
        'en busca de señales de riesgo de inyección de comandos: una llamada que SIEMPRE invoca una shell (exec, ' +
        'execSync, os.system, os.popen, shell_exec, passthru, system, y equivalentes) con un argumento que depende ' +
        'de una variable/entrada externa sin ninguna validación o escape reconocible cerca; una llamada que invoca ' +
        'una shell solo CONDICIONALMENTE (spawn/execFile de Node, subprocess.run/Popen/call de Python) únicamente ' +
        'cuando trae la opción shell:true/shell=True explícita — sin esa opción, un arreglo de argumentos se ejecuta ' +
        'directamente sin pasar por ningún intérprete de shell y no se marca como riesgo; el patrón "descargar y ' +
        'ejecutar" (curl/wget encadenado con una tubería directa a bash/sh); y ausencia de cualquier filtrado ' +
        'reconocible de metacaracteres de shell (;, &&, |, `, $(), >, <) — una lista de comandos permitidos que solo ' +
        'revisa el primer token del comando deja pasar cualquier cosa encadenada después de ese token, el patrón ' +
        'exacto detrás de CVE-2026-55581/55582 (mcp-shell, CVSS hasta 8.6). Motivada por ser la SEGUNDA categoría más ' +
        'grande de vulnerabilidades reales en un censo de 2026 sobre 9.695 servidores MCP escaneados: inyección de ' +
        'comandos fue el 9.6% de los 4.982 problemas encontrados (476 casos) — solo detrás de acceso arbitrario a ' +
        'archivos. También documentado en CVE-2025-6514 (CVSS 9.6, crítico) en mcp-remote. Es un análisis estático ' +
        'por patrones de texto (no ejecuta el código) — mismo enfoque que detect_ssrf_risk y ' +
        'detect_path_traversal_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ver ' +
        'POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que ejecuta un comando del sistema, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkCommandInjectionRisk({ codigo, lenguaje });
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
    'detect_sql_injection_risk',
    {
      title: 'Detectar riesgo de inyección SQL',
      description:
        'Analiza el código fuente de una herramienta MCP que ejecuta una consulta SQL a partir de una entrada que le ' +
        'pasa el agente (un nombre de usuario, un filtro de búsqueda, un identificador cualquiera) en busca de dos ' +
        'señales de riesgo distintas: (1) el patrón clásico de inyección — una llamada que ejecuta SQL crudo ' +
        '(.query, .execute, .raw, .exec_driver_sql, mysqli_query, y equivalentes) con la consulta armada por ' +
        'concatenación o interpolación de una variable/entrada externa, en vez de un parámetro preparado, sin ' +
        'ninguna función de escape reconocible cerca; y (2) un patrón propio de Garita motivado por un caso real: el ' +
        'código (o su comentario/descripción) afirma que la herramienta es de "solo lectura", pero no hay ninguna ' +
        'señal de que eso se aplique de verdad a nivel de base de datos — exactamente lo que Datadog Security Labs ' +
        'encontró en el servidor MCP de referencia de Postgres de Anthropic, donde la restricción de "solo lectura" ' +
        'vivía únicamente en el texto que lee el agente, no como un permiso real. Motivada por un censo real de 2026 ' +
        'sobre 9.695 servidores MCP escaneados: inyección SQL fue el 4.2% de los 4.982 problemas encontrados (211 ' +
        'casos). También documentado en CVE-2026-7206 (sqlite-mcp) y CVE-2025-66335 (Apache Doris MCP Server). Es un ' +
        'análisis estático por patrones de texto (no ejecuta el código) — mismo enfoque que detect_ssrf_risk, ' +
        'detect_path_traversal_risk y detect_command_injection_risk. Requiere una llave de acceso válida (usos ' +
        'gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que ejecuta una consulta SQL, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkSqlInjectionRisk({ codigo, lenguaje });
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
    'detect_token_passthrough_risk',
    {
      title: 'Detectar riesgo de reenvío de tokens OAuth (token passthrough)',
      description:
        'Analiza el código fuente de un middleware o herramienta MCP que maneja el token de autorización de quien ' +
        'lo llama, en busca de señales del antipatrón "token passthrough" (confused deputy): (1) un middleware que ' +
        'deja pasar la petición (next()/call_next()) sin ninguna verificación de autorización reconocible antes — ' +
        'el patrón exacto detrás de CVE-2026-48039 (Meta Ads MCP, CVSS 9.1 CRÍTICO), donde un dispatch() reenviaba ' +
        'peticiones sin validar el header Authorization y filtraba el token de larga duración del operador; (2) el ' +
        'token de autorización de la petición ENTRANTE reenviado tal cual hacia otra llamada saliente, sin ' +
        'revalidarlo ni reemitir uno propio — la especificación oficial de MCP prohíbe explícitamente que un ' +
        'servidor acepte o reenvíe tokens que no fueron emitidos para él; (3) una verificación de JWT (jwt.verify/ ' +
        'jwt.decode) que no valida el claim "audience"/"aud", con lo que nada distingue un token emitido para este ' +
        'servidor de uno emitido para cualquier otro; y (4) un token colocado como parámetro de una URL en vez de ' +
        'en un header, expuesto en logs y cabeceras Referer. El mismo patrón de reenvío sin validar también aparece ' +
        'en CVE-2025-6514 (mcp-remote, CVSS 9.6) y CVE-2026-27826 (MCP Atlassian, CVSS 8.2). Es un análisis estático ' +
        'por patrones de texto (no ejecuta el código) — mismo enfoque que detect_ssrf_risk, ' +
        'detect_path_traversal_risk, detect_command_injection_risk y detect_sql_injection_risk. Requiere una llave ' +
        'de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente del middleware/herramienta que maneja el token de autorización, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkTokenPassthroughRisk({ codigo, lenguaje });
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
    'detect_hardcoded_secrets_risk',
    {
      title: 'Detectar secretos embebidos en texto plano (credenciales hardcodeadas)',
      description:
        'Analiza código fuente o un archivo de configuración (incluido el bloque "env" de un servidor en la config ' +
        'de mcpServers, o un archivo ".env") en busca de credenciales escritas tal cual en texto plano, en vez de ' +
        'venir de una variable de entorno o un gestor de secretos: (1) cadenas con el formato reconocible de una ' +
        'credencial real (llaves de OpenAI, AWS, GitHub, Slack, Google, o el encabezado de una llave privada PEM); ' +
        '(2) una variable o llave de configuración con nombre de credencial (api_key, secret, token, password…) ' +
        'con un valor literal en el propio código; (3) una línea al estilo ".env" que asigna un valor literal a una ' +
        'variable de entorno cuyo nombre indica una credencial; y (4) una variable de entorno con un valor de ' +
        'reserva ("fallback") hardcodeado — si la variable de entorno no está definida, el código sigue ' +
        'funcionando igual con el secreto embebido, lo que anula el propósito de usar una variable de entorno. ' +
        'Motivada por un reporte real de Hush Security (septiembre 2026) que escaneó ~82.000 archivos de ' +
        'configuración MCP públicos en GitHub: el 12% de los espacios de credenciales tenía un secreto literal ' +
        'embebido, el 53% de esos con acceso a nivel de toda la organización, y el 55% sin ningún formato de token ' +
        'conocido. También documentado por Trend Micro (48% de 19.402 servidores MCP con almacenamiento inseguro ' +
        'de secretos) y catalogado como MCP01 en el OWASP MCP Top 10. Reconoce placeholders/ejemplos comunes ' +
        '("your-api-key-here", "changeme", la llave de ejemplo oficial de AWS) para no marcarlos como riesgo. Es un ' +
        'análisis estático por patrones de texto (no ejecuta el código ni revisa el historial de git) — mismo ' +
        'enfoque que detect_ssrf_risk, detect_path_traversal_risk, detect_command_injection_risk, ' +
        'detect_sql_injection_risk y detect_token_passthrough_risk. Requiere una llave de acceso válida (usos ' +
        'gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente o archivo de configuración a revisar, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python", "json", "env") — la detección ya cubre varios formatos a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkHardcodedSecretsRisk({ codigo, lenguaje });
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
    'detect_insecure_deserialization_risk',
    {
      title: 'Detectar riesgo de deserialización insegura',
      description:
        'Analiza el código fuente de una herramienta MCP que carga datos serializados (un modelo de IA, un archivo ' +
        'de configuración, un objeto guardado) en busca de funciones que pueden terminar ejecutando código ' +
        'arbitrario al momento de "leer" esos datos: (1) funciones que SIEMPRE reconstruyen objetos arbitrarios sin ' +
        'ninguna variante segura (pickle.load/loads, cPickle, marshal.loads, dill.loads, joblib.load, y ' +
        'unserialize() de PHP); (2) funciones que solo son peligrosas si no se usa su opción segura — yaml.load() ' +
        'sin Loader=yaml.SafeLoader (o yaml.safe_load()), y torch.load() sin weights_only=True; y (3) un método ' +
        '__reduce__/__reduce_ex__ que ejecuta un comando del sistema al reconstruirse — la firma clásica de un ' +
        'payload malicioso de pickle. Motivada por CVE-2025-45146 (CVSS 9.8, CRÍTICO) en ModelCache, una librería ' +
        'de caché para agentes/LLM que llamaba a torch.load() sobre bytes sin validar; y CVE-2025-32434 (CVSS 9.3), ' +
        'que mostró que ni siquiera weights_only=True bastaba solo en versiones de PyTorch anteriores a la 2.6.0 — ' +
        'por eso esta herramienta trata esa opción como una señal que reduce el riesgo, no como algo que lo ' +
        'elimina. Reconoce un Unpickler restringido (RestrictedUnpickler/find_class) como señal de que ya se tomó ' +
        'una precaución real. Es un análisis estático por patrones de texto (no ejecuta el código) — mismo enfoque ' +
        'que detect_ssrf_risk, detect_path_traversal_risk, detect_command_injection_risk, detect_sql_injection_risk, ' +
        'detect_token_passthrough_risk y detect_hardcoded_secrets_risk. Requiere una llave de acceso válida (usos ' +
        'gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que deserializa datos, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python", "javascript", "php") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkInsecureDeserializationRisk({ codigo, lenguaje });
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
    'detect_toxic_flow_risk',
    {
      title: 'Detectar flujos tóxicos (combinaciones peligrosas de herramientas)',
      description:
        'A diferencia de las otras herramientas de detección (que analizan una función de código a la vez), esta ' +
        'analiza el MANIFIESTO completo de un servidor MCP — igual que audit_mcp_server — buscando una COMBINACIÓN ' +
        'peligrosa de capacidades: una herramienta que lee datos privados/sensibles (archivos locales, base de ' +
        'datos, credenciales, repos privados) o contenido externo no confiable (correo, páginas web, issues/tickets ' +
        'públicos, adjuntos), junto con una herramienta que puede enviar/publicar datos hacia afuera (correo, HTTP, ' +
        'webhook, crear un comentario o issue público, subir un adjunto) sin ningún campo de confirmación EXIGIDO ' +
        '(required) en su esquema de entrada — cada herramienta individual puede estar perfectamente descrita y no ' +
        'tener ningún problema por sí sola; el riesgo está en la combinación ("confused deputy" / "lethal ' +
        'trifecta"). Marca con más severidad el caso donde coinciden las TRES piezas completas: datos privados + ' +
        'contenido no confiable + canal de salida. Motivada por CVE-2026-77255 (mcp-atlassian, CVSS 8.6, ' +
        'septiembre 2026), EchoLeak/CVE-2025-32711 (Microsoft 365 Copilot, CVSS 9.3, primer exploit real de ' +
        'inyección de prompt de cero clics) y el caso reportado por Invariant Labs en un servidor MCP de GitHub ' +
        '("Toxic Flow Analysis"). Complementa a audit_mcp_server (puntaje general del manifiesto) y a ' +
        'detect_poisoned_tool_descriptions (texto oculto dentro de UNA descripción) — úsala para revisar cómo ' +
        'INTERACTÚAN entre sí las herramientas que un agente tendría disponibles a la vez. Requiere una llave de ' +
        'acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        manifest: z
          .record(z.string(), z.any())
          .describe('El manifiesto del servidor MCP como objeto JSON: { serverInfo, tools: [...] } (mismo formato que audit_mcp_server), o directamente un arreglo de herramientas.')
      }
    },
    async ({ manifest }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkToxicFlowRisk({ manifest });
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
    'detect_ssti_risk',
    {
      title: 'Detectar inyección en plantillas (SSTI)',
      description:
        'Analiza el código fuente de una herramienta que compila una plantilla (Jinja2, EJS, Handlebars, Pug, ' +
        'Mustache, lodash, o un PromptTemplate de LangChain) en busca de una fuente de plantilla que no escribió ' +
        'el desarrollador — una variable/entrada externa usada como el TEXTO de la plantilla, en vez de como un ' +
        'dato que se rellena en una plantilla fija. La mayoría de estos motores permiten llamar métodos y recorrer ' +
        'atributos de objetos desde dentro de la plantilla, así que una plantilla controlada por un atacante puede ' +
        'terminar en ejecución arbitraria de código en el servidor (SSTI) — algo distinto de XSS y no cubierto por ' +
        'ningún analizador de HTML. También detecta una falsa sensación de seguridad propia de Garita: el código ' +
        'afirma estar protegido porque "escapa la salida" (autoescape=True, html.escape, MarkupSafe) — una defensa ' +
        'real contra XSS pero irrelevante acá, porque la ejecución ocurre al COMPILAR la plantilla, antes de que ' +
        'exista ninguna salida que escapar. Reconoce un entorno sandboxeado de Jinja2 (SandboxedEnvironment) como ' +
        'una mitigación real. Motivada por CVE-2026-33154 (CVSS 8.1) en Dynaconf, una librería de configuración ' +
        'muy usada por apps de IA/agentes; un aviso en Agenta-AI (plataforma de evaluación de LLMs) por SSTI vía ' +
        'plantillas Jinja2 de evaluador personalizado; y un aviso en LangChain mismo, el framework de agentes más ' +
        'usado, por inyección en plantillas de prompt vía acceso a atributos. Es un análisis estático por patrones ' +
        'de texto (no ejecuta el código) — mismo enfoque que detect_sql_injection_risk, detect_command_injection_risk ' +
        'y detect_insecure_deserialization_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ' +
        'ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que compila una plantilla, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python", "javascript") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkSsTemplateInjectionRisk({ codigo, lenguaje });
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
    'detect_dynamic_code_risk',
    {
      title: 'Escudo de Código Dinámico',
      description:
        'Analiza el código fuente de una herramienta/agente en busca de ejecución de código dinámico no confiable ' +
        '(CWE-95): eval(), el constructor Function() de JS, exec() de Python, y las variantes del módulo "vm" de ' +
        'Node (vm.runInContext/runInNewContext/runInThisContext) llamadas con un texto que NO escribió el ' +
        'desarrollador — una variable, la respuesta de un modelo, un documento recuperado de un pipeline RAG, o un ' +
        'parámetro de herramienta — en vez de un texto fijo. También detecta el patrón de "eval implícito": ' +
        'setTimeout()/setInterval() llamado con un string en vez de una referencia a función. Detecta además una ' +
        'falsa sensación de seguridad propia de Garita: usar la librería vm2 para "sandboxear" la ejecución no es ' +
        'una mitigación real — vm2 está oficialmente deprecada desde 2023 tras varias fugas de sandbox críticas y ' +
        'documentadas (CVE-2023-32314, CVE-2023-37903, CVE-2023-37466); reconoce isolated-vm (aislamiento real a ' +
        'nivel de V8 Isolate) como mitigación genuina. Motivada por CVE-2026-26030 (CVSS 9.8, feb 2026) en Microsoft ' +
        'Semantic Kernel: el filtro de un vector store (InMemoryVectorStore) interpolaba contenido recuperado de un ' +
        'documento indexado — es decir, dato envenenado de un pipeline RAG, no una entrada directa del usuario — ' +
        'directamente en una expresión evaluada con eval(), dando RCE completo en el proceso del agente. Es un ' +
        'análisis estático por patrones de texto (no ejecuta el código) — mismo enfoque que detect_ssti_risk y ' +
        'detect_command_injection_risk, y una clase de vulnerabilidad distinta de esta última: ahí se invoca una ' +
        'shell externa (CWE-78), acá se evalúa código directamente dentro del propio intérprete/motor del agente. ' +
        'Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente de la función/herramienta que evalúa código dinámicamente, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python", "javascript") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkDynamicCodeRisk({ codigo, lenguaje });
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
    'detect_dns_rebinding_risk',
    {
      title: 'Escudo de Rebinding DNS',
      description:
        'Analiza el código que arma el transporte HTTP/SSE de un servidor MCP (el endpoint que un cliente usa para ' +
        'hablarle por JSON-RPC) en busca de la ausencia de validación del header Origin (o Host) antes de procesar ' +
        'peticiones entrantes. Sin esa validación, una página web maliciosa que el navegador de la víctima visita ' +
        'puede hacer que el navegador hable directamente con ese servidor MCP — que suele correr en localhost o en ' +
        'la red interna del usuario — como si fuera un cliente de confianza (ataque de "DNS rebinding"): el ' +
        'atacante registra un dominio que primero resuelve a su propio servidor y luego cambia el DNS para que ' +
        'resuelva a 127.0.0.1, y el navegador sigue tratando la página como el mismo origen mientras habla con el ' +
        'servidor local de la víctima. Detecta además un malentendido documentado propio de Garita: creer que ' +
        'bindear el servidor solo a localhost/127.0.0.1 ya protege — eso NO evita el rebinding; la única defensa ' +
        'real es validar el header Origin contra una lista explícita de orígenes permitidos. Motivada por un ' +
        'patrón repetido en 2026, encontrado de forma independiente en tres SDKs/implementaciones de MCP en tres ' +
        'lenguajes distintos: CVE-2026-42559 (CVSS 8.8) en rmcp, el SDK oficial de Rust; CVE-2026-35568 en el SDK ' +
        'de Java; y CVE-2026-59971 en mysql-mcp-server (Python) — todas por la misma causa raíz. Es un análisis ' +
        'estático por patrones de texto sobre el código de configuración del transporte (no abre ningún puerto ni ' +
        'ejecuta nada) — mismo enfoque que detect_ssrf_risk y detect_command_injection_risk. Requiere una llave de ' +
        'acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código que arma el transporte HTTP/SSE del servidor MCP (constructor de transporte o registro de la ruta), en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python", "javascript") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkDnsRebindingRisk({ codigo, lenguaje });
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
    'detect_missing_auth_risk',
    {
      title: 'Centinela de Autenticación',
      description:
        'Analiza el código que arma el transporte HTTP/SSE de un servidor MCP (el endpoint que un cliente usa para ' +
        'hablarle por JSON-RPC — "/mcp", "/sse", "/messages") en busca de la ausencia de CUALQUIER verificación de ' +
        'autenticación antes de despachar la petición (CWE-306): sin login, sin llave de API, sin token, cualquiera ' +
        'que sepa la URL puede invocar las herramientas del servidor. Es distinto de validar el header Origin ' +
        '(detect_dns_rebinding_risk): ahí el problema es DE DÓNDE viene la petición; aquí es que no se verifica ' +
        'QUIÉN la hace, en absoluto. No es un caso aislado — es el patrón MÁS repetido entre los CVEs de MCP de ' +
        '2026: CVE-2026-44895 (CVSS 9.1, crítico) en @yoda.digital/gitlab-mcp-server, donde el transporte SSE no ' +
        'verificaba autenticación en ningún code path y además respondía con "Access-Control-Allow-Origin: *", ' +
        'permitiendo a cualquier llamador no autenticado invocar las 86 herramientas de GitLab del servidor — ' +
        'incluido borrar repositorios — usando el token de acceso personal del operador; el mismo patrón (CWE-306) ' +
        'confirmado también en Azure MCP Server de Microsoft (CVE-2026-32211), deepseek-mcp-server ' +
        '(CVE-2026-55605), NetLicensing-MCP (CVE-2026-54446), obsidian-web-mcp (CVE-2026-54618) y ' +
        'mcp-documentation-server (CVE-2026-54504). Detecta además una regla propia de Garita: cuando además de ' +
        'faltar la autenticación el CORS está completamente abierto ("Access-Control-Allow-Origin: *" o un ' +
        'middleware cors() sin restringir origen), el riesgo es estrictamente peor — es exactamente la combinación ' +
        'que hizo explotable a CVE-2026-44895 desde cualquier página web. Es un análisis estático por patrones de ' +
        'texto (no ejecuta nada, no abre ningún puerto) — mismo enfoque que detect_dns_rebinding_risk y ' +
        'detect_command_injection_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST ' +
        '/crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código que arma el transporte HTTP/SSE del servidor MCP (constructor de transporte o registro de la ruta), en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python", "javascript") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkMissingAuthRisk({ codigo, lenguaje });
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
    'detect_mcp_stdio_launch_risk',
    {
      title: 'Escudo de Lanzamiento MCP (STDIO)',
      description:
        'Analiza el código que arma la conexión de un CLIENTE MCP por transporte "stdio" (StdioClientTransport del ' +
        'SDK de TypeScript, StdioServerParameters del SDK de Python) en busca de una falla de DISEÑO confirmada en ' +
        'los cuatro SDKs oficiales de MCP (Python, TypeScript, Java, Rust) en 2026: el sistema operativo ejecuta el ' +
        'campo "command" de inmediato al construir/conectar el transporte, ANTES de que exista ninguna validación ' +
        'del protocolo MCP — "incluso cuando el comando malicioso falla en establecer una sesión MCP válida... el ' +
        'comando ya se ejecutó" (Cloud Security Alliance). Si "command"/"args" viene de una entrada externa sin ' +
        'restringirlo a una lista de lanzadores conocidos, cualquiera que controle ese campo ejecuta código ' +
        'arbitrario. Detecta: (1) "command" dependiente de una entrada externa sin ninguna validación reconocible ' +
        'contra una lista de lanzadores permitidos; (2) una variante más sutil ("brecha de rehidratación"): el ' +
        'archivo sí valida en algún lado, pero el lanzamiento analizado viene de una configuración ya guardada/ ' +
        'cargada antes, sin volver a validar al momento de lanzarla de verdad — el patrón exacto detrás de ' +
        'CVE-2026-30623 (LiteLLM) antes de su parche; (3) un comando SÍ presente en una lista blanca razonable ' +
        '(python, node, etc.) cuyos argumentos incluyen una bandera de ejecución directa de código (-c/-e/--eval) ' +
        'con un valor que no es fijo — la lista blanca por nombre de binario no alcanza si el atacante solo elige ' +
        'el código que ese binario ya permitido va a ejecutar; y (4) la falsa sensación de seguridad de asumir que ' +
        'si el comando no resulta un servidor MCP válido "el protocolo fallaría" y ahí termina el problema. También ' +
        'documentado en CVE-2026-22688 (Tencent WeKnora, CVSS 9.9): mismo patrón, expuesto en un endpoint "/test" ' +
        'sin control de acceso de administrador. Distinto y complementario a detect_command_injection_risk: ese ' +
        'cubre la inyección de comandos clásica vía una shell del sistema; este cubre el contrato específico de los ' +
        'SDKs de MCP, donde el riesgo existe aunque no haya ninguna shell de por medio. Es un análisis estático por ' +
        'patrones de texto (no ejecuta el código) — mismo enfoque que detect_command_injection_risk y ' +
        'detect_missing_auth_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST ' +
        '/crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código que arma la conexión stdio de un cliente MCP (construcción de StdioClientTransport/StdioServerParameters), en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios SDKs a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkMcpStdioLaunchRisk({ codigo, lenguaje });
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
    'detect_redos_risk',
    {
      title: 'Escudo Anti-ReDoS',
      description:
        'Analiza el código fuente de una herramienta/agente que compila o aplica una expresión regular, en busca ' +
        'de (1) un patrón con forma de "cuantificador anidado" (backtracking catastrófico, ej. (a+)+, (\\s*\\w+)*, ' +
        '(a|a)*) aplicado contra una entrada que no es un texto fijo, sin ningún tope de longitud ni motor con ' +
        'timeout/librería segura (re2, safe-regex, recheck) reconocibles cerca — un solo string cuidadosamente ' +
        'armado puede colgar el proceso del agente entero (ReDoS, CWE-1333); y (2) un regex compilado dinámicamente ' +
        '(RegExp()/new RegExp()/re.compile()) a partir de una fuente que NO es un texto fijo que escribió el ' +
        'desarrollador, sino una variable — quien llame a la herramienta puede inyectar directamente un patrón ' +
        'catastrófico o cambiar por completo la lógica de validación. El mismo patrón detrás de CVE-2026-0621 ' +
        '(CVSS 7.5). Es un análisis estático por patrones de texto (no ejecuta el código ni mide tiempos reales de ' +
        'backtracking) — mismo enfoque que detect_dynamic_code_risk y detect_ssti_risk. Requiere una llave de ' +
        'acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente que compila o aplica una expresión regular, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkRedosRisk({ codigo, lenguaje });
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
    'detect_session_hijack_risk',
    {
      title: 'Escudo de Secuestro de Sesión',
      description:
        'Analiza el código fuente que busca o genera sesiones de un cliente, en busca de (1) una sesión resuelta ' +
        'SOLO por el identificador que trae la petición (sessions[id]/.get(id)/.findOne({id})), sin comparar ' +
        'después ningún campo de dueño/principal (userId/owner/accountId) contra quien hace la petición ahora — ' +
        'quien consiga ese ID hereda la sesión de otro cliente por completo (CWE-384); y (2) un identificador de ' +
        'sesión generado con poca entropía (Math.random(), Date.now()/time.time() solo, o un contador incremental) ' +
        'en vez de un generador criptográficamente seguro (crypto.randomBytes/randomUUID, secrets.token_hex), ' +
        'adivinable por fuerza bruta. El mismo patrón detrás de CVE-2026-52869. Es un análisis estático por ' +
        'patrones de texto (no ejecuta el código) — mismo enfoque que detect_missing_auth_risk y ' +
        'detect_token_passthrough_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST ' +
        '/crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente que busca o genera sesiones, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkSessionHijackRisk({ codigo, lenguaje });
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
    'detect_oauth_audience_confusion_risk',
    {
      title: 'Escudo de Confusión de Audiencia OAuth',
      description:
        'Analiza el código fuente del VERIFICADOR PROPIO de tokens OAuth/JWT de un servidor con más profundidad ' +
        'que detect_token_passthrough_risk (que solo mira si "audience"/"aud" aparece cerca, una señal superficial): ' +
        'detecta cuando esa validación SÍ existe pero está rota de forma sutil — (1) condicionada a una bandera de ' +
        'configuración (config.checkAudience, options.strictMode) que puede estar desactivada; (2) su rama de "no ' +
        'coincide" solo registra una advertencia en vez de rechazar la petición (throw/return/res.status); o (3) un ' +
        'bloque catch() silencia el error que la librería ya lanzó al detectar la discrepancia — y también detecta ' +
        '(4) la ausencia total de cualquier chequeo de audiencia en el verificador. En los tres primeros casos el ' +
        'código "tiene" una validación que un lector apurado asumiría que funciona, pero que en la práctica deja ' +
        'pasar un token emitido para otro servidor (confused deputy vía audiencia). El mismo patrón detrás de ' +
        'CVE-2026-14541. Es un análisis estático por patrones de texto (no ejecuta el código) — mismo enfoque que ' +
        'detect_token_passthrough_risk y detect_missing_auth_risk. Requiere una llave de acceso válida (usos gratis ' +
        'o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente del verificador de tokens OAuth/JWT del servidor, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkOAuthAudienceConfusionRisk({ codigo, lenguaje });
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
    'detect_unbounded_allocation_risk',
    {
      title: 'Escudo de Asignación sin Límite',
      description:
        'Analiza el código fuente de un servidor/herramienta en busca de agotamiento de memoria/CPU (CWE-770): (1) ' +
        'lectura completa de un cuerpo de petición o un archivo hacia memoria sin ningún tope de tamaño configurado ' +
        '(sin "limit" en express.json()/bodyParser, sin chequeo de tamaño en la acumulación manual de un stream ' +
        '"req.on(\'data\')", o sin fs.statSync() antes de leer un archivo con ruta no fija); y (2) una reserva de ' +
        'array/buffer (new Array()/Buffer.alloc()), o un bucle, cuyo tamaño/cantidad de vueltas viene directamente ' +
        'de una variable sin ningún tope (Math.min/comparación contra un máximo) antes — un solo mensaje o número ' +
        'grande puede agotar la memoria o la CPU del proceso del agente. El mismo patrón detrás de CVE-2026-14539. ' +
        'Es un análisis estático por patrones de texto (no ejecuta el código ni mide uso real de memoria) — mismo ' +
        'enfoque que detect_dynamic_code_risk y detect_ssrf_risk. Requiere una llave de acceso válida (usos gratis ' +
        'o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente que lee un cuerpo/archivo o reserva memoria/itera, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "python") — la detección ya cubre varios lenguajes a la vez, este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkUnboundedAllocationRisk({ codigo, lenguaje });
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
    'detect_cross_client_leak_risk',
    {
      title: 'Escudo de Fuga Entre Clientes',
      description:
        'Analiza el código fuente que arma el transporte HTTP/SSE de un servidor MCP en busca de estado compartido ' +
        'sin aislamiento por sesión/cliente: (1) una sola instancia de McpServer/Server creada a nivel de módulo ' +
        '(una vez al arrancar) que se conecta a un transporte nuevo dentro de cada handler de petición, en vez de ' +
        'crear también una instancia nueva del servidor por cliente — las respuestas pueden mezclarse entre ' +
        'clientes distintos; y (2) una variable mutable (let/var) a nivel de módulo escrita por un handler de ' +
        'petición y leída dentro del callback de una herramienta registrada, sin que haga falta reutilizar ninguna ' +
        'instancia completa de servidor. El mismo patrón detrás de CVE-2026-25536 (CVSS 7.1) en el propio SDK ' +
        'oficial de TypeScript de MCP — "Context Injection and Over Sharing" del OWASP MCP Top 10. Es un análisis ' +
        'estático por patrones de texto (no ejecuta el código) — mismo enfoque que detect_dns_rebinding_risk y ' +
        'detect_missing_auth_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código fuente que arma el transporte HTTP/SSE de un servidor MCP, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "typescript") — este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkCrossClientLeakRisk({ codigo, lenguaje });
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
    'detect_sampling_hijack_risk',
    {
      title: 'Escudo de Secuestro de Sampling',
      description:
        'Analiza el código del lado cliente/host que maneja peticiones de sampling entrantes de un servidor MCP ' +
        '(setRequestHandler sobre CreateMessageRequestSchema / "sampling/createMessage") en busca de: (1) ausencia ' +
        'de cualquier paso reconocible de revisión/aprobación humana antes de cumplir la petición — lo que la ' +
        'propia especificación de MCP recomienda exigir, y la puerta que un servidor malicioso usa para esconder ' +
        'instrucciones que el modelo sigue sin que la persona note nada raro; (2) invocación encubierta de una ' +
        'herramienta (callTool/executeTool) disparada desde ese mismo handler sin aprobación, el vector más grave; ' +
        'y (3) ausencia de un tope de longitud/tokens (maxTokens/max_tokens), el vector de "robo de recursos". ' +
        'Documentado en una investigación de Unit42 (Palo Alto Networks) y reportado de nuevo el 16 de octubre de ' +
        '2026 contra una app de tipo copiloto de código. Es un análisis estático por patrones de texto (no ejecuta ' +
        'el código) — mismo enfoque que detect_toxic_flow_risk. Requiere una llave de acceso válida (usos gratis o ' +
        'créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código del lado cliente/host que maneja peticiones de sampling de un servidor MCP, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "javascript", "typescript") — este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkSamplingHijackRisk({ codigo, lenguaje });
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
    'detect_output_schema_ssrf_risk',
    {
      title: 'Escudo de Esquema de Salida',
      description:
        'Analiza el código del lado CLIENTE que valida el outputSchema/inputSchema de una herramienta MCP en busca ' +
        'de: (1) una validación con la librería jsonschema (Draft*Validator/validator_for/jsonschema.validate) ' +
        'sobre un esquema que vino de un servidor MCP no confiable, sin ningún Registry/Resolver que restrinja la ' +
        'resolución de referencias externas ($ref/$dynamicRef/$id) — un servidor malicioso puede forzar al cliente ' +
        'a hacer una petición SSRF hacia una URL arbitraria (CWE-918); y (2) una llamada de red SÍNCRONA ' +
        '(urllib.request.urlopen/requests.get-post-put-delete) dentro de una función "async def", sin "timeout" ' +
        'ni delegarse a un hilo aparte — un solo endpoint que nunca responde congela el event loop entero del ' +
        'proceso (denegación de servicio). El mismo patrón detrás de CVE-2026-116686 (CVSS 6.5) en el SDK oficial ' +
        'de Python de MCP (paquete "mcp" en PyPI, versiones 1.10.0-1.29.1 y 2.0.0-2.1.1; parchado en 1.30.0/2.2.0). ' +
        'Es un análisis estático por patrones de texto (no ejecuta el código) — mismo enfoque que detect_ssrf_risk ' +
        'y detect_redos_risk. Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código del lado cliente que valida outputSchema/inputSchema de herramientas MCP, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python") — este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkOutputSchemaSsrfRisk({ codigo, lenguaje });
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
    'detect_excessive_agency_risk',
    {
      title: 'Escudo de Agencia Excesiva',
      description:
        'Analiza el MANIFIESTO de un servidor MCP — igual que audit_mcp_server y detect_toxic_flow_risk — en busca ' +
        'de "agencia excesiva" (OWASP LLM06): una herramienta cuyo nombre o descripción indica una acción ' +
        'irreversible o de alto valor (transferir, retirar, pagar, borrar, eliminar, apagar) sin ningún campo de ' +
        'confirmación EXIGIDO (required) en su esquema de entrada, y/o sin ningún tope máximo (maximum/' +
        'exclusiveMaximum) en un campo de monto/cantidad — nada impide que una sola llamada mueva una cantidad ' +
        'arbitrariamente grande ni que se ejecute sin que nada la revise antes. Motivada directamente por el ' +
        'hackeo de Binance de octubre de 2026 (6.300 millones de dólares, el mayor robo cripto de la historia): ' +
        'según el relato preliminar de Binance y el análisis de TRM Labs, un solo dispositivo/credencial ' +
        'comprometido alcanzó un sistema con autoridad para autorizar retiros, y pudo ordenarlos sin ninguna ' +
        'aprobación independiente ni tope por operación — el mismo patrón de diseño que esta herramienta busca en ' +
        'el esquema de entrada de una herramienta MCP. Misma convención de "gatillo real vs. afirmación de texto" ' +
        'que detect_toxic_flow_risk: una herramienta separada de "pedir aprobación" no cuenta como mitigación real. ' +
        'Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        manifest: z
          .record(z.string(), z.any())
          .describe('El manifiesto del servidor MCP como objeto JSON: { serverInfo, tools: [...] } (mismo formato que audit_mcp_server), o directamente un arreglo de herramientas.')
      }
    },
    async ({ manifest }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkExcessiveAgencyRisk({ manifest });
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
    'detect_call_spoofing_risk',
    {
      title: 'Escudo de Suplantación de Llamada',
      description:
        'Analiza el código de orquestación del lado del AGENTE (la capa que interpreta la respuesta del modelo) ' +
        'en busca de la extracción de llamadas a herramientas desde el TEXTO LIBRE de la respuesta (una marca ' +
        'como TOOL_CALL:, un bloque ```json, una etiqueta <tool_call>) en vez de leerlas únicamente del campo ' +
        'ESTRUCTURADO y dedicado de la API (tool_calls/function_call/tool_use), que solo se llena cuando el ' +
        'modelo invocó de verdad el mecanismo nativo de function-calling. Contenido que solo PARECE una llamada ' +
        'a herramienta — incrustado en un documento, una página web o el resultado de otra herramienta que el ' +
        'modelo simplemente "repite" — puede terminar ejecutado como si fuera real (ataque "Repeat-After-Me", ' +
        'documentado en octubre de 2026 contra 6 frameworks de agentes de uso extendido: LangGraph, Microsoft ' +
        'Agent Framework, Google ADK 2.0, AutoGen, AWS Strands y CrewAI). Es un análisis estático por patrones ' +
        'de texto (no ejecuta el código) — mismo enfoque que detect_sampling_hijack_risk y detect_toxic_flow_risk. ' +
        'Requiere una llave de acceso válida (usos gratis o créditos) — ver POST /crear-llave.',
      inputSchema: {
        codigo: z.string().describe('El código de orquestación del lado del agente que interpreta la respuesta del modelo, en texto plano.'),
        lenguaje: z.string().optional().describe('Solo informativo (ej. "python") — este campo no cambia el resultado.')
      }
    },
    async ({ codigo, lenguaje }) => {
      const check = await licensing.checkAndConsume(apiKey);
      if (!check.allowed) return licenseErrorResult(check);
      let result;
      try {
        result = checkCallSpoofingRisk({ codigo, lenguaje });
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

// ---------- CORS acotado para el botón "pagar con cripto" del sitio web ----------
// El resto de la API no tiene CORS — nada más la llama un navegador desde
// estos dos endpoints (crear una llave gratis y arrancar un pago). Abrir
// CORS de más sin necesidad es justo el patrón de riesgo que
// detect_missing_auth_risk marca ("Access-Control-Allow-Origin: *" sin
// restringir origen), así que esto solo responde al origen exacto del
// sitio — nunca con "*" — y solo en estas dos rutas.
const ALLOWED_WEB_ORIGINS = new Set([
  'https://garitalabs.dev',
  'https://www.garitalabs.dev'
]);
function allowWebOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && ALLOWED_WEB_ORIGINS.has(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
    res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}
app.use('/crear-llave', allowWebOrigin);
app.use('/comprar-creditos', allowWebOrigin);
app.use('/comprar-creditos-paypal', allowWebOrigin);

app.get('/', (req, res) => {
  res.type('text/plain').send(
    'Garita MCP server — remote MCP endpoint en POST /mcp (requiere llave de acceso en el header Authorization).\n\n' +
    'Herramientas MCP disponibles: audit_mcp_server, simulate_approval, detect_poisoned_tool_descriptions (Garita Escudo), check_known_vulnerabilities, detect_tool_rug_pull, detect_poisoned_config_files, check_package_authenticity, detect_memory_poisoning, detect_ssrf_risk, detect_path_traversal_risk, detect_command_injection_risk, detect_sql_injection_risk, detect_token_passthrough_risk, detect_hardcoded_secrets_risk, detect_insecure_deserialization_risk, detect_toxic_flow_risk, detect_ssti_risk, detect_dynamic_code_risk, detect_dns_rebinding_risk, detect_missing_auth_risk, detect_mcp_stdio_launch_risk, detect_redos_risk, detect_session_hijack_risk, detect_oauth_audience_confusion_risk, detect_unbounded_allocation_risk, detect_cross_client_leak_risk, detect_sampling_hijack_risk, detect_output_schema_ssrf_risk, detect_excessive_agency_risk, detect_call_spoofing_risk.\n\n' +
    'Vigía — agente especializado que decide por sí mismo cuáles de esas herramientas usar y devuelve un informe en español: POST /vigia/analizar.\n\n' +
    'Endpoints:\n' +
    '  POST /crear-llave              — consigue una llave de acceso gratis (' + licensing.DEFAULT_FREE_USES + ' usos de prueba)\n' +
    '  GET  /consultar-llave?apiKey=  — consulta cuántos usos gratis/créditos le quedan a una llave\n' +
    '  POST /comprar-creditos         — { apiKey, pack: "basico"|"pro"|"empresarial" } → devuelve un link de pago CoinGate\n' +
    '                                    ("empresarial" además quita el tope diario de 50 usos/día para siempre en esa llave)\n' +
    '  GET  /verificar-pago?orderId=  — revisa a mano si un pago ya se confirmó (respaldo, normalmente no hace falta)\n' +
    '  POST /coingate/webhook         — (uso interno de CoinGate, no lo llames a mano)\n' +
    '  POST /comprar-creditos-paypal  — { apiKey, pack } → devuelve un link de pago PayPal (misma idea que /comprar-creditos, con PayPal en vez de cripto)\n' +
    '  GET  /paypal/retorno           — (uso interno, a donde PayPal manda al comprador después de aprobar el pago)\n' +
    '  POST /mcp                      — endpoint MCP, ver README para conectarlo desde un agente\n' +
    '  POST /vigia/analizar           — { apiKey, mensaje } → el agente Vigía analiza y responde en español\n'
  );
});

   // ---------- verificación de propiedad del conector para Glama.ai ----------
   app.get('/mcp/.well-known/glama.json', (req, res) => {
     res.json({
       '$schema': 'https://glama.ai/mcp/schemas/connector.json',
       'claim': 'glama_claim_TV9FqLaRW43vedIBB_ueJ_0h_azh2rgs'
     });
   });// ---------- llaves de acceso ----------

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

// ---------- compra de créditos (PayPal) ----------
// Mismos paquetes y precios que CoinGate (lib/coingate.js sigue siendo la
// única fuente de verdad de precios). A diferencia de CoinGate, PayPal no
// usa un webhook por defecto acá: el propio navegador del comprador vuelve
// a /paypal/retorno después de aprobar el pago, y ahí se captura y acredita
// — por eso basta con registrar la orden, sin "token" de firma como el de
// CoinGate (la seguridad acá la da que solo nosotros sabemos capturar esa
// orden exacta contra la cuenta de PayPal configurada).
app.post('/comprar-creditos-paypal', async (req, res) => {
  try {
    const apiKey = String((req.body && req.body.apiKey) || '');
    const pack = String((req.body && req.body.pack) || '');
    const record = await licensing.getKeyRecord(apiKey);
    if (!record) return res.status(404).json({ error: true, message: 'Llave no encontrada. Crea una primero en POST /crear-llave.' });
    if (!paypal.CREDIT_PACKS[pack]) {
      return res.status(400).json({ error: true, message: 'Paquete inválido. Opciones: ' + Object.keys(paypal.CREDIT_PACKS).join(', ') });
    }

    const base = publicBaseUrl(req);
    const { packConfig, payment_url, paypalOrderId } = await paypal.createOrder({
      pack,
      returnUrl: base + '/paypal/retorno',
      cancelUrl: base + '/paypal/cancelado'
    });
    await licensing.createOrderRecord(paypalOrderId, {
      apiKey,
      credits: packConfig.credits,
      enterprise: !!packConfig.enterprise,
      provider: 'paypal'
    });

    res.json({
      payment_url,
      orderId: paypalOrderId,
      paquete: packConfig.label,
      creditos: packConfig.credits,
      empresarial: !!packConfig.enterprise,
      precio: packConfig.price_amount + ' ' + packConfig.price_currency,
      nota: 'Vas a volver a este sitio automáticamente después de aprobar el pago en PayPal — ahí se acreditan los créditos solos.'
    });
  } catch (err) {
    console.error('Error en /comprar-creditos-paypal:', err);
    res.status(500).json({ error: true, message: 'No se pudo crear la orden de pago: ' + err.message });
  }
});

function paginaPago(titulo, mensaje, colorAcento) {
  return '<!doctype html><html lang="es"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + titulo + ' — Garita Labs</title>' +
    '<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:560px;margin:80px auto;padding:0 24px;color:#16211C;line-height:1.6}' +
    'h1{font-size:1.4rem;border-left:4px solid ' + colorAcento + ';padding-left:14px}' +
    'a{color:#33415C}</style></head><body>' +
    '<h1>' + titulo + '</h1><p>' + mensaje + '</p>' +
    '<p><a href="https://garitalabs.dev/#acceso">← Volver a Garita Labs</a></p>' +
    '</body></html>';
}

// A donde PayPal manda de vuelta al comprador después de que aprueba el
// pago (experience_context.return_url en createOrder). PayPal agrega
// ?token=ID_DE_LA_ORDEN&PayerID=... — "token" acá es el ID de la orden, no
// tiene relación con el "token" de firma que usa el webhook de CoinGate.
app.get('/paypal/retorno', async (req, res) => {
  const orderId = String(req.query.token || '');
  try {
    const order = await licensing.getOrderRecord(orderId);
    if (!order) {
      return res.status(404).send(paginaPago('Orden no encontrada', 'No encontramos esta orden de pago. Si ya pagaste, escríbenos a williamdanielramirez@gmail.com con el ID ' + (orderId || '(vacío)') + ' y lo revisamos a mano.', '#9C3B2E'));
    }
    if (order.processed) {
      return res.send(paginaPago('¡Ya estaba acreditado!', 'Este pago ya se había confirmado antes. Tu llave de acceso ya tiene los créditos — no hace falta hacer nada más.', '#2F6B4F'));
    }

    const captured = await paypal.captureOrder(orderId);
    const result = await creditOrderIfPaid(orderId, order, captured.status === 'COMPLETED' ? 'paid' : captured.status);

    if (result.credited) {
      return res.send(paginaPago('¡Pago confirmado!', 'Se acreditaron ' + order.credits + ' usos a tu llave de acceso. Ya puedes seguir usando las herramientas de Garita Labs.', '#2F6B4F'));
    }
    res.send(paginaPago('Pago pendiente', 'Tu pago todavía no quedó confirmado del lado de PayPal (estado: ' + (captured.status || 'desconocido') + '). Si creés que ya pagaste, escríbenos a williamdanielramirez@gmail.com con el ID ' + orderId + '.', '#A9701C'));
  } catch (err) {
    console.error('Error en /paypal/retorno:', err);
    res.status(500).send(paginaPago('Algo salió mal', 'No pudimos confirmar tu pago automáticamente. Si ya pagaste, escríbenos a williamdanielramirez@gmail.com con el ID ' + (orderId || '(vacío)') + ' y lo acreditamos a mano — no se pierde.', '#9C3B2E'));
  }
});

app.get('/paypal/cancelado', (req, res) => {
  res.send(paginaPago('Pago cancelado', 'No se completó ningún cobro. Si fue un error, volvé a intentarlo cuando quieras.', '#A9701C'));
});

// ---------- Vigía (agente especializado, "Centinela Básico" / Escalón 1) ----------

// A diferencia de /mcp (que expone las 20 herramientas sueltas para que un
// agente/cliente MCP decida cuál llamar), este endpoint expone un agente
// propio de Garita Labs que decide por sí mismo cuáles de esas 20
// herramientas usar sobre lo que el cliente le mande, y devuelve un informe
// ya combinado y explicado en español — pensado para alguien sin perfil
// técnico de seguridad, o para integrarlo directo en un flujo (CI/CD, un
// bot) sin tener que orquestar las 20 herramientas a mano.
//
// Requiere una llave de acceso de Garita Labs válida (igual que /mcp) — cada
// herramienta real que Vigía decide llamar se cobra de la misma licencia.
// Además requiere que el servidor tenga configurada la variable de entorno
// ANTHROPIC_API_KEY (la propia, de Garita Labs — no la del cliente); si
// falta, responde 503 en vez de 500, para distinguir "no configurado todavía"
// de un error real.
app.post('/vigia/analizar', async (req, res) => {
  try {
    const apiKey = extractApiKey(req) || String((req.body && req.body.apiKey) || '');
    const record = await licensing.getKeyRecord(apiKey);
    if (!record) {
      return res.status(401).json({
        error: true,
        message: 'Necesitas una llave de acceso válida de Garita Labs. Crea una gratis en POST /crear-llave, y mándala en el header "Authorization: Bearer <llave>" o en el campo "apiKey" del cuerpo.'
      });
    }

    const mensaje = String((req.body && req.body.mensaje) || '');
    if (!mensaje.trim()) {
      return res.status(400).json({ error: true, message: 'Debes enviar "mensaje" con el código, manifiesto o descripción que quieres que Vigía analice.' });
    }
    if (mensaje.length > 20000) {
      return res.status(400).json({ error: true, message: 'El mensaje es demasiado largo (máximo 20,000 caracteres). Divídelo en partes más chicas.' });
    }

    const resultado = await vigia.analizar({ mensaje, apiKey });
    res.json(resultado);
  } catch (err) {
    if (/ANTHROPIC_API_KEY/.test(err.message || '')) {
      console.error('Vigía no está configurado:', err.message);
      return res.status(503).json({ error: true, message: err.message });
    }
    console.error('Error en /vigia/analizar:', err);
    res.status(500).json({ error: true, message: err.message || 'No se pudo completar el análisis.' });
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
