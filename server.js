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
    'Herramientas MCP disponibles: audit_mcp_server, simulate_approval, detect_poisoned_tool_descriptions (Garita Escudo), check_known_vulnerabilities, detect_tool_rug_pull, detect_poisoned_config_files, check_package_authenticity, detect_memory_poisoning, detect_ssrf_risk, detect_path_traversal_risk, detect_command_injection_risk, detect_sql_injection_risk, detect_token_passthrough_risk, detect_hardcoded_secrets_risk, detect_insecure_deserialization_risk, detect_toxic_flow_risk, detect_ssti_risk.\n\n' +
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
