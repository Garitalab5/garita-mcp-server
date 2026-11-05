"use strict";
// Vigía — el agente especializado de ciberseguridad de Garita Labs
// ================================================================================
// Este es "Escalón 1 / Centinela Básico": un agente que usa la API de
// Anthropic (Claude, con tool-use) para decidir POR SÍ MISMO cuáles de las
// 30 herramientas de detección de Garita Labs llamar sobre lo que el
// cliente le mande (código, un manifiesto MCP, el nombre de un paquete, una
// descripción en texto libre — o varias cosas a la vez), combina los
// resultados, y responde en español claro con un informe priorizado y
// recomendaciones concretas de corrección.
//
// Se llama "Vigía" y no "Centinela" para no chocar con el nombre comercial
// de la herramienta 20 ("Centinela de Autenticación", detect_missing_auth_risk).
//
// Principio de diseño acordado con el negocio: Vigía NUNCA modifica ni aplica
// cambios directamente sobre el código/sistema del cliente. Solo analiza,
// explica y sugiere — igual que un analista humano entregando un reporte.
// Aplicar una corrección automáticamente (con aprobación humana de por medio)
// queda reservado para un escalón futuro ("Centinela Enterprise").
//
// Cada herramienta de Garita que Vigía decide llamar se cobra exactamente
// igual que si el cliente la hubiera llamado directo por MCP — se reutiliza
// licensing.checkAndConsume()/refundUse() por cada llamada real, sin inventar
// un sistema de cobro paralelo. El costo de los tokens de Claude que usa el
// propio Vigía para razonar NO se cobra todavía por separado (ver README) —
// es una decisión de negocio pendiente, no técnica.

const heuristics = require('./heuristics');
const escudo = require('./escudo');
const { checkKnownVulnerabilities } = require('./vulnerabilidades');
const { detectToolRugPull } = require('./rugpull');
const { detectPoisonedConfigFiles } = require('./config-poison');
const { checkPackageAuthenticity } = require('./slopsquatting');
const { checkMemoryPoisoning } = require('./memoria');
const { checkSsrfRisk } = require('./ssrf');
const { checkPathTraversalRisk } = require('./traversal');
const { checkCommandInjectionRisk } = require('./command-injection');
const { checkSqlInjectionRisk } = require('./sql-injection');
const { checkTokenPassthroughRisk } = require('./token-passthrough');
const { checkHardcodedSecretsRisk } = require('./hardcoded-secrets');
const { checkInsecureDeserializationRisk } = require('./deserialization');
const { checkToxicFlowRisk } = require('./toxic-flows');
const { checkSsTemplateInjectionRisk } = require('./ssti');
const { checkDynamicCodeRisk } = require('./dynamic-code');
const { checkDnsRebindingRisk } = require('./dns-rebinding');
const { checkMissingAuthRisk } = require('./missing-auth');
const { checkMcpStdioLaunchRisk } = require('./mcp-stdio');
const { checkRedosRisk } = require('./redos');
const { checkSessionHijackRisk } = require('./session-hijack');
const { checkOAuthAudienceConfusionRisk } = require('./oauth-audience');
const { checkUnboundedAllocationRisk } = require('./unbounded-allocation');
const { checkCrossClientLeakRisk } = require('./cross-client-leak');
const { checkSamplingHijackRisk } = require('./sampling-hijack');
const { checkOutputSchemaSsrfRisk } = require('./output-schema-ssrf');
const { checkExcessiveAgencyRisk } = require('./excessive-agency');
const { checkCallSpoofingRisk } = require('./call-spoofing');
const licensing = require('./licensing');

// Configurable por si el modelo disponible cambia — así no hay que tocar
// código para apuntar a un modelo nuevo, solo la variable de entorno.
const MODEL = process.env.VIGIA_MODEL || 'claude-sonnet-4-5-20250929';
const MAX_TURNS = 6; // tope de vueltas de razonamiento+herramientas, por costo y para evitar loops
const MAX_TOKENS = 3072;

// -------------------------------------------------------------------------
// Definiciones de herramientas en formato "tool use" de la API de Anthropic.
// Las descripciones acá son más cortas que las de server.js (esas están
// pensadas para un cliente MCP humano/agente externo decidiendo si conectar
// la herramienta; estas son solo para que Vigía decida cuál usar, y se
// mandan en cada vuelta de la conversación, así que largas saldrían caras).
// -------------------------------------------------------------------------
const TOOL_DEFS = [
  {
    name: 'audit_mcp_server',
    description: 'Audita el manifiesto completo de un servidor MCP (serverInfo + tools[]) y da un puntaje de confianza 0-100: autenticación no declarada, verbos destructivos sin anotar, agencia excesiva (openWorldHint), campos de código libre.',
    input_schema: {
      type: 'object',
      properties: { manifest: { type: 'object', description: 'El manifiesto MCP: { serverInfo, tools: [...] }.' } },
      required: ['manifest']
    }
  },
  {
    name: 'simulate_approval',
    description: 'Evalúa si una acción que un agente quiere ejecutar debería quedar retenida para revisión humana o auto-aprobarse (destructiveHint, verbos irreversibles, openWorldHint, monto, código libre).',
    input_schema: {
      type: 'object',
      properties: {
        action: { type: 'object', description: 'La acción propuesta: { tool, description, arguments, annotations }.' },
        rules: { type: 'object', description: 'Qué reglas de la política están activas (destructive, verbs, openWorld, amount, code — todos boolean). Por defecto todas activas.' },
        threshold: { type: 'number', description: 'Umbral de monto que dispara retención. Por defecto 500.' }
      },
      required: ['action']
    }
  },
  {
    name: 'detect_poisoned_tool_descriptions',
    description: 'Garita Escudo: busca instrucciones ocultas o inyectadas en la(s) descripción(es) de una o más herramientas MCP (caracteres invisibles, homoglifos, bloques <IMPORTANT>, instrucciones de ocultar algo al usuario o manipular otra herramienta).',
    input_schema: {
      type: 'object',
      properties: {
        manifest: { type: 'object', description: 'Manifiesto MCP, un arreglo de herramientas, o una sola { name, description }.' },
        text: { type: 'string', description: 'Alternativa a "manifest": una descripción suelta en texto plano.' }
      }
    }
  },
  {
    name: 'check_known_vulnerabilities',
    description: 'Revisa en OSV.dev si un paquete (npm, PyPI, Go, crates.io, Maven, RubyGems, etc.) tiene CVEs ya conocidos y publicados.',
    input_schema: {
      type: 'object',
      properties: {
        ecosistema: { type: 'string', description: 'Ecosistema del paquete tal como lo espera OSV.dev (ej. "npm", "PyPI", "Go").' },
        nombre: { type: 'string', description: 'Nombre exacto del paquete.' },
        version: { type: 'string', description: 'Versión exacta a revisar. Si se omite, busca en cualquier versión.' }
      },
      required: ['ecosistema', 'nombre']
    }
  },
  {
    name: 'detect_tool_rug_pull',
    description: 'Compara dos versiones del manifiesto de un mismo servidor MCP ("anterior" vs "actual") y avisa si el texto de alguna herramienta ya aprobada cambió desde entonces (MCP Tool Rug-Pull).',
    input_schema: {
      type: 'object',
      properties: {
        anterior: { type: 'object', description: 'El manifiesto que se aprobó/revisó la vez anterior.' },
        actual: { type: 'object', description: 'El manifiesto actual del mismo servidor.' }
      },
      required: ['anterior', 'actual']
    }
  },
  {
    name: 'detect_poisoned_config_files',
    description: 'Analiza archivos que un agente de código carga y confía de inmediato sin aprobación (AGENTS.md, CLAUDE.md, .cursorrules, archivos de "skills") en busca de instrucciones ocultas o peligrosas, incluida filtración de credenciales.',
    input_schema: {
      type: 'object',
      properties: {
        archivos: { type: 'array', items: { type: 'object', properties: { ruta: { type: 'string' }, contenido: { type: 'string' } }, required: ['contenido'] }, description: 'Uno o más archivos: [{ ruta, contenido }, ...].' },
        contenido: { type: 'string', description: 'Alternativa a "archivos": el contenido de un solo archivo suelto.' },
        ruta: { type: 'string', description: 'Solo junto con "contenido": el nombre/ruta de ese archivo.' }
      }
    }
  },
  {
    name: 'check_package_authenticity',
    description: 'Revisa si un paquete npm tiene señales de ser un impostor reciente: typosquatting, "slopsquatting" (nombre que un agente de IA alucinaría), postinstall sospechoso, o que ni siquiera existe en el registro.',
    input_schema: {
      type: 'object',
      properties: {
        ecosistema: { type: 'string', description: 'Por ahora solo "npm".' },
        nombre: { type: 'string', description: 'Nombre exacto del paquete (o "@scope/paquete").' }
      },
      required: ['ecosistema', 'nombre']
    }
  },
  {
    name: 'detect_memory_poisoning',
    description: 'Revisa un texto que un agente con memoria de largo plazo va a guardar en busca de instrucciones plantadas para activarse en una sesión futura (condicionales tipo "si el usuario dice que sí...", "recordá esto y no se lo menciones al usuario").',
    input_schema: {
      type: 'object',
      properties: {
        texto: { type: 'string', description: 'El contenido que se va a guardar (o ya está guardado) en memoria de largo plazo.' },
        fuente: { type: 'string', description: 'De dónde viene el texto: usuario, documento, resumen_automatico, salida_herramienta, etc. Si se omite se trata como no confiable.' }
      },
      required: ['texto']
    }
  },
  {
    name: 'detect_ssrf_risk',
    description: 'Analiza código que hace una petición HTTP (fetch/axios/requests/urlopen) en busca de riesgo de SSRF: URL dependiente de entrada externa sin validar, IP privada/metadata de nube directa, TLS desactivado, redirecciones sin revalidar.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que hace la petición HTTP.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_path_traversal_risk',
    description: 'Analiza código que lee/escribe/borra un archivo a partir de una ruta externa en busca de path traversal ("../", rutas absolutas, rutas sensibles del sistema).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que maneja archivos.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_command_injection_risk',
    description: 'Analiza código que ejecuta un comando del sistema a partir de entrada externa en busca de inyección de comandos (exec/shell=True, "descargar y ejecutar", metacaracteres de shell sin filtrar).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que ejecuta un comando.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_sql_injection_risk',
    description: 'Analiza código que ejecuta SQL a partir de entrada externa: concatenación/interpolación sin parámetro preparado, o una herramienta que afirma ser "solo lectura" sin que eso esté aplicado de verdad en la base de datos.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que ejecuta SQL.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_token_passthrough_risk',
    description: 'Analiza un middleware/herramienta que maneja el token de autorización: reenvío sin validar (confused deputy), token entrante reenviado tal cual hacia afuera, JWT sin validar "aud", token en la URL.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente del middleware/herramienta que maneja el token.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_hardcoded_secrets_risk',
    description: 'Analiza código o configuración (incluido .env o el bloque "env" de mcpServers) en busca de credenciales escritas en texto plano en vez de venir de una variable de entorno o gestor de secretos.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente o archivo de configuración a revisar.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_insecure_deserialization_risk',
    description: 'Analiza código que carga datos serializados (pickle, yaml.load sin SafeLoader, torch.load sin weights_only, unserialize de PHP) en busca de ejecución arbitraria de código al deserializar.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que deserializa datos.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_toxic_flow_risk',
    description: 'Analiza el manifiesto completo de un servidor MCP buscando la COMBINACIÓN peligrosa: una herramienta que lee datos privados/contenido no confiable junto con una que puede enviar datos hacia afuera sin confirmación exigida ("lethal trifecta").',
    input_schema: {
      type: 'object',
      properties: { manifest: { type: 'object', description: 'El manifiesto MCP { serverInfo, tools: [...] }, o un arreglo de herramientas.' } },
      required: ['manifest']
    }
  },
  {
    name: 'detect_ssti_risk',
    description: 'Analiza código que compila una plantilla (Jinja2, EJS, Handlebars, Pug, LangChain PromptTemplate) con una fuente de plantilla controlada por entrada externa (SSTI — distinto de XSS).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que compila una plantilla.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_dynamic_code_risk',
    description: 'Analiza código en busca de eval()/Function()/exec()/vm.runInContext llamados con texto que no escribió el desarrollador (CWE-95), y detecta la falsa sensación de seguridad de usar vm2 (deprecada y con fugas conocidas).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código fuente de la función que evalúa código dinámicamente.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_dns_rebinding_risk',
    description: 'Analiza el código que arma el transporte HTTP/SSE de un servidor MCP en busca de falta de validación del header Origin/Host (rebinding DNS) — incluido el malentendido de creer que bindear solo a localhost ya protege.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que arma el transporte HTTP/SSE del servidor MCP.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_missing_auth_risk',
    description: 'Centinela de Autenticación: analiza el código que arma el transporte HTTP/SSE de un servidor MCP en busca de la ausencia de CUALQUIER verificación de autenticación (CWE-306) antes de despachar la petición, y si además el CORS está completamente abierto.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que arma el transporte HTTP/SSE del servidor MCP.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_mcp_stdio_launch_risk',
    description: 'Escudo de Lanzamiento MCP (STDIO): analiza código que arma una conexión de CLIENTE MCP por transporte stdio (StdioClientTransport/StdioServerParameters) en busca de un "command" dependiente de entrada externa sin lista de lanzadores permitidos, brechas de rehidratación (se valida al guardar pero no al lanzar), y bypass vía banderas de ejecución directa (-c/-e/--eval) aunque el binario esté permitido.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que arma la conexión stdio de un cliente MCP.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_redos_risk',
    description: 'Escudo Anti-ReDoS: analiza una expresión regular en busca de backtracking catastrófico (cuantificadores anidados, ej. (a+)+) aplicado contra una entrada variable sin tope/timeout, y de un regex compilado dinámicamente a partir de una fuente no literal.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que compila o aplica una expresión regular.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_session_hijack_risk',
    description: 'Escudo de Secuestro de Sesión: analiza código que busca/genera sesiones en busca de una sesión resuelta solo por ID sin vínculo con el dueño (CWE-384), y de un identificador de sesión generado con poca entropía (Math.random(), contador).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que busca o genera sesiones.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_oauth_audience_confusion_risk',
    description: 'Escudo de Confusión de Audiencia OAuth: analiza el verificador propio de tokens en busca de una validación de "audience"/"aud" condicionada a una bandera de configuración, que no rechaza la petición al no coincidir (solo loguea), silenciada por un catch(), o totalmente ausente.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código del verificador de tokens OAuth/JWT del servidor.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_unbounded_allocation_risk',
    description: 'Escudo de Asignación sin Límite: analiza código en busca de lectura completa de un cuerpo/archivo sin tope de tamaño, y de una reserva de memoria (array/buffer) o un bucle cuyo tamaño/cantidad depende de una entrada externa sin ningún límite (CWE-770).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que lee un cuerpo/archivo o reserva memoria/itera.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_cross_client_leak_risk',
    description: 'Escudo de Fuga Entre Clientes: analiza el código que arma el transporte HTTP/SSE de un servidor MCP en busca de una instancia de McpServer/Server compartida entre clientes sin aislamiento por sesión, o de una variable mutable a nivel de módulo leída dentro de una herramienta registrada.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código que arma el transporte HTTP/SSE de un servidor MCP.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_sampling_hijack_risk',
    description: 'Escudo de Secuestro de Sampling: analiza el código del lado cliente/host que maneja peticiones de sampling de un servidor MCP en busca de ausencia de revisión humana, invocación encubierta de herramientas desde la respuesta del modelo, o ausencia de un tope de longitud/tokens.',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código del lado cliente/host que maneja peticiones de sampling.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_output_schema_ssrf_risk',
    description: 'Escudo de Esquema de Salida: analiza el código del lado cliente que valida el outputSchema/inputSchema de una herramienta MCP con jsonschema en busca de SSRF por referencias externas no restringidas, y de una llamada de red síncrona dentro de una función async sin timeout (congela el event loop).',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código del lado cliente que valida outputSchema/inputSchema con jsonschema.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  },
  {
    name: 'detect_excessive_agency_risk',
    description: 'Escudo de Agencia Excesiva: analiza el MANIFIESTO de un servidor MCP en busca de una herramienta que ejecuta una acción irreversible o de alto valor (transferir, retirar, pagar, borrar) sin un campo de confirmación exigido en su esquema de entrada, y/o sin ningún tope máximo en un campo de monto/cantidad.',
    input_schema: {
      type: 'object',
      properties: { manifest: { type: 'object', description: 'El manifiesto del servidor MCP como objeto JSON ({ tools: [...] } o un arreglo de herramientas).' } },
      required: ['manifest']
    }
  },
  {
    name: 'detect_call_spoofing_risk',
    description: 'Escudo de Suplantación de Llamada: analiza el código de orquestación del lado del agente en busca de la extracción de llamadas a herramientas desde el texto libre de la respuesta del modelo (TOOL_CALL:, ```json, <tool_call>) en vez del campo estructurado de la API (tool_calls/function_call/tool_use) — el ataque "Repeat-After-Me".',
    input_schema: {
      type: 'object',
      properties: { codigo: { type: 'string', description: 'Código de orquestación del lado del agente que interpreta la respuesta del modelo.' }, lenguaje: { type: 'string', description: 'Solo informativo.' } },
      required: ['codigo']
    }
  }
];

// Handlers: casi todos reciben el "input" de Claude tal cual porque ya
// tiene la misma forma que espera la función lib correspondiente — salvo
// audit_mcp_server y simulate_approval, que en server.js se llaman con
// argumentos posicionales en vez de un solo objeto.
const TOOL_HANDLERS = {
  audit_mcp_server: (input) => heuristics.auditManifest(input.manifest),
  simulate_approval: (input) => heuristics.simulateApproval(input.action, input.rules, input.threshold),
  detect_poisoned_tool_descriptions: (input) => escudo.auditToolDescriptions(input),
  check_known_vulnerabilities: (input) => checkKnownVulnerabilities(input),
  detect_tool_rug_pull: (input) => detectToolRugPull(input),
  detect_poisoned_config_files: (input) => detectPoisonedConfigFiles(input),
  check_package_authenticity: (input) => checkPackageAuthenticity(input),
  detect_memory_poisoning: (input) => checkMemoryPoisoning(input),
  detect_ssrf_risk: (input) => checkSsrfRisk(input),
  detect_path_traversal_risk: (input) => checkPathTraversalRisk(input),
  detect_command_injection_risk: (input) => checkCommandInjectionRisk(input),
  detect_sql_injection_risk: (input) => checkSqlInjectionRisk(input),
  detect_token_passthrough_risk: (input) => checkTokenPassthroughRisk(input),
  detect_hardcoded_secrets_risk: (input) => checkHardcodedSecretsRisk(input),
  detect_insecure_deserialization_risk: (input) => checkInsecureDeserializationRisk(input),
  detect_toxic_flow_risk: (input) => checkToxicFlowRisk(input),
  detect_ssti_risk: (input) => checkSsTemplateInjectionRisk(input),
  detect_dynamic_code_risk: (input) => checkDynamicCodeRisk(input),
  detect_dns_rebinding_risk: (input) => checkDnsRebindingRisk(input),
  detect_missing_auth_risk: (input) => checkMissingAuthRisk(input),
  detect_mcp_stdio_launch_risk: (input) => checkMcpStdioLaunchRisk(input),
  detect_redos_risk: (input) => checkRedosRisk(input),
  detect_session_hijack_risk: (input) => checkSessionHijackRisk(input),
  detect_oauth_audience_confusion_risk: (input) => checkOAuthAudienceConfusionRisk(input),
  detect_unbounded_allocation_risk: (input) => checkUnboundedAllocationRisk(input),
  detect_cross_client_leak_risk: (input) => checkCrossClientLeakRisk(input),
  detect_sampling_hijack_risk: (input) => checkSamplingHijackRisk(input),
  detect_output_schema_ssrf_risk: (input) => checkOutputSchemaSsrfRisk(input),
  detect_excessive_agency_risk: (input) => checkExcessiveAgencyRisk(input),
  detect_call_spoofing_risk: (input) => checkCallSpoofingRisk(input)
};

// Las dos únicas herramientas que llaman a un servicio externo (OSV.dev,
// registro de npm) y por eso devuelven el uso/crédito si fallan — mismo
// criterio que server.js.
const HERRAMIENTAS_REEMBOLSABLES = new Set(['check_known_vulnerabilities', 'check_package_authenticity']);

const SYSTEM_PROMPT = [
  'Eres Vigía, el analista de ciberseguridad especializado de Garita Labs.',
  'Tu trabajo es revisar lo que el cliente te manda — código fuente, un manifiesto de servidor MCP, el nombre de un paquete, un archivo de configuración/instrucciones, o una descripción en texto libre, a veces varias cosas a la vez — y decidir TÚ MISMO cuáles de tus herramientas de detección usar para encontrar problemas reales de seguridad.',
  '',
  'Tienes 30 herramientas disponibles, cada una especializada en un tipo de riesgo (SSRF, path traversal, inyección de comandos, inyección SQL, secretos hardcodeados, deserialización insegura, SSTI, código dinámico (eval), rebinding DNS, falta de autenticación, lanzamiento inseguro de un cliente MCP por stdio, reenvío de tokens, envenenamiento de descripciones/config/memoria, flujos tóxicos, rug-pull de herramientas, vulnerabilidades conocidas (CVEs) y autenticidad de paquetes, auditoría de manifiesto MCP, simulación de aprobación de una acción, ReDoS (backtracking catastrófico), secuestro de sesión, confusión de audiencia OAuth, asignación de memoria/recursos sin límite, fuga de estado entre clientes de un servidor MCP, secuestro de peticiones de sampling, SSRF/denegación de servicio vía validación de esquemas de salida, agencia excesiva en el esquema de una herramienta, y suplantación de llamada a herramienta desde texto libre ("Repeat-After-Me")). No llames una herramienta si claramente no aplica a lo que te mandaron (por ejemplo, no llames detect_sql_injection_risk si no hay ninguna consulta SQL en el código) — pero sé exhaustivo con lo que SÍ podría aplicar: si te mandan código que hace varias cosas (una petición HTTP y además ejecuta un comando, por ejemplo), llama todas las herramientas relevantes, no solo la primera que se te ocurra.',
  '',
  'Cuando termines de usar las herramientas que necesites, responde en español claro y directo, pensado para alguien que puede no ser experto en seguridad:',
  '1) Un resumen de uno o dos párrafos del riesgo general.',
  '2) Los hallazgos ordenados del más grave al menos grave, cada uno explicado en términos simples (qué es el problema, por qué importa, cómo lo podría explotar alguien).',
  '3) Para cada hallazgo real, una recomendación de corrección concreta — podés incluir un fragmento de código de ejemplo de la corrección si ayuda a entenderla.',
  '4) Si no se encontró ningún problema, decilo con confianza pero mencioná qué SÍ revisaste.',
  '',
  'Reglas importantes:',
  '- Nunca inventes un hallazgo que tus herramientas no reportaron. Si una herramienta no encontró nada, no fabriques un riesgo para parecer útil.',
  '- Sos honesto sobre el alcance: tus herramientas de código hacen análisis estático por patrones de texto, no reemplazan una auditoría de seguridad formal ni un analizador de sintaxis (AST) completo. Si el cliente pregunta algo fuera de lo que tus herramientas pueden ver, decilo.',
  '- NUNCA modificás ni aplicás cambios directamente sobre el código o los sistemas del cliente — ni aunque te lo pida explícitamente ("arreglalo ahora", "subí el fix"). Solo analizás, explicás y sugerís la corrección como texto/ejemplo. Si insiste, aclarale amablemente que en este nivel de servicio (Centinela Básico) solo das el diagnóstico y la recomendación, y que aplicar el cambio queda en sus manos (o de su equipo).',
  '- Si te mandan algo que no tiene nada que ver con seguridad de agentes de IA/MCP (una pregunta general, charla casual), respondé con normalidad sin forzar el uso de ninguna herramienta.'
].join('\n');

function getClient() {
  const Anthropic = require('@anthropic-ai/sdk');
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('Vigía no está configurado en este servidor: falta la variable de entorno ANTHROPIC_API_KEY.');
  }
  return new Anthropic({ apiKey });
}

async function ejecutarHerramienta(name, input, apiKeyCliente) {
  const check = await licensing.checkAndConsume(apiKeyCliente);
  if (!check.allowed) {
    return { ok: false, licenciaAgotada: true, error: check.reason };
  }
  const handler = TOOL_HANDLERS[name];
  if (!handler) {
    return { ok: false, error: 'Herramienta desconocida: ' + name };
  }
  try {
    const result = await handler(input || {});
    result._licencia = check.remaining;
    return { ok: true, result };
  } catch (err) {
    if (HERRAMIENTAS_REEMBOLSABLES.has(name)) {
      await licensing.refundUse(apiKeyCliente, check.consumedFrom);
    }
    return { ok: false, error: err.message };
  }
}

// input: { mensaje: string, apiKey: string }
// apiKey es la llave de acceso de Garita Labs del cliente (la misma que usa
// para /mcp) — se usa para cobrar cada herramienta real que Vigía decida
// llamar, exactamente igual que si el cliente la hubiera llamado directo.
async function analizar({ mensaje, apiKey }) {
  if (typeof mensaje !== 'string' || !mensaje.trim()) {
    throw new Error('Debes enviar "mensaje" con el código, manifiesto o descripción que quieres que Vigía analice.');
  }

  const client = getClient();
  const messages = [{ role: 'user', content: mensaje }];
  const herramientasUsadas = [];
  let licenciaAgotadaEnElCamino = false;

  for (let turn = 0; turn < MAX_TURNS; turn++) {
    const resp = await client.messages.create({
      model: MODEL,
      max_tokens: MAX_TOKENS,
      system: SYSTEM_PROMPT,
      tools: TOOL_DEFS,
      messages
    });

    messages.push({ role: 'assistant', content: resp.content });

    if (resp.stop_reason !== 'tool_use') {
      const texto = resp.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text)
        .join('\n');
      return {
        informe: texto,
        herramientasUsadas,
        licenciaAgotada: licenciaAgotadaEnElCamino,
        vueltas: turn + 1
      };
    }

    const toolUseBlocks = resp.content.filter((b) => b.type === 'tool_use');
    const toolResults = [];
    for (const block of toolUseBlocks) {
      const outcome = await ejecutarHerramienta(block.name, block.input, apiKey);
      if (!outcome.ok && outcome.licenciaAgotada) licenciaAgotadaEnElCamino = true;
      herramientasUsadas.push({ herramienta: block.name, entrada: block.input, ok: outcome.ok });
      toolResults.push({
        type: 'tool_result',
        tool_use_id: block.id,
        content: JSON.stringify(outcome.ok ? outcome.result : { error: true, message: outcome.error }),
        is_error: !outcome.ok
      });
    }
    messages.push({ role: 'user', content: toolResults });

    // Si la licencia se agotó en el camino, no tiene sentido seguir dándole
    // más vueltas a Claude para que siga pidiendo herramientas que ya sabemos
    // que van a fallar por falta de usos/créditos — se corta ahí y se le
    // informa al cliente.
    if (licenciaAgotadaEnElCamino) {
      return {
        informe: 'Se agotaron los usos/créditos de tu llave de acceso a mitad del análisis. Lo que se llegó a revisar está en "herramientasUsadas". Consigue más créditos en POST /comprar-creditos y volvé a intentarlo.',
        herramientasUsadas,
        licenciaAgotada: true,
        vueltas: turn + 1,
        incompleto: true
      };
    }
  }

  return {
    informe: 'Vigía alcanzó el límite de pasos de análisis (' + MAX_TURNS + ') sin terminar — probablemente el pedido es muy amplio. Intenta dividirlo en partes más chicas (por ejemplo, un archivo o una función a la vez).',
    herramientasUsadas,
    licenciaAgotada: licenciaAgotadaEnElCamino,
    vueltas: MAX_TURNS,
    incompleto: true
  };
}

module.exports = {
  analizar: analizar,
  TOOL_DEFS: TOOL_DEFS,
  TOOL_HANDLERS: TOOL_HANDLERS,
  MODEL: MODEL,
  MAX_TURNS: MAX_TURNS
};
