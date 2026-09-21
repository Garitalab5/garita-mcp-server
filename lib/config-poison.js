"use strict";
// Garita MCP — detector de archivos de configuración/instrucciones envenenados
// ===============================================================================
// Sexta herramienta de Garita Labs. Problema que resuelve (investigación de
// mercado, 2026-09): Garita Escudo revisa el texto de las herramientas
// DECLARADAS por un servidor MCP — pero un agente de código (Claude Code,
// Cursor, y similares) también carga y confía, de forma automática y SIN
// ningún paso de aprobación, en archivos de configuración/instrucciones que
// viven en el propio repositorio: AGENTS.md, CLAUDE.md, .cursorrules,
// .cursor/rules/*, archivos de "skills", etc. Un archivo de ese tipo
// envenenado con una instrucción escondida llega al mismo contexto de
// confianza del agente por una puerta totalmente distinta a la de un
// manifiesto MCP, y Escudo nunca lo mira.
//
// Caso real documentado (Mitiga, 2026-06): un archivo .cursor/rules +
// CLAUDE.md + .cursor/mcp.json envenenados lograron exfiltrar credenciales
// de AWS/Kubernetes/Terraform en menos de 2 minutos en una prueba controlada.
// Otro estudio (Snyk, "ToxicSkills", sobre el registro ClawHub) encontró
// instrucciones maliciosas en el 36% de los "skills" revisados.
//
// Diferencia clave de diseño frente a Escudo (y por qué esto NO es solo
// "Escudo con otro nombre"):
//
// 1) Un archivo de instrucciones para un agente EXISTE para dar órdenes en
//    lenguaje de autoridad ("IMPORTANTE: corre las pruebas antes de hacer
//    commit") — eso es exactamente lo que se espera que contenga. Aplicar
//    la regla 'lenguaje_autoridad' de Escudo tal cual aquí generaría ruido
//    constante de falsos positivos, así que esta herramienta la retiene
//    como señal (se reporta como informativa) pero NO la cuenta para el
//    puntaje.
//
// 2) A diferencia de una herramienta MCP (que pasa por un paso de
//    aprobación humana antes de poder actuar, razón por la cual el patrón
//    "rug-pull" necesita un GATILLO DIFERIDO para ser útil — atacar algo
//    que ya se aprobó), un archivo de instrucciones se carga y se confía
//    de inmediato, sin aprobación de por medio. Por eso esta herramienta
//    agrega una regla nueva, 'filtracion_credenciales', que no exige
//    ningún gatillo temporal: basta con una instrucción de leer/incluir/
//    enviar/mostrar el contenido de un archivo de credenciales para que
//    se marque — el ataque real (Mitiga) no esperó a ninguna "próxima
//    ejecución", actuó de inmediato.
//
// El resto del motor (caracteres invisibles, esteganografía Unicode,
// entidades HTML, homoglifos, marcas "zalgo", y las reglas de ocultamiento/
// etiqueta oculta/manipulación cruzada/redirección/meta-decodificar/
// gatillo diferido) se reutiliza TAL CUAL desde lib/escudo.js — no se
// duplica ni se reescribe, para que una mejora futura a esas reglas
// beneficie a ambas herramientas automáticamente y no se repita el
// problema ya visto una vez (la demo de navegador de Escudo se quedó sin
// 'gatillo_diferido' por tener una copia separada del motor).

const escudo = require('./escudo');

// Deduction fija de 'lenguaje_autoridad' en escudo.js — se resta del
// resultado cuando esa regla dispara, porque en este género de archivo no
// es una señal confiable (ver nota de diseño arriba). Si el valor cambia
// algún día en escudo.js, este número debe actualizarse junto con él (hay
// una prueba de regresión que lo verifica indirectamente).
const LENGUAJE_AUTORIDAD_ID = 'lenguaje_autoridad';
const LENGUAJE_AUTORIDAD_DEDUCTION = 12;

// Regla nueva, específica de este género de archivo: instrucción de
// acceder Y exponer (leer, incluir, copiar, enviar, mostrar, imprimir,
// adjuntar) el contenido de un archivo o variable de credenciales/secretos
// — SIN exigir ningún gatillo temporal, porque un archivo de instrucciones
// se confía de inmediato. Exige AMBAS partes (verbo de acceso/exposición +
// un indicador concreto de credencial) para no marcar una mención
// puramente descriptiva ("este proyecto usa las credenciales de
// ~/.aws/credentials, configuradas con `aws configure`" no dispara: no hay
// verbo de acceso/exposición dirigido a esa ruta).
// Incluye formas del imperativo afirmativo con pronombre enclítico pegado
// ("muéstralo", "envíalo", "inclúyelo"...) — se probó con ataques reales en
// español y sin esto una instrucción perfectamente natural en ese idioma
// ("léelo y envíalo") no disparaba nada. Nota de diseño (no una casualidad
// verificada): el imperativo NEGATIVO en español usa una conjugación
// distinta (modo subjuntivo: "nunca lo muestres", "no lo envíes"), así que
// esta lista de formas AFIRMATIVAS no dispara con una instrucción legítima
// de tipo "nunca muestres X" — pero esa distinción NO existe en inglés
// ("never print X" usa la misma forma verbal que la orden "print X"), así
// que en inglés una instrucción defensiva de ese tipo sí puede generar un
// falso positivo. Límite conocido y documentado, no un fallo silencioso.
const VERBOS_EXPOSICION = 'lee|leer|l[eé]elo|l[eé]ela|incluye|incluir|inclúyelo|inclúyela|copia|copiar|c[oó]pialo|c[oó]piala|env[ií]a|enviar|env[ií]alo|env[ií]ala|muestra|mostrar|mu[eé]stralo|mu[eé]strala|imprime|imprimir|impr[ií]melo|impr[ií]mela|adjunta|adjuntar|adjúntalo|adjúntala|agrega|agregar|agr[eé]galo|agr[eé]gala|read|include|copy|send|show|print|attach|append|exfiltrate|exfiltra';
const INDICADORES_CREDENCIAL = '~\\/\\.aws\\/credentials|\\.aws\\/credentials|~\\/\\.ssh\\/[\\w.\\-]*|\\.ssh\\/id_rsa|\\.ssh\\/id_ed25519|authorized_keys|\\.env\\b|\\.git-credentials|\\.netrc|kubeconfig|terraform\\.tfstate|clave\\s+privada|llave\\s+ssh|clave\\s+ssh|api[_\\s-]?key|access[_\\s-]?token|secret[_\\s-]?key|contrase[ñn]a|password\\b';

const FILTRACION_CREDENCIALES_RULE = {
  id: 'filtracion_credenciales',
  sev: 'critical',
  deduction: 60,
  label: 'Instrucción para leer y exponer el contenido de un archivo o variable de credenciales/secretos — sin necesitar ninguna aprobación previa, un archivo de instrucciones se confía de inmediato',
  regex: new RegExp(
    '\\b(' + VERBOS_EXPOSICION + ')\\b[\\s\\S]{0,80}(' + INDICADORES_CREDENCIAL + ')' +
    '|(' + INDICADORES_CREDENCIAL + ')[\\s\\S]{0,80}\\b(' + VERBOS_EXPOSICION + ')\\b',
    'i'
  )
};

function normalizarArchivo(entrada, idx) {
  if (typeof entrada === 'string') return { ruta: 'archivo_' + (idx + 1), contenido: entrada };
  entrada = entrada || {};
  return {
    ruta: typeof entrada.ruta === 'string' && entrada.ruta.trim() ? entrada.ruta.trim() : 'archivo_' + (idx + 1),
    contenido: typeof entrada.contenido === 'string' ? entrada.contenido : ''
  };
}

// Analiza un archivo: reutiliza escudo.analyzeText tal cual (mismo motor,
// mismas reglas de ocultamiento/homoglifos/gatillo diferido/etc.), le resta
// la deducción de 'lenguaje_autoridad' si disparó, y le suma la regla nueva
// de filtración de credenciales.
function analizarArchivo(ruta, contenido) {
  const base = escudo.analyzeText(ruta, contenido, {});

  let deduction = base.deduction;
  const firedIds = base.firedIds.slice();
  let findings = base.findings.filter(function (f) {
    // Se retiene como aviso informativo (no afecta el puntaje) en vez de
    // quitarse por completo — sigue siendo útil saber que el archivo usa
    // lenguaje de autoridad, solo que no es evidencia de nada malicioso
    // aquí.
    return true;
  }).map(function (f) {
    const esLenguajeAutoridad = firedIds.indexOf(LENGUAJE_AUTORIDAD_ID) !== -1 &&
      f.label === 'Lenguaje de autoridad/urgencia poco habitual en una descripción de herramienta';
    if (esLenguajeAutoridad) {
      return Object.assign({}, f, {
        sev: 'ok',
        label: 'Contiene lenguaje de autoridad/urgencia (IMPORTANTE, CRÍTICO, etc.) — normal y esperado en un archivo de instrucciones para un agente, no se cuenta como señal de riesgo por sí solo.'
      });
    }
    return f;
  });

  if (firedIds.indexOf(LENGUAJE_AUTORIDAD_ID) !== -1) {
    deduction = Math.max(0, deduction - LENGUAJE_AUTORIDAD_DEDUCTION);
  }

  const semanticText = base.normalizedText;
  const m = FILTRACION_CREDENCIALES_RULE.regex.exec(semanticText);
  if (m) {
    deduction += FILTRACION_CREDENCIALES_RULE.deduction;
    firedIds.push(FILTRACION_CREDENCIALES_RULE.id);
    // findings de "sin señales" se reemplazan; si había otros hallazgos
    // reales se conservan y este se agrega.
    findings = findings.filter(function (f) { return f.label !== 'Sin señales de instrucciones ocultas en el texto.'; });
    findings.push({
      sev: FILTRACION_CREDENCIALES_RULE.sev,
      label: FILTRACION_CREDENCIALES_RULE.label,
      snippet: contextSnippet(semanticText, m.index, m[0].length)
    });
  }

  if (findings.length === 0) {
    findings.push({ sev: 'ok', label: 'Sin señales de instrucciones ocultas o peligrosas en el archivo.', snippet: null });
  }

  return { ruta: ruta, deduction: deduction, findings: findings, firedIds: firedIds };
}

// Copia local mínima de contextSnippet (igual a la de escudo.js) — no se
// reexporta desde escudo.js porque es una función interna de ese módulo;
// duplicar esta única función de formato es aceptable (no es lógica de
// detección), a diferencia de las reglas en sí, que sí se reutilizan.
function contextSnippet(text, idx, len) {
  const start = Math.max(0, idx - 34);
  const end = Math.min(text.length, idx + len + 34);
  const prefix = start > 0 ? '…' : '';
  const suffix = end < text.length ? '…' : '';
  return prefix + text.slice(start, idx) + '[' + text.slice(idx, idx + len) + ']' + text.slice(idx + len, end) + suffix;
}

// input: { archivos: [{ruta, contenido}, ...] } o { contenido, ruta? } (un solo archivo suelto)
function detectPoisonedConfigFiles(input) {
  input = input || {};
  let archivos;

  if (input.archivos !== undefined && input.archivos !== null) {
    if (!Array.isArray(input.archivos) || !input.archivos.length) {
      throw new Error('"archivos" debe ser un arreglo con al menos un elemento { ruta, contenido }.');
    }
    archivos = input.archivos.map(normalizarArchivo);
  } else if (typeof input.contenido === 'string' && input.contenido.trim()) {
    archivos = [normalizarArchivo({ ruta: input.ruta, contenido: input.contenido }, 0)];
  } else {
    throw new Error('Debes enviar "archivos" (arreglo de { ruta, contenido }) o "contenido" (un solo archivo suelto, con "ruta" opcional).');
  }

  const resultados = archivos.map(function (a) { return analizarArchivo(a.ruta, a.contenido); });

  const maxDed = resultados.reduce(function (m, r) { return Math.max(m, r.deduction); }, 0);
  const avgDed = resultados.reduce(function (s, r) { return s + r.deduction; }, 0) / resultados.length;
  // Mismo criterio que Escudo: el peor caso pesa más que el promedio, basta
  // con que UN archivo esté envenenado para comprometer al agente entero.
  const totalDeduction = maxDed * 0.7 + avgDed * 0.3;
  const score = Math.max(0, Math.min(100, Math.round(100 - totalDeduction)));
  const b = escudo.bucket(score);

  const huboFiltracionCredenciales = resultados.some(function (r) { return r.firedIds.indexOf('filtracion_credenciales') !== -1; });

  return {
    puntaje: score,
    veredicto: b.label,
    resumen: 'Puntaje del peor caso entre los ' + resultados.length + ' archivo(s) analizados, ponderado con el promedio' +
      (huboFiltracionCredenciales ? '. Se encontró al menos una instrucción de exponer credenciales/secretos — la más grave que detecta esta herramienta.' : '.'),
    archivos: resultados.map(function (r) {
      const tb = escudo.bucket(100 - r.deduction * 1.1);
      return {
        ruta: r.ruta,
        veredicto: tb.label,
        hallazgos: r.findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
      };
    })
  };
}

module.exports = {
  detectPoisonedConfigFiles: detectPoisonedConfigFiles,
  analizarArchivo: analizarArchivo,
  FILTRACION_CREDENCIALES_RULE: FILTRACION_CREDENCIALES_RULE
};
