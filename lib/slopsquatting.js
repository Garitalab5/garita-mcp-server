"use strict";
// Garita MCP — verificador de autenticidad de paquetes (typosquatting / "slopsquatting")
// ==========================================================================================
// Séptima herramienta de Garita Labs. Problema que resuelve (investigación de
// mercado, 2026-09): un asistente de código con IA a veces ALUCINA el nombre
// de un paquete que no existe cuando sugiere una dependencia — y desde 2026
// hay campañas activas de atacantes que registran esos nombres alucinados de
// verdad, con malware adentro, apostando a que un agente (o una persona
// copiando la sugerencia del agente) lo termine instalando ("slopsquatting").
// Caso real documentado (Cloud Security Alliance / Sonatype / The Hacker
// News, agosto 2026): una sola campaña publicó 800-1.000+ paquetes
// maliciosos en npm con nombres genéricos plausibles (ej. "bigops-api"),
// diseñados a propósito para parecerse al tipo de nombre que un modelo de
// lenguaje alucina al sugerir una dependencia — y publicados con un número
// de versión inicial sospechosamente alto (ej. 35.x.y) para simular un
// paquete ya establecido.
//
// Diferencia clave frente a check_known_vulnerabilities (lib/vulnerabilidades.js):
// esa herramienta busca fallas YA conocidas y publicadas (CVEs) en un
// paquete que probablemente es legítimo. Esta herramienta no busca CVEs —
// busca señales de que el paquete en sí NO es lo que parece: acaba de
// aparecer, se ve casi idéntico a uno popular, o está armado para parecer
// más viejo/confiable de lo que es. Un paquete puede no tener ningún CVE
// todavía y aun así ser un impostor recién publicado.
//
// Fuente de datos: el registro público de npm (registry.npmjs.org),
// gratis, sin llave de API, con CORS habilitado (se puede consultar directo
// desde el navegador, igual que Vulnerabilidades consulta OSV.dev).
// Alcance actual: solo npm. Otros ecosistemas (PyPI, crates.io, etc.) usan
// APIs de registro distintas y no están cubiertos todavía — límite conocido
// y documentado, no oculto (ver ECOSISTEMAS_SOPORTADOS).

const NPM_REGISTRY_BASE = 'https://registry.npmjs.org/';

const ECOSISTEMAS_SOPORTADOS = ['npm'];

// Paquetes muy populares y ampliamente conocidos, usados como referencia
// para detectar un nombre "casi idéntico" (typosquatting clásico): un
// paquete NUEVO con un nombre a 1-2 ediciones de distancia de uno de estos,
// que no sea el paquete real, es una señal fuerte. Esta lista es solo un
// punto de partida (no pretende ser exhaustiva) — incluye paquetes
// genéricos muy usados y paquetes propios del ecosistema de servidores MCP,
// que es el público principal de Garita Labs.
const PAQUETES_POPULARES_NPM = [
  'react', 'react-dom', 'lodash', 'express', 'axios', 'chalk', 'commander',
  'dotenv', 'webpack', 'typescript', 'eslint', 'prettier', 'jest', 'mocha',
  'chai', 'moment', 'uuid', 'request', 'socket.io', 'next', 'vue', 'redux',
  'rxjs', 'jquery', 'bootstrap', 'tailwindcss', 'vite', 'rollup', 'nodemon',
  'pm2', 'cors', 'body-parser', 'multer', 'mongoose', 'sequelize', 'pg',
  'mysql', 'redis', 'jsonwebtoken', 'bcrypt', 'passport', 'stripe',
  'aws-sdk', 'firebase', 'puppeteer', 'playwright', 'cheerio', 'node-fetch',
  'ws', 'yargs', 'inquirer', 'figlet', 'ora', 'glob', 'fs-extra', 'rimraf',
  'semver', 'ajv', 'joi', 'zod', 'yup', 'winston', 'pino', 'dayjs',
  'date-fns', 'underscore', 'left-pad', 'colors', 'debug', 'minimist',
  'tslib', 'core-js', '@modelcontextprotocol/sdk', 'mcp-remote'
];

// ---------- Levenshtein (distancia de edición) ----------
// Iterativo (no recursivo), con una matriz de dos filas para no gastar
// memoria de más en nombres largos.
function distanciaLevenshtein(a, b) {
  a = String(a || '');
  b = String(b || '');
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  let prev = new Array(b.length + 1);
  let curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;

  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const costo = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // borrar
        curr[j - 1] + 1,  // insertar
        prev[j - 1] + costo // sustituir
      );
    }
    const tmp = prev; prev = curr; curr = tmp;
  }
  return prev[b.length];
}

// Busca, entre los paquetes populares de referencia, el más parecido al
// nombre dado (por distancia de edición absoluta, solo entre nombres de
// longitud similar — comparar "a" contra "aws-sdk" con una distancia de 6
// no dice nada útil). Ignora una coincidencia EXACTA (ese es el paquete
// real, no un impostor).
function coincidenciaCercana(nombre) {
  const n = String(nombre || '').toLowerCase();
  let mejor = null;
  for (const popular of PAQUETES_POPULARES_NPM) {
    const p = popular.toLowerCase();
    if (p === n) return null; // es el paquete real, no una imitación
    if (Math.abs(p.length - n.length) > 3) continue;
    const d = distanciaLevenshtein(n, p);
    if (d <= 2 && (!mejor || d < mejor.distancia)) {
      mejor = { paquete: popular, distancia: d };
    }
  }
  return mejor;
}

function esPlaceholderReadme(readme) {
  if (typeof readme !== 'string') return true;
  const r = readme.trim();
  if (r.length < 40) return true;
  if (/ERROR:\s*No README data found/i.test(r)) return true;
  return false;
}

function repositorioDeclarado(repository) {
  if (!repository) return false;
  if (typeof repository === 'string') return repository.trim().length > 0;
  return !!(repository.url && String(repository.url).trim());
}

// npm exige que el "@" de un paquete con alcance (scope) vaya literal y
// solo la "/" que le sigue vaya codificada como "%2f" — encodeURIComponent
// por sí solo codifica también el "@", lo que rompe la consulta.
function urlDelRegistro(nombre) {
  const partes = String(nombre).split('/');
  const codificado = partes.map(encodeURIComponent).join('%2f');
  return NPM_REGISTRY_BASE + codificado;
}

function primeraVersionPublicada(data) {
  const time = data && data.time;
  if (!time || typeof time !== 'object') return null;
  let mejor = null;
  for (const version of Object.keys(time)) {
    if (version === 'created' || version === 'modified') continue;
    const fecha = Date.parse(time[version]);
    if (!Number.isFinite(fecha)) continue;
    if (!mejor || fecha < mejor.fecha) mejor = { version, fecha };
  }
  return mejor ? mejor.version : null;
}

function versionMayor(version) {
  if (typeof version !== 'string') return null;
  const m = /^v?(\d+)\./.exec(version.trim());
  return m ? parseInt(m[1], 10) : null;
}

function tieneScriptDeInstalacion(data, latest) {
  const v = data && data.versions && latest && data.versions[latest];
  const scripts = v && v.scripts;
  if (!scripts || typeof scripts !== 'object') return false;
  return !!(scripts.postinstall || scripts.preinstall || scripts.install);
}

function bucket(score) {
  if (score >= 80) return { label: 'Aceptable', sev: 'ok' };
  if (score >= 50) return { label: 'Riesgo moderado', sev: 'warn' };
  return { label: 'Alto riesgo', sev: 'critical' };
}

const MS_POR_DIA = 24 * 60 * 60 * 1000;

// input: { ecosistema, nombre }
async function checkPackageAuthenticity(input) {
  input = input || {};
  const ecosistema = String(input.ecosistema || '').trim();
  const nombre = String(input.nombre || '').trim();

  if (!ecosistema || !nombre) {
    throw new Error('Debes enviar "ecosistema" (ej. "npm") y "nombre" del paquete.');
  }
  if (ecosistema.toLowerCase() !== 'npm') {
    throw new Error(
      'Por ahora solo se soporta el ecosistema "npm" (límite conocido — ver ECOSISTEMAS_SOPORTADOS). ' +
      'Recibido: "' + ecosistema + '".'
    );
  }

  let res;
  try {
    res = await fetch(urlDelRegistro(nombre));
  } catch (err) {
    throw new Error('No se pudo contactar el registro de npm: ' + err.message);
  }

  if (res.status === 404) {
    return {
      ecosistema: 'npm',
      paquete: nombre,
      existe: false,
      sev: 'warn',
      veredicto: 'Este paquete NO existe en el registro de npm.',
      resumen: 'Si un asistente de IA te sugirió instalar este paquete, es posible que haya alucinado el nombre — no lo instales sin verificar de otra forma. ' +
        'Esto también es, por sí solo, una situación de riesgo latente: si el nombre exacto se hace público (por ejemplo, en un tutorial, un commit, o la sugerencia de un agente), un atacante puede registrarlo después con malware adentro y esperar a que alguien lo instale sin volver a revisar ("slopsquatting") — ya ocurrió a escala real en 2026.'
    };
  }

  let data;
  try {
    data = await res.json();
  } catch (err) {
    throw new Error('El registro de npm devolvió una respuesta que no se pudo interpretar: ' + err.message);
  }
  if (!res.ok) {
    throw new Error('El registro de npm rechazó la consulta (' + res.status + ').');
  }

  const creadoEl = data.time && data.time.created ? data.time.created : null;
  const creadoTs = creadoEl ? Date.parse(creadoEl) : NaN;
  const diasDesdeCreado = Number.isFinite(creadoTs) ? Math.floor((Date.now() - creadoTs) / MS_POR_DIA) : null;

  const totalVersiones = data.versions && typeof data.versions === 'object' ? Object.keys(data.versions).length : 0;
  const latest = data['dist-tags'] && data['dist-tags'].latest;
  const primeraVersion = primeraVersionPublicada(data) || latest;
  const mayorInicial = versionMayor(primeraVersion);

  const tieneRepositorio = repositorioDeclarado(data.repository);
  const tieneHomepage = !!(data.homepage && String(data.homepage).trim());
  const tieneReadme = !esPlaceholderReadme(data.readme);
  const scriptInstalacion = tieneScriptDeInstalacion(data, latest);
  const maintainersCount = Array.isArray(data.maintainers) ? data.maintainers.length : null;
  const cercano = coincidenciaCercana(nombre);

  const findings = [];
  let deduction = 0;

  // Regla 1: nombre casi idéntico a uno de los paquetes más populares
  // (típico typosquatting), Y todavía joven/con poco historial — un
  // paquete distinto pero parecido con años de versiones propias no es un
  // impostor, es solo un nombre parecido por casualidad.
  //
  // La cantidad de versiones por sí sola es una señal manipulable: publicar
  // varios "patch bumps" vacíos en minutos es gratis para un atacante, así
  // que además de "totalVersiones <= 3" se usa la ANTIGÜEDAD real del
  // paquete (diasDesdeCreado) como criterio independiente — un paquete con
  // nombre casi idéntico a uno popular creado hace muy poco (<=14 días) se
  // marca igual sin importar cuántas versiones ya publicó (evasión real
  // encontrada y corregida: "loadash" creado hoy con 4 versiones triviales
  // publicadas en minutos pasaba limpio con el criterio viejo).
  var muyReciente = diasDesdeCreado !== null && diasDesdeCreado <= 14;
  if (cercano && (totalVersiones <= 3 || muyReciente)) {
    deduction += 55;
    findings.push({
      sev: 'critical',
      id: 'posible_typosquat',
      label: 'Nombre a ' + cercano.distancia + ' edición(es) de distancia de "' + cercano.paquete + '" (uno de los paquetes más populares de npm), ' +
        (muyReciente
          ? 'publicado hace solo ' + diasDesdeCreado + ' día(s) — el relleno de versiones triviales no es una señal confiable de legitimidad cuando el paquete es tan nuevo.'
          : 'y con muy poco historial de versiones (' + totalVersiones + ')') +
        ' — patrón típico de typosquatting.'
    });
  }

  // Regla 2: publicado hace muy poco Y con un número de versión inicial
  // ya "maduro" (ej. empieza en 35.x.y en vez de 0.x/1.x) — el patrón
  // documentado en la campaña de "slopsquatting" de agosto 2026: simular
  // que el paquete lleva tiempo establecido.
  if (diasDesdeCreado !== null && diasDesdeCreado <= 14 && totalVersiones <= 2 && mayorInicial !== null && mayorInicial >= 10) {
    deduction += 45;
    findings.push({
      sev: 'critical',
      id: 'version_inicial_anomala',
      label: 'Publicado hace ' + diasDesdeCreado + ' día(s), con una sola versión (o casi) pero un número de versión inicial inusualmente alto ("' + primeraVersion + '") — así se disfrazan de paquete ya establecido en vez de empezar en 0.x/1.x, patrón documentado en campañas reales de 2026.'
    });
  } else if (diasDesdeCreado !== null && diasDesdeCreado <= 14) {
    deduction += 15;
    findings.push({
      sev: 'warn',
      id: 'publicado_recientemente',
      label: 'Publicado hace solo ' + diasDesdeCreado + ' día(s) — no es necesariamente malicioso, pero es una señal a tener en cuenta junto con las demás.'
    });
  }

  // Regla 3: tiene un script que se ejecuta solo al instalar (postinstall/
  // preinstall/install) Y es reciente — combinado, es el vector real
  // documentado (Microsoft, 2026) para robar credenciales/secretos de
  // CI/CD apenas alguien instala el paquete. Un paquete legítimo y viejo
  // que use esto (para compilar binarios nativos, por ejemplo) no se
  // penaliza solo por tenerlo.
  if (scriptInstalacion && diasDesdeCreado !== null && diasDesdeCreado <= 90) {
    deduction += 30;
    findings.push({
      sev: 'warn',
      id: 'script_instalacion_reciente',
      label: 'Tiene un script que se ejecuta automáticamente al instalar (postinstall/preinstall/install) y el paquete es reciente (' + diasDesdeCreado + ' día(s)) — revisa qué hace ese script antes de instalar; es el vector real usado en varias campañas de robo de credenciales en 2026.'
    });
  }

  // Regla 4: sin repositorio, sin homepage, y sin README real — los tres
  // a la vez. Un paquete legítimo casi siempre tiene al menos uno.
  if (!tieneRepositorio && !tieneHomepage && !tieneReadme) {
    deduction += 15;
    findings.push({
      sev: 'warn',
      id: 'sin_metadatos_basicos',
      label: 'No declara repositorio, ni homepage, ni tiene un README real — un paquete legítimo casi siempre tiene al menos uno de los tres.'
    });
  }

  if (findings.length === 0) {
    findings.push({ sev: 'ok', id: 'sin_senales', label: 'Sin señales de typosquatting/slopsquatting encontradas para este paquete.' });
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));
  const b = bucket(score);

  return {
    ecosistema: 'npm',
    paquete: nombre,
    existe: true,
    puntaje: score,
    veredicto: b.label,
    sev: b.sev,
    metadatos: {
      creadoEl: creadoEl,
      diasDesdeCreado: diasDesdeCreado,
      totalVersiones: totalVersiones,
      primeraVersionPublicada: primeraVersion,
      ultimaVersion: latest || null,
      tieneRepositorio: tieneRepositorio,
      tieneHomepage: tieneHomepage,
      tieneReadme: tieneReadme,
      scriptDeInstalacionAutomatica: scriptInstalacion,
      cantidadMantenedores: maintainersCount,
      coincidenciaCercana: cercano ? cercano.paquete : null
    },
    hallazgos: findings,
    nota: 'Esto revisa metadatos públicos del registro de npm (antigüedad, historial de versiones, similitud de nombre con paquetes muy populares, scripts de instalación automática) — no analiza el código del paquete línea por línea. No sustituye una auditoría de seguridad formal.'
  };
}

module.exports = {
  checkPackageAuthenticity: checkPackageAuthenticity,
  ECOSISTEMAS_SOPORTADOS: ECOSISTEMAS_SOPORTADOS,
  PAQUETES_POPULARES_NPM: PAQUETES_POPULARES_NPM,
  distanciaLevenshtein: distanciaLevenshtein,
  coincidenciaCercana: coincidenciaCercana
};
