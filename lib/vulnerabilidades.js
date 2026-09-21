"use strict";
// Garita MCP — verificador de vulnerabilidades conocidas (CVEs)
// =================================================================
// Cuarta herramienta de Garita Labs: dado un paquete (ej. de npm, PyPI,
// Go, etc.) revisa si tiene vulnerabilidades conocidas y publicadas,
// consultando OSV.dev (Open Source Vulnerabilities — proyecto de Google,
// gratis, sin llave de API, base de datos abierta que agrega CVEs de GitHub
// Advisory Database, PyPA, Go, npm, RustSec y más).
//
// Motivación (investigación de mercado, 2026-09): se documentaron 30+ CVEs
// en servidores/paquetes del ecosistema MCP en una ventana de 60 días,
// incluyendo casos con cientos de miles de instalaciones afectadas
// (ej. mcp-remote, CVE-2025-6514). La idea de esta herramienta es la misma
// que las otras tres de Garita: "antes de confiar en algo, revísalo" — acá
// aplicado a si el PAQUETE en sí (no la descripción de sus herramientas)
// tiene una falla de seguridad ya conocida y publicada.
//
// Referencia de la API: https://google.github.io/osv.dev/post-v1-query/
// (consultada el 2026-09-18). Endpoint público, sin autenticación, sin
// límite de tasa documentado para uso normal.

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

// Ecosistemas más comunes, solo como guía para quien llama la herramienta
// (OSV.dev acepta bastantes más — no se restringe la entrada a esta lista,
// se manda tal cual a la API y ella misma responde vacío si no reconoce el
// ecosistema).
const ECOSISTEMAS_CONOCIDOS = [
  'npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'NuGet', 'RubyGems', 'Packagist', 'Hex', 'Pub'
];

function severidadDe(vuln) {
  // OSV no tiene un único campo de severidad garantizado — se intenta en
  // orden de qué tan específico/confiable es cada uno.
  // OJO (ronda 5, 2026-09): esta función confía en que cada elemento de
  // "severity"/"affected" sea un objeto — un elemento null/no-objeto (una
  // respuesta malformada de OSV.dev, o un espejo/proxy comprometido) hacía
  // que TODA la herramienta reventara con una excepción no controlada, en
  // vez de degradarse con gracia como el resto del código ya hace para
  // fallas de red/HTTP. Ahora se revisa cada elemento antes de leer sus
  // propiedades.
  vuln = vuln || {};
  if (Array.isArray(vuln.severity) && vuln.severity.length) {
    var cvss = vuln.severity.find(function (s) { return s && /CVSS/i.test(s.type || ''); });
    if (cvss && cvss.score) return cvss.score;
    var first = vuln.severity[0];
    return (first && first.score) || null;
  }
  if (vuln.database_specific && vuln.database_specific.severity) {
    return vuln.database_specific.severity;
  }
  if (Array.isArray(vuln.affected)) {
    for (var i = 0; i < vuln.affected.length; i++) {
      var a = vuln.affected[i];
      if (!a) continue;
      var es = a.ecosystem_specific;
      if (es && es.severity) return es.severity;
      var db = a.database_specific;
      if (db && db.severity) return db.severity;
    }
  }
  return null;
}

function cveDe(vuln) {
  // El id principal de OSV a veces es su propio identificador (OSV-2020-744,
  // GHSA-...) y el CVE oficial (si existe) suele venir en "aliases".
  vuln = vuln || {};
  if (/^CVE-/i.test(vuln.id || '')) return vuln.id;
  if (Array.isArray(vuln.aliases)) {
    var cve = vuln.aliases.find(function (a) { return typeof a === 'string' && /^CVE-/i.test(a); });
    if (cve) return cve;
  }
  return null;
}

// Tope al tamaño del resumen de texto libre que devuelve OSV.dev
// (summary/details) — sin este tope, una sola entrada con un campo de
// texto enorme (real o malicioso) se pasaba tal cual al agente que llamó
// la herramienta, sin ningún límite de tamaño.
var RESUMEN_MAX_LEN = 300;
function recortar(str, len) {
  var s = String(str || '');
  return s.length > len ? s.slice(0, len) + '…' : s;
}

function resumirVuln(vuln) {
  // Un elemento null/no-objeto dentro de "vulns" (respuesta malformada) ya
  // no revienta la herramienta — pero tampoco se descarta en silencio (eso
  // ocultaría que hubo un registro que no se pudo leer, justo lo contrario
  // de lo que debe hacer una herramienta de seguridad): se reporta como
  // "malformada" para que quede visible.
  if (!vuln || typeof vuln !== 'object') {
    return {
      id: null,
      cve: null,
      resumen: 'Registro de vulnerabilidad malformado devuelto por OSV.dev — no se pudo interpretar, revisar manualmente en osv.dev.',
      severidad: null,
      publicada: null,
      modificada: null,
      link: null,
      malformada: true
    };
  }
  return {
    id: vuln.id || null,
    cve: cveDe(vuln),
    resumen: recortar(vuln.summary || vuln.details || 'Sin resumen disponible.', RESUMEN_MAX_LEN),
    severidad: severidadDe(vuln),
    publicada: vuln.published || null,
    modificada: vuln.modified || null,
    // Sin "id" no hay a qué enlazar — antes esto generaba un link roto
    // terminando en ".../undefined".
    link: vuln.id ? ('https://osv.dev/vulnerability/' + encodeURIComponent(vuln.id)) : null
  };
}

// input: { ecosistema, nombre, version? }
async function checkKnownVulnerabilities(input) {
  input = input || {};
  var ecosistema = String(input.ecosistema || '').trim();
  var nombre = String(input.nombre || '').trim();
  var version = input.version !== undefined && input.version !== null ? String(input.version).trim() : '';

  if (!ecosistema || !nombre) {
    throw new Error('Debes enviar "ecosistema" (ej. "npm", "PyPI", "Go") y "nombre" del paquete.');
  }

  var body = { package: { name: nombre, ecosystem: ecosistema } };
  if (version) body.version = version;

  var res;
  try {
    res = await fetch(OSV_QUERY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  } catch (err) {
    throw new Error('No se pudo contactar la base de datos de vulnerabilidades (OSV.dev): ' + err.message);
  }

  var data = await res.json().catch(function () { return {}; });
  if (!res.ok) {
    throw new Error('OSV.dev rechazó la consulta (' + res.status + '): ' + JSON.stringify(data));
  }

  var vulns = Array.isArray(data.vulns) ? data.vulns : [];
  var resumenes = vulns.map(resumirVuln);
  // Orden: primero las que tienen CVE oficial y severidad, luego el resto —
  // para que lo más accionable aparezca primero.
  resumenes.sort(function (a, b) {
    var pa = (a.cve ? 2 : 0) + (a.severidad ? 1 : 0);
    var pb = (b.cve ? 2 : 0) + (b.severidad ? 1 : 0);
    return pb - pa;
  });

  // OJO (ronda 5, 2026-09): sin un tope, una respuesta con una cantidad
  // desproporcionada de entradas (real, o de un proxy/espejo comprometido)
  // se devolvía completa al agente que llamó la herramienta, sin límite de
  // tamaño. Se recorta a las más accionables (ya ordenadas arriba) y se
  // avisa con un campo aparte de "truncado" (que ya significa otra cosa:
  // que OSV.dev tiene más páginas).
  var RESULTADOS_MAX = 500;
  var demasiadosResultados = resumenes.length > RESULTADOS_MAX;
  if (demasiadosResultados) resumenes = resumenes.slice(0, RESULTADOS_MAX);

  return {
    paquete: nombre,
    ecosistema: ecosistema,
    version: version || null,
    totalEncontradas: vulns.length,
    demasiadosResultados: demasiadosResultados,
    truncado: !!data.next_page_token,
    veredicto: vulns.length === 0
      ? 'Sin vulnerabilidades conocidas publicadas para este paquete/versión en OSV.dev.'
      : 'Se encontraron ' + vulns.length + ' vulnerabilidad(es) conocida(s) publicada(s) para este paquete' + (version ? ' en esta versión' : '') + (demasiadosResultados ? ' (se muestran las primeras ' + RESULTADOS_MAX + ', las más accionables).' : '.'),
    nota: 'Esto solo revisa vulnerabilidades YA publicadas en bases de datos abiertas (GitHub Advisory, PyPA, Go, npm, RustSec, entre otras, vía OSV.dev). No es una auditoría de código ni garantiza que el paquete esté libre de fallas sin descubrir.',
    vulnerabilidades: resumenes
  };
}

module.exports = { checkKnownVulnerabilities: checkKnownVulnerabilities, ECOSISTEMAS_CONOCIDOS: ECOSISTEMAS_CONOCIDOS };
