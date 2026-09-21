"use strict";
// Garita MCP — detector de "rug-pull" (redefinición de herramientas tras la
// aprobación)
// =============================================================================
// Quinta herramienta de Garita Labs. Problema que resuelve (investigación de
// mercado, 2026-09): Garita Escudo revisa el texto de una herramienta en UN
// SOLO momento — pero el patrón de ataque documentado como "MCP Tool
// Rug-Pull" (catalogado como ATR-2026-00581, OWASP Agentic ASI02/ASI05,
// MITRE ATLAS AML.T0053/T0051/T0104) no depende de que el texto sea
// sospechoso desde el principio: una herramienta se aprueba viéndose
// benigna, y su definición cambia DESPUÉS (en una actualización, en la
// siguiente carga) para meter la instrucción peligrosa. Un escaneo estático
// de una sola foto no lo detecta — hace falta comparar "cómo era" contra
// "cómo es ahora".
//
// Esta herramienta recibe dos manifiestos del mismo servidor MCP — uno
// anterior (la versión que se aprobó/revisó la vez pasada) y uno actual — y
// para cada herramienta que existe en ambos, revisa si su texto cambió. Si
// cambió, analiza el texto NUEVO con el mismo motor de Garita Escudo
// (incluida la regla nueva 'gatillo_diferido' pensada justo para este
// patrón) para decidir si el cambio es solo cosmético o es una señal real
// de rug-pull.
//
// No reemplaza a detect_poisoned_tool_descriptions (que revisa un
// manifiesto en un solo momento) — lo complementa: úsalos juntos, esta
// herramienta para "¿algo cambió desde la última vez que confié en esto?".

const escudo = require('./escudo');

function nombreDe(tool, idx) {
  return (tool && tool.name) || ('herramienta_' + (idx + 1));
}

// De un manifiesto (mismo formato aceptado por Garita Escudo/Auditor:
// {tools:[...]}, un arreglo, o una sola herramienta suelta) construye un
// mapa nombre -> { texto, truncado, tool } para poder comparar por nombre.
// También devuelve, por separado, cualquier nombre que aparezca MÁS DE UNA
// VEZ en el manifiesto (ver "ronda 5" más abajo).
function mapaDeHerramientas(manifest) {
  if (manifest === undefined || manifest === null) {
    throw new Error('Falta el manifiesto.');
  }
  var data = manifest;
  var tools = Array.isArray(data) ? data : (data.tools || (data.name || data.description ? [data] : []));
  if (!tools.length) {
    throw new Error('El manifiesto no tiene un arreglo "tools", ni es una herramienta suelta con "name"/"description".');
  }
  var mapa = new Map();
  var porNombre = new Map();
  tools.forEach(function (rawTool, idx) {
    var tool = escudo.normalizeToolEntry(rawTool);
    var nombre = nombreDe(tool, idx);
    var ct = escudo.collectToolText(tool);
    var entrada = { texto: ct.text, truncado: ct.truncated, tool: tool };
    // OJO (ronda 5, 2026-09): si dos herramientas del mismo manifiesto
    // comparten nombre, se sigue comparando solo contra la ÚLTIMA (igual
    // que antes) por compatibilidad con el resto de esta función — pero
    // ahora TAMBIÉN se guardan todas las copias en "porNombre" para poder
    // analizarlas y avisar del nombre repetido. Guardar solo la última sin
    // más escondía por completo una copia anterior maliciosa: si la última
    // copia coincidía con la versión aprobada, el hallazgo se reportaba
    // como "sin cambios" a pesar de que el manifiesto sí traía una versión
    // peligrosa con ese mismo nombre ("tool shadowing" — un cliente MCP
    // real puede invocar cualquiera de las copias, no necesariamente la
    // última listada).
    if (!porNombre.has(nombre)) porNombre.set(nombre, []);
    porNombre.get(nombre).push(entrada);
    mapa.set(nombre, entrada);
  });
  var duplicados = new Map();
  porNombre.forEach(function (entradas, nombre) {
    if (entradas.length > 1) duplicados.set(nombre, entradas);
  });
  return { mapa: mapa, duplicados: duplicados };
}

function resumenCorto(texto, len) {
  len = len || 160;
  var t = String(texto || '').replace(/\s+/g, ' ').trim();
  return t.length > len ? t.slice(0, len) + '…' : t;
}

// Reglas de Garita Escudo cuya presencia hace que un texto NUEVO (sin
// versión anterior con la cual compararlo, o una copia duplicada) se trate
// con la misma alarma que un rug-pull confirmado — mismo criterio ya usado
// para "cambiadas".
var RUG_PULL_IDS = ['gatillo_diferido', 'ocultamiento', 'redireccion', 'manipulacion_cruzada', 'meta_decodificar'];
function esSospechosoDeRugPull(firedIds) {
  return firedIds.some(function (id) { return RUG_PULL_IDS.indexOf(id) !== -1; });
}

// input: { anterior: manifest, actual: manifest }
function detectToolRugPull(input) {
  input = input || {};
  if (input.anterior === undefined || input.anterior === null || input.actual === undefined || input.actual === null) {
    throw new Error('Debes enviar "anterior" (el manifiesto que aprobaste/revisaste antes) y "actual" (el manifiesto de ahora), ambos con contenido.');
  }

  var resAnterior = mapaDeHerramientas(input.anterior);
  var resActual = mapaDeHerramientas(input.actual);
  var mapaAnterior = resAnterior.mapa;
  var mapaActual = resActual.mapa;

  var nuevas = [];
  var eliminadas = [];
  var cambiadas = [];
  var sinCambios = 0;

  mapaActual.forEach(function (actualEntry, nombre) {
    var anteriorEntry = mapaAnterior.get(nombre);

    if (!anteriorEntry) {
      // Herramienta nueva desde la última revisión: no es un "rug-pull" por
      // definición (no había nada previo que comparar), pero de todas
      // formas vale la pena revisarla — es una herramienta sin revisar
      // todavía. Se analiza con el mismo motor de Escudo.
      var analisisNueva = escudo.analyzeText(nombre, actualEntry.texto, { schemaTruncated: actualEntry.truncado });
      var bNueva = escudo.bucket(100 - analisisNueva.deduction * 1.1);
      // OJO (ronda 5, 2026-09): un ataque real y de costo casi nulo es
      // renombrar la herramienta comprometida entre una revisión y otra —
      // así "desaparece" (va a "eliminadas") y "aparece" una nueva (va
      // aquí, a "nuevas") en vez de a "cambiadas", que es la única
      // categoría que antes alimentaba la alarma de nivel superior
      // ("Posible rug-pull"). Ahora una herramienta nueva con las mismas
      // señales de riesgo que definen un rug-pull también dispara esa
      // alarma — ver "riesgoAlto" más abajo.
      var esNuevaSospechosa = esSospechosoDeRugPull(analisisNueva.firedIds);
      nuevas.push({
        nombre: nombre,
        veredicto: bNueva.label,
        riesgoAlto: esNuevaSospechosa,
        nota: esNuevaSospechosa
          ? 'Herramienta nueva desde la última revisión Y con señales de riesgo del mismo tipo que un rug-pull (gatillo diferido, ocultamiento, redirección, etc.) — revisar antes de confiar en ella. No es un "rug-pull" en sentido estricto (no había una versión anterior con la cual compararla), pero el efecto práctico es el mismo, y un simple cambio de nombre entre revisiones produce justamente este caso.'
          : 'Herramienta nueva desde la última revisión — no había una versión anterior con la cual compararla. Revisada igual con el motor de Garita Escudo.',
        hallazgos: analisisNueva.findings.map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
      });
      return;
    }

    if (anteriorEntry.texto === actualEntry.texto) {
      sinCambios++;
      return;
    }

    // El texto cambió: se analiza la versión NUEVA (incluye la regla
    // 'gatillo_diferido' pensada para este patrón) para decidir qué tan
    // grave es el cambio.
    var analisis = escudo.analyzeText(nombre, actualEntry.texto, { schemaTruncated: actualEntry.truncado });
    var esRugPullSospechoso = esSospechosoDeRugPull(analisis.firedIds);
    var b = escudo.bucket(100 - analisis.deduction * 1.1);

    cambiadas.push({
      nombre: nombre,
      severidad: esRugPullSospechoso ? 'critical' : 'warn',
      etiqueta: esRugPullSospechoso
        ? 'La descripción cambió desde la última revisión Y el texto nuevo tiene señales de riesgo — posible rug-pull, revisar antes de seguir confiando en esta herramienta.'
        : 'La descripción cambió desde la última revisión (sin señales de riesgo detectadas en el texto nuevo) — confirma que el cambio sea legítimo antes de asumir que sigue siendo la misma herramienta que aprobaste.',
      veredictoTextoNuevo: b.label,
      antes: resumenCorto(anteriorEntry.texto),
      ahora: resumenCorto(actualEntry.texto),
      hallazgosTextoNuevo: analisis.findings
        .filter(function (f) { return f.sev !== 'ok'; })
        .map(function (f) { return { severidad: f.sev, etiqueta: f.label, fragmento: f.snippet }; })
    });
  });

  mapaAnterior.forEach(function (_entry, nombre) {
    if (!mapaActual.has(nombre)) {
      eliminadas.push({ nombre: nombre, nota: 'Ya no aparece en el manifiesto actual.' });
    }
  });

  // Nombres repetidos en el manifiesto ACTUAL (ver el comentario en
  // mapaDeHerramientas): se analizan TODAS las copias, no solo la que
  // "ganó" en el mapa, y se avisa del nombre ambiguo en sí aunque ninguna
  // copia individual dispare una regla de riesgo.
  var nombresDuplicados = [];
  resActual.duplicados.forEach(function (entradas, nombre) {
    var huboRiesgo = false;
    entradas.forEach(function (e) {
      var a = escudo.analyzeText(nombre, e.texto, { schemaTruncated: e.truncado });
      if (esSospechosoDeRugPull(a.firedIds)) huboRiesgo = true;
    });
    nombresDuplicados.push({
      nombre: nombre,
      veces: entradas.length,
      severidad: huboRiesgo ? 'critical' : 'warn',
      nota: huboRiesgo
        ? 'La herramienta "' + nombre + '" aparece ' + entradas.length + ' veces en el manifiesto actual con textos distintos, y AL MENOS UNA copia tiene señales de riesgo tipo rug-pull. Este análisis compara solo la última copia listada contra la versión anterior — un cliente MCP real podría invocar cualquiera de las copias ("tool shadowing"), incluida la peligrosa.'
        : 'La herramienta "' + nombre + '" aparece ' + entradas.length + ' veces en el manifiesto actual — nombre ambiguo. Ningún servidor MCP bien formado debería declarar el mismo nombre de herramienta más de una vez; revisa por qué pasa esto aunque ninguna copia muestre señales de riesgo por sí sola.'
    });
  });

  // Orden: primero las cambiadas críticas (lo más accionable), luego el
  // resto de cambiadas.
  cambiadas.sort(function (a, b) {
    return (b.severidad === 'critical' ? 1 : 0) - (a.severidad === 'critical' ? 1 : 0);
  });

  var huboRugPullSospechoso = cambiadas.some(function (c) { return c.severidad === 'critical'; });
  var huboNuevaDeAltoRiesgo = nuevas.some(function (n) { return n.riesgoAlto; });
  var huboDuplicadoDeAltoRiesgo = nombresDuplicados.some(function (d) { return d.severidad === 'critical'; });

  var veredicto;
  if (huboRugPullSospechoso) {
    veredicto = 'Posible rug-pull: al menos una herramienta cambió de descripción Y el texto nuevo tiene señales de riesgo.';
  } else if (huboNuevaDeAltoRiesgo) {
    veredicto = 'Alerta: al menos una herramienta NUEVA desde la última revisión tiene señales de riesgo del mismo tipo que un rug-pull — revisar antes de confiar en ella (un simple cambio de nombre entre revisiones produce exactamente este caso).';
  } else if (huboDuplicadoDeAltoRiesgo) {
    veredicto = 'Alerta: el manifiesto actual repite el nombre de al menos una herramienta y una de las copias tiene señales de riesgo — un cliente MCP real podría invocar la copia peligrosa en vez de la que se comparó aquí.';
  } else if (cambiadas.length) {
    veredicto = 'Hubo cambios sin señales de riesgo detectadas, pero cualquier cambio en una herramienta ya aprobada merece revisión manual.';
  } else {
    veredicto = 'Sin cambios sospechosos — las herramientas que existían en ambas versiones tienen el mismo texto.';
  }

  return {
    totalHerramientasAntes: mapaAnterior.size,
    totalHerramientasAhora: mapaActual.size,
    sinCambios: sinCambios,
    veredicto: veredicto,
    resumen: 'De ' + mapaActual.size + ' herramienta(s) en la versión actual: ' + sinCambios + ' sin cambios, ' + cambiadas.length + ' cambiada(s), ' + nuevas.length + ' nueva(s) desde la última revisión' + (eliminadas.length ? ', ' + eliminadas.length + ' eliminada(s).' : '.') + (nombresDuplicados.length ? ' ' + nombresDuplicados.length + ' nombre(s) repetido(s) en el manifiesto actual.' : ''),
    cambiadas: cambiadas,
    nuevas: nuevas,
    eliminadas: eliminadas,
    nombresDuplicados: nombresDuplicados
  };
}

module.exports = { detectToolRugPull: detectToolRugPull };
