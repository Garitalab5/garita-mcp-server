"use strict";
// Pruebas para lib/mcp-stdio.js — Escudo de Lanzamiento MCP (STDIO)
// (detect_mcp_stdio_launch_risk).
//
// Correr con: node test-mcp-stdio.js

const assert = require('assert');
const { checkMcpStdioLaunchRisk } = require('./lib/mcp-stdio');

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

test('StdioClientTransport (TS) con "command" dinámico y sin validación -> alto riesgo', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const transport = new StdioClientTransport({
  command: req.body.command,
  args: req.body.args || []
});
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.ok(r.hallazgos.some((h) => /sin ninguna validación/.test(h.etiqueta)));
});

test('StdioServerParameters (Python) con "command" dinámico y sin validación -> alto riesgo', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
server_params = StdioServerParameters(
    command=request.json["command"],
    args=request.json.get("args", [])
)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('propiedad abreviada de JS "{ command, args }" (siempre variable) sin validación -> alto riesgo', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
function makeTransport(command, args) {
  return new StdioClientTransport({ command, args });
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('sink sin ningún campo "command" reconocible cerca -> se trata como riesgo, no se ignora', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const transport = new StdioClientTransport(configArmadoEnOtroLugar);
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('2 construcciones sin validar bajan más el puntaje que 1 sola', () => {
  const uno = checkMcpStdioLaunchRisk({
    codigo: `const t = new StdioClientTransport({ command: req.body.command, args: [] });`
  });
  const dos = checkMcpStdioLaunchRisk({
    codigo: `
const t1 = new StdioClientTransport({ command: req.body.command, args: [] });
const t2 = new StdioClientTransport({ command: req.query.cmd, args: [] });
    `
  });
  assert.ok(dos.puntaje < uno.puntaje);
});

test('REGLA 2: brecha de rehidratación — validación en otra función, lanzamiento viene de configuración ya guardada', () => {
  const relleno = '// relleno de separación '.repeat(80); // > 800 caracteres, para que el lanzamiento no quede "cerca" de la validación
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const ALLOWED_MCP_STDIO_COMMANDS = new Set(['npx', 'uvx', 'python', 'node']);
function createServerConfig(command, args) {
  const base = path.basename(command);
  if (!ALLOWED_MCP_STDIO_COMMANDS.has(base)) throw new Error('comando no permitido');
  db.save({ command, args });
}

${relleno}

async function launchServer(serverId) {
  const storedConfig = await db.get(serverId);
  const transport = new StdioClientTransport({
    command: storedConfig.command,
    args: storedConfig.args
  });
  return transport;
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.ok(r.hallazgos.some((h) => /rehidrataci[oó]n/.test(h.etiqueta)));
});

test('control: el mismo patrón de "config guardada" SIN ninguna validación en el archivo -> riesgo genérico, no "rehidratación"', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
async function launchServer(serverId) {
  const storedConfig = await db.get(serverId);
  const transport = new StdioClientTransport({
    command: storedConfig.command,
    args: storedConfig.args
  });
  return transport;
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.ok(!r.hallazgos.some((h) => /rehidrataci[oó]n/.test(h.etiqueta)));
  assert.ok(r.hallazgos.some((h) => /sin ninguna validación/.test(h.etiqueta)));
});

test('REGLA 3: comando en lista blanca razonable (python) pero con "-c" + argumento dinámico -> alto riesgo', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const transport = new StdioClientTransport({
  command: 'python',
  args: ['-c', codigoRecibidoDelUsuario]
});
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
  assert.ok(r.hallazgos.some((h) => /bandera de ejecución directa/.test(h.etiqueta)));
});

test('control: "python -c" con un script LITERAL (fijo) -> no dispara la regla de la bandera', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const transport = new StdioClientTransport({
  command: 'python',
  args: ['-c', '"print(1)"']
});
    `
  });
  assert.ok(!r.hallazgos.some((h) => /bandera de ejecución directa/.test(h.etiqueta)));
});

test('REGLA 4: comentario que asume que el protocolo MCP "fallaría" protege -> hallazgo extra de falsa seguridad', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
// Nota: no hay problema, si el comando no es un servidor MCP válido, el protocolo MCP fallaría y ya.
const transport = new StdioClientTransport({ command: req.body.command, args: [] });
    `
  });
  assert.ok(r.hallazgos.some((h) => /ya se ejecut[oó]/.test(h.etiqueta)));
});

// ---------- Casos de control (NO deben marcar riesgo) ----------

test('comando fijo (literal) sin ninguna entrada externa -> aceptable', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const transport = new StdioClientTransport({
  command: 'npx',
  args: ['-y', '@official/server']
});
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('comando dinámico pero validado contra una lista blanca por nombre de constante -> aceptable', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
const ALLOWED_MCP_STDIO_COMMANDS = new Set(['npx', 'uvx', 'python', 'node']);
function makeTransport(command, args) {
  const base = path.basename(command);
  if (!ALLOWED_MCP_STDIO_COMMANDS.has(base)) throw new Error('comando no permitido');
  return new StdioClientTransport({ command, args });
}
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('comando dinámico validado con "basename(command) not in <lista>" (Python, en la misma expresión) -> aceptable', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `
def launch(command, args):
    if os.path.basename(command) not in listaPermitida:
        raise ValueError('bloqueado')
    return StdioServerParameters(command=command, args=args)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna construcción de transporte stdio de MCP en el código -> aceptable', () => {
  const r = checkMcpStdioLaunchRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos[0].severidad, 'ok');
});

// ---------- Casos de entrada inválida ----------

test('sin "codigo" -> lanza error', () => {
  assert.throws(() => checkMcpStdioLaunchRisk({}), /codigo/i);
});

test('"codigo" vacío -> lanza error', () => {
  assert.throws(() => checkMcpStdioLaunchRisk({ codigo: '   ' }), /codigo/i);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
process.exit(fail > 0 ? 1 : 0);
