"use strict";
// Pruebas para lib/ssti.js — el motor de detect_ssti_risk (inyección en plantillas).
//
// Correr con: node test-ssti.js

const assert = require('assert');
const { checkSsTemplateInjectionRisk } = require('./lib/ssti');

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

test('Flask render_template_string() sobre datos del pedido -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def saludo(request):
    nombre = request.args.get('nombre')
    return render_template_string(nombre)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('Jinja2 Environment().from_string() sobre una plantilla armada por el agente -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def render(tool_input):
    env = Environment()
    tmpl = env.from_string(tool_input)
    return tmpl.render()
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('LangChain PromptTemplate(template=...) con texto que no escribió el desarrollador -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def build_prompt(user_supplied_template):
    prompt = PromptTemplate(input_variables=["input"], template=user_supplied_template)
    return prompt
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('LangChain .from_template() con una variable -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def build(plantilla_dinamica):
    return PromptTemplate.from_template(plantilla_dinamica)
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('EJS ejs.render() sobre una plantilla que llega en el body -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
function render(req, res) {
  var html = ejs.render(req.body.template, { user: req.user });
  res.send(html);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('Handlebars.compile() sobre una variable -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
function render(plantillaDelUsuario, datos) {
  var tmpl = Handlebars.compile(plantillaDelUsuario);
  return tmpl(datos);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('lodash _.template() sobre una variable -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
function render(plantilla, datos) {
  var compiled = _.template(plantilla);
  return compiled(datos);
}
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('concatenación implícita de literales adyacentes de Python (dos strings pegados sin operador) -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def render(tool_input):
    tmpl = Template("Hola " f"{tool_input}, tenés mensajes nuevos.")
    return tmpl.render()
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('PromptTemplate(input_variables=extract_vars(x), template=x) — llamada a función ANTES de template= -> alto riesgo', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def build_prompt(x):
    prompt = PromptTemplate(input_variables=extract_vars(x), template=x)
    return prompt
    `
  });
  assert.strictEqual(r.veredicto, 'Alto riesgo');
});

test('afirmar que "escapar la salida" (autoescape) protege, sin sandbox -> hallazgo adicional y peor puntaje', () => {
  const sinClaim = checkSsTemplateInjectionRisk({
    codigo: `
def render(tool_input):
    env = Environment()
    tmpl = env.from_string(tool_input)
    return tmpl.render()
    `
  });
  const conClaim = checkSsTemplateInjectionRisk({
    codigo: `
# autoescape=True ya nos protege de cualquier problema acá
def render(tool_input):
    env = Environment(autoescape=True)
    tmpl = env.from_string(tool_input)
    return tmpl.render()
    `
  });
  assert.ok(conClaim.puntaje < sinClaim.puntaje, 'la afirmación de "escapar la salida" como defensa debe restar puntos aparte: ' + conClaim.puntaje + ' vs ' + sinClaim.puntaje);
  assert.ok(conClaim.hallazgos.length > sinClaim.hallazgos.length);
});

// ---------- Casos negativos (no deben marcar riesgo) ----------

test('Template() con un texto fijo que escribió el desarrollador (con variables para RELLENAR) -> aceptable', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `tmpl = Template("Hola {{ nombre }}, tenés {{ cantidad }} mensajes nuevos.")`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('Environment sandboxeado (SandboxedEnvironment) con una fuente dinámica -> aceptable', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `
def render(tool_input):
    env = SandboxedEnvironment()
    tmpl = env.from_string(tool_input)
    return tmpl.render()
    `
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('PromptTemplate con texto fijo del desarrollador (placeholders para RELLENAR) -> aceptable', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `prompt = PromptTemplate(input_variables=["input"], template="Respondé la siguiente pregunta: {input}")`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
});

test('sin ninguna compilación de plantilla en el código -> aceptable', () => {
  const r = checkSsTemplateInjectionRisk({
    codigo: `function sumar(a, b) { return a + b; }`
  });
  assert.strictEqual(r.veredicto, 'Aceptable');
  assert.strictEqual(r.hallazgos[0].severidad, 'ok');
});

// ---------- Casos de entrada inválida ----------

test('sin "codigo" -> lanza error', () => {
  assert.throws(() => checkSsTemplateInjectionRisk({}), /codigo/i);
});

test('"codigo" vacío -> lanza error', () => {
  assert.throws(() => checkSsTemplateInjectionRisk({ codigo: '   ' }), /codigo/i);
});

console.log('\n' + pass + ' pasaron, ' + fail + ' fallaron.');
process.exit(fail > 0 ? 1 : 0);
