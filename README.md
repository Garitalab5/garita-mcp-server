# Garita MCP — servidor remoto

Esto convierte a Garita MCP de "una página que un humano abre" a "algo que un agente de IA puede llamar directamente". Expone siete herramientas que cualquier cliente MCP puede invocar:

- **`audit_mcp_server`** — audita el manifiesto de un servidor MCP (mismo motor probado en `garita-mcp.html`, Versión 4, después de 3 rondas de ataques) y devuelve un puntaje de 0 a 100.
- **`simulate_approval`** — decide si una acción de un agente debería auto-aprobarse o quedar retenida para revisión humana.
- **`detect_poisoned_tool_descriptions`** (Garita Escudo) — analiza el texto de la(s) descripción(es) de una herramienta MCP en busca de instrucciones escondidas o inyectadas (caracteres invisibles, esteganografía Unicode, homoglifos, entidades HTML en capas, pseudo-instrucciones ocultas, instrucciones para ocultar la acción al usuario, manipular otra herramienta, redirigir datos, o activarse recién después de la aprobación combinada con acceso a credenciales/SSH). Es el mismo motor probado en `garita-tools/garita-escudo/tool.html` (Versión 4, 4 rondas de ataques), portado a Node (`lib/escudo.js`) — mismas reglas, mismo orden de decodificación, mismo puntaje, solo devuelve JSON en vez de HTML.
- **`check_known_vulnerabilities`** — revisa si un paquete (npm, PyPI, Go, crates.io, Maven, RubyGems, entre otros) tiene vulnerabilidades ya conocidas y publicadas, consultando la base de datos abierta OSV.dev (gratis, sin llave de API). Devuelve cada vulnerabilidad con su CVE oficial (si existe), severidad, fecha y link. A diferencia de las otras, esta depende de un servicio externo (OSV.dev) — si ese servicio falla o no responde, la llamada **no descuenta ningún uso ni crédito** (se revierte automáticamente, ver `lib/vulnerabilidades.js` y `licensing.refundUse`), porque el cliente no recibió ningún resultado real.
- **`detect_tool_rug_pull`** — compara dos versiones del manifiesto de un mismo servidor MCP (la que aprobaste antes y la de ahora) y avisa si el texto de alguna herramienta ya aprobada cambió desde entonces. Detecta el patrón conocido como "MCP Tool Rug-Pull" (catalogado como ATR-2026-00581, OWASP Agentic ASI02/ASI05, MITRE ATLAS AML.T0053/T0051/T0104): una herramienta se ve benigna al aprobarse, pero su descripción se redefine DESPUÉS para meter una instrucción peligrosa. `detect_poisoned_tool_descriptions` revisa una sola foto en el tiempo; esta herramienta revisa si algo cambió desde la última vez — se complementan. Construida en `lib/rugpull.js`, reutiliza el motor de Garita Escudo para analizar lo que cambió.
- **`detect_poisoned_config_files`** — sexta herramienta (2026-09). Analiza archivos de configuración/instrucciones que un agente de código carga y confía DE INMEDIATO, sin ningún paso de aprobación (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, archivos de "skills", y similares) — un canal totalmente distinto al de un manifiesto MCP, que `detect_poisoned_tool_descriptions` nunca mira. Motivada por un caso real de 2026 (Mitiga): un archivo de reglas envenenado exfiltró credenciales de AWS/Kubernetes/Terraform en menos de 2 minutos en una prueba controlada. Reutiliza el motor de Garita Escudo tal cual (`lib/escudo.js`, sin duplicar reglas), pero ajustado a este género de archivo: el lenguaje de autoridad (IMPORTANTE, CRÍTICO) no se penaliza porque es normal ahí, y se agrega una regla nueva sin gatillo temporal ("filtración de credenciales") porque, a diferencia de una herramienta MCP, un archivo de instrucciones no pasa por ningún paso de aprobación. Construida en `lib/config-poison.js`.
- **`check_package_authenticity`** — séptima herramienta (2026-09). Revisa si un paquete (por ahora solo npm) tiene señales de ser un impostor recién publicado en vez de un paquete legítimo: nombre casi idéntico a uno de los paquetes más populares con muy poco historial propio (typosquatting clásico, ej. "loadash" en vez de "lodash"), publicado hace muy poco con un número de versión inicial ya "maduro" (ej. 35.x.y en vez de 0.x/1.x — el patrón documentado en una campaña real de agosto 2026 con 800-1.000+ paquetes maliciosos en npm), un script que se ejecuta solo al instalar (postinstall/preinstall) en un paquete reciente, o ausencia total de repositorio/homepage/README. Motivada por el fenómeno de 2026 conocido como "slopsquatting": un asistente de código con IA a veces alucina el nombre de un paquete que no existe, y hay campañas activas que registran esos nombres alucinados de verdad con malware adentro, apostando a que alguien lo instale sin volver a revisar. Si el paquete no existe en el registro, la herramienta avisa de ese riesgo directamente. Distinta y complementaria a `check_known_vulnerabilities`: esa busca CVEs ya publicados en un paquete probablemente legítimo; esta busca señales de que el paquete en sí es falso, aunque no tenga ningún CVE todavía. Construida en `lib/slopsquatting.js`.

**Las siete herramientas requieren una llave de acceso** (con usos gratis y luego créditos comprados) — ver la sección "Cobro con llave de acceso" más abajo. Las páginas web (`garita-mcp.html`, `garita-escudo/tool.html`) siguen siendo gratis e ilimitadas, esto solo aplica a este servidor.

## Antes de empezar: qué es distinto de la página web

La página web (`garita-mcp.html`) la abre una persona en el navegador y funciona sola, sin nada que mantener corriendo. **Esto es distinto**: es un programa que tiene que quedar encendido todo el tiempo en algún servidor con una dirección pública (una URL), para que otros sistemas lo puedan llamar por internet. Eso implica cosas nuevas que la página no necesitaba:

1. Hay que "publicarlo" en un servicio de hosting (Render, gratis, ver abajo).
2. Necesita una base de datos pequeña para recordar las llaves de acceso y sus créditos entre reinicios (Upstash, gratis, ver abajo).
3. Para cobrar créditos de verdad necesita una cuenta de CoinGate (la misma que ya elegiste para Garita Labs).
4. Vas a necesitar cuentas de GitHub, Render, Upstash y CoinGate — todas tienen plan gratis y ninguna pide tarjeta de crédito para lo que necesitamos, excepto CoinGate cuando actives el modo real (no el de pruebas).

## Paso a paso para publicarlo (usando Render, gratis, sin tarjeta)

**1. Crea una cuenta de GitHub** (si no tienes una ya): entra a github.com, "Sign up", sigue los pasos con tu correo.

**2. Sube esta carpeta a un repositorio nuevo:**
   - En github.com, dale a "New repository" (botón verde).
   - Ponle un nombre, por ejemplo `garita-mcp-server`. Puede ser privado o público, no importa.
   - Sigue las instrucciones de GitHub para "upload existing files" (subir archivos existentes) y arrastra ahí todos los archivos de esta carpeta (`server.js`, `package.json`, la carpeta `lib/`, este `README.md`, y el `.gitignore` — **no** subas la carpeta `node_modules` si la ves, no hace falta; tampoco hace falta subir los `test-*.js`, aunque no pasa nada si los subes).

**3. Crea una cuenta en Render:** entra a render.com, "Get Started", puedes registrarte con tu cuenta de GitHub directamente (más fácil, un solo clic).

**4. Crea el servicio:**
   - En el panel de Render, "New +" → "Web Service".
   - Conecta el repositorio `garita-mcp-server` que acabas de subir.
   - Render va a detectar que es Node.js solo. Déjalo con los valores que proponga (Build command: `npm install`, Start command: `npm start`).
   - Elige el plan **Free**.
   - **Todavía no le des a "Create Web Service"** — primero baja a la sección "Environment Variables" en esta misma pantalla y sigue el siguiente paso, para que arranque ya configurado.

## Cobro con llave de acceso (usos gratis + créditos comprados)

Cada cliente recibe una **llave de acceso** (un texto largo que empieza con `gar_`). Las primeras **5 llamadas son gratis** por llave — de una sola vez, nunca se renuevan — y después de eso, cada llamada a cualquiera de las siete herramientas (`audit_mcp_server`, `simulate_approval`, `detect_poisoned_tool_descriptions`, `check_known_vulnerabilities`, `detect_tool_rug_pull`, `detect_poisoned_config_files`, `check_package_authenticity`) consume un crédito. Cuando se acaban los créditos, el servidor responde con un mensaje explicando cómo comprar más — nunca deja pasar una llamada sin cobrar cuando corresponde. Excepción: si `check_known_vulnerabilities` o `check_package_authenticity` fallan porque el servicio externo que consultan (OSV.dev o el registro de npm) no respondió, ese uso/crédito se devuelve solo — no es justo cobrarle al cliente por una falla que no es suya.

Aparte de eso hay un **tope diario de 50 llamadas por llave** (constante `DAILY_CALL_LIMIT` en `lib/licensing.js`, fácil de subir o bajar), que aplica **incluso si la llave tiene créditos de sobra** — es una protección aparte, pensada para que un agente con un error en bucle no se gaste de golpe todos los créditos comprados en minutos. Se resetea solo cada día, sin que tengas que hacer nada.

El **paquete empresarial** (ver tabla de paquetes abajo) es la excepción: además de sumar créditos, marca la llave para siempre como exenta de ese tope diario (`unlimitedDaily`, en `lib/licensing.js`) — pensado para un cliente cuyos agentes llaman las herramientas en volumen alto y constante, donde el tope de 50/día se volvería una limitación real del negocio en vez de una protección contra abuso. Una vez otorgado, no hay forma de quitarlo desde el código (ni siquiera si después se le acaban los créditos) — solo se otorga comprando ese paquete, o a mano desde Upstash (ver más abajo).

Esto necesita dos cosas configuradas en el servidor: un lugar donde recordar las llaves y sus créditos (Upstash), y la conexión con CoinGate para procesar los pagos.

### 5. Crea una base de datos gratis en Upstash (para recordar las llaves y créditos)

Sin esto, el servidor "olvida" todas las llaves y créditos cada vez que se reinicia o se duerme — inaceptable para cobrar de verdad, así que este paso no es opcional.

1. Entra a [upstash.com](https://upstash.com) y crea una cuenta gratis (puedes usar tu cuenta de GitHub).
2. En el panel, crea una base de datos nueva: "Create Database" → dale un nombre (ej. `garita-licencias`) → tipo **Redis** → elige la región más cercana a donde esté tu servidor de Render → plan **Free**.
3. Dentro de la base de datos ya creada, busca la sección "REST API" (o "Connect" → "REST API"). Ahí vas a ver dos valores que necesitas copiar:
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`

### 6. Crea tu cuenta de CoinGate y saca el token de la API

Si ya tienes cuenta de CoinGate de cuando la elegimos para Garita Labs, puedes reusarla.

1. Para probar primero SIN dinero real: crea una cuenta en [sandbox.coingate.com](https://sandbox.coingate.com) (es una copia de pruebas, separada de la cuenta real).
2. En el panel de esa cuenta, busca "API Apps" o "Integrations" → crea una App nueva → ahí te da un **API Token**. Ese es tu `COINGATE_API_TOKEN` de pruebas.
3. Cuando quieras cobrar dinero real, repite el mismo proceso pero en [coingate.com](https://coingate.com) (cuenta real, verificación de identidad incluida) y usa ese otro token en su lugar — son dos cuentas y dos tokens completamente separados, no se mezclan.
4. En esa misma App, en la configuración de "Callbacks" o "Webhooks", asegúrate de que el formato esté puesto en **JSON** (no form-encoded) — el servidor espera ese formato.

### 7. Configura las variables de entorno en Render

De vuelta en la pantalla de creación del servicio en Render (o en "Environment" si ya lo creaste), agrega estas variables:

| Variable | Valor |
|---|---|
| `UPSTASH_REDIS_REST_URL` | el que copiaste de Upstash |
| `UPSTASH_REDIS_REST_TOKEN` | el que copiaste de Upstash |
| `COINGATE_API_TOKEN` | el token de tu App de CoinGate (sandbox al probar, real cuando ya quieras cobrar de verdad) |
| `COINGATE_ENV` | `sandbox` mientras pruebas, `live` cuando ya cobres de verdad |
| `PUBLIC_BASE_URL` | la URL pública que te va a dar Render, ej. `https://garita-mcp-server.onrender.com` (si no la sabes todavía, puedes dejarla vacía y agregarla después de que Render te dé la URL — sin esta variable el servidor adivina la URL sola, pero es más confiable ponerla a mano) |

Dale a "Create Web Service" (o guarda las variables si ya lo habías creado — Render lo reinicia solo).

**8. Espera unos minutos.** Cuando termine, te va a dar una URL parecida a `https://garita-mcp-server.onrender.com`. Si pusiste `PUBLIC_BASE_URL` antes de saber la URL final, entra otra vez a "Environment" y corrígela para que coincida exactamente, luego guarda (Render se reinicia solo).

**9. Prueba que funciona:** abre esa URL en el navegador — deberías ver la lista de endpoints. Si ves eso, ya está publicado.

### Paquetes de créditos y precios

Definidos en `lib/coingate.js`, se pueden ajustar ahí cuando quieras:

| Paquete | Créditos | Precio | Extra |
|---|---|---|---|
| `basico` | 50 usos | 5 USD | |
| `pro` | 300 usos | 25 USD | |
| `empresarial` | 5.000 usos | 300 USD | quita el tope diario de 50 usos/día para siempre en esa llave |

CoinGate cobra su comisión (1%) sobre el precio — no está restada en la tabla de arriba, es lo que paga el cliente.

### Cómo consigue un cliente su llave y compra créditos

1. **Conseguir una llave gratis:** `POST https://tu-servidor.onrender.com/crear-llave` (sin cuerpo). Devuelve la llave y le avisa que la guarde — no se puede recuperar después si la pierde (tocaría crear una nueva, empezando de cero con otros 5 usos gratis).
2. **Usarla:** al conectar el servidor MCP, manda el header `Authorization: Bearer gar_...` con esa llave.
3. **Consultar cuánto le queda:** `GET https://tu-servidor.onrender.com/consultar-llave?apiKey=gar_...` — devuelve usos gratis, créditos, y cuántos usos lleva hoy contra el tope diario.
4. **Comprar créditos cuando se acaben:** `POST https://tu-servidor.onrender.com/comprar-creditos` con cuerpo `{ "apiKey": "gar_...", "pack": "basico" }` (o `"pro"`, o `"empresarial"` para quitar además el tope diario). Devuelve un `payment_url` de CoinGate (el cliente paga ahí, con cripto) y un `orderId` — en cuanto CoinGate confirma el pago, el servidor acredita los créditos solo, sin que tengas que hacer nada manualmente.

### Si el pago tarda en confirmarse

Con cripto es normal que la confirmación tarde — desde un par de minutos hasta más, según qué tan congestionada esté la red de esa moneda en ese momento. Eso no es un error de nada: mientras tanto, la llave sigue sin créditos hasta que se confirme.

CoinGate avisa solo en cuanto se confirma (el webhook), y si por lo que sea nuestro servidor no llega a recibir ese aviso a la primera (por ejemplo, si Render estaba "dormido" en el plan gratis), CoinGate reintenta avisar automáticamente durante varios días — así que casi nunca debería perderse un pago confirmado.

Si un cliente escribe preguntando "ya pagué, ¿por qué no me llegaron los créditos?", puedes revisar el estado real en el momento (sin esperar el próximo reintento) con: `GET https://tu-servidor.onrender.com/verificar-pago?orderId=EL_ORDERID_QUE_DEVOLVIÓ_/comprar-creditos`. Si CoinGate ya confirmó el pago, esto lo acredita ahí mismo; si todavía está "confirmando", te lo dice y no hace falta hacer nada más que esperar.

### Emitir una llave a mano (por ejemplo, para un cliente que te escribió directo)

Si quieres regalarle créditos a alguien sin pasar por CoinGate (una cortesía, una prueba extendida), puedes hacerlo llamando directamente a la base de datos de Upstash desde su panel web (pestaña "Data Browser" o "CLI"), con el comando:

```
SET garita:key:gar_LO-QUE-SEA {"freeUsesRemaining":0,"credits":100,"createdAt":"2026-01-01T00:00:00.000Z"}
```

(cambia `gar_LO-QUE-SEA` por una llave que tú inventes y le mandes al cliente, y `100` por los créditos que quieras regalarle). Para regalar también la condición "empresarial" (sin tope diario), agrega `"unlimitedDaily":true` al mismo JSON.

## Cómo lo conecta un agente

Cualquier cliente MCP (Claude, u otro) se conecta agregando esta URL como un "servidor MCP remoto" (a veces llamado "conector"), apuntando a `https://tu-servicio.onrender.com/mcp`, **mandando el header `Authorization: Bearer <llave>`** con una llave conseguida en `/crear-llave`. Una vez conectado, el agente ve las siete herramientas (`audit_mcp_server`, `simulate_approval`, `detect_poisoned_tool_descriptions`, `check_known_vulnerabilities`, `detect_tool_rug_pull`, `detect_poisoned_config_files` y `check_package_authenticity`) y las puede llamar solo, sin que una persona abra nada — cada llamada consume un uso gratis o un crédito automáticamente, y el propio mensaje de error le explica al agente (o a quien lo esté configurando) cómo conseguir más si se acaban.

## Una cosa a tener en cuenta con el plan gratis de Render

El plan gratis de Render "duerme" el servicio después de 15 minutos sin uso, y tarda como un minuto en despertar cuando llega la próxima llamada. Para un uso moderado está perfectamente bien; si esto se vuelve algo que se usa todo el tiempo, ahí sí conviene pasar a un plan pago para que no "duerma".

## Probar todo localmente antes de subirlo (opcional, para verificar cambios)

```
npm install
node server.js
```

Sin las variables de Upstash configuradas, el servidor arranca en un **modo de memoria** (avisa con una advertencia bien visible) — sirve para probar el flujo completo sin gastar nada, pero se le olvida todo al reiniciarse. Con el servidor corriendo:

- `node test-heuristics.js` — prueba el motor de reglas en sí (sin servidor). Incluye la ronda 5 de ataques (2026-09), propia de este puerto a servidor: notación científica como string, lista de invisibles ampliada, y `destructiveHint: false` mintiendo sobre una herramienta destructiva.
- `node test-licensing.js` — prueba el ciclo completo de una llave: usos gratis, agotamiento, tope diario, compra simulada, webhook, créditos, sin llamar a CoinGate de verdad.
- `node test-verificar-pago.js` — prueba el respaldo manual de `/verificar-pago` (pago que tarda, se confirma después, y no se duplica), simulando las respuestas de CoinGate sin llamarlo de verdad.
- `node test-client.js` — se conecta como lo haría un agente real: pide una llave, llama las dos herramientas, y agota los usos gratis para ver el mensaje de "compra más créditos".
- `node test-escudo.js` — prueba el motor de Garita Escudo (sin servidor), reutilizando los casos de las 4 rondas de ataques ya hechas contra la versión de navegador, más una 5ª ronda (2026-09) contra la regla `gatillo_diferido`: exfiltración con curl/wget sin tubería y scp/rsync a host remoto, y dos frases-gatillo en español que faltaban.
- `node test-vulnerabilidades.js` — prueba el parseo de respuestas de OSV.dev (severidad, CVE, orden, truncado, errores) con un fetch simulado — no depende de tener salida a internet ni de que el contenido de OSV.dev no cambie. Incluye una ronda de ataques de robustez (2026-09): registros malformados que antes reventaban la herramienta entera, y topes de tamaño en el resumen y en la cantidad de resultados.
- `node test-rugpull.js` — prueba el detector de rug-pull: ataque real (instrucción diferida + ssh/exfiltración), cambio benigno de redacción, sin cambios, herramienta nueva, herramienta eliminada, un caso mixto con las cuatro categorías a la vez, y una ronda de ataques (2026-09) contra su propia lógica de comparación: renombrar la herramienta comprometida entre revisiones, y un nombre de herramienta duplicado en el manifiesto.
- `node test-config-poison.js` — prueba el detector de archivos de configuración/instrucciones envenenados (sexta herramienta, 2026-09): verifica que el lenguaje de autoridad NO se penalice en este género de archivo, que la regla nueva de filtración de credenciales dispare sin necesitar gatillo temporal (en ambos órdenes, y con pronombres enclíticos en español — "léelo y envíalo" — encontrado como evasión real durante la construcción y ya corregido), que una instrucción defensiva en español ("nunca lo muestres") NO dispare por la diferencia de conjugación, documenta como límite conocido que la misma defensa en inglés SÍ puede disparar un falso positivo, y confirma que el resto del motor de Garita Escudo (invisibles, homoglifos, etiquetas ocultas, gatillo diferido) se reutiliza tal cual dentro de este archivo.
- `node test-slopsquatting.js` — prueba el verificador de autenticidad de paquetes (séptima herramienta, 2026-09): paquete inexistente (avisa de alucinación + riesgo de squat futuro), typosquat clásico (nombre a 1 edición de un paquete popular con poco historial, con su control de que un nombre parecido pero YA establecido no se marca), el patrón de "slopsquatting" documentado en 2026 (recién publicado + versión inicial anómala tipo 35.x.y, con su control de que un paquete nuevo con versión 0.x/1.x normal no dispara la regla fuerte), script de instalación automática en un paquete reciente (con su control de que el mismo script en un paquete viejo no se penaliza), y ausencia total de repositorio/homepage/README. La mayoría usa un fetch simulado del registro de npm; un puñado de casos confirmados aparte contra la API real (`left-pad`, `chalkk`, `loadash` — este entorno sí tiene salida a `registry.npmjs.org`, a diferencia de `api.osv.dev`).

Las cuatro rondas "2026-09" de arriba están documentadas con más detalle (hallazgo por hallazgo, con ejemplos de antes/después) en la ficha técnica que resume esa ronda de ataques. La séptima herramienta (`check_package_authenticity`) es posterior a esa ficha y no está incluida ahí — su diseño y pruebas quedan documentados en este README y en `lib/slopsquatting.js`/`test-slopsquatting.js`.

## Si algo se corrige más adelante en garita-mcp.html

Ojo: este servidor **no comparte código en vivo** con la página publicada como Artifact — son dos copias separadas del mismo motor. Si en una sesión futura se encuentra y corrige otra falla en `garita-mcp.html`, hay que traer ese mismo arreglo aquí, a `lib/heuristics.js`, y volver a publicar (basta con subir el archivo corregido a GitHub — Render vuelve a desplegar solo).

## Sobre Garita Escudo

Garita Escudo ya tiene su propia herramienta dentro de este servidor (`detect_poisoned_tool_descriptions`, ver arriba) — no hace falta un servidor aparte. La página web (`garita-escudo/tool.html`) sigue existiendo también, gratis e ilimitada, como una segunda forma de usar el mismo motor sin pasar por el servidor MCP.
