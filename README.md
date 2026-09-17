# Garita MCP — servidor remoto

Esto convierte a Garita MCP de "una página que un humano abre" a "algo que un agente de IA puede llamar directamente". Es el mismo motor de reglas ya probado en `garita-mcp.html` (Versión 4, después de 3 rondas de ataques), expuesto como dos herramientas que cualquier cliente MCP puede invocar:

- **`audit_mcp_server`** — audita el manifiesto de un servidor MCP y devuelve un puntaje de 0 a 100.
- **`simulate_approval`** — decide si una acción de un agente debería auto-aprobarse o quedar retenida para revisión humana.

**Desde esta versión, las dos herramientas requieren una llave de acceso** (con usos gratis y luego créditos comprados) — ver la sección "Cobro con llave de acceso" más abajo. La página web (`garita-mcp.html`) sigue siendo gratis e ilimitada, esto solo aplica a este servidor.

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

Cada cliente recibe una **llave de acceso** (un texto largo que empieza con `gar_`). Las primeras **5 llamadas son gratis** por llave — de una sola vez, nunca se renuevan — y después de eso, cada llamada a `audit_mcp_server` o `simulate_approval` consume un crédito. Cuando se acaban los créditos, el servidor responde con un mensaje explicando cómo comprar más — nunca deja pasar una llamada sin cobrar cuando corresponde.

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

Cualquier cliente MCP (Claude, u otro) se conecta agregando esta URL como un "servidor MCP remoto" (a veces llamado "conector"), apuntando a `https://tu-servicio.onrender.com/mcp`, **mandando el header `Authorization: Bearer <llave>`** con una llave conseguida en `/crear-llave`. Una vez conectado, el agente ve las dos herramientas (`audit_mcp_server` y `simulate_approval`) y las puede llamar solo, sin que una persona abra nada — cada llamada consume un uso gratis o un crédito automáticamente, y el propio mensaje de error le explica al agente (o a quien lo esté configurando) cómo conseguir más si se acaban.

## Una cosa a tener en cuenta con el plan gratis de Render

El plan gratis de Render "duerme" el servicio después de 15 minutos sin uso, y tarda como un minuto en despertar cuando llega la próxima llamada. Para un uso moderado está perfectamente bien; si esto se vuelve algo que se usa todo el tiempo, ahí sí conviene pasar a un plan pago para que no "duerma".

## Probar todo localmente antes de subirlo (opcional, para verificar cambios)

```
npm install
node server.js
```

Sin las variables de Upstash configuradas, el servidor arranca en un **modo de memoria** (avisa con una advertencia bien visible) — sirve para probar el flujo completo sin gastar nada, pero se le olvida todo al reiniciarse. Con el servidor corriendo:

- `node test-heuristics.js` — prueba el motor de reglas en sí (sin servidor).
- `node test-licensing.js` — prueba el ciclo completo de una llave: usos gratis, agotamiento, tope diario, compra simulada, webhook, créditos, sin llamar a CoinGate de verdad.
- `node test-verificar-pago.js` — prueba el respaldo manual de `/verificar-pago` (pago que tarda, se confirma después, y no se duplica), simulando las respuestas de CoinGate sin llamarlo de verdad.
- `node test-client.js` — se conecta como lo haría un agente real: pide una llave, llama las dos herramientas, y agota los usos gratis para ver el mensaje de "compra más créditos".

## Si algo se corrige más adelante en garita-mcp.html

Ojo: este servidor **no comparte código en vivo** con la página publicada como Artifact — son dos copias separadas del mismo motor. Si en una sesión futura se encuentra y corrige otra falla en `garita-mcp.html`, hay que traer ese mismo arreglo aquí, a `lib/heuristics.js`, y volver a publicar (basta con subir el archivo corregido a GitHub — Render vuelve a desplegar solo).

## Sobre Garita Escudo

Garita Escudo (la página que detecta descripciones de herramientas MCP envenenadas) todavía **no** tiene su propio servidor — sigue siendo solo la página web gratuita. El sistema de llaves y créditos de este servidor está pensado para poder sumarle una tercera herramienta el día que Escudo también tenga su servidor propio, sin tener que rehacer nada del cobro.
