---
title: Reconocimiento en Bug Bounty con n8n + Claude
date: 2026-10-18 01:24:00 -0500
categories: [BugBounty, Hacking, Automatizacion]
tags: [bugbounty, hacking, automatizacion]
image:
  path: /assets/img/posts/2026-10-18-automation-bug-bounty-n8n.png
  alt: Automation bug bounty n8n
---

En el ecosistema del bug bounty y el pentesting web, el mayor enemigo del hunter no es la complejidad de las defensas de un objetivo, sino el volumen masivo de ruido y datos repetitivos. Lanzar un escáner de reconocimiento (recon) sobre un programa grande suele devolver miles de subdominios, archivos estáticos, rutas de redirección y endpoints basura que consumen horas de análisis antes de encontrar un vector de ataque viable.

Tradicionalmente, este proceso se fragmentaba entre scripts sueltos en Bash, comandos manuales en la terminal y revisiones oculares interminables. Para resolver este problema, se puede implementar un sistema de automatización modular de extremo a extremo utilizando n8n como orquestador central de herramientas como (subfinder, httpx, katana, nuclei) y Claude como motor analítico inteligente.

La filosofía detrás de esta arquitectura se rige por una regla estricta: automatizar el trabajo pesado, el filtrado y la priorización, manteniendo la explotación y la validación final bajo un control humano absoluto.

## 1. Arquitectura General del Flujo de Trabajo

El pipeline está concebido como una máquina de estados controlada por webhooks que procesa la información de forma secuencial y limpia. La estructura se divide en ocho fases clave:

1. Interfaz de Control (Webhook Form): Un panel web corporativo en modo oscuro donde se introducen el dominio objetivo, las reglas de alcance (scope) y los parámetros de severidad.
2. Validación de Alcance (Scope Check): Un filtro de seguridad mediante expresiones regulares que bloquea automáticamente cualquier objetivo fuera del programa autorizado.
3. Reconocimiento Pasivo y Activo (Recon): Descubrimiento encadenado de subdominios, verificación de hosts activos y rastreo profundo de rutas de la aplicación.
4. Procesamiento y Deduplicación: Limpieza de extensiones estáticas irrelevantes (imágenes, fuentes, estilos) para reducir la carga de datos.
5. Análisis Inteligente con IA: Envío de los endpoints estructurados a Claude para identificar rutas críticas con alta probabilidad de fallos (IDORs, APIs expuestas, parámetros de control de acceso).
6. Escaneo Quirúrgico (Security Checks): Ejecución acotada y focalizada de nuclei exclusivamente sobre los objetivos priorizados por la inteligencia artificial.
7. Correlación y Alertas: Filtrado de falsos positivos y envío de notificaciones en tiempo real a Telegram o Slack.
8. Validación Humana y Reporte: Verificación manual del impacto mediante Burp Suite y posterior redacción del informe técnico.

<img width="2043" height="562" alt="Captura de pantalla 2026-10-18 160037" src="https://github.com/user-attachments/assets/4ea0fe33-db6c-4a52-8051-7d177c148f04" />

## 2. Endpoint de Entrada

Para evitar depender de herramientas externas de terceros y mantener el control total de los datos de entrada, el sistema arranca sirviendo un formulario HTML dinámico de alto rendimiento directamente desde un nodo Webhook GET en n8n.
Cuando el usuario pulsa el botón de inicio, los datos viajan mediante una petición POST a un webhook secundario que inicializa la estructura JSON que consumirá el resto de la automatización.

<img width="1825" height="999" alt="Captura de pantalla 2026-10-18 160100" src="https://github.com/user-attachments/assets/23aafe09-ca26-4647-a3b7-02fbcb575f4c" />

Uno de los mayores riesgos al automatizar tareas ofensivas es golpear por error activos que no se encuentran cubiertos por el programa de recompensas. Para mitigar esto, el segundo nodo del flujo es un bloque de código en JavaScript que actúa como un filtro implacable de alcance (scope).

```
const inputItem = $input.first().json;
const data = inputItem.body || inputItem;

const targetDomain = (data.target_domain || '').trim().toLowerCase();
const inScopePattern = (data.in_scope_pattern || '').trim().toLowerCase();
const outOfScopeRaw = data.out_of_scope || '';

if (!targetDomain || !inScopePattern) {
  return [{ json: { is_in_scope: false, reason: "Datos incompletos de target o scope" } }];
}

// Conversión de comodines (*.example.com) a expresiones regulares seguras
const regexPattern = new RegExp(
  '^' + inScopePattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$',
  'i'
);

const matchesScope = regexPattern.test(targetDomain) || targetDomain.endsWith(inScopePattern.replace('*.', ''));
const exclusions = outOfScopeRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const isExcluded = exclusions.some(ex => targetDomain.includes(ex));

const isInScope = matchesScope && !isExcluded;

return [{
  json: {
    is_in_scope: isInScope,
    platform_name: data.platform_name || 'Desconocida',
    target_domain: targetDomain,
    in_scope_pattern: inScopePattern,
    nuclei_severity: data.nuclei_severity || 'critical,high,medium',
    katana_depth: parseInt(data.katana_depth) || 3
  }
}];
```

Un nodo condicional (If) bifurca el camino: si is_in_scope es falso, el flujo se desvía de forma segura hacia un nodo sin operaciones (No Operation), terminando la ejecución de manera limpia. Si es verdadero, arranca la fase ofensiva.

## 4. Orquestación del Reconocimiento

Superado el control de alcance, un nodo de tipo Execute Command se encarga de invocar las herramientas CLI instaladas en el entorno local del servidor:

```
TARGET="{{ $json.target_domain }}"
DEPTH="{{ $json.katana_depth }}"
WORK_DIR="/tmp/recon_${TARGET}"

mkdir -p $WORK_DIR

subfinder -d $TARGET -silent -o$WORK_DIR/subdomains.txt
httpx -l $WORK_DIR/subdomains.txt -silent -mc 200,301,302,403 -json -o$WORK_DIR/httpx.json
katana -list $WORK_DIR/subdomains.txt -silent -jc -d $DEPTH -json -o$WORK_DIR/katana.json
cat $WORK_DIR/httpx.json $WORK_DIR/katana.json
```

Las herramientas de crawling como Katana devuelven miles de registros que incluyen hojas de estilo, imágenes, fuentes tipográficas y scripts de terceros que no contienen lógica vulnerable. Para evitar saturar a la inteligencia artificial con información inútil, un nodo de procesamiento posterior filtra todas las extensiones estáticas y normaliza las URLs:

```
const items = $input.all();
const uniqueEndpoints = new Map();
const staticExtensions = /\.(css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|pdf|zip|tar|gz)$/i;

for (const item of items) {
  let line = item.json.stdout || item.json;
  if (typeof line === 'string') {
    line.split('\n').forEach(rawRow => {
      if (!rawRow.trim()) return;
      try {
        const parsedData = JSON.parse(rawRow);
        processEntry(parsedData);
      } catch (e) {}
    });
  } else {
    processEntry(line);
  }
}

function processEntry(entry) {
  const rawUrl = entry.url || entry.endpoint;
  if (!rawUrl || staticExtensions.test(rawUrl)) return;

  try {
    const parsedUrl = new URL(rawUrl);
    const cleanUrl = `${parsedUrl.origin}${parsedUrl.pathname}`;

    if (!uniqueEndpoints.has(cleanUrl)) {
      uniqueEndpoints.set(cleanUrl, {
        url: cleanUrl,
        method: entry.method || 'GET',
        status_code: entry.status_code || entry.status || 200,
        tech: entry.tech || entry.technologies || []
      });
    }
  } catch (e) {}
}

return Array.from(uniqueEndpoints.values()).map(endpoint => ({ json: endpoint }));
```

## 5. Análisis Inteligente y Priorización

En lugar de aplicar reglas estáticas de fuerza bruta, integramos Claude para actuar como un analista de seguridad experto. Gracias a su amplia ventana de contexto, el modelo puede procesar listados extensos de endpoints limpios y evaluar su contexto arquitectónico.

Configuramos el nodo LLM con un System Prompt estricto que restringe la salida a un formato JSON estructurado:

```
Eres un auditor de ciberseguridad experto en Bug Bounty. Recibirás un listado estructurado de URLs y endpoints extraídos durante la fase de reconocimiento.
Tu objetivo es analizar las rutas y devolver un JSON estricto con los endpoints con mayor probabilidad de contener vulnerabilidades (como IDOR, SSRF, LFI, SQLi, Auth Bypass o endpoints de API sin autenticar).
Responde ÚNICAMENTE con un JSON válido con la estructura: {"prioritized_targets": [{"url": "...", "priority": 9, "reason": "..."}]}
```

## 6. Escaneo con Nuclei

Con la lista de objetivos priorizados por la inteligencia artificial, el sistema ejecuta Nuclei de forma focalizada exclusivamente sobre las rutas señaladas, evitando escaneos masivos ruidosos:

```
TARGET_URL="{{ $json.url }}"
EXPORT_FILE="/tmp/nuclei_$(date +%s%N).json"

nuclei -u "$TARGET_URL" -t vulnerabilities/,cves/,exposures/ -severity critical,high,medium -json-export "$EXPORT_FILE" -silent

if [ -f "$EXPORT_FILE" ]; then
  cat "$EXPORT_FILE"
else
  echo "[]"
fi
```

Si los resultados devuelven un positivo tras un filtrado de seguridad, el sistema activa de inmediato una notificación push en Telegram, Slack o Email:

<div align="center">

<img width="693" height="223" alt="image" src="https://github.com/user-attachments/assets/5162718a-eb78-48af-baf7-88daac742e4a" />

</div>

## 7. Conclusión

Al final del día, este pipeline no es más que una pequeña demostración de lo que se puede lograr combinando la orquestación visual de n8n, la potencia analítica de Claude y las herramientas CLI de toda la vida.

Esta estructura sirve como un punto de partida, una base sólida sobre la cual cada investigador puede construir, adaptar y escalar sus propios flujos según las necesidades de cada programa o metodología de trabajo. La verdadera magia de la automatización abierta reside en eso: coger una idea, adaptarla a tu propio flujo y llevarla tan lejos como tu curiosidad e imaginación te permitan.
