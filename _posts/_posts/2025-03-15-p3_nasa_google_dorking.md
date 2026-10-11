---
title: P3 NASA GOOGLE DORKING
date: 2025-03-12 01:24:00 -0500
categories: [BugBounty, Hacking]
tags: [bugbounty, hacking]
image:
  path: /assets/img/posts/2025-03-15-p3_nasa_google_dorking.png
  alt: Nasa p3 google dorking
---

En ciberseguridad, no todos los hallazgos requieren explotar una vulnerabilidad, ejecutar código o acceder a sistemas protegidos. En ocasiones, la información más relevante aparece durante una tarea de reconocimiento: analizar qué recursos están indexados por los motores de búsqueda y qué documentos se encuentran disponibles públicamente.

En este caso, utilicé Google Dorking como técnica de reconocimiento OSINT para buscar documentos potencialmente sensibles alojados en dominios relacionados con organismos públicos estadounidenses.
Durante la búsqueda encontré un documento alojado en la infraestructura web de la NASA que llamó mi atención por su contenido: una hoja de cálculo de autorizaciones de vuelo correspondiente al proyecto ASIA-AQ, fechada el 22 de febrero de 2024.
El documento estaba disponible sin autenticación. Tras revisar su contenido, identifiqué información relacionada con estados de autorización médica, cuestionarios médicos y formación de evacuación de aeronaves.
El hallazgo planteaba una cuestión importante: ¿estaba información potencialmente sensible siendo publicada sin los controles de acceso adecuados?

## 1. ¿Qué es Google Dorking?

Google Dorking, también conocido como Google Hacking, consiste en utilizar operadores avanzados de búsqueda para localizar recursos específicos que los motores de búsqueda pueden indexar.
En lugar de realizar una búsqueda genérica, podemos restringir los resultados por dominio, extensión de archivo, palabras clave o contenido presente en las páginas.

Algunos operadores habituales son:

- site: limita los resultados a un dominio o sitio determinado.
- filetype: busca archivos de una extensión concreta, como PDF, DOCX o XLSX.
- intitle: permite buscar términos presentes en el título de una página.
- Las comillas permiten buscar una expresión exacta.

Estas técnicas tienen usos legítimos en auditorías de seguridad, investigaciones OSINT y evaluaciones de exposición de información. Sin embargo, encontrar un documento mediante un buscador no demuestra, por sí solo, que exista una vulnerabilidad: es necesario analizar los permisos, el contexto y la sensibilidad de los datos publicados.

## 2. Preparando la búsqueda

Mi objetivo era localizar documentos indexados públicamente en dominios relacionados con organismos estadounidenses que pudieran contener información sensible.
Para ello, utilicé una consulta que combinaba varios dominios, extensiones de archivo y términos relacionados con información confidencial.

La búsqueda original fue la siguiente:

```
site:*nasa.gov | site:*usgeo.gov | site:*scijinks.gov | site:*globe.gov ext:pdf | ext:doc | ext:docx | ext:txt | ext:odt | ext:odf | ext:xls | ext:xlsx | ext:csv "confidential" OR "social security number" OR "credit card" OR "password" OR "bank account" OR "PII" -api
```

La idea era ampliar la superficie de búsqueda y detectar documentos que contuvieran indicadores habituales de información sensible, como PII, confidential o referencias a datos financieros y credenciales.

Una consideración técnica: la consulta original combina operadores y alternativas de una forma que puede producir resultados distintos de los esperados. Google no interpreta necesariamente los símbolos | como un operador OR universal ni aplica siempre los filtros de extensión a todas las alternativas. Por eso, conviene probar consultas más pequeñas y comprobar los resultados de cada una.

Por ejemplo, una búsqueda más específica para localizar PDF que mencionen información personal en el dominio de la NASA sería:

```
site:nasa.gov filetype:pdf "PII"
```

Y para buscar documentos que mencionen confidencialidad:

```
site:nasa.gov filetype:pdf "confidential"
```

## 3. El hallazgo: una hoja de cálculo de autorizaciones de vuelo

Durante la investigación encontré un documento titulado ASIA-AQ Flight Clearance Spreadsheet (22 February 2024).
El archivo estaba alojado en el sitio web oficial del proyecto ESPO de la NASA y podía consultarse directamente mediante una URL pública, sin iniciar sesión.

<img width="1442" height="1091" alt="datos_nasa" src="https://github.com/user-attachments/assets/81ed77cf-46eb-4374-a117-34ab7a186d28" />

## 4. ¿Por qué es relevante desde el punto de vista de la seguridad?

La exposición de un documento no implica automáticamente que todos sus campos sean confidenciales. Es necesario valorar qué información contiene, a quién pertenece, con qué finalidad se publicó y qué controles deberían aplicarse.
En este caso, el riesgo potencial procedía de la combinación de varios factores.

### Exposición de información personal

Los nombres completos permiten identificar a las personas mencionadas en el archivo. Cuando se combinan con otros detalles operativos, pueden facilitar la elaboración de perfiles no deseados.

### Información relacionada con autorizaciones médicas

Los estados de autorización y las referencias a cuestionarios médicos pueden revelar aspectos del proceso de evaluación de una persona, aunque no incluyan un diagnóstico clínico.

La sensibilidad jurídica de esta información depende del contexto y de la legislación aplicable. No sería correcto concluir automáticamente que se ha producido una infracción de HIPAA u otra normativa específica sin analizar las circunstancias y el ámbito de aplicación correspondiente.

### Riesgo de ingeniería social

Los datos organizativos y operativos pueden utilizarse para elaborar mensajes de phishing más creíbles o para hacerse pasar por personal autorizado.

Por ejemplo, conocer la existencia de un proceso de autorización de vuelo puede ayudar a construir un mensaje fraudulento que simule proceder de un equipo de coordinación. Esto describe un riesgo potencial, no evidencia de que se haya producido un ataque.

### Gestión de documentos públicos

El caso también pone de manifiesto un problema habitual: un archivo puede publicarse en un servidor legítimo y, aun así, contener más información de la necesaria para su distribución pública.

La cuestión de seguridad es determinar si el documento debía ser público en su totalidad o si requería una versión redactada, una ubicación restringida o una revisión previa a su publicación.

## 5. Conclusión

Esta investigación demuestra cómo una búsqueda OSINT relativamente sencilla puede ayudar a identificar documentación que merece una revisión de seguridad y privacidad.

Mediante Google Dorking localicé una hoja de cálculo de autorizaciones de vuelo alojada en un dominio oficial de la NASA. El documento contenía nombres y detalles relacionados con procesos de autorización médica y formación operativa, lo que planteaba dudas razonables sobre la conveniencia de publicar toda esa información sin restricciones.

El aprendizaje principal no es que Google Dorking permita acceder a sistemas internos, sino que la gestión de documentos públicos forma parte de la superficie de exposición de una organización.

En seguridad, identificar un recurso es solo el primer paso. La diferencia entre una búsqueda y una investigación responsable está en verificar el contexto, evaluar el impacto con rigor, preservar la privacidad y comunicar el hallazgo de forma que facilite su corrección.
