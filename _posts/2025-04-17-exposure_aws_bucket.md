---
title: Exposición de Zowe en AWS S3
date: 2025-04-17 01:24:00 -0500
categories: [BugBounty, Hacking]
tags: [bugbounty, hacking]
image:
  path: /assets/img/posts/2025-04-17-exposure_aws_bucket
  alt: Exposure AWS Bucket
---

Durante mis investigaciones identifiqué una exposición de información relacionada con la configuración de Zowe, alojada en un bucket de Amazon S3. El hallazgo fue reportado a través de Bugcrowd y reconocido con una recompensa de 300 USD.

Este caso demuestra que un recurso puede parecer protegido a nivel de bucket y, aun así, permitir el acceso directo a un objeto que contiene información sensible. También pone de manifiesto la importancia de revisar los permisos efectivos de acceso y evitar la exposición de archivos de configuración internos.

<img width="1162" height="1354" alt="image" src="https://github.com/user-attachments/assets/57223358-7a69-4f6a-bf0e-bfae4a4669b3" />

## 1. Descripción de la vulnerabilidad

El hallazgo consistía en un archivo denominado zowe.config.txt que podía consultarse o descargarse mediante una URL directa sin autenticación.

Aunque el acceso a la raíz del bucket devolvía una respuesta Access Denied, el archivo específico seguía siendo accesible. Esta diferencia es importante: que un bucket no permita listar públicamente su contenido no significa necesariamente que todos sus objetos estén protegidos.

La exposición permitía consultar información técnica sobre la infraestructura interna y los perfiles de conexión configurados para distintos servicios de Zowe

## 2. Información expuesta

El archivo contenía varios elementos relevantes desde la perspectiva de la seguridad:

 - Nombres de host internos: información que puede facilitar la identificación y el reconocimiento de sistemas corporativos.

- Puertos y servicios: referencias a distintos servicios, útiles para comprender la arquitectura y orientar posibles investigaciones posteriores.

- Perfiles de conexión: configuraciones asociadas a servicios como z/OSMF, TSO, SSH y ZMF.

- Validación de certificados TLS: una opción configurada como rejectUnauthorized: false, que deshabilita la validación de certificados en el contexto en que se utiliza.

La combinación de estos datos puede facilitar el reconocimiento de infraestructura y aumentar el riesgo de ataques dirigidos. La exposición de una configuración no implica por sí sola que exista acceso al sistema, pero puede proporcionar información valiosa para preparar ataques posteriores.

## 3. Cómo se identificó el problema

La investigación comenzó mediante técnicas de reconocimiento pasivo y búsquedas específicas en motores de búsqueda para localizar archivos alojados en dominios de Amazon S3 relacionados con la organización afectada.

Google dork usado:

```
(site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com OR site:*.s3.dualstack.us-east-1.amazonaws.com OR site:*.s3.ap-south-1.amazonaws.com) "example.com"  
```

Tras localizar una referencia al archivo de configuración, comprobé dos condiciones:

- El acceso a la raíz del bucket devolvía Access Denied, por lo que no era posible listar públicamente su contenido.

<img width="2170" height="725" alt="image" src="https://github.com/user-attachments/assets/80ce9f71-1aef-41fe-9907-63b80d5d0ba7" />

- El archivo concreto podía abrirse o descargarse directamente sin autenticación.

<img width="2172" height="724" alt="image" src="https://github.com/user-attachments/assets/84900399-8912-40da-b746-7a7f33d0810a" />

<img width="2167" height="726" alt="image" src="https://github.com/user-attachments/assets/9ed5ab97-2b68-4d11-b0f9-3855fc62f26b" />

- Finalmente, revisé su contenido para determinar qué información exponía y evaluar el posible impacto sobre la confidencialidad de la infraestructura.

## 4. Conclusiones

Este hallazgo es un ejemplo de cómo un error en los controles de acceso puede convertirse en una fuente de exposición de información interna, incluso cuando el recurso parece estar protegido.

La diferencia entre ambas respuestas fue el aspecto central del hallazgo: la protección aparente del contenedor no garantizaba la protección efectiva del archivo.
