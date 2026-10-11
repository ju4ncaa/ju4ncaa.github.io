---
title: GET Based Open Redirect in Bugcrowd
date: 2026-03-18 01:24:00 -0500
categories: [BugBounty, Hacking]
tags: [bugbounty, hacking]
image:
  path: /assets/img/posts/2026-03-18-bugcrowd_redirect.png
  alt: Bugcrowd open redirect
---

Durante un proceso de reconocimiento y análisis de la superficie de ataque de Bugcrowd, identifiqué un posible caso de Open Redirect en el parámetro returnTo del endpoint de autenticación identity.bugcrowd.com.

Este tipo de vulnerabilidad se produce cuando una aplicación permite redirigir al usuario hacia una URL externa sin validar adecuadamente si el destino es legítimo o de confianza.

En este caso, el parámetro returnTo permite especificar la dirección a la que se redirigirá al usuario. Si la aplicación acepta destinos arbitrarios, un atacante podría construir enlaces que comiencen con un dominio legítimo de Bugcrowd y posteriormente redirijan a una página controlada por un tercero.

Este comportamiento puede utilizarse en campañas de phishing y otras técnicas de ingeniería social para aumentar la credibilidad de enlaces maliciosos.

## 1. Reconocimiento y enumeración de URLs

El primer paso consistió en recopilar URLs históricas y conocidas asociadas al dominio objetivo mediante la herramienta waymore.

```
waymore -i bugcrowd.com -mode U -oU -u "BugCrowd(ju4ncaa)" -o bugcrowd.com.txt
```

Este comando permite obtener URLs que pueden contener parámetros interesantes para el análisis de seguridad.

A continuación, filtré las URLs que contenían valores HTTP o HTTPS dentro de sus parámetros, buscando posibles puntos de redirección:

```
cat bugcrowd.com.txt | grep "=http" | sort -u | uro > openredirect_test1.txt
```

Este filtrado sirve como una primera aproximación para localizar parámetros que reciben URLs externas. Sin embargo, los resultados deben validarse manualmente, ya que no todas las coincidencias representan vulnerabilidades.

## 2. Identificación del endpoint vulnerable

Durante la enumeración, encontré la siguiente URL:

```
https://identity.bugcrowd.com/login?user_hint=researcher&returnTo=https://bugcrowd.com/neohrms/updates
```

<img width="1482" height="135" alt="image" src="https://github.com/user-attachments/assets/031393af-b8bc-4c36-9e16-8f9f8b23a5db" />

El parámetro returnTo contiene la URL de destino a la que la aplicación debe redirigir al usuario después de acceder al endpoint de autenticación.

El siguiente paso consistió en comprobar si era posible modificar dicho parámetro para utilizar un dominio externo no autorizado.

## 3. Prueba de concepto (PoC)

Para comprobar el comportamiento, sustituí el destino original por un dominio externo:

```
https://identity.bugcrowd.com/login?user_hint=researcher&returnTo=http://evil.com
```

La prueba consiste en abrir la URL modificada y observar el destino final de la navegación.

Resultado observado: si la aplicación acepta el valor proporcionado y redirige al navegador hacia http://evil.com sin validar adecuadamente el destino, se confirma la existencia de una redirección externa no controlada.

<img width="1399" height="182" alt="image" src="https://github.com/user-attachments/assets/2a9bf78c-6440-4126-8c05-a3325b445ab3" />

<img width="1669" height="576" alt="image" src="https://github.com/user-attachments/assets/a941ae54-c921-4ec6-8e70-3dfb7a92fb92" />

Comportamiento esperado: la aplicación debería comprobar que la URL de destino pertenece a una lista de destinos autorizados y rechazar cualquier redirección hacia dominios no permitidos.

La diferencia entre ambos comportamientos permite determinar si el parámetro returnTo está expuesto a una vulnerabilidad de tipo Open Redirect.

## 4. Impacto potencial

Una vulnerabilidad de redirección abierta puede tener consecuencias relevantes cuando afecta a un dominio legítimo y reconocido.

### Phishing e ingeniería social

Un atacante podría distribuir enlaces que comiencen con el dominio legítimo de Bugcrowd y que posteriormente conduzcan a una página fraudulenta. Esto puede aumentar la confianza de las víctimas en el enlace y facilitar ataques de phishing.

### Robo de credenciales

Si el usuario termina en una página de inicio de sesión falsa, podría introducir sus credenciales creyendo que se encuentra en un sitio legítimo. La redirección por sí sola no roba las credenciales, pero puede utilizarse como parte de una campaña de engaño.

### Abuso de la reputación del dominio

Los enlaces que utilizan un dominio legítimo antes de redirigir a un sitio externo pueden resultar más convincentes para los usuarios y dificultar la identificación de destinos maliciosos.

### Posible encadenamiento con otras vulnerabilidades

En determinados escenarios, una redirección abierta puede contribuir a ataques más complejos relacionados con flujos de autenticación. No obstante, el secuestro de sesiones o la exposición de tokens no deben darse por demostrados sin una prueba adicional que confirme esos efectos.
