---
title: Bounty Stored XSS in Profile Description
date: 2026-01-20 01:24:00 -0500
categories: [BugBounty, Hacking]
tags: [bugbounty, hacking]
image:
  path: /assets/img/posts/2026-01-20-stored_xss.png
  alt: Stored xss in profile
---

Durante el análisis de seguridad de la aplicación web de AnyTask, se identificó una vulnerabilidad de Stored Cross-Site Scripting (XSS) en el campo de descripción del perfil.

El problema permite almacenar contenido HTML con código JavaScript asociado a eventos en el campo de descripción. Cuando el usuario vuelve a acceder a la página de edición del perfil, la aplicación procesa ese contenido sin aplicar una sanitización o codificación de salida adecuada, provocando la ejecución del código en el navegador.

A diferencia de un ataque Reflected XSS, en el que el contenido malicioso se procesa a partir de una petición concreta, el Stored XSS permanece almacenado y puede ejecutarse de nuevo cuando se visualiza el contenido afectado.


## 1. El descubrimiento de la vulnerabilidad

La investigación comenzó examinando el comportamiento de la funcionalidad de edición del perfil. Durante el proceso, se interceptó la comunicación con el endpoint https://api.example.com/user para analizar cómo se enviaban y procesaban los datos de la cuenta.

Al revisar el flujo de actualización, se comprobó que el campo de descripción podía modificarse mediante una petición interceptada. Esto permitió investigar si la aplicación validaba correctamente el contenido antes de almacenarlo y cómo lo representaba posteriormente en el navegador.

Para comprobar el comportamiento, se utilizó una prueba de concepto sencilla:

```
<p onmouseover="alert(1)">1</p>
```

El fragmento contiene un elemento HTML con un atributo onmouseover, que ejecuta JavaScript cuando se produce el evento correspondiente. En este caso, la llamada a alert(1) se utiliza únicamente como indicador visual para verificar la ejecución del código.

Tras enviar la modificación y regresar a la página de edición del perfil, se observó que el contenido almacenado podía provocar la ejecución del JavaScript.

Este comportamiento confirmó que la aplicación no estaba tratando el contenido del perfil de forma segura en ese contexto.

## 2. Pasos a reproducir

- Iniciar sesión con una cuenta de usuario válida.
- Navega hasta Editar imagen de perfil
- Subir una imagen e intercepta la respuesta de la solicitud.
- Cambiar summary a: ```<p onmouseover="alert(1)">1</p>```

<img width="1674" height="940" alt="image" src="https://github.com/user-attachments/assets/2528dc61-05be-4a5f-90b5-5959ea7f9958" />

- Reenviar todo -> Volver a la página de edición de perfil.
- Al cargarse, el script se ejecuta y muestra un cuadro de alerta JS.

<img width="1271" height="610" alt="image" src="https://github.com/user-attachments/assets/04cf48e7-e2e1-4252-bdc7-ea3ce9df6fa6" />

## 3. Impacto

- Permite a los atacantes ejecutar código JavaScript arbitrario en el contexto de la sesión del usuario.
- Podría provocar el secuestro de sesión, la manipulación del DOM, ataques de phishing o la escalada de privilegios si se activa en cuentas de administrador.
- El script se almacena de forma permanente en la base de datos, lo que permite repetir el ataque en cada vista de edición de perfil.

## 4. Conclusión

Esta investigación demuestra cómo un campo de descripción aparentemente trivial puede convertirse en un punto de entrada para ejecutar JavaScript cuando los datos del usuario no se gestionan correctamente.

La característica más importante del caso es la persistencia del contenido: el código podía quedar almacenado y ejecutarse de nuevo al acceder a la vista vulnerable. Por ello, la solución debe abordar tanto la aceptación de los datos como su representación posterior en el navegador.
