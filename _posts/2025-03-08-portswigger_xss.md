---
description: >-
  Writeup de los laboratorio de XSS de la página https://portswigger.net/
title: PortSwigger - XSS
date: 2025-03-08
categories: [Writeup, Bug Bounty Labs]
tags: [portswigger, hacking, bug bounty, hacking web, xss, writeup, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/c5642bae-077b-44f2-98a1-e3c0af53f06b
---

## 1. Reflected XSS into HTML context with nothing encoded

### Description

Este laboratorio contiene una vulnerabilidad simple de cross-site scripting reflejada en la funcionalidad de búsqueda.

### Mission

Para resolver el laboratorio, realiza un ataque de cross-site scripting que llame a la función `alert()`

### Solution

Al acceder puedo observar la barra de búsqueda para filtrar por los posts

![image](https://github.com/user-attachments/assets/96fa38c6-324f-495b-b81e-a677ee1f7f74)

Envío un texto y lo intercepto con BurpSuite para visualizar como se imprime la respuesta

![image](https://github.com/user-attachments/assets/2525aa28-be19-4e08-afc3-ee2747fc00de)

![image](https://github.com/user-attachments/assets/045ea01f-debd-4709-a3ca-cf137250604d)

Observo que el input se imprime en una etiqueta `<h1>`, si supuestamente no se está realizando ningún tipo de validación, simplemente con inyectar la etiqueta `<script>` con el código javascript sería suficiente

#### Payload

```
/?search=<script>alert(1)</script> 
```

![image](https://github.com/user-attachments/assets/14cc2f64-53c6-48c9-b254-2e765e315596)

![image](https://github.com/user-attachments/assets/9d0f8239-7e00-4116-8584-44ec8d864a68)

![image](https://github.com/user-attachments/assets/a7a88242-1543-445b-bb2c-2ee3c84fd19f)

## 2. Stored XSS into HTML context with nothing encoded

### Description

Este laboratorio contiene una vulnerabilidad de cross-site scripting almacenada en la funcionalidad de comentarios.

### Mission

Para resolver el laboratorio, envía un comentario que llame a la función de `alert()` cuando se visualice la entrada del blog.

### Solution

Al acceder observo una web que cuenta con diferentes posts

![image](https://github.com/user-attachments/assets/287be7ab-fd77-4944-b763-45dcc5f361d6)

Cada post cuenta con un sistema de comentarios

![image](https://github.com/user-attachments/assets/ed6545c7-8e2e-4665-b04f-af388c6a3e1c)

Realizo un comentario de prueba para visualizar como se almacenan

![image](https://github.com/user-attachments/assets/15e50ab6-6842-4fee-ae3f-40e4b1dc0fe8)

![image](https://github.com/user-attachments/assets/ce0570d7-948b-4a64-ad97-691e28eb42ba)

Observo que el contenido del comentario se almacena en una etiqueta `<p>`, si supuestamente no se está realizando ningún tipo de validación, simplemente con inyectar la etiqueta `<script>` con el código javascript sería suficiente

#### Payload

```
<script>alert()</script>
```

![image](https://github.com/user-attachments/assets/a331917b-b7c7-41ad-bebf-049d796076ad)

![image](https://github.com/user-attachments/assets/29c915e6-4efe-4fcd-b8ae-2184013e3d8d)

## 3. DOM XSS in document.write sink using source location.search

### Description

Este laboratorio contiene una vulnerabilidad DOM-based cross-site scripting en la funcionalidad de seguimiento de consultas de búsqueda que utiliza la función javascript `document.write`, esta escribe datos en la página, la función document.write se llama con datos de location.search, que pueden controlarse mediante la URL del sitio web.

### Mission

Para resolver este laboratorio, realiza un ataque de secuencias de comandos en sitios cuzados que llame a la función `alert()`

### Solution

Al acceder puedo observar la barra de búsqueda para filtrar por los posts

![image](https://github.com/user-attachments/assets/cb1f5ec1-c529-4faf-9c76-764c845d6ab3)

Envío un texto y lo intercepto con BurpSuite para visualizar como se imprime la respuesta

![image](https://github.com/user-attachments/assets/9dbaa3a2-9511-4cb9-a84b-536eb40f23aa)

![image](https://github.com/user-attachments/assets/dc792ce0-7c5c-4ce5-ab59-99e656a34777)

Al intentar inyectar código javascript observo que los símbolos mayor y menor son convertidos en entidades HTML, esto provoca que no se inteprete el código

![image](https://github.com/user-attachments/assets/34bf78a9-1c11-4340-97ba-f38cd9569686)

![image](https://github.com/user-attachments/assets/1350d417-d7c0-47c4-aed0-c30cf2874618)

Observo que el texto introducido a través de la barrá de búsqueda también se ve reflejado en el `src=` de la etiqueta `<img>`, sabiendo esto es posible intentar escapar la comilla de `src=` e intentar ejecutar código javascript

![image](https://github.com/user-attachments/assets/967d8e0c-8743-4c84-a6e6-8dc4c4ee8be2)

#### Payload

```
/?search="><script>alert()</script>
```

![image](https://github.com/user-attachments/assets/98349670-b761-4d88-8a37-9136866f8b86)

## 4. DOM XSS in innerHTML sink using source location.search

### Description

Este laboratorio contiene una vulnerabilidad de cross-site scripting basada en DOM en la funcionalidad del blog de búsqueda, utiliza una asignación `innerHTML`, que cambia el contenido HTML de un elemento div, utilizando los datos de `location.search`

### Mission

Para resolver este laboratorio, realice un ataque de secuencias de comandos en sitios cruzados que llame a la función `alert()`

### Solution

Al acceder puedo observar la barra de búsqueda para filtrar por los posts

![image](https://github.com/user-attachments/assets/95438aea-c5c5-4024-b93e-58ddebe35774)

Envío un texto y analizo con las dev tools en que partes del código aparece

![image](https://github.com/user-attachments/assets/d9d74adc-a085-4e4d-94df-939978d90b9c)

![image](https://github.com/user-attachments/assets/eb034d47-6905-45c3-b657-0b885f0adfc8)

Observo que el texto introducido se encuentra dentro de una etiqueta `<span>`, intento inyectar un texto de color rojo para comprobar si es posible realizar un HTML Injection

![image](https://github.com/user-attachments/assets/1c103c68-3b99-4cea-ac10-a2c6cd184c90)

![image](https://github.com/user-attachments/assets/458e94c8-aa0b-46d9-9bd3-447a4b62df62)

Veo que es posible inyectar HTML, pero a la hora de intentar inyectar código javascript, el mismo no se interpreta, por lo que podemos jugar con la etiqueta img y carga un recurso inexistente, jugando con el evento `onerror` ejecutar código javascript

#### Payload

```
/?search=<img src=x onerror=alert()>
```

![image](https://github.com/user-attachments/assets/ffb8ea8c-ee13-4804-bbeb-aadea70e9203)

## 5. DOM XSS in jQuery anchor href attribute sink using location.search source

### Description

Este laboratorio contiene una vulnerabilidad de secuencias de comandos entre sitios basada en DOM en la página de envío de comentarios, utiliza la función $ selector de la biblioteca jQuery para econtrar y cambia su atributo href utilizando los datos de location.search.

### Mission

Para resolver este laboratorio, haz que el enlace «back» ejecute un `alert()` con `document.cookie`

### Solution

Al acceder observo una web que cuenta con diferentes posts

![image](https://github.com/user-attachments/assets/2d9be873-20c3-4851-a7ef-ede05d11fdc7)

Accedo a Submit feedback y en la URL observo el parámetro `?returnPath=/`

![image](https://github.com/user-attachments/assets/d687a1b4-acf8-4e8e-9efc-bb503ba988df)

Introduzco un valor diferente y busco en el código donde se ve reflejado, consigo observar que el valor de `?returnPath=` se almacena en el `href` del boton del boton Back

![image](https://github.com/user-attachments/assets/776828af-a290-4305-928b-b6e7292c758f)

![image](https://github.com/user-attachments/assets/6af7ca1f-57a7-47fb-8154-61bc405fd327)

Desde Jquery se puede llamar a javascript desde el HTML con `javascript:`, por lo que inyecto un `alert()` con `document.cookie`

#### Payload

```
/feedback?returnPath=javascript:alert(document.cookie)
```

Al hacer click sobre el boton de `<Back` se ejecuta el código javascript

![image](https://github.com/user-attachments/assets/3053b69a-e8da-4b59-99fb-0ea6f69e5e54)

## 6. Reflected XSS into attribute with angle brackets HTML-encoded

### Description

Este laboratorio contiene una vulnerabilidad de secuencia de comandos en sitios cruzados reflejada en la funcionalidad del blog de búsqueda donde los paréntesis angulares están codificados en entidades HTML. 

### Mission

Para resolver este laboratorio, realice un ataque de secuencias de comandos en sitios cruzados que inyecte un atributo y llame a la función `alert()`

### Solution

Al acceder puedo observar la barra de búsqueda para filtrar por los posts

![image](https://github.com/user-attachments/assets/a75d3d37-0d49-45f7-9c00-fc990d7808b9)

Envío un texto y compruebo con las dev tools en que partes del código se ve reflejado, pudiendo observar que se visualiza en la etiqueta `<h1>` y en el `value` del input

![image](https://github.com/user-attachments/assets/2d6a1f33-c6a1-4da0-8fb1-6b2a0e667e60)

![image](https://github.com/user-attachments/assets/6a157ca5-e222-4511-91f7-db5eb9c54659)

Intento inyectar código JavaScript, pero en BurpSuite observo que el mayor y menor son convertidos en entidades HTML

![image](https://github.com/user-attachments/assets/5a27db70-bd20-4e62-9210-d02436a6b020)

![image](https://github.com/user-attachments/assets/a2ef343f-20cb-4820-8889-0e502b33b968)

Al inyectar una comilla puedo observo que está no se convierte en una entidad HTML, por lo que es posible escapar del atributo `value` y ejecutar código javascript en la etiqueta `<input>`

#### Payload

```
/?search="onfocus=alert() autofocus
```

![image](https://github.com/user-attachments/assets/a5650b67-9ab8-49cf-a0f1-8908b15643d6)

## 7. Stored XSS into anchor href attribute with double quotes HTML-encoded

### Description

Este laboratorio contiene una vulnerabilidad de cross-site scripting almacenada en la funcionalidad de comentarios.

### Mission

Para resolver este laboratorio, envía un comentario que llame a la función `alert()` cuando se haga clic en el nombre del autor del comentario.

### Solution

Al acceder observo una web que cuenta con diferentes posts

![image](https://github.com/user-attachments/assets/93af461b-909e-4139-90f9-3f0c6175549e)

Cada post cuenta con un sistema de comentarios

![image](https://github.com/user-attachments/assets/df6f8a37-f10d-4b9b-ab56-191f8b3fd8e3)
