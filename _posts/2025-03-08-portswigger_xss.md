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
