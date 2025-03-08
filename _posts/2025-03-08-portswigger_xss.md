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
