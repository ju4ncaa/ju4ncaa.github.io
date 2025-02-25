---
description: >-
  Writeup del laboratorio de dificultad fácil Reflection de la página https://bugbountylabs.com/
title: BBLabs - Reflection | (Difficulty Easy) - XSS
date: 2025-02-25
categories: [Writeup, Bug Bounty Labs]
tags: [bblabs, hacking, bug bounty labs, hacking web, easy, writeup, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/32140452-3a09-43d6-b1db-8791d9d0097f
---

## Lab 1 - Reflected XSS

**Descripción:** En este laboratorio podrás introducir un payload XSS y ver cómo se refleja en la misma página.

![image](https://github.com/user-attachments/assets/18d7a55b-40c2-4afd-8d10-a38679d680ef)

Comienzo introduciendo un texto de prueba sencillo para observar el comportamiento de la página, consigo observar que el contenido que se introduce se ve reflejado en la web

![image](https://github.com/user-attachments/assets/547404d0-65d9-4e99-b37b-f631e4407ea9)

Intento inyectar una etiqueta HTML, por ejemplo, un título **`<h1>`** de forma sencilla, puediendo ver que soy capaz de alterar el texto y hacer que sea un titulo, consiguiendo realizar el HTML Injection de forma satisfactoria.

### Payload

```html
<h1>HTML Injection</h1>
```

![image](https://github.com/user-attachments/assets/652bb423-2b89-4d13-98f7-4325e22e9bce)

![image](https://github.com/user-attachments/assets/c9ab7112-26ec-4741-9afc-7844f0815545)

Pudiendo haber realizar una inyección de código HTML lo suyo sería intentar inyectar código JavaScript, utilizando la etiqueta **`<script>`** no funciona, por lo que una alternativa de tantas es utilizar la etiqueta **`<img>`** y apuntar a una imagen inexistente, luego por ultimo indicar que cuando se produzca un error se ejecute el código JavaScript que deseemos.

### Payload

```html
<img src=x onerror=alert('xss')>
```

![image](https://github.com/user-attachments/assets/c78486ae-91e8-49f7-b934-683a4d6585d9)

![image](https://github.com/user-attachments/assets/0755f846-8873-411d-b0c6-2f082f7e5a22)

## Lab2 - Stored XSS

**Descripción:** **Este laboratorio te permite practicar inyecciones de script que se almacenan y se muestran a posteriores visitantes.

![image](https://github.com/user-attachments/assets/964ef6e4-9830-46e9-a799-c93da77d76fe)

Comienzo introduciendo un texto de prueba sencillo para observar el comportamiento de la página, consigo observar que el contenido que se introduce se almacena en la web en la web

![image](https://github.com/user-attachments/assets/fe679107-7412-463e-9bdd-17993ec4a684)

![image](https://github.com/user-attachments/assets/ce311a3e-a2eb-46aa-b122-fb88dfaa2053)

Intento inyectar una etiqueta HTML, por ejemplo, un título **`<h1>`** de forma sencilla, puediendo ver que soy capaz de alterar el texto y hacer que sea un titulo, consiguiendo realizar el HTML Injection de forma satisfactoria.

### Payload

```html
<h1>HTML Injection</h1>
```

![image](https://github.com/user-attachments/assets/1b40dbbd-b51c-470f-b08e-06e6a91c22aa)

![image](https://github.com/user-attachments/assets/370f3a0f-77df-4d91-979a-0f1fb56bb4b3)

Pudiendo haber realizar una inyección de código HTML lo suyo sería intentar inyectar código JavaScript, utilizando la etiqueta **`<script>`** no funciona, por lo que una alternativa de tantas es utilizar la etiqueta **`<img>`** y apuntar a una imagen inexistente, luego por ultimo indicar que cuando se produzca un error se ejecute el código JavaScript que deseemos, al ser un XSS almacenado cada vez que un usuario acceda a la página se le ejecutará el código malicioso JS

### Payload

```html
<img src=x onerror=alert('xss')>
```

![image](https://github.com/user-attachments/assets/b74a3309-d449-478a-95e7-bdae47d45dc2)

![image](https://github.com/user-attachments/assets/72abe976-b362-4b7e-be93-26b04b4762aa)

## Lab 3 - Dropdown + XSS

## Lab 4 - Reflected XSS through the URL
