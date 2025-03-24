---
description: >-
  Encuentra tu primer NTLM Auth Disclosure
title: Identificar NTLM Authentication Disclosure
date: 2025-03-24
categories: [Bug Bounty]
tags: [hacking, bug bounty, hacking web, bugcrowd]
image_post: true
image: https://github.com/user-attachments/assets/05aeef08-242d-4e62-874d-762a34c5c4af
---

## ¿Qué es NTLM Auth Disclosure?

Un NTLM Authentication Disclosure es una vulnerabilidad en la que un servidor o aplicación expone inadvertidamente encabezados de autenticación NTLM en respuestas HTTP u otros protocolos. Esto puede permitir a un atacante capturar hashes NTLM y usarlos en ataques como NTLM Relay o Pass-the-Hash, comprometiendo credenciales y accediendo a sistemas internos sin necesidad de conocer la contraseña real.

## Flujo de autenticación

NTLM autentica a los usuarios mediante un proceso de desafío/respuesta en el cual la contraseña real del usuario no se transmite nunca a través de la red. En lugar de eso, el cliente que realiza la solicitud recibe un desafío del servidor y debe realizar un cálculo para demostrar su identidad.

Estoy simplificando el proceso, pero el diagrama a continuación es una excelente ilustración de cómo opera este esquema de autenticación en un entorno de Windows AD.


<div align="center">
  <img src="https://github.com/user-attachments/assets/732c1ee4-5665-4e54-a0f3-566ea981b993" alt="ntlm authentication">
</div>


## ¿Como se obtiene información interna o sensible?

Una vez que se identifica que un objetivo emplea autenticación NTLM, podemos establecer una conexión y enviar credenciales anónimas (nulas). Esto hará que el servidor responda con un mensaje de desafío NTLM Tipo 2.

Este mensaje de respuesta puede ser decodificado para extraer información sobre el servidor, como: NetBIOS, DNS e información sobre la versión de compilación del sistema operativo.

> Ejemplo de explotación real

![image](https://github.com/user-attachments/assets/46efd4ad-4cb2-411e-996a-3b4a61807f96)

## Impacto

Durante un pentesting, esta información puede ser utilizada para identificar nombres internos, determinar sistemas operativos obsoletos o al final de su ciclo de vida, y descubrir nombres DNS internos.

Aunque no es la vulnerabilidad más destacada, si se encuentra en un objetivo de un programa de recompensas por errores, es posible que puedas aprovechar esta divulgación interna para obtener unos puntos y una recompensa rápida, aunque esto dependerá del programa específico y de los criterios establecidos por el mismo.

## Exploración

El primer paso es obtener todos los subdominios del dominio objetivo. Para esto, puedes usar Subfinder, una herramienta popular para descubrir subdominios.

```
subfinder -d target.com -o subs.txt
```

Una vez que tengas la lista de subdominios, puedes usar httpx para detectar las tecnologías asociadas a cada subdominio. Para enfocarte en las tecnologías relacionadas con Microsoft, como servidores que podrían estar usando NTLM, ejecuta el siguiente comando:

```
cat subs.txt | httpx -td
```

Para buscar servidores que responden con un 401 Unauthorized, lo que indica que requieren autenticación, puedes usar el siguiente comando con httpx. Esto es útil porque los servidores que requieren autenticación NTLM a menudo responden con este código de estado HTTP.

```
cat subs.txt | httpx -mc 401
```

Para identificar servidores que podrían estar divulgando NTLM, puedes realizar una búsqueda avanzada en Shodan. Utilizando parámetros como el nombre común del certificado SSL (ssl.cert.subject.CN), el título de la página HTTP (http.title), y el encabezado de autenticación NTLM (WWW-Authenticate: NTLM), puedes encontrar servidores expuestos que requieren autenticación NTLM.

```
ssl.cert.subject.CN:"example.com" http.title:"401 Unauthorized" "WWW-Authenticate: NTLM"
```

## Explotación

Por lo general, cuando se accede a un sitio web o directorio que requiere privilegios especiales, el servidor solicita que se inicie sesión. Este proceso permite al cliente enviar un nombre de usuario y una contraseña vacía para verificar la autenticación NTLM y recibir la respuesta cifrada.

Sin embargo, si el servidor está configurado para aceptar la autenticación de Windows, es posible obtener esta respuesta sin necesidad de iniciar sesión previamente. Para hacerlo, basta con agregar la siguiente línea en los encabezados de la solicitud HTTP:

```
Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
```

![image](https://github.com/user-attachments/assets/08453059-bc94-4104-b3a5-cf2acac96e02)

Una vez que se devuelve un desafío NTLM a través del encabezado de respuesta WWW-Authenticate, se puede decodificar para capturar información interna, se pueden usar dos formas para decodificar

* [NTLM Challenge Decoder Burp Extension](https://portswigger.net/bappstore/30d095e075e64a109b8d12fc8281b5e3)
* [Python Script NTLM Challenger](https://github.com/nopfor/ntlm_challenger)
