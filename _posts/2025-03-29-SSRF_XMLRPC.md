---
description: >-
  Obtén tu primer Blind SSRF de forma sencilla
title: Blind SSRF a través de XMLRPC (Easy Bounty)
date: 2025-03-29
categories: [Bug Bounty]
tags: [hacking, bug bounty, hacking web, bugcrowd]
image_post: true
image: https://github.com/user-attachments/assets/2e53ad2d-344b-4e3f-b255-14d772ce7d1f
---

## ¿Qué es SSRF (Server Side Request Forgery)?

SSRF es una vulnerabilidad web en la que un atacante puede manipular un servidor para que realice solicitudes HTTP a destinos arbitrarios, incluidos recursos internos de la red que normalmente están protegidos.

## Identificar xmlrpc

* Asegurarse de que el objetivo tiene Wordpress
* Revisar robots.txt y analiza las rutas para detectar cualquier mención a xmlrpc.
* Usar katana para obtener endpoints y filtrar por xmlrpc

```
katana -u http://example.com -jc -d 5 -o katana_urls.txt
```
```
grep xmlrpc katana_urls.txt
```

* Usar waymore para obtener endpoints y filtrar por xmlrpc

```
waymore -i https://example.com -mode U -oU waymore_urls.txt
```
```
grep xmlrpc waymore_urls.txt
```
* Usar Webarchive para filtrar por xmlrpc

```
https://web.archive.org/cdx/search/cdx?url=*example.com/*&output=text&fl=original&collapse=urlkey
```

## Explotación
