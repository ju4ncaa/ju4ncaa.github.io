---
description: >-
  Writeup de la máquina de dificultad fácil Chimichurri de la página https://thehackerslabs.com
title: THL - Chimichurri | (Difficulty Easy) - Windows
date: 2025-02-18
categories: [Writeup, The Hackers Labs]
tags: [thl, hacking, the hacker labs, active directory, easy, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/710c66e4-f2ae-45ad-bdfe-832f6cdf83e9
---

## Useful Skills

* 
* 

## Enumeration

### TCP Scan

```bash

```

```bash

```

### UDP Scan

```bash

```

> Hay que añadir el dominio example.com y el FQDN dc.example.com en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 192.168.1.x
{: .prompt-tip }


### DNS Enumeration

Intento obtener información adicional sobre el dominio a través de consultas DNS con dig, donde intento obtener los registros NS, MX, CNAME entre otros, posteriormente, trato de realizar una transferencia de zona, pero esta resulta fallida.

```bash

```
