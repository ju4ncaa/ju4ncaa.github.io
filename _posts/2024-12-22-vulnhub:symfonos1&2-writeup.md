---
title: VulnHub, Symfonos1 & Symfonos2 Pentesting, WriteUp
date: 2024-12-22
description: WriteUp de las máquina Symfonos1 y Symfonos2 de la página VulnHub
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: https://github.com/user-attachments/assets/d67a2408-e7a1-494e-8064-c1587ccd6318
image: https://github.com/user-attachments/assets/d67a2408-e7a1-494e-8064-c1587ccd6318
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/b58af12e-5a40-47db-a87e-c2e4064ff2bf)

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar. Por una parte, tenemos la máquina atacante, Kali Linux, con dirección IP 192.168.2.128, por otro lado, se encuentran las máquinas víctimas: Symfonos1 con direcciones IP dentro del rango (192.168.2.0/24) y (10.0.2.0/24) y Symfonos2 con dirección IP dentro del rango (10.0.2.0/24) En este escenario inicial, solo podemos ver y acceder a Symfonos1 desde Kali Linux, lo que indica que es nuestra primera máquina objetivo. Una vez comprometamos Symfonos1, deberemos realizar un pivoting para acceder a Symfonos2, que no es directamente visible desde Kali Linux.

## **Habilidades empleadas**  

* Enumeración SMB
* Filtración de Información
* Enumeración de WordPress
* Abuso del Plugin de WordPress - Mail Masta 1.0
* Local File Inclusion (LFI)
* LFI + Abuso del servicio SMTP para lograr RCE
* Abuso de privilegios SUID + PATH Hijacking [Privilege escalation]
* Pivoting hacia Symfonos 2 [Socat + Chisel + ProxyChains]
* Explotación de FTP - Abuso de SITE CPFR/CPTO
* Abuso de FTP y SMB - Obtención de archivos de la máquina
* SSH (Local Port Forwarding) + Abuso de LibreNMS
* Explotación de LibreNMS a través de un RCE (User Pivoting)
* Abuso de privilegios sudoers (MySQL) [Privilege escalation]
