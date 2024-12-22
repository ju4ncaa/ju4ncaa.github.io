---
title: VulnHub, Symfonos1 & Symfonos2 Pentesting, WriteUp
date: 2024-12-22
description: WriteUp de las máquina Symfonos1 y Symfonos2 de la página VulnHub
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: 
image: 
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/16a58501-81af-41dc-9300-12427bc36990)


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
