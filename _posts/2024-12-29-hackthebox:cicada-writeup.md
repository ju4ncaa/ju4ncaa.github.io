---
title: HackTheBox, Cicada Pentesting, WriteUp
date: 2024-12-25
description: Writeup de la máquina UnderPass de la página HackTheBox
categories: [Writeup's, Active Directory]
tags: [Hacking, Pentesting, Active Directory]
image_path: https://github.com/user-attachments/assets/a5fd9492-c574-40df-9fa4-0952ae30b6c4
image: https://github.com/user-attachments/assets/a5fd9492-c574-40df-9fa4-0952ae30b6c4
---

## **Introducción**

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es Cicada, con dirección IP 10.10.11.35

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/97dadd82-4f78-4a00-98bc-f126413e0d04" alt="machine info" width=700px></div>

## **Habilidades empleadas**

* Ataque Domain Zone Transfer - AXFR (Fallido)
* Enumeración anónima RPC (Fallido)
* Enumeración SMB (netexec + smbclient)
* Password Spraying (Netexec)
* Enumeracion LDAP + Obtencion de credenciales (ldapsearch)
* Abuso del privilegio SeBackupPrivilege [Privilege escalation]
* Volcado de contraseñas en formato hash (impacket-secretsdump)
* Pass The Hass (evil-winrm)

## **Enumeración**

### **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 10.10.11.35, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Linux.
