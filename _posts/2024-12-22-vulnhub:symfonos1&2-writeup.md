---
title: VulnHub, Symfonos1 & Symfonos2 Pentesting, WriteUp
date: 2024-12-22
description: WriteUp de las máquina Symfonos1 y Symfonos2 de la página VulnHub
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: https://github.com/user-attachments/assets/48f18f51-be98-43df-bc27-70e0425b5220
image: https://github.com/user-attachments/assets/48f18f51-be98-43df-bc27-70e0425b5220
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
* Reutilización de credenciales
* Explotación de LibreNMS a través de un RCE (User Pivoting)
* Abuso de privilegios sudoers (MySQL) [Privilege escalation]

## **Enumeración (192.168.1.137)**

### **Descubrimiento de hosts**

Utilizamos **arp-scan** para descubrir los dispositivos activos en nuestra red, fijamos como objetivo el host **192.168.1.137**

![image](https://github.com/user-attachments/assets/0fa5549e-cefe-4616-8048-568c0550fca9)

Usamos **ping** para verificar la conectividad del host **192.168.1.137**, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del **TTL (Time To Live)** también podemos identificar que se trata de un equipo Linux.

![image](https://github.com/user-attachments/assets/0ab4a9bd-7eaa-48c2-9c22-cbf44b721d00)

### **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta **whichSystem.py**, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. **Windows tiene un ttl=128** y **Linux tiene un ttl=64** por defecto.

![image](https://github.com/user-attachments/assets/1b3b4591-9232-404e-bb94-af263c8677bc)

### **Nmap (Network Mapper)**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos sobre la dirección IP objetivo **192.168.1.137**, usando los siguientes parámetros:

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-p-`         | Escanea todos los puertos (del 1 al 65535).                             |
| `--open`      | Muestra solo los puertos que están abiertos.                            |
| `-sS`         | Realiza un escaneo de tipo SYN (escaneo sigiloso) para detectar puertos abiertos sin establecer una conexión completa. |
| `--min-rate`  | Establece la velocidad mínima de envío de paquetes (útil para aumentar la velocidad del escaneo). |
| `-vvv`        | Muestra la salida en modo detallado y verbose (nivel máximo de información). |
| `-n`          | Desactiva la resolución de DNS, lo que acelera el escaneo al no intentar resolver nombres de dominio. |
| `-Pn`         | Desactiva la detección de hosts, lo que indica que Nmap no realice un "ping" previo para determinar si el host está activo. |
| `-oG`         | Guarda los resultados en formato "grepable" para facilitar la posterior búsqueda de resultados. |

![image](https://github.com/user-attachments/assets/c8b84917-b7eb-4505-844e-e4859c4fc9c1)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.1.137**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![image](https://github.com/user-attachments/assets/41d5d2b5-68f9-45aa-805f-f632255d8fff)

#### **Detalles del escaneo**

En el escaneo realizado a la dirección IP objetivo **192.168.1.137**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 22         | SSH           | OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0) |
| 25         | SMTP          | Postfix smtpd |
| 80         | HTTP          | Apache httpd 2.4.25 ((Debian)) |
| 139        | NetBIOS Session Service | smbd 3.X - 4.X |
| 445        | Direct Hosting of SMB | smbd 4.5.16-Debian |

También se puede observar que se está aplicando **Virtual Hosting**, el dominio utilizado en este caso parece ser **symfonos.localdomain**, el cual agregamos al archivo **/etc/hosts** el cual nos permite mapear nombres de host a direcciones IP de forma estática.

![image](https://github.com/user-attachments/assets/bad37816-5201-4fed-a058-fae224a41cd2)

### **Enumeración de servicios (SSH - Puerto 22)**

La versión de **OpenSSH 7.4p1** es vulnerable a [CVE-2018-15473 ](https://nvd.nist.gov/vuln/detail/cve-2018-15473) **[OpenSSH < 7.7 - User Enumeration]**
