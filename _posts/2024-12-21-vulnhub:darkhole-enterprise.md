---
title: VulnHub, DarkHole Enterprise Pentesting, WriteUp
date: 2024-12-21
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: https://github.com/user-attachments/assets/e360d62b-370f-4135-9d39-06d9250fe52f
image: https://github.com/user-attachments/assets/7de8a25c-9cfb-4764-a7ac-ded02d10831e
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/4fbfab85-4434-48e7-97b3-cea058cb1e28)

Este laboratorio simula un "**entorno empresarial pequeño**" con una infraestructura básica dividida en dos redes, una red externa y una red interna

1. **Kali (192.168.2.x):** Máquina atacante ubicada en la red externa, el objetivo es comprometer los sistemas internos de la empresa.
2. **Darkhole 1 (192.168.2.x / 10.0.2.x):** Servidor en la red perimetral que actúa como puente entre la red externa e interna, permite el movimiento lateral hacia la red interna.
3. **Darkhole 2 (10.0.2.x):** Servidor crítico ubicado exclusivamente en la red interna, objetivo final.

## **Informe Pentesting**

Se adjunta un informe donde se resume el proceso de pentesting, donde se capturan los hallazgos, la metodología utilizada y las recomendaciones para mejorar la seguridad de la infraestructura.

## **Habilidades empleadas**

### **DarkHole 1**

* Enumeración Web
* Abuso del panel de cambio de contraseña - Cambio de contraseña para el usuario administrador
* Abuso de carga de archivos - Subida de un archivo PHAR malicioso
* Abuso de un binario SUID personalizado - [User pivoting]
* Abuso de privilegios sudoers - Manipulación de scripts en Python [Privilege escalation]

### **DarkHole 2**

* Fuga de Información
* Enumeración de proyecto en GitHub
* SQLI (Inyección SQL)
* Chisel (Remote Port Forwarding) + Abuso del Servidor Web Interno
* Bash history - Fuga de Información [User pivoting]
* Abuso de privilegios sudoers [Privilege escalation]

## **Enumeración**

### **Descubrimiento de hosts**

Utilizamos **arp-scan** para descubrir los dispositivos activos en nuestra red, fijamos como objetivo el host **192.168.2.129**

![imagen](https://github.com/user-attachments/assets/1787b025-78b6-42e1-96a8-91c30f658a85)

Usamos **ping** para verificar la conectividad del host **192.168.2.129**, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del **TTL (Time To Live)** también podemos identificar que se trata de un equipo Linux.

![imagen](https://github.com/user-attachments/assets/38ed40c1-8f61-41f0-abdf-6b6a1f791f03)

### **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta **whichSystem.py**, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. **Windows tiene un ttl=128** y **Linux tiene un ttl=64** por defecto.

![imagen](https://github.com/user-attachments/assets/c45068ba-2b06-4972-9946-293092cfd888)

### **Nmap (Network Mapper)**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos sobre la dirección IP objetivo **192.168.2.129**, usando los siguientes parámetros:

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

![imagen](https://github.com/user-attachments/assets/f32341c2-1096-4b57-8dba-24eb13237688)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.2.129**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![imagen](https://github.com/user-attachments/assets/d6f4a8ed-17ad-4505-883f-66d663e0ebab)

#### Detalles del escaneo

En el escaneo realizado a la dirección IP objetivo **192.168.2.129**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 22         | SSH           | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux) |
| 80         | HTTP          | Apache HTTPD 2.4.41 (Ubuntu) |
