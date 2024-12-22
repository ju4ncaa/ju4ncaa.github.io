---
title: VulnHub, DarkHole2 Pentesting, WriteUp
date: 2024-12-21
description: WriteUp de la máquina DarkHole 2 de la página VulnHub
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: https://i.ibb.co/5RvhKwb/darkhole2.png
image: https://i.ibb.co/5RvhKwb/darkhole2.png
---

## **Habilidades empleadas**

* Fuga de información
* Enumeración de Proyectos en Github
* Inyección SQL (SQL Injection)
* Chisel (Remote Port Forwarding) + Abuso de Servidor Web Interno
* Bash history - Fugas de información [User Pivoting]
* Abuso de privilegios sudoers -  [Privilege escalation]

## **Enumeración**

### **Descubrimiento de hosts**

Utilizamos **arp-scan** para descubrir los dispositivos activos en nuestra red, fijamos como objetivo el host **192.168.2.131**

![imagen](https://github.com/user-attachments/assets/d4e7328f-f07b-4415-9432-1c1d0f011c03)

Usamos **ping** para verificar la conectividad del host **192.168.2.131**, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del **TTL (Time To Live)** también podemos identificar que se trata de un equipo Linux.

![imagen](https://github.com/user-attachments/assets/1ad59142-8eee-4762-931e-4e740b49f175)

### **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta **whichSystem.py**, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. **Windows tiene un ttl=128** y **Linux tiene un ttl=64** por defecto.

![imagen](https://github.com/user-attachments/assets/49803cc1-cf64-47bc-88d8-f01a1b176c5d)

### **Nmap (Network Mapper)**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos sobre la dirección IP objetivo **192.168.2.131**, usando los siguientes parámetros:

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

![imagen](https://github.com/user-attachments/assets/d6ddbcdd-ac12-4e13-8098-2bd6ffcb58fe)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.2.131**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![imagen](https://github.com/user-attachments/assets/8c6c9226-a2cf-4d07-8d82-74259d0fa83b)

#### **Detalles del escaneo**

En el escaneo realizado a la dirección IP objetivo **192.168.2.131**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones. Ademas se ha podido identificar un repositorio git en **192.168.2.131:80/.git/**

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 22         | SSH           | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)|
| 80         | HTTP          | Apache httpd 2.4.41 (Ubuntu) |

### **Enumeración de servicios (SSH - Puerto 22)**

La versión de **OpenSSH 8.2p1** no es vulnerable a la enumeración de usuarios, y no se encontraron usuarios accesibles para realizar ataques de fuerza bruta.

### **Enumeración de servicios (HTTP - Puerto 80)**

#### **WhatWeb**

Utilizamos la herramienta **WhatWeb**, esta nos permite obtener información detallada sobre el servidor web, incluyendo el software utilizado, tecnologías relacionadas y posibles vulnerabilidades.

![imagen](https://github.com/user-attachments/assets/1df60098-b943-4d0b-b173-066c6fdeb889)

#### **Reconocimiento web inicial**

Accedemos al servicio web HTTP a través de `http://192.168.2.131`, podemos identificar que existe una opción **Login**.

![imagen](https://github.com/user-attachments/assets/bc6a1ab9-3527-433a-a5f9-c167d8fc8545)

Accedemos a **Login** y probamos diferentes combinaciones de credenciales para intentar acceder, sin exito ninguno.

![imagen](https://github.com/user-attachments/assets/dc2961fb-942a-41c8-9f48-6f058e1a2cab)

Intentamos difentes inyecciones SQL típicas, sin exito ninguno.

![imagen](https://github.com/user-attachments/assets/8d0dffc2-d35a-4093-9062-bfd77f1a47cc)

![imagen](https://github.com/user-attachments/assets/e92e141f-ca6d-4984-8701-cac507979198)

![imagen](https://github.com/user-attachments/assets/3afe84cb-eb44-4d00-a479-bf3b612ef00b)

#### **Enumeración de proyecto git**

Accedemos al **proyecto git** detectado con **Nmap** el cual se encuentra alojado en http://192.168.2.131/.git

![imagen](https://github.com/user-attachments/assets/900c35c5-c33f-47d4-a28e-db2034022cd2)

Descargamos con **wget** de forma recursiva todo el contenido del proyecto.

![imagen](https://github.com/user-attachments/assets/cc3b4f6f-f208-48ab-a8cc-5f29f19d14f3)

Utilizamos **tree** para mostrar el contenido descargado de manera mas visual, es decir, en forma de árbol. No observamos nada relevante en el contenido.

![imagen](https://github.com/user-attachments/assets/ed3c426d-1cc3-46a1-b1da-07a6c6cdd106)

Utilizamos el comando **git log** para enumerar todos los commit del proyecto en orden cronológico inverso. Podemos observar un commit importante donde se indica que se han añadido a **login.php** las credenciales por defecto.

![imagen](https://github.com/user-attachments/assets/5c3fc9ad-3e1a-4d7b-bebb-2f2cc14c39a2)

Utilizamos el comando **git show** para visualizar el commit **a4d900a8d85e8938d3601f3cef113ee293028e10** de forma detallada. Obtenemos las credenciales por defecto: `lush@admin.com - 321`

![imagen](https://github.com/user-attachments/assets/5907accf-4d69-4da7-a566-d12acb4c6b7e)

## **Análisis de vulnerabilidades**

Accedemos a la web como el usuario `lush@admin.com - 321` y la vista inicial es un panel donde se muestran nuestros datos de usuario y un boton submit. Por otro lado en la URL tenemos un **parámetro GET** **?id=** con valor **1**

![imagen](https://github.com/user-attachments/assets/4682b540-b430-4d8e-80b6-f9a81b6f4e40)


![imagen](https://github.com/user-attachments/assets/fb405603-c41f-4012-aa4a-58c9f8fd84a8)

