---
title: TheHackersLabs, B.I.G Pentesting, WriteUp
date: 2025-01-02
description: Writeup de la máquina B.I.G de la página TheHackerLabs
categories: [Writeup's, Active Directory]
tags: [Hacking, Pentesting, Active Directory]
image_path: https://github.com/user-attachments/assets/e89004dd-95c1-40ab-a2b3-fc59b236d233
image: https://github.com/user-attachments/assets/e89004dd-95c1-40ab-a2b3-fc59b236d233
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/5e3bac00-b9dd-4f1d-8d94-30a62b3026be)

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux, con dirección IP 192.168.1.133, que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es B.I.G, con dirección IP 192.168.1.138. Ambas máquinas están conectadas en la misma red local privada (192.168.1.0/24).

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/86b2da18-3a25-41d9-8957-b1f3c1952d27" alt="machine info" width=700px></div>

## **Habilidades empleadas**

* Ataque Domain Zone Transfer - AXFR (Fallido)
* Enumeración anónima RPC (Fallido)
* Enumeración anónima de recursos SMB  (Fallido)

## **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 192.168.1.138, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Windows.

![imagen](https://github.com/user-attachments/assets/c602a5a3-a03f-4f16-a407-5b37532ca0b5)

## **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta whichSystem.py, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. Windows tiene un ttl=128 y Linux tiene un ttl=64 por defecto.

![imagen](https://github.com/user-attachments/assets/b5972d21-fcb2-4c59-89a2-cc4ffe0fd20c)

## **Nmap (Network Mapper)**

### **Escaneo de Puertos TCP**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos TCP sobre la dirección IP objetivo **192.168.1.138**, usando los siguientes parámetros:

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

![imagen](https://github.com/user-attachments/assets/d3c61574-cf52-4424-b57c-f42eee0f5693)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.1.138**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![imagen](https://github.com/user-attachments/assets/cb6beacb-bce7-4cec-8de0-63d0acf417d9)

### **Detalles del escaneo**

En el escaneo de puertos TCP realizado a la dirección IP objetivo **192.168.1.138**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 53         | DNS           | Simple DNS Plus |
| 80         | HTTP          | Microsoft IIS httpd 10. |
| 88         | KERBEROS      | Microsoft Windows Kerberos |
| 135        | MSRPC         | Microsoft Windows RPC |
| 139        | NETBIOS-SSN   | Microsoft Windows netbios-ssn |
| 389        | LDAP          | Microsoft Windows Active Directory LDAP |
| 445        | MICROSOFT-DS  | - |
| 464        | KPASSWD5      | - |
| 593        | NCACN_HTTP    | Microsoft Windows RPC over HTTP 1.0 |
| 636        | SSL/LDAP      | Microsoft Windows Active Directory LDAP |
| 3268       | LDAP          | Microsoft Windows Active Directory LDAP |
| 3269       | SSL/LDAP      | Microsoft Windows Active Directory LDAP |
| 5985       | WINRM         | Microsoft HTTPAPI httpd 2.0 |
| 9389       | MC-NMF        | .NET Message Framing |
| 47001      | HTTP          | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) |
| 49664      | MSRPC         | Microsoft Windows RPC |
| 49665      | MSRPC         | Microsoft Windows RPC |
| 49666      | MSRPC         | Microsoft Windows RPC |
| 49667      | MSRPC         | Microsoft Windows RPC |
| 49669      | MSRPC         | Microsoft Windows RPC |
| 49671      | MSRPC         | Microsoft Windows RPC |
| 49672      | MSRPC         | Microsoft Windows RPC |
| 49674      | MSRPC         | Microsoft Windows RPC |
| 49677      | MSRPC         | Microsoft Windows RPC |
| 49687      | MSRPC         | Microsoft Windows RPC |

También se ha encontrado un dominios el cual es **"bbr.thl"**, lo añadimos en el **/etc/hosts** para que resuelva el nombre de dominio a la direccion IP víctima **192.168.1.138**.

![imagen](https://github.com/user-attachments/assets/ac602701-08dc-4df0-9f9a-3c3844dd45be)

## **Enumeración de servicios (DNS - Puerto 53)**

Intentamos realizar una transferencia de zona con **dig** para obtener toda la información de la base de datos de registros DNS, el resultado que obtenemos es una transferencia fallida.

![imagen](https://github.com/user-attachments/assets/2c8a21ee-26b7-4dcb-8d06-582f3d4c8181)


## **Enumeración de servicios (RPC - Puerto 139)**

Usamos la herramienta **rpcclient** conectándonos de forma anónima e intentando enumerar los usuarios del dominio **bbr.thl**, la operación resulta fallida.

![imagen](https://github.com/user-attachments/assets/c2e7b435-c081-4564-95a7-e75604a3e9ff)

## **Enumeración de servicios (SMB - Puerto 445)**

Utilizamos la herramienta netexec usando usuario nulo y contraseña nula para comprobar si el servidor admite conexiones anónimas. El resultado obtenido es un **STATUS_LOGON_FAILURE** lo que nos indica que el servidor no admite conexiones nulas.

![imagen](https://github.com/user-attachments/assets/818ca3ee-499d-4174-8ded-ae28f2543120)

## **Enumeración de servicios (HTTP - Puerto 80)**

### **WhatWeb**

Utilizamos la herramienta **WhatWeb**, esta nos permite obtener información detallada sobre el servidor web, incluyendo el software utilizado, tecnologías relacionadas y posibles vulnerabilidades.

![imagen](https://github.com/user-attachments/assets/cb3ac795-7fed-43b6-8164-a465192e4d91)

### **Reconocimiento web inicial**

Accedemos al servicio web HTTP a través de `http://192.168.1.138`, podemos observar a simple vista una imagen.

![imagen](https://github.com/user-attachments/assets/d6c60e83-b21f-43fc-81a2-58d73f17febc)

### **Gobuster**

Utilizamos la herramienta **Gobuster** para realizar un escaneo de directorios y archivos en el servidor web objetivo alojado en la dirección IP **192.168.1.138**, empleando los siguientes parámetros:

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `dir`         | Modo dir, búsqueda de directorios y archivos. |
| `-u`          | Permite especificar la URL o dirección del objetivo que será analizada. |
| `-w`          | Permite indicar el archivo de palabras que se utilizará como diccionario para el escaneo. |
| `-t`          | Permite definir el número de hilos que Gobuster utilizará para ejecutar el escaneo en paralelo. |

![imagen](https://github.com/user-attachments/assets/d2de0df9-1530-4045-957d-8b54f98eca1d)

En el escaneo de directorios y archivos realizado con **Gobuster** a la dirección IP objetivo **192.168.1.138**, se han identificado las siguientes rutas accesibles, así como posibles archivos y directorios presentes en el servidor.

| **Ruta**             | **Estado** | Redirección                          |
|----------------------|------------|--------------------------------------|
| /images              | 301        | `http://192.168.1.138/images/`       |
| /Images              | 301        | `http://192.168.1.138/Images/`       |
| /contents            | 301        | `http://192.168.1.138/contents/`     |
| /IMAGES              | 301        | `http://192.168.1.138/IMAGES/`       |
| /songs               | 301        | `http://192.168.1.138/songs/`        |
| /Contents            | 301        | `http://192.168.1.138/Contents/`     |
| /Songs               | 301        | `http://192.168.1.138/Songs/`        |

### **Inspección de directorios**

Comenzamos accediendo al directorio **/images** podemos observar 4 imagenes **big[1,2,3,4].jpg** y un archivo **web.config** al cual si intentamos acceder obtenemos un **404 - Not Found**. Nos descargamos las 4 imágenes a nuestro equipo local para inspeccionarlas mas tarde.

![imagen](https://github.com/user-attachments/assets/ce18bd63-a0e5-4877-b59b-b741f2046a16)

![imagen](https://github.com/user-attachments/assets/ec24370a-2127-45cd-8f54-6581d3cd4641)

Accedemos tambien al directorio **/contents**, en este podemos observar un fichero llamado **notify.txt** y el archivo **web.config**, al cual si intentamos acceder obtenemos un **404 - Not Found**, si visualizamos el fichero **notify.txt** podemos leer una nota donde se quejan de que hay alguien que esta ocultando claves en formato **MD5**

![imagen](https://github.com/user-attachments/assets/0f29f826-5bf6-4088-88ef-217635b9f1bf)

Por último accedemos al directorio **/songs** donde podemos osbervar diferentes canciones, pero si accedemos al utlimo archivo llamado **Skyisthelimit.txt** vemos lo que es una lista de posibles contraseñas potenciales. Nos descargamos todos los archivos del directorio.

![imagen](https://github.com/user-attachments/assets/d1c402e0-e637-4c3f-8e8c-a2d490b6fbeb)
