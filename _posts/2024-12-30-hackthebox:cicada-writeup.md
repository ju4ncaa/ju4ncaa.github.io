---
title: HackTheBox, Cicada Pentesting, WriteUp
date: 2024-12-30
description: Writeup de la máquina UnderPass de la página HackTheBox
categories: [Writeup's, Active Directory]
tags: [Hacking, Pentesting, Active Directory]
image_path: https://github.com/user-attachments/assets/a5fd9492-c574-40df-9fa4-0952ae30b6c4
image: https://github.com/user-attachments/assets/a5fd9492-c574-40df-9fa4-0952ae30b6c4
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/b86cbdf6-fc55-4e3d-be8c-868bcc31d873)

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es Cicada, con dirección IP 10.10.11.35

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/97dadd82-4f78-4a00-98bc-f126413e0d04" alt="machine info" width=700px></div>

## **Habilidades empleadas**

* Ataque Domain Zone Transfer - AXFR (Fallido)
* Enumeración anónima RPC (Fallido)
* Enumeración SMB (netexec + smbclient)
* Fugas de información
* RID Brute-Force para identificar usuarios válidos (netexec)
* Password Spraying (netexec)
* AS-REP Roasting con impacket (Fallido)
* Enumeracion LDAP + Obtencion de credenciales (ldapsearch)
* Abuso del privilegio SeBackupPrivilege [Privilege escalation]
* Volcado de contraseñas en formato hash (impacket-secretsdump)
* Pass The Hass (evil-winrm)


## **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 10.10.11.35, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Windows.

![image](https://github.com/user-attachments/assets/e9f217dd-deea-4cbe-bd46-e8f63d24ede1)

## **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta whichSystem.py, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. Windows tiene un ttl=128 y Linux tiene un ttl=64 por defecto.

![image](https://github.com/user-attachments/assets/50368221-909d-48a6-97ea-61433f955ae4)

## **Nmap (Network Mapper)**

### **Escaneo de Puertos TCP**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos TCP sobre la dirección IP objetivo **10.10.11.35**, usando los siguientes parámetros:

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

![image](https://github.com/user-attachments/assets/2d3ec811-51fa-47b7-b332-85c1510d0b5d)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **10.10.11.35**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![image](https://github.com/user-attachments/assets/a4964f32-9af7-439c-999f-f9b9cde370a2)

### **Detalles del escaneo**

En el escaneo de puertos TCP realizado a la dirección IP objetivo **10.10.11.35**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 53         | DNS           | Simple DNS Plus |
| 88         | KERBEROS      | Microsoft Windows Kerberos |
| 135        | MSRPC         | Microsoft Windows RPC |
| 139        | NETBIOS-SSN   | Microsoft Windows netbios-ssn |
| 389        | LDAP          | Microsoft Windows Active Directory LDAP |
| 445        | MICROSOFT-DS  | <div align="center">-</div> |
| 464        | KPASSWD5      | <div align="center">-</div> |
| 593        | NCACN_HTTP    | Microsoft Windows RPC over HTTP 1.0 |
| 636        | SSL/LDAP      | Microsoft Windows Active Directory LDAP |
| 3268       | LDAP          | Microsoft Windows Active Directory LDAP |
| 3269       | SSL/LDAP      | Microsoft Windows Active Directory LDAP |
| 5985       | WINRM         | Microsoft HTTPAPI httpd 2.0  |
| 54750      | MSRPC         | Microsoft Windows RPC |

También se han encontrado dos dominios los cuales son **"cicada.htb"** y **"CICADA-DC.cicada.htb"**, añadimos los dominios en el **/etc/hosts** para que resuelva el nombre de dominio a la direccion IP víctima **10.10.11.35**.

![image](https://github.com/user-attachments/assets/43914c23-8b79-42e0-b7bf-8e12e5af0bae)

## **Enumeración de servicios (DNS - Puerto 53)**

Intentamos realizar una transferencia de zona con **dig** para obtener toda la información de la base de datos de registros DNS, el resultado que obtenemos es una transferencia fallida.

![image](https://github.com/user-attachments/assets/8a280c4a-e856-46f8-92b0-4b5bbe215ae1)

## **Enumeración de servicios (RPC - Puerto 139)**

Usamos la herramienta **rpcclient** conectándonos de forma anónima e intentando enumerar los usuarios del dominio **cicada.htb**, la operación resulta fallida.

![image](https://github.com/user-attachments/assets/056bf9f9-e127-4876-ad12-6abfda9100d5)

## **Enumeración de servicios (SMB - Puerto 445)**

Utilizamos la herramienta netexec utilizando usuario nulo y contraseña nula para comprobar si el servidor admite conexiones anónimas.

![image](https://github.com/user-attachments/assets/5a3beb5a-acdd-449d-a00d-56cd747b5322)

Como el servidor SMB admite conexiones nulas seremos capaces de listar los recursos compartidos y comprobar si en alguno de ellos podemos leer o escribir.

![image](https://github.com/user-attachments/assets/d980a234-f11c-4cb6-889c-3a050e494e00)

Tenemos capacidad de lectura en dos recursos compartidos los cuales son **"IPC$"** y **"HR"**, **IPC$** es principalmente para la administración y las operaciones internas del sistema por lo tanto no es relevante en este momento, accedemos con **smbclient** al recurso **HR**

![image](https://github.com/user-attachments/assets/0bde7660-f59b-4743-83cb-893013fc22c0)

Visualizamos el archivo **"Notice from HR.txt"** en el cual podemos ver una fuga de información sensible, en este caso una contraseña la cual es **Cicada$M6Corpb*@Lp#nZp!8**

![image](https://github.com/user-attachments/assets/79d12f99-fb69-4566-a3be-e1dbb6633bd1)

No disponemos de usuarios disponibles y no hemos sido capaces de enumerarlos con la herramienta **rpcclient**, tenemos otra opcion la cual es utilizar el módulo **rid-brute** de la herramienta **netexec** el cual nos permite enumerar los RIDs para identificar usuarios en el sistema mediante el protocolo SMB.

![image](https://github.com/user-attachments/assets/f8bf4bba-c259-4461-9715-79f93f6a3e8d)

Obtenemos los usuarios y los almacenamos en un archivo llamado **users.txt**

![image](https://github.com/user-attachments/assets/88ae2850-35fc-447f-87ff-2de8d9dbbd46)

Con la lista de usuarios obtenida realizamos un **Password Spraying** con **netexec** para comprobar si la contraseña **Cicada$M6Corpb*@Lp#nZp!8** es válida para alguno de los usuarios. El resultado obtenido indica que la contraseña es válida para el usuario **"michael.wrightson"**

![image](https://github.com/user-attachments/assets/744211f0-90dd-4799-b05d-87d196c3bb29)

Comprobamos con **netexec** si con el usuario **"michael.wrightson"** y la contraseña **"Cicada$M6Corpb*@Lp#nZp!8"**, tenemos permisos de lectura sobre mas recursos uno de ellos **SYSVOL**, al tratarse de un Windows Server 2022 omitimos la parte de intentar buscar el archivo **Groups.xml** y descifrar la contraseña con **gpp-decrypt**

![image](https://github.com/user-attachments/assets/b92156f1-e93d-449d-ad19-9fc7539ccefa)

### **Enumeración de servicios (KERBEROS - Puerto 88)**

Disponemos de una lista potencial de usuarios, con la cual podemos intentar realizar un ataque llamado **AS-REP Roast**, este ataque se aprovecha de la autenticación Kerberos, si algún usuario tiene habilitada la opción de no pedir la autenticación previa de Kerberos obtendremos un TGT cifrado el cual podemos crackear de forma offline posteriormente. El resultado del AS-REP Roast resulta fallido.

![image](https://github.com/user-attachments/assets/cb4608fb-fb7b-47a7-ba9d-29015beea1af)

## **Enumeración de servicios (LDAP - Puerto 389)**

Aunque ya hemos obtenido los usuarios con el módulo **rid-brute** de la herramienta **netexec** también lo realizaré con ldap para una mayor claridad.

![image](https://github.com/user-attachments/assets/0a0e6ba8-aac3-4853-8a99-6232d15509e9)

Enumeramos para buscar contraseñas con **ldapsearch** y obtenemos la credencial **"aRt$Lp#7t*VQ!3"**

![image](https://github.com/user-attachments/assets/0454500c-9919-44af-9c33-44b1ef78cc63)

## **Enumeración de servicios (SMB - Puerto 445)**

Utilizamos la herramienta **netexec** para realizar un **Password Spraying** y validar para que usuarios es válida la credencial **"aRt$Lp#7t*VQ!3"**. Obtenemos como respuesta que la contraseña es válida para el usuario **"david.orelious"**

![image](https://github.com/user-attachments/assets/f7310162-fab2-4bd9-bfd7-136f96356d66)

Utilizamos la herramienta **netexec** para listar los recursos compartidos con el usuario **"david.orelious"** y la contraseña **"aRt$Lp#7t*VQ!3"**. La respuesta obtenida es que tenemos permisos de lectura en un recurso compartido diferente a los anteriores el cual es **DEV**.

![image](https://github.com/user-attachments/assets/c7ad0136-6753-4a7d-a707-b3b175eabb12)

Accedemos con **smbclient** con el usuario **"david.orelious"** al recurso compartido **DEV** y obtenemos el archivo **Backup_script.ps1** que se encuentra disponible.

![image](https://github.com/user-attachments/assets/b0972ba3-df32-4cbd-94f9-5fc0634e7f33)

Visualizamos el archivo **Backup_script.ps1** y podemos ver que contiene una contraseña la cual es **"Q!3@Lp#M6b*7t*Vt"**

![image](https://github.com/user-attachments/assets/a6c23552-7e1b-4418-9d95-32e0de72be1a)

Utilizamos la herramienta **netexec** para realizar un **Password Spraying** y validar para que usuarios es válida la credencial **"Q!3@Lp#M6b*7t*Vt"**. Obtenemos como respuesta que la contraseña es válida para el usuario **"emily.oscars"**

![image](https://github.com/user-attachments/assets/002be751-f5f6-4134-97c3-9f71001a4fdf)

## **Ganando acceso**

Utilizamos la herramienta **netexec** para validar si el usuario **"emily.oscars"** se puede autenticar con winrm. Obtenemos como respuesta que se permite la autenticacón mediante winrm.

![image](https://github.com/user-attachments/assets/080bc19b-7f32-4831-af80-39336f5997ce)

Utilizamos evil-winrm para autenticarnos y ganar acceso al sistema como el usuario **"emily.oscars"** 

![image](https://github.com/user-attachments/assets/69bcc01c-7382-4d62-a201-368c5a60a37f)

## Escalada de privilegios

### Abuso de los privilegios asociados al usuario

Utilizamos el comando **whoami /priv** para listar los permisos asociados el usuarios actual. Podemos observar que unos de los privilegios es SeBackupPrivilege el cual permite hacer copias de seguridad de archivos y directorios, incluso si el usuario no tiene permisos explícitos sobre esos archivos. 

![image](https://github.com/user-attachments/assets/da7ce58d-cb0c-4bc8-9f8a-7ffd760ea6fe)

Nos creamos un directorio **Temporal** en **C:\** y copiamos la **SAM** y **SYSTEM**, posteriomente los descargamos a nuestra máquina atacante Kali Linux.

![image](https://github.com/user-attachments/assets/e58a4e8f-de12-4c91-98f1-589d0097be57)

Utilizamos la herramienta **impacket-secretsdump** para realizar un volcado de contraseñas en formato hash.

![image](https://github.com/user-attachments/assets/d4045264-9d44-45cb-8115-1c0c2efadb47)

Utilizamos el hash de **Administrator** para realizar un **Pass The Hash** con **evil-winrm** y ganar acceso al sistema con privilegios de administrador.

![image](https://github.com/user-attachments/assets/48233f1a-8069-42a7-9e0d-8991550590e0)
