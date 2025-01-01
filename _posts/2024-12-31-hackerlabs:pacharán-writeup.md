---
title: TheHackersLabs, Pacharán Pentesting, WriteUp
date: 2024-12-31
description: Writeup de la máquina Pacharán de la página TheHackerLabs
categories: [Writeup's, Active Directory]
tags: [Hacking, Pentesting]
image_path: https://github.com/user-attachments/assets/9d118570-9421-4d26-918a-b396af39a2b9
image: https://github.com/user-attachments/assets/9d118570-9421-4d26-918a-b396af39a2b9
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/ce605901-9ff5-42cc-b822-984c468ef86d)


En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es Pacharán, con dirección IP 192.168.1.132

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/bed9a231-6ac7-4118-89c8-a6fce4b4688e" alt="machine info" width=700px></div>

## **Habilidades empleadas**

* Ataque Domain Zone Transfer - AXFR (Fallido)
* Enumeración anónima RPC (Fallido)
* Enumeración SMB (netexec + smbclient)
* Fugas de información
* RID Brute-Force para identificar usuarios válidos (netexec)
* Password Spraying (netexec)
* AS-REP Roasting con impacket (Fallido)
* Kerberoasting con impacket (Fallido)
* Enumeración de impresores RPC (fuga de información) [Gain access]
* Abuso del privilegio SeLoadDriverPrivilege [Privilege escalation]
* Volcado de contraseñas en formato hash (mimikatz)
* Pass The Hass (evil-winrm)

## **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 192.168.1.132, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Windows.

![imagen](https://github.com/user-attachments/assets/0224c6ff-d245-4dc0-92c2-32df07f5adf3)

## **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta whichSystem.py, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. Windows tiene un ttl=128 y Linux tiene un ttl=64 por defecto.

![imagen](https://github.com/user-attachments/assets/c1cd1c27-9039-4a29-8b39-c37af5d938e6)

## **Nmap (Network Mapper)**

### **Escaneo de Puertos TCP**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos TCP sobre la dirección IP objetivo **192.168.1.132**, usando los siguientes parámetros:

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

![imagen](https://github.com/user-attachments/assets/3a24cf2e-bf07-43f0-aad5-ad396d03d960)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.1.132**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![imagen](https://github.com/user-attachments/assets/1f368332-4398-4a63-80dd-0c20b675791d)

### **Detalles del escaneo**

En el escaneo de puertos TCP realizado a la dirección IP objetivo **192.168.1.132**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 53         | DNS           | Simple DNS Plus |
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
| 49670      | MSRPC         | Microsoft Windows RPC |
| 49674      | NCACN_HTTP    | Microsoft Windows RPC over HTTP 1.0 |
| 49675      | MSRPC         | Microsoft Windows RPC |
| 49677      | MSRPC         | Microsoft Windows RPC |
| 49681      | MSRPC         | Microsoft Windows RPC |
| 49692      | MSRPC         | Microsoft Windows RPC |
| 49727      | MSRPC         | Microsoft Windows RPC |

También se ha encontrado un dominios el cual es **"PACHARAN.THL"**, lo añadimos en el **/etc/hosts** para que resuelva el nombre de dominio a la direccion IP víctima **192.168.1.132**.

![imagen](https://github.com/user-attachments/assets/2ac0362a-db3b-4188-ac48-b78c614fb92d)

## **Enumeración de servicios (DNS - Puerto 53)**

Intentamos realizar una transferencia de zona con **dig** para obtener toda la información de la base de datos de registros DNS, el resultado que obtenemos es una transferencia fallida.

![imagen](https://github.com/user-attachments/assets/3a3cb887-fd67-48ce-86ed-0071836b01d5)

## **Enumeración de servicios (RPC - Puerto 139)**

Usamos la herramienta **rpcclient** conectándonos de forma anónima e intentando enumerar los usuarios del dominio **PACHARAN.THL**, la operación resulta fallida.

![imagen](https://github.com/user-attachments/assets/25c80d36-ef0b-434f-bf0c-c07a24f31165)

## **Enumeración de servicios (SMB - Puerto 445)**

Utilizamos la herramienta netexec usando usuario nulo y contraseña nula para comprobar si el servidor admite conexiones anónimas.

![imagen](https://github.com/user-attachments/assets/7e66d439-92ae-44b8-b7d3-bb9dc0eae11a)

Como el servidor SMB admite conexiones nulas seremos capaces de listar los recursos compartidos y comprobar si en alguno de ellos podemos leer o escribir.

![imagen](https://github.com/user-attachments/assets/022e2078-eac8-4a18-98bf-228a287a97d0)

Tenemos capacidad de lectura en dos recursos compartidos los cuales son **"IPC$"** y **"NETLOGON2"**, **IPC$** es principalmente para la administración y las operaciones internas del sistema por lo tanto no es relevante en este momento, accedemos con **smbclient** al recurso **NETLOGON2**

![imagen](https://github.com/user-attachments/assets/3046bdb4-fc03-4338-ae2d-1a0a947e0e0a)

Visualizamos el archivo **"Orujo.txt"** en el cual podemos ver una fuga de información sensible, en este caso una contraseña la cual es `Pericodelospalotes6969`

![imagen](https://github.com/user-attachments/assets/f920aa78-e2f5-4c11-8db0-390d6a52afe9)

No disponemos de usuarios disponibles y no hemos sido capaces de enumerarlos con la herramienta **rpcclient**, tenemos otra opcion la cual es utilizar el módulo **rid-brute** de la herramienta **netexec** el cual nos permite enumerar los RIDs para identificar usuarios en el sistema mediante el protocolo SMB.

![imagen](https://github.com/user-attachments/assets/929be565-f552-43d3-a0f0-034dd89936b9)

Obtenemos los usuarios y los almacenamos en un archivo llamado **users.txt**

![imagen](https://github.com/user-attachments/assets/3e1fcf3c-66cd-48f4-a227-5e032e39e143)

Con la lista de usuarios obtenida realizamos un **Password Spraying** con **netexec** para comprobar si la contraseña `Pericodelospalotes6969` es válida para alguno de los usuarios. El resultado obtenido indica que la contraseña es válida para el usuario **"Orujo"**

![imagen](https://github.com/user-attachments/assets/5d460fc4-58b6-4c8c-9105-c6bf9c8dfd35)

Comprobamos con **netexec** si con el usuario **"Orujo"** y la contraseña `Pericodelospalotes6969` tenemos permisos de lectura sobre mas recursos, el resultado obtenido es que tenemos permisos de lectura sobre un recurso nuevo llamado **PACHARAN**

![imagen](https://github.com/user-attachments/assets/131bb79b-bd81-405d-97aa-952244380477)

Accedemos con **smbclient** al recurso **PACHARAN** utilizando las credenciales `Orujo:Pericodelospalotes6969`

![imagen](https://github.com/user-attachments/assets/44c79890-203d-42a8-b51b-443c38b5b1dd)

Visualizamos el archivo **"ah.txt"** en el cual podemos ver una lista de posibles credenciales.

![imagen](https://github.com/user-attachments/assets/1b80ce14-ebb0-46b5-bca9-798f900a11b5)

Utilizamos la herramienta **netexec** para realizar un **Password Spraying** con la lista de usuarios y la lista de contraseñas de la cual disponemos. El resultado obtenido indica que el usuario **"Whisky"** y la contraseña `MamasoyStream2er@` son válidos.

![imagen](https://github.com/user-attachments/assets/9215ae09-ae4b-401f-8313-9f29a758ef60)

![imagen](https://github.com/user-attachments/assets/1d0f7dc3-8813-4806-99c3-326d76417c6c)

Comprobamos con **netexec** si con el usuario **"Whiksy"** y la contraseña `MamasoyStream2er@` tenemos permisos de lectura sobre mas recursos, el resultado obtenido es que tenemos permisos de lectura sobre los recursos **IPC$** y **NETLOGON**

![imagen](https://github.com/user-attachments/assets/6d93b48e-38ee-4178-a59a-ce5c693402a4)

Nos conectamos con **smbclient** al recurso compartido **NETLOGON** proporcionando las credenciales `Whisky:MamasoyStream2er@`, puediendo observar que no hay contenido en el recurso.

![imagen](https://github.com/user-attachments/assets/2832b36c-a26a-466c-acfb-f020fe95f488)

### **Enumeración de servicios (KERBEROS - Puerto 88)**

Disponemos de una lista potencial de usuarios, con la cual podemos intentar realizar un ataque llamado **AS-REP Roast**, este ataque se aprovecha de la autenticación Kerberos, si algún usuario tiene habilitada la opción de no pedir la autenticación previa de Kerberos obtendremos un TGT cifrado el cual podemos crackear de forma offline posteriormente. El resultado del AS-REP Roast resulta fallido.

![imagen](https://github.com/user-attachments/assets/070e5624-4265-4eb2-a85c-8dd97f34bb69)

Disponemos de dos usuarios junto con sus respectivas contraseñas, con los cuales podemos intentar realizar un ataque llamado **Kerberoasting**, este ataque se aprovecha de la funcionalidad de delegación de servicios en Kerberos, si alguno de los usuarios tiene asociado un **SPN (Service Principal Name)**, podremos solicitar un **ticket de servicio (TGS)** cifrado con la contraseña del usuario del servicio correspondiente y crackearlo de forma offline posteriormente. El resultado del Kerberoasting resulta fallido.

![imagen](https://github.com/user-attachments/assets/f4f3b32c-5c78-40a9-8218-fc686a5f8297)

## **Enumeración de servicios (RPC - Puerto 139)**

Usamos la herramienta **rpcclient** conectándonos con las credenciales `Whisky:MamasoyStream2er@`, utilizamos el comando **enumprinters** para enumerar las impresoras configuradas en el servidor y sus correspondientes descripciones, pudiendo obtener una contraseña la cual es `TurkisArrusPuchuchuSiu1`

![imagen](https://github.com/user-attachments/assets/470ee8fa-e7a6-4294-a46e-6df551f77563)

Utilizamos la herramienta **netexec** para realizar un **Password Spraying** y comprobar si la contraseña `TurkisArrusPuchuchuSiu1` es válida para alguno de los usuarios. El resultado obtenido indica que la contraseña es válida para el usuario **"Chivas Regal"**

![imagen](https://github.com/user-attachments/assets/06efc187-1d3b-4589-903f-9b384e1c5e40)

## **Ganando acceso**

Validamos con **netexec** si alguno de los usuarios y contraseñas que hemos recopilado hasta el momento tiene capacidad de autenticarse mediante **winrm**. El resultado obtenido es que el usuario **"Chivas Regal"** puede autenticarse con la contraseña `TurkisArrusPuchuchuSiu1`.

![imagen](https://github.com/user-attachments/assets/0a4578f1-9085-403b-8d2e-6e7572ba6a19)

Usamos la herramienta **evil-winrm** para autenticarnos y ganar acceso al sistema como el usuario **"Chivas Regal"** 

![imagen](https://github.com/user-attachments/assets/5e426d7d-b0a7-4b81-8112-275ec855eeef)

## **Escalada de privilegios**

### Abuso de los privilegios asociados al usuario

Utilizamos el comando **whoami /priv** para listar los permisos asociados el usuarios actual. Podemos observar que unos de los privilegios es **SeLoadDriverPrivilege** el cual permite a un usuario cargar y descargar controladores de dispositivos en el kernel de Windows, este privilegio es extremadamente poderoso porque los controladores de dispositivos se ejecutan en modo kernel, lo que les otorga un control total sobre el sistema operativo.

![imagen](https://github.com/user-attachments/assets/ba9b21a1-ec63-44e0-80ff-06ce0022fa6e)

Creamos un payload que con **msfvenom** que contengan una revserse shell hacia nuestro equipos de atacante por el **puerto 4444** y lo llamamos **rev.exe**

![imagen](https://github.com/user-attachments/assets/ca877f5f-5c3f-4c88-8499-2fc8a0cffcff)

Creamos un directorio llamado **Temp** en el sistema victima y transferimos **Capcom.sys**, **LoadDriver.exe**, **rev.exe** y **ExploitCapcom.exe**

![imagen](https://github.com/user-attachments/assets/a438ebec-6bc4-4396-848e-ebfd0bb3b9e0)

Invocamos **LoadDriver.exe**, **obtenemos NTSTATUS: 00000000, WinError: 0**, si no hubiera sido así tendriamos que intentar cambiar la ubicación de **Capcom.sys** o la ubicación desde donde estamos ejecutando **LoadDriver.exe.**

![imagen](https://github.com/user-attachments/assets/e13f0b3e-768c-4601-b449-61c156777cb2)

Inicamos un listener con **netcat** desde la máquina atacante por el puerto indicado en el payload de **msfvenom**, usando los siguientes parámetros:

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-l`          | Activa el modo servidor para aceptar conexiones entrantes. |
| `-v`          | Proporciona información detallada sobre las conexiones. |
| `-n`          | Evita la resolución de nombres de host a IP.   |
| `-p`          | Especifica el puerto en el que netcat escuchará. |

![imagen](https://github.com/user-attachments/assets/56f1ef84-4527-41a0-816a-3b710927d0a1)

Ejecutamos **ExploitCapcom.exe** e indicamos donde se aloja la reverse shell.

![imagen](https://github.com/user-attachments/assets/ecf96a20-c5e2-4b30-b2d9-156b3b5f0868)

Conseguimos ganar acceso al sistema como **nt authority\system**

![imagen](https://github.com/user-attachments/assets/4309b253-6bb4-431f-8648-efcd176da4c7)

## **Post Explotación**

Creamos un servidor en Python y compartimos **mimikatz.exe**

![imagen](https://github.com/user-attachments/assets/5d8e5187-7e51-4293-aa73-fac53a18b85c)

En la máquina victima nos descargamos con **certutil** el **mimikatz.exe**

![imagen](https://github.com/user-attachments/assets/cb84340f-c2ee-476e-944e-ccfce00e66b9)

Iniciamos **mimikatz.exe** y ejecutamos `privilege::debug`, debemos de obtener como respuesta `Privilege '20' OK`, esto nos garantiza que estamos corriendo mimikatz como administrador.

![imagen](https://github.com/user-attachments/assets/7077fea8-fb74-4e25-85e7-2413cd3097e9)

Ejecutamos el comando `lsadump::lsa /patch` para modificar el proceso LSASS y extraer los hashes de las contraseñas de los usuarios.

![imagen](https://github.com/user-attachments/assets/79593c84-4aa8-4a88-a2ed-f651bda33e21)

Por ultimo habiendo obtenido el **Hash NTLM** de todos los usuarios podríamos crackearlos con herramientas como **hashcat** o realizar un **Pass The Hash** con herramientas como **impacket-psexec** o **evil-winrm**.

![imagen](https://github.com/user-attachments/assets/f14dd395-59b6-4dfa-833d-520b8a752830)
