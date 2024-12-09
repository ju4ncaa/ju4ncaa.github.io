---
title: Resolución INE CTF Arena 
description: Resolución del CTF PortStorm de INE Security
date: 2024-12-9
categories: [CTFs, Hacking]
tags: [CTFs, Hacking]
img_path: https://i.ibb.co/L8B5h2z/inectf.png
image: https://i.ibb.co/L8B5h2z/inectf.png
---

## **Introducción**

Este desafío CTF está diseñado como un escenario de penetración en una red de múltiples capas, simulando un entorno realista con niveles de seguridad cada vez más complejos. Los participantes deben de emplear diversas técnicas para moverse lateralmente entre equipos, realizar pivoting a través de redes restringidas y escalar privilegios con el fin de capturar las banderas ocultas en cada máquina. El desafío pone énfasis en el descubrimiento de redes, la explotación de vulnerabilidades y el uso de enfoques creativos para obtener acceso en condiciones de alta restricción.

### The Flaw is a map, trace it

* **Introducción:** En este entorno de laboratorio, se proporciona una máquina GUI Kali equipada con todas las herramientas necesarias para la explotación y un objetivo vulnerable situado en target.ine.local. La bandera está en un formato de hash md5.
* **Objetivo:** Enumerar el objetivo proporcionado, identificar cualquier vulnerabilidad y explotarlas para obtener todas las banderas.
* **Flag:**

Comprobamos conectividad con el objetivo **target.ine.local (10.2.30.147)**

![image](https://github.com/user-attachments/assets/9d62f6cb-2348-4f07-927e-2c5a212c2201)

Utilizamos la herramienta **Nmap (Network Mapper)** y realizamos un escaneo de **puertos**, **versiones** y **scripts básicos** de reconocimiento.

![image](https://github.com/user-attachments/assets/50383aab-4dcb-4fb3-9757-c13d17b1345b)

![image](https://github.com/user-attachments/assets/07e4951c-3064-4d97-82a6-b9144e352e56)

Accedemos a **https://10.2.30.147:8443** y obtenemos un **404 Not Found** de **Apache Tomcat**

![image](https://github.com/user-attachments/assets/040d39ab-b3f5-421d-9073-c1916dfb1b1e)

Utilizamos la herramienta de fuzzing **Gobuster** para realizar un descubrimiento de directorios ocultos, obtenemos los siguientes:

* **marketing**
* **accounting**

![image](https://github.com/user-attachments/assets/fc395502-1f40-4e9e-9fe6-0f6949c65e19)

