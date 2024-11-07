---
title: Resolución CTF HackMyVM:Venus, Level 0-50 Write-Up
description: En este apartado se resuleven los 50 niveles del CTF de HackMyVM Venus.
date: 2024-11-7
categories: [CTFs]
tags: [CTFs, Linux]
img_path: https://i.ibb.co/j5SFvBf/venus.png
image: https://i.ibb.co/j5SFvBf/venus.png
---

## **Introducción**

En este apartado se resuelven los 50 niveles del CTF de HackMyVM Venus, son una serie de retos que se simulan escenarios del mundo real, permitiendo ponerte a prueba y mejorar tus habilidades de hacking ético, resolución de vulnerabilidades y análisis de sistemas. En definitva es una paso mas allá de Bandit ya que los retos son más complejos y requieren una comprensión más profunda de técnicas de hacking y seguridad informática. Por eso si estás comenzando en el mundo de la ciberseguridad, te recomendaría empezar con Bandit para aprender lo básico y luego avanzar hacia Venus.

### ¿Empezamos?
* **Objetivo:** Utilizar el cliente SSH para conectarse a Venus.
* **Host:** venus.hackmyvm.eu
* **Puerto:** 5000
* **Nombre de usuario** hacker
* **Contraseña:** havefun!

Utilizamos ssh para conectarnos remotamente al CTF utilizando los siguientes parámetros:
* **-p:** Indicasr puerto al que conectarse en el host remoto.
* **-q:** Modo silencioso para suprimir la mayoría de los mensajes de advertencia y diagnóstico.

![image](https://github.com/user-attachments/assets/f21c34ec-c7c6-4ad1-b78d-edb3198ea87f)

### Level 0 -> Level 1
* **Misión:** La usuaria sophia ha guardado su contraseña en un fichero oculto en esta carpeta . Encuentralo y logueate como sophia.
* **Contraseña sophia:** Y1o645M3mR84ejc

Utilizamos el comando **ls** el cual permite listar el contenido del directorio en el que nos encontramos y lo combinamos con el parámetro **-a** lo cual permite mostrar todos los archivos incluidos los ocultos.

![image](https://github.com/user-attachments/assets/14becad5-9719-417f-a9d5-0caa904ea546)

Observamos que existe un fichero oculto llamado **".myhiddenpazz"** al cual si realizamos un **cat** obtenemos la contraseña del usuario sophia.

![image](https://github.com/user-attachments/assets/a3ae83a7-2fdb-4616-8823-bec0bcb6ee93)
