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

* 

## **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 192.168.1.138, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Windows.

![imagen](https://github.com/user-attachments/assets/c602a5a3-a03f-4f16-a407-5b37532ca0b5)

## **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta whichSystem.py, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. Windows tiene un ttl=128 y Linux tiene un ttl=64 por defecto.

![imagen](https://github.com/user-attachments/assets/b5972d21-fcb2-4c59-89a2-cc4ffe0fd20c)
