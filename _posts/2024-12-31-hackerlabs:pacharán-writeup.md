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

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es Cicada, con dirección IP 0.0.0.0

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/bed9a231-6ac7-4118-89c8-a6fce4b4688e" alt="machine info" width=700px></div>

## **Habilidades empleadas**

* 1

## **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 10.10.11.35, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Windows.



## **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta whichSystem.py, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. Windows tiene un ttl=128 y Linux tiene un ttl=64 por defecto.

