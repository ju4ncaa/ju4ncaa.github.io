---
title: HackTheBox, Cicada Pentesting, WriteUp
date: 2024-12-25
description: Writeup de la máquina UnderPass de la página HackTheBox
categories: [Writeup's]
tags: [Hacking, Pentesting, Active Directory]
image_path: https://github.com/user-attachments/assets/a5fd9492-c574-40df-9fa4-0952ae30b6c4
image: https://github.com/user-attachments/assets/a5fd9492-c574-40df-9fa4-0952ae30b6c4
---

## **Introducción**

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es Cicada, con dirección IP 0.0.0.0

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/97dadd82-4f78-4a00-98bc-f126413e0d04" alt="machine info" width=700px></div>

## **Habilidades empleadas**

## **Enumeración**

### **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 0.0.0.0, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Linux.
