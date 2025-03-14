---
description: >-
  Cómo descubrí mi primer Open Redirect en un programa de Bug Bounty de pago
title: Mi primer Open Redirect en un Bug Bounty de pago
date: 2025-03-14
categories: [Bug Bounty]
tags: [hacking, bug bounty, hacking web, open redirect, bugcrowd]
image_post: true
image: https://github.com/user-attachments/assets/e4a62da2-314a-47a6-ae62-3beebd4df24e

---

## ¿Qué es un Open Redirect?

Un Open Redirect es una vulnerabilidad de seguridad web en la que una aplicación permite redirigir a los usuarios a una URL externa sin validación adecuada, esto puede ser explotado para realizar phishing, engañando a las víctimas para que visiten sitios maliciosos que parecen legítimos.

## Páginas comunes donde ocurre

Los Open Redirects se ven comúnmente en:

* Páginas de Inicio de Sesión
* Páginas de Cierre de Sesión
* Páginas de Registro
* Páginas de Restablecimiento de Contraseña
* Pasarelas de Pago

## Método que Seguí para identificar el Open Redirect

Por temas de cofidencialidad del programa supondremos que estamos trabajando con un dominio ficticio, por ejemplo example.com

### Escanear Subdominios con subfinder

El primer paso en el proceso fué identificar los subdominios activos de example.com

```
subfinder -d example.com -all -recursive > subs.txt
```

### Filtrar Subdominios activos usando httpx

Después de obtener la lista de subdominios con Subfinder, el siguiente paso fué filtrar los subdominios activos 

```
cat subs.txt | httpx > alive_subs.txt
```

### Búsqueda de endpoints con Katana y Waymore

Una vez filtrados los dominios activos escogí uno que llamo mi atención, llamado production.ap01.ecm.example.com y utilice la herramienta Katana para explorar los posibles endpoints o puntos de entrada

```
katana -u https://production.ap01.ecm.example.com -jc -d 5 > katana_urls.txt
```

Para obtener una lista más exhaustiva de URLs relacionadas con production.ap01.ecm.example.com utilice Waymore

```
waymore -i production.ap01.ecm.example.com -mode U -oU waymore_urls.txt
```

###  Filtrar y Buscar Open Redirect en las URLs

Con las listas de URLs obtenidas de Katana y Waymore filtre las URLs que contenian parámetros de redirección, buscando aquellos parámetros que contienen el término =http, que podría indicar que hay una URL de redirección definida por el usuario.

```
cat katana_urls.txt | grep "=http" | sort -u | uro > openredirect_test1.txt
```

```
cat waymore_urls.txt | grep "=http" | sort -u | uro > openredirect_test2.txt
```

### Encontrar el endpoint vulnerable

En mi caso, solamente obtuve un endpoint, el cual era **https://production.ap01.ecm.example.com/login-logout?redirectURL=https%3a%2f%2fexample%2ecom%2fwelcome** 

### Probar Open Redirect

De normal no me gusta probar manualmente, pero al ser esta pequeña tarea simplemente probe a reemplazar el valor de `redirectURL` para redirigir a un dominio externo arbitrario, como evil.com

```
https://production.ap01.ecm.example.com/login-logout?redirectURL=http://evil.com
```

> Vulnerabilidad Open Redirect

![image](https://github.com/user-attachments/assets/5b792ad5-fde9-4770-a00a-6a2d67b2ddc5)
