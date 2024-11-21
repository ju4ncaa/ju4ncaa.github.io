---
title: Resolución CTF OverTheWire:Natas, Level 0-34 Write-Up
description: En este apartado se resuleven los 34 niveles del CTF de OverTheWire Natas.
date: 2024-11-21
categories: [CTFs]
tags: [CTFs, Linux]
img_path: https://i.ibb.co/NsS3QzS/natas.png
image: https://i.ibb.co/NsS3QzS/natas.png
---

## **Introducción**
En este apartado se resuelven los 33 niveles del CTF de OverTheWire Natas. Estos retos están diseñados para principiantes con el objetivo de enseñar los fundamentos de la seguridad web y la explotación de vulnerabilidades. A lo largo de estos niveles, puedes familiarizarte con una variedad de conceptos y técnicas esenciales en el ámbito de la ciberseguridad, como la inyección de código, la manipulación de sesiones y la gestión de autenticaciones. Cada nivel presenta un desafío específico que va desde tareas simples, como la identificación de vulnerabilidades en aplicaciones web, hasta desafíos más complejos que requieren habilidades en análisis de seguridad, explotación de fallos y comprensión de protocolos de comunicación. Natas es una excelente manera de aprender y practicar habilidades críticas en un entorno seguro y controlado.

### Level 0 -> Level 1
* **Nombre de usuario** natas0
* **Contraseña natas0:** natas0
* **URL:** http://natas0.natas.labs.overthewire.org
* **Misión:** Encontrar la contraseña para el siguiente nivel (natas1) en esta página.
* **Contraseña natas1:** 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq


Utilizamos el shortcut **Ctrl + U**, esto nos permite visualizar el codigo fuente de la página donde en un comentario HTML se encuentra la contraseña de **natas1**

![image](https://github.com/user-attachments/assets/b58d1b7f-51a8-47f1-aeca-147f3a04d039)

### Level 1 -> Level 2
* **Contraseña natas2:** TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI
* **URL:** http://natas1.natas.labs.overthewire.org
* **Misión:** Encontrar la contraseña para el siguiente nivel en esta página, ¡pero el botón derecho del ratón ha sido bloqueado!

Utilizamos el shortcut **Ctrl + U**, esto nos permite visualizar el codigo fuente de la página de la misma forma que haciendo clic derecho y seleccionar **View Page Source**, observamos que en un comentario HTML se encuentra la contraseña de **natas2**

![image](https://github.com/user-attachments/assets/fd24ea3e-74e4-4418-8512-e8759604f9a0)

### Level 2 -> Level 3
* **Contraseña natas3:** 3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH
* **URL:** http://natas2.natas.labs.overthewire.org
* **Misión:**  No hay nada en esta página

Observamos el codigo fuente y observamos que hay una imagen llamado **pixel.png** que se carga desde el directorio **/files**

![image](https://github.com/user-attachments/assets/eb92e349-fbf3-4e65-9e41-59caf1b01b2f)

Nos dirigimos a el directorio **/files** donde podemos observar un fichero de texto llamado **users.txt**, dentro del mismo se encuentra la contraseña de **natas3**.

![image](https://github.com/user-attachments/assets/444ea6fb-7230-4879-9346-5190b11420f4)

![image](https://github.com/user-attachments/assets/c8394321-ea92-40fa-9388-d421f87fcfa2)

### Level 3 -> Level 4
* **Contraseña natas4:** QryZXc2e0zahULdHrtHxzyYkj59kUxLQ
* **URL:** http://natas3.natas.labs.overthewire.org
* **Misión:**  No hay nada en esta página

Utilizamos el shortcut **Ctrl + U** para inspeccionar el codigo fuente de la página pero no encontramos ninguna fuga de información.

![image](https://github.com/user-attachments/assets/765b0549-34fc-40ad-bae7-2eeccf330d80)

Existe un archivo llamado **robots.txt** el cual contiene estructura de un sitio web, si este se encuentra habilitado puede contener información valiosa.

![image](https://github.com/user-attachments/assets/8902600d-02d1-4849-9a71-4147d45ad2c2)

En el archivo **robots.txt** podemos observar un directorio llamado **s3cr3t** al cual si accedemos podemos ver un fichero llamado **users.txt** dentro del mismo se encuentra la contraseña de **natas4**.

![image](https://github.com/user-attachments/assets/8963064a-396c-4680-b7ef-8b63a411fdd2)

![image](https://github.com/user-attachments/assets/525380a3-2cee-4200-8b74-b735838d31e7)

### Level 4 -> Level 5
* **Contraseña natas5:** 0n35PkggAPm2zbEpOU802c0x0Msn1ToK
* **URL:** http://natas4.natas.labs.overthewire.org
* **Misión:** Acceso denegado, estás visitando desde `"http://natas4.natas.labs.overthewire.org/"` mientras que los usuarios autorizados deben venir sólo de `"http://natas5.natas.labs.overthewire.org/"`

Podemos observar las **cabeceras de solicitud** en concreto el **Referer** que es la dirección de la página web desde la que se realiza la solicitud.

![image](https://github.com/user-attachments/assets/2cc9f763-7740-46af-9574-e79b84745bf5)

Interceptamos la petición con el proxy BurpSuite y cambiamos el Referer a **http://natas5.natas.labs.overthewire.org/**

![image](https://github.com/user-attachments/assets/b50f2d73-84e7-40e4-b38a-34b211ee9e6a)

### Level 5 -> Level 6
* **Contraseña natas6:** 0RoJwHdSKWFTYR5WuiAewauSuNaBXned
* **URL:** http://natas5.natas.labs.overthewire.org
* **Misión:**  Acceso denegado, no has iniciado sesión

Interceptamos la petiicón con el proxy BurpSuite y observamos que el Header Cookie tiene el paráemtro `logeddin=0`

![image](https://github.com/user-attachments/assets/efda2130-6213-44d1-9aaa-9afac32fdf00)

Supongo que `**0 es igual a False**` y `**1 es igual a True**`, lo que me permitirá indicar que si esto logeado como el usuario **natas5**

![image](https://github.com/user-attachments/assets/4f144080-26e0-4f58-aa99-78b851267aad)

### Level 6 -> Level 7
* **Contraseña natas7:** 
* **URL:** http://natas6.natas.labs.overthewire.org
* **Misión:** Introduce el secreto para obtener la contraseña del usuario natas7

Observamos un campo donde se nos permite introducir una frase secreta.

![image](https://github.com/user-attachments/assets/0f7d6943-63eb-4845-8813-1e28eecc8c15)

Observamos el codigo fuente, podemos ver un codigo **PHP** el cual se encarga de validar a través del método **POST** que lo que introducimos en el input equivale a la frase secreta, de ser así nos muestra la contraseña de **natas7** y si no es así se nos muestra `Wrong secret`

![image](https://github.com/user-attachments/assets/c6e6ff76-d95c-4ad0-80fc-dad7429332af)
