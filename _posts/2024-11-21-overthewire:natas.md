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
* **Contraseña natas5:** 
* **URL:** http://natas4.natas.labs.overthewire.org
* **Misión:** Acceso denegado. Usted está visitando desde "" mientras que los usuarios autorizados deben venir sólo de "http://natas5.natas.labs.overthewire.org/"
