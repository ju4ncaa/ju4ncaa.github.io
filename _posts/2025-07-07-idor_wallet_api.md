---
title: 300 USD Bounty IDOR in Wallet Address API
date: 2025-07-07 01:24:00 -0500
categories: [BugBounty, Hacking]
tags: [bugbounty, hacking]
image:
  path: /assets/img/posts/2025-07-07-idor_wallet_api.png
  alt: Idor wallet address api
---

Durante una de mis investigaciones de seguridad, encontré una vulnerabilidad de tipo IDOR (Insecure Direct Object Reference) en una API relacionada con las recompensas Gems de una plataforma blockchain.

El problema permitía consultar información de recompensas asociada a diferentes direcciones de wallet modificando un parámetro de la petición, sin que el servidor comprobara adecuadamente si el solicitante estaba autorizado para acceder a esos datos.

En este artículo explicaré en qué consistía el fallo, cómo lo identifiqué y cuáles eran sus posibles implicaciones desde el punto de vista de la seguridad.

## 1. ¿Qué es una vulnerabilidad IDOR?

Una vulnerabilidad IDOR aparece cuando una aplicación permite acceder a un recurso mediante un identificador controlado por el usuario, pero no comprueba correctamente los permisos necesarios para consultarlo.

Por ejemplo, una API puede utilizar un identificador de usuario, un número de pedido o una dirección de wallet para recuperar información. Si el servidor confía directamente en ese valor sin verificar los permisos del solicitante, un usuario podría acceder a información perteneciente a otra persona.

Este tipo de fallo está relacionado con el control de acceso deficiente y puede afectar a aplicaciones web, aplicaciones móviles y servicios que utilizan API REST.

## 2. Identificación de la vulnerabilidad

Durante la investigación, centré mi atención en un endpoint encargado de recuperar información sobre las recompensas Gems asociadas a una dirección de wallet.

El endpoint identificado tenía la siguiente estructura:

```
GET /v1/rewards/gems/{wallet_address}
Host: api.example.com
```

El parámetro wallet_address determinaba qué dirección se consultaba. Al analizar el comportamiento del endpoint, observé que era posible sustituir esa dirección por otra y obtener información de recompensas asociada a la wallet indicada.

El problema no era que la dirección pudiera modificarse, ya que cualquier parámetro enviado por el cliente puede manipularse. El fallo estaba en que el servidor no aplicaba una comprobación de autorización adecuada sobre el recurso solicitado.

## 3. ¿Cómo comprobé el fallo?

Para validar el comportamiento, utilicé una petición HTTP dirigida al endpoint de la API.

El procedimiento consistió en:

- Identificar el endpoint encargado de consultar las recompensas Gems.

- Analizar el parámetro utilizado para seleccionar la dirección de wallet.

- Modificar ese parámetro para consultar otra dirección dentro del alcance autorizado de la investigación.

- Examinar la respuesta del servidor y comprobar que contenía información de recompensas asociada a la dirección indicada.

- Verificar que el acceso a esos datos no estaba condicionado por una comprobación efectiva de autorización sobre la wallet consultada.

<img width="2172" height="724" alt="image" src="https://github.com/user-attachments/assets/7f33b87d-dcb4-404f-972a-e33bfdb6d50a" />

## 4. Impacto potencial

La gravedad de una vulnerabilidad IDOR depende de los datos expuestos, de los controles existentes y de las operaciones que permita realizar la API.

En este caso, identifiqué varios riesgos potenciales.

### Exposición de información de recompensas

Un usuario podía consultar información relacionada con las recompensas Gems de otras direcciones de wallet sin una autorización adecuada.

Aunque las direcciones de blockchain pueden ser públicas, eso no significa que toda la información asociada a ellas deba estar disponible sin restricciones. Los datos adicionales que proporciona una plataforma pueden revelar información sobre la actividad de sus usuarios.

### Enumeración de direcciones

Las direcciones de wallet pueden obtenerse de fuentes públicas, como exploradores de blockchain. Si una API permite consultar los datos asociados a esas direcciones sin comprobar los permisos, podría facilitar la recopilación automatizada de información.

La limitación de peticiones puede dificultar este tipo de actividad, pero no soluciona la causa principal de la vulnerabilidad.

### Posibles riesgos en funcionalidades relacionadas

También es importante revisar si otros endpoints de la misma API permiten reclamar, modificar o transferir recompensas.

Si existieran fallos de autorización similares en esas operaciones, las consecuencias podrían ser más graves. Sin embargo, en esta investigación, el comportamiento demostrado fue la consulta no autorizada de información; no debe asumirse que fuera posible modificar o reclamar recompensas.

## 5. Conclusión

Esta investigación vuelve a demostrar que los controles de autorización son una parte esencial de la seguridad de cualquier API.

Un identificador puede ser público, predecible o fácil de modificar. Lo importante es que el servidor compruebe siempre si el solicitante tiene permiso para acceder al recurso asociado.

Las vulnerabilidades IDOR pueden pasar desapercibidas durante el desarrollo porque las peticiones funcionan correctamente desde el punto de vista técnico. Sin embargo, una respuesta válida no significa que el acceso esté autorizado.
