---
title: 750 USD Bounty Graphql with Salary Information
date: 2025-09-29 01:24:00 -0500
categories: [BugBounty, Hacking]
tags: [bugbounty, hacking]
image:
  path: /assets/img/posts/2025-09-29-graphql_info.png
  alt: Api salary info exposed
---

Durante una evaluación de seguridad junto a un compañero, identificamos un endpoint GraphQL accesible públicamente que permitía consultar información salarial estructurada por puesto de trabajo y ubicación geográfica sin necesidad de autenticación.

El problema no era evidente desde la interfaz pública. Al analizar el endpoint y las operaciones disponibles, pude comprender cómo la API exponía información relacionada con los puestos de trabajo y cómo utilizar sus consultas para recuperar estimaciones salariales.

## 1. Descubrimiento del esquema GraphQL

El primer paso consistió en examinar el esquema de la API mediante introspección de GraphQL. Este mecanismo permite descubrir las operaciones, los argumentos, los tipos y los campos disponibles.

El esquema accesible proporcionó información sobre la funcionalidad de la API y permitió identificar consultas relevantes para recuperar datos relacionados con los puestos de trabajo.

## 2. Enumeración de puestos de trabajo

Identificamos una consulta denominada getNormalisedRoles, que aceptaba un título de puesto como parámetro y devolvía metadatos relacionados con los roles disponibles.

La respuesta incluía campos como identificadores de roles, títulos normalizados, alias y URL asociadas. Estos valores permitían determinar los parámetros necesarios para realizar consultas posteriores.

```
query {
    getNormalisedRoles(roleTitles:"administrator") {
        caRole {
            additionalLocales
            alias
            id
            isReleased
            isThick
            role_id
            title
            updatedAt
            url
        }
        normalisedId
        normalisedText
        title
    }
}
```

## 3. Obtención de información salarial

A continuación, analizamos la consulta salarySuggestionsByRoleId, que aceptaba como parámetros el identificador del puesto, su título y un valor correspondiente al idioma o la configuración regional.

Al proporcionar los valores adecuados, era posible recuperar estimaciones salariales asociadas a diferentes puestos y ubicaciones.

La respuesta incluía:

- Rangos salariales mínimos, medianos y máximos.
- Títulos de puestos y ubicaciones geográficas.
- Identificadores de roles y metadatos de ubicación.
- URL relacionadas con búsquedas de empleo.

```
query {
    salarySuggestionsByRoleId(roleId: "administration-officer", roleTitle: "Administration Officer", locationType: "en-ph") {
        in_months
        locationId
        locationName
        roleId
        roleTitle
        salary_max
        salary_median
        salary_min
        suggestion
        urlToSearch
    }
}
```

<img width="1784" height="882" alt="image" src="https://github.com/user-attachments/assets/5c891438-13c3-4778-a5c1-21124ab68858" />

## 4. Conclusiones

Revisar los esquemas GraphQL y las operaciones disponibles durante las evaluaciones de seguridad autorizadas.

Comprobar si las consultas y los campos sensibles aplican controles adecuados de autenticación y autorización.

Diferenciar la información empresarial pública de los datos realmente confidenciales.

Evaluar el impacto demostrado en lugar de asumir que cualquier endpoint sin autenticación constituye una vulnerabilidad crítica.
