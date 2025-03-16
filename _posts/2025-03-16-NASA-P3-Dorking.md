---
description: >-
  Google Dorking - El rey del reconocimiento en bug bounty
title: NASA P3 Google Dorking
date: 2025-03-14
categories: [Bug Bounty]
tags: [hacking, bug bounty, hacking web, bugcrowd]
image_post: true
image: https://github.com/user-attachments/assets/eb905007-48b3-40f1-a566-8fe354dfc2ae
---

Un detalle clave que muchos Bug Bounty Hunters pasan por alto cuando tienen prisa es dedicar al menos 10 a 15 minutos a leer detenidamente el alcance, las normas y los dominios donde ya se han enviado y resuelto informes. También es fundamental revisar las categorías de vulnerabilidades reportadas, posibles cambios en el alcance y otros detalles clave. Para mí, esto es una parte esencial de la recopilación inicial de información, ya que me permite orientarme y enfocarme en aspectos que otros podrían ignorar.

![image](https://github.com/user-attachments/assets/6eb7cd58-d791-4004-aeb9-6a2581eb0cb3)

El scope incluye una gran cantidad de dominios, pero la mayoría de los Bug Bounty Hunters parecen centrarse en nasa.gov, dejando el resto prácticamente intacto. Por eso, decidí enfocar mi búsqueda en estos dominios menos explorados. Comencé buscando exposiciones de información personal (PII Disclosure), revisando documento por documento y utilizando diversas combinaciones de dorks, que detallo a continuación.

```
site:domain.com "CONFIDENTIAL"
site:domain.com "SOCIAL SECURITY NUNBER"
site:domain.com "CREDIT CARD"
site:domain.com "PASSWORD"
site:domain.com "BANK ACCOUNT"
site:domain.com "PII"

#file extensions
ext:pdf
ext:doc
ext:docx
ext:txt
ext:odt
ext:odf
ext:xls
ext:xlsx
ext:csv

#negative filtering removing the unwanted ones
-api -form -doc -template -default -sample -public
```

La cantidad de documentos disponibles era enorme, lo que me daba esperanzas de encontrar algo valioso, pero también resultaba abrumador. Después de una semana intensa de búsqueda, con varios reportes rechazados y algunos marcados como duplicados, finalmente logré descubrir una filtración de datos de usuarios. Por respeto a la política del programa, no puedo compartir detalles más específicos sobre la información expuesta.

> Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure

![image](https://github.com/user-attachments/assets/e9bbf68a-3413-4303-b258-081b4e7c250a)

Confío en que puedan resolverlo pronto, ya que espero con gran entusiasmo y alegría mi carta de reconocimiento. Este hallazgo fue especialmente significativo para mí, ya que marcó mi primer informe válido en la plataforma BugCrowd. Desde entonces, he desarrollado una gran pasión por el Google Dorking, convirtiéndose en una de mis principales áreas de enfoque dentro del reconocimiento.
