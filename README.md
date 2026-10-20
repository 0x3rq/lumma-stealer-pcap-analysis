# Lumma Stealer - Network Traffic & C2 Forensics

Análisis forense de tráfico de red (PCAP) e identificación de la infraestructura de Mando y Control (C2) del infostealer **Lumma Stealer**.

**[Ver Dashboard Interactivo en Vivo](https://0x3rq.github.io/lumma-stealer-pcap-analysis/)**

---

## Objetivo del Proyecto

Investigar el comportamiento en red del malware Lumma Stealer a partir de capturas de tráfico `.pcap`, automatizando la extracción de indicadores de compromiso (IoCs), la geolocalización de nodos C2 y el filtrado de dominios señuelo (*decoy domains*).

---

## Tecnologías y Herramientas Utilizadas

* **Análisis de Tráfico & Forense:** Wireshark, `tshark`, NetworkMiner.
* **Automatización & Scripting:** PowerShell (API REST `ipwho.is`).
* **Inteligencia de Amenazas:** VirusTotal API / Reputational Check.
* **Visualización:** HTML5, Leaflet.js, Chart.js, Tailwind CSS (GitHub Pages).

---

## Alcance y Metodología

1. **Extracción Automática de Tráfico:** Filtrado de registros DNS e IPs de destino mediante sintaxis `tshark`.
2. **Geolocalización & Enriquecimiento (Script `geo.ps1`):** Consulta automatizada para mapear coordenadas, países y proveedores de red (ASN/ISP).
3. **Discriminación de Infraestructura C2 vs. Decoys:** Identificación de servidores reales de Mando y Control frente a dominios legítimos usados como distracción.
4. **Análisis Forense Pasivo:** Inspección de exfiltración de credenciales y artefactos capturados.

---

## Estructura del Repositorio

* **`index.html`**: Dashboard web interactivo para explorar el mapa mundial de IPs y métricas de tráfico.
* **`Informe_Lumma_Stealer.pdf`**: Documento técnico forense con desglose completo del análisis.
* **`geo.ps1`**: Script en PowerShell para geolocalizar IPs a través de la API `ipwho.is`.
* **`geo_lumma.csv`**: Base de datos de IPs enriquecidas con coordenadas y ASN.

---

**Para ver el análisis forense paso a paso y los IoCs extraídos, descarga el [Informe Técnico PDF](./Informe_Lumma_Stealer.pdf) o explora el [Dashboard en Vivo](https://0x3rq.github.io/lumma-stealer-pcap-analysis/).**
