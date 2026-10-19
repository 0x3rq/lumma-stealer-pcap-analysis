# Lumma Stealer - Network Traffic & C2 Forensics

Análisis forense de tráfico de red (PCAP) e infraestructura de Mando y Control (C2) del infostealer **Lumma Stealer**.

## Contenido del Repositorio

* **`index.html`**: Dashboard web interactivo para visualizar el tráfico y los mapas.
* **`Informe_Lumma_Stealer.pdf`**: Documento y reporte técnico forense completo.
* **`geo.ps1`**: Script en PowerShell desarrollado para automatizar la geolocalización de IPs mediante la API `ipwho.is`.
* **`geo_lumma.csv`**: Resultados de la geolocalización, proveedores (ASN) y coordenadas.

## 🛠️ Metodología

1. **Extracción de Tráfico:** Filtrado de registros DNS e IPs de destino mediante `tshark`.
2. **Geolocalización Automática:** Enriquecimiento de datos con `geo.ps1` identificando nodos sospechosos en Moldavia (AVA HOST SRL) y Lituania (Hostinger).
3. **Análisis Forense:** Inspección pasiva con NetworkMiner (exfiltración de archivos `.zip`) y gráficos en Wireshark.
