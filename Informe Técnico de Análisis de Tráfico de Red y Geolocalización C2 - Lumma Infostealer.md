### Informe Técnico Forense: Análisis de Tráfico de Red (PCAP) de Lumma Stealer e Infraestructura C2

##### 1\. Resumen Ejecutivo y Perfil de la Amenaza

El presente análisis forense de red documenta la inspección técnica del archivo de captura de tráfico (lumma.pcap), correspondiente a una infección activa del malware  **Lumma Stealer** . Esta amenaza está clasificada dentro de la categoría de  *infostealers*  y se comercializa bajo el modelo de Malware-as-a-Service (MaaS) en foros de la dark web.  
El propósito primario de Lumma Stealer es la exfiltración silenciosa de datos sensibles del sistema comprometido. Una vez ejecutado en el host de la víctima, el malware inicia una secuencia de recolección de artefactos locales, empaquetado de datos e identificación de red para posteriormente exfiltrar la información sustraída hacia la infraestructura de Mando y Control (C2) administrada por los atacantes.  
Durante el análisis forense del tráfico interceptado, se han identificado los siguientes vectores y categorías de datos exfiltrados:

* **Credenciales de acceso:**  Extracción de contraseñas almacenadas en navegadores web e identificación única del host infectado.  
* **Cookies de sesión:**  Captura de tokens y cookies de navegación activos para el secuestro de sesiones autorizadas.  
* **Carteras de criptomonedas:**  Localización y robo de archivos de billeteras digitales ( *wallets* ).  
* **Tokens de autenticación:**  Sustracción de credenciales de acceso para aplicaciones locales y servicios web.  
* **Información del sistema:**  Recolección de datos del entorno afectado, incluyendo direccionamiento IP local/público, nombre del equipo, dirección MAC y geolocalización.

##### 2\. Extracción Forense de Artefactos de Red con TShark

Para el procesamiento pasivo del archivo de captura de red (lumma.pcap), se utilizó la herramienta de línea de comandos  **TShark**  (incluida en la suite de Wireshark). Mediante la aplicación de filtros sintácticos específicos, se extrajeron de forma automatizada los artefactos de red clave hacia archivos de texto plano para su posterior análisis e inteligencia de fuentes abiertas.

###### *1\. Extracción de consultas DNS realizadas (dns\_lumma.txt)*

El siguiente comando procesa las solicitudes de resolución de nombres registradas en la captura de tráfico:  
tshark \-r .\\lumma.pcap \-Y "dns" \-T fields \-e dns.qry.name \> .\\dns\_lumma.txt

###### *2\. Extracción de direcciones IP de destino (ip\_lumma.txt)*

El comando aisla la totalidad de las direcciones IP remotas a las que el sistema infectado intentó o estableció comunicación:  
tshark \-r .\\lumma.pcap \-Y "ip" \-T fields \-e ip.dst \> .\\ip\_lumma.txt

##### 3\. Automatización de Geolocalización y Enriquecimiento de Datos (PowerShell & API ipwho.is)

A fin de determinar la distribución geográfica y el Proveedor de Servicios de Internet (ISP) asociado a cada dirección IP destino, se diseñó e implementó un script automatizado en PowerShell (geo.ps1).

###### *Lógica de Procesamiento del Script:*

1. **Lectura e Higienización:**  Carga el listado de direcciones IP extraídas (ip\_lumma.txt), remueve espacios en blanco, filtra direcciones IP privadas locales (p. ej., 192.168.137.1) y elimina entradas duplicadas mediante filtrado sintáctico (Sort-Object \-Unique).  
2. **Consulta REST:**  Realiza peticiones HTTPS a la API pública de geolocalización ipwho.is.  
3. **Control de Tasa (Rate Limiting):**  Incorpora una pausa de 400 milisegundos (Start-Sleep \-Milliseconds 400\) entre iteraciones para no exceder las restricciones de peticiones por minuto impuestas por la API.  
4. **Estructuración y Exportación:**  Procesa la respuesta JSON y exporta un informe estructurado en formato CSV (geo\_lumma.csv) con codificación UTF-8.

\$in \= ".\\ip\_lumma.txt"  
\$out \= ".\\geo\_lumma.csv"

\# Leer, limpiar, filtrar la IP local y eliminar duplicados  
\$ips \= Get-Content \$in | ForEach-Object { \$\_.Trim() } | Where-Object { \$\_ \-and \$\_ \-ne "192.168.137.1" } | Sort-Object \-Unique

\# Escribir la cabecera en el archivo CSV de salida  
"IP,Country,Region,City,ISP" | Out-File \$out \-Encoding utf8

\# Iterar sobre las IPs obtenidas  
foreach (\$ip in \$ips) {  
    try {  
        \$r \= Invoke-RestMethod \-Uri "https\://ipwho.is/\$ip" \-TimeoutSec 10

        if (\$r.success) {  
            "\$(\$r.ip),\$(\$r.country),\$(\$r.region),\$(\$r.city),\$(\$r.connection.isp)" | Add-Content \$out  
            Write-Host "OK \$ip" \-ForegroundColor Green  
        } else {  
            Write-Host "SKIP \$ip \- \$(\$r.message)" \-ForegroundColor Yellow  
        }  
    } catch {  
        Write-Warning ("Error con {0}: {1}" \-f \$ip, \$\_.Exception.Message)  
    }

    \# Pausa de 400ms para respetar los límites de la API  
    Start-Sleep \-Milliseconds 400  
}

###### *Ejemplificación de Resultados Extrapolados del Reporte (geo\_lumma.csv):*

IP,Country,Region,City,ISP  
153.92.1.49,Lithuania,Vilnius County,Vilnius,Hostinger International Limited  
62.72.32.156,Lithuania,Vilnius County,Vilnius,Hostinger International Limited  
80.97.160.24,Moldova,Municipiul Chisinau,Centru,AVA HOST SRL  
172.178.240.162,United States,California,San Jose,Microsoft Corporation  
172.217.72.94,United States,Texas,Dallas,Google LLC

##### 4\. Análisis Reputacional, Infraestructura C2 y Técnica de Dominios Señuelo (Decoy Domains)

La correlación entre las peticiones DNS/IPs interceptadas y las bases de datos de inteligencia de amenazas en  **VirusTotal**  reveló el patrón de evasión de Lumma Stealer.

###### *1\. Técnica de Ocultación mediante Dominios Señuelo (Decoy Domains)*

Para evitar la detección basada en anomalías DNS y dificultar la labor de los analistas de red, Lumma Stealer genera peticiones DNS masivas a multitud de dominios y servicios legítimos de alta reputación (como Google, Microsoft, Cloudflare y Akamai) mezcladas concurrentemente con peticiones a dominios de prueba o dominios C2 reales (tales como whitepepper.su, holiday-forever.cc, communicationfirewall-security.cc, whooptm.cyou, hiyter.com, media.megafilehub4.lat o arch.filemegahab4.sbs). Esta inundación de tráfico actúa como cortina de humo para saturar los registros e inspecciones de red.

###### *2\. Identificación de Servidores de Mando y Control (C2)*

Al cruzar la reputación de los rangos IP en VirusTotal, se descartaron los proveedores de servicios CDN/Cloud legítimos y se aislaron las direcciones IP que poseen reportes activos de seguridad vinculados a infraestructura de botnets, actividades de Phishing y ataques DDoS. Se confirmó la localización de nodos C2 privados alojados en proveedores específicos:

* **AVA HOST SRL**  localizado en Chisinau, Moldavia (80.97.160.24).  
* **Hostinger International Limited**  localizado en Vilnius, Lituania (153.92.1.49 y 62.72.32.156).

###### *Matriz Comparativa de Infraestructura de Red:*

Dirección IP,Proveedor / ISP,Ubicación / País,Clasificación Reputacional / Uso  
172.217.72.94,Google LLC,Estados Unidos,Legítima / Señuelo:  Tráfico benigno para dispersión forense  
172.178.240.162,Microsoft Corporation,Estados Unidos,Legítima / Señuelo:  Servicios del sistema operativo / Ruido DNS  
104.16.79.73,"Cloudflare, Inc.",Estados Unidos,Legítima / Señuelo:  Infraestructura CDN pública  
173.223.146.43,"Akamai Technologies, Inc.",Estados Unidos,Legítima / Señuelo:  Servidores de distribución de contenido  
80.97.160.24,AVA HOST SRL,Moldavia,C2 Confirmada:  Servidor del atacante / Actividad maliciosa  
153.92.1.49,Hostinger International Limited,Lituania,C2 Confirmada:  Botnet / Phishing / Exfiltración C2  
62.72.32.156,Hostinger International Limited,Lituania,C2 Confirmada:  Botnet / Phishing / Exfiltración C2

##### 5\. Inspección Forense Pasiva de Red con NetworkMiner

El análisis del archivo .pcap mediante la herramienta forense pasiva  **NetworkMiner 3.2**  permitió reconstruir las acciones ejecutadas por la amenaza organizadas en sus pestañas principales:

###### *5.1 Hosts*

* **Host Comprometido:**  Identificado bajo la dirección IP 10.1.21.58 (Hostname: DESKTOP-ES9F3ML).  
* **Perfil Forense del Cliente:**  
* **Dirección MAC:**  00:21:6D:C3:0E:72 (Vendor: Intel Corporate).  
* **TTL (**  ***Time to Live***  **):**  128 (Lógica de hops directos de sistema operativo  **Windows** ).  
* **Métricas de Transmisión:**  Registra 24.117 paquetes enviados (5.735.889 Bytes) y 20.008 paquetes recibidos (13.521.113 Bytes), acumulando un total de 145 sesiones salientes activas.  
* **Tráfico Excesivo Saliente:**  El sistema mantiene conexiones abiertas dirigidas a los nodos C2 confirmados de Hostinger International Limited (153.92.1.49, 62.72.32.156) y AVA HOST SRL (80.97.160.24), acumulando un volumen masivo de exfiltración saliente que supera los  **6 GB**  de datos transmitidos fuera de la red corporativa.

###### *5.2 Credenciales*

* **Registro Inicial:**  Se detectaron 2 registros de credenciales capturados en las sesiones HTTP dirigidas a la infraestructura del atacante. Corresponden al envío de la primera petición POST de registro e identificación unívoca de la víctima (DESKTOP-ES9F3ML) al reportarse exitosamente ante el servidor C2.

###### *5.3 Archivos (Files)*

* **Empaquetado y Exfiltración:**  Se identificó la captura y reconstrucción de archivos temporales que contienen cookies de navegador, claves guardadas en los gestores de contraseñas y archivos de billeteras digitales de criptomonedas.  
* **Mecanismo de Envío:**  Toda la información sustraída es agrupada y comprimida localmente en un contenedor .zip para posteriormente ser transmitida mediante peticiones  **HTTP POST**  cifradas hacia los nodos del atacante, reduciendo la huella volumétrica para intentar evadir los controles DLP ( *Data Loss Prevention* ).

###### *5.4 Sesiones y DNS*

* **Peticiones DNS Interceptadas:**  Se contabilizan  **545 consultas DNS**  en total, reflejando el elevado volumen de peticiones saturantes generadas por la técnica de dominios señuelo.  
* **Sesiones de Exfiltración:**  Se identificaron  **178 sesiones**  activas que alternan tráfico de comandos y transporte de payload cifrado (vía HTTP y SSL/TLS) orientado a los canales C2.

##### 6\. Análisis Estadístico y Flujo Temporal en Wireshark

Para validar formalmente el impacto volumétrico y la cronología del ataque, se emplearon los módulos estadísticos de  **Wireshark** :

###### *6.1 Statistics \-\> Endpoints*

Esta función permitió la identificación y aislamiento de las direcciones IP únicas involucradas en la captura. A través de la tabla de endpoints TCP/UDP, se auditó la simetría de tráfico (contabilización de paquetes y bytes transmitidos/recibidos), confirmando que el host 10.1.21.58 actuó mayoritariamente como emisor ( *Tx Bytes*  significativamente superiores a  *Rx Bytes*  en los puertos efímeros de conexión hacia los nodos maliciosos).

###### *6.2 Statistics \-\> I/O Graph*

La gráfica de Entradas/Salidas ( *I/O Graph* ) muestra el comportamiento temporal del volumen de paquetes por segundo. El análisis reveló picos agudos e inusuales de tráfico saliente en intervalos breves de tiempo. Estos picos corresponden al momento exacto en el que Lumma Stealer transfiere los archivos comprimidos .zip con los datos exfiltrados hacia la infraestructura externa.

###### *6.3 Statistics \-\> Flow Graph*

El gráfico de flujo ( *Flow Graph* ) reconstruyó la secuencia cronológica precisa del intercambio de paquetes a nivel TCP/UDP entre el cliente 10.1.21.58 y las direcciones remotas. Permitió visualizar el establecimiento del saludo de tres vías (TCP Handshake), seguido de ráfagas intensas de paquetes con banderas PSH, ACK transmitidos desde puertos efímeros del cliente (como TCP 50768). Estas ráfagas PSH, ACK representan el empuje directo desde los búferes del sistema operativo con los fragmentos del archivo .zip exfiltrado antes del cierre o desconexión de las sesiones TCP.

##### 7\. Matriz de Indicadores de Compromiso (IoCs) y Conclusiones Forenses

El análisis forense pasivo del tráfico de red confirma la infección por  **Lumma Stealer**  en el host DESKTOP-ES9F3ML (10.1.21.58). La amenaza utilizó un mecanismo de evasión basado en la consulta masiva de dominios señuelo legítimos para enmascarar la exfiltración de credenciales, cookies de sesión y billeteras de criptomonedas. La transferencia remota de información se ejecutó mediante peticiones HTTP POST cifradas, utilizando archivos comprimidos .zip dirigidos hacia nodos C2 alojados en Lituania y Moldavia.  
A continuación, se compilan los Indicadores de Compromiso (IoCs) consolidados durante la investigación forense:  
Tipo de IoC,Valor / Artefacto,Descripción / Rol Forense  
Dirección IP C2,"80.97.160.24 (TCP 80, 443)",Servidor de Mando y Control (C2) \- AVA HOST SRL (Moldavia) / Exfiltración HTTP POST  
Dirección IP C2,"153.92.1.49 (TCP 80, 443)",Servidor C2 / Infraestructura de Exfiltración \- Hostinger (Lituania)  
Dirección IP C2,"62.72.32.156 (TCP 80, 443)",Servidor C2 / Infraestructura de Exfiltración \- Hostinger (Lituania)  
Dominio C2 / Malicioso,whitepepper.su,Dominio C2 activo / Comunicación remota y exfiltración de datos  
Dominio C2 / Malicioso,holiday-forever.cc,Dominio de la infraestructura C2 / Canal de comando  
Dominio C2 / Malicioso,communicationfirewall-security.cc,Dominio de la infraestructura C2 / Canal de comando  
Dominio C2 / Malicioso,whooptm.cyou,Dominio involucrado en la resolución DNS de la amenaza C2  
Dominio C2 / Malicioso,hiyter.com,Dominio involucrado en la resolución DNS de la amenaza C2  
Dominio C2 / Malicioso,media.megafilehub4.lat,Dominio involucrado en la resolución DNS de la amenaza C2  
Dominio C2 / Malicioso,arch.filemegahab4.sbs,Dominio involucrado en la resolución DNS de la amenaza C2  
Host Comprometido,10.1.21.58 / DESKTOP-ES9F3ML,"IP y hostname de la víctima (MAC: 00:21:6D:C3:0E:72, OS Windows, TTL 128)"  
Protocolo / Artefacto,HTTP POST / .zip (TCP 50768),"Método de empaquetado y exfiltración de datos sensibles mediante ráfagas PSH, ACK"  
