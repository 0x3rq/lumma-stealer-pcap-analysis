$in = ".\ip_lumma.txt"
$out = ".\geo_lumma.csv"

# Leer, limpiar, filtrar la IP local y eliminar duplicados
$ips = Get-Content $in | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne "192.168.137.1" } | Sort-Object -Unique

# Escribir la cabecera en el archivo CSV de salida
"IP,Country,Region,City,ISP" | Out-File $out -Encoding utf8

# Iterar sobre las IPs obtenidas
foreach ($ip in $ips) {
    try {
        $r = Invoke-RestMethod -Uri "https://ipwho.is/$ip" -TimeoutSec 10
        
        if ($r.success) {
            "$($r.ip),$($r.country),$($r.region),$($r.city),$($r.connection.isp)" | Add-Content $out
            Write-Host "OK $ip"
        } else {
            Write-Host "SKIP $ip - $($r.message)"
        }
    } catch {
        Write-Warning ("Error con {0}: {1}" -f $ip, $_.Exception.Message)
    }
    
    # Pausa de 400ms para respetar los límites de la API
    Start-Sleep -Milliseconds 400
}