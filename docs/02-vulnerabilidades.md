# Vulnerabilidades y correcciones

Código original vulnerable:

```python
from flask import Flask, request
app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name')
    return f"Hello, {name}!"

if __name__ == '__main__':
    app.run(debug=True)
```

Las correcciones están en el commit `1805740`, *"Corrige vulnerabilidades detectadas en build #1"*.

| ID | Vulnerabilidad | CWE / OWASP Top 10 | Detectada por | Corrección | Verificación |
|----|----------------|--------------------|---------------|------------|--------------|
| V1 | XSS reflejado: `name` se devuelve sin escapar | CWE-79 / A03 Injection | ZAP 40012 y 40026, prueba manual | Lista blanca `NAME_PATTERN` (HTTP 400 si no cumple) y escapado de salida con `markupsafe.escape` | ZAP sin XSS; `test_xss_reflejado_es_rechazado`; `/hello?name=<script>...` responde **400 Invalid name** |
| V2 | Modo debug y servidor de desarrollo en producción (debugger de Werkzeug en `/console`) | CWE-489 / A05 Security Misconfiguration | SonarQube, prueba manual | `debug` solo si `FLASK_DEBUG=1`; ejecución con **gunicorn**; manejador genérico de error 500 | `test_modo_debug_desactivado`; `/console` responde **404** |
| V3 | Protección CSRF ausente | CWE-352 / A01 Broken Access Control | SonarQube (Alta) | `CSRFProtect` de Flask-WTF y `SECRET_KEY` aleatoria o desde el entorno | `test_proteccion_csrf_activa`; SonarQube con 0 issues |
| V4 | Entrada no validada (`name` ausente devuelve "Hello, None!") | CWE-20 / A03 | Revisión de código | Valor por defecto `guest`; longitud máxima de 50 y caracteres permitidos | `test_hello_sin_parametro_usa_valor_por_defecto` |
| V5 | Cabeceras de seguridad ausentes y versión del servidor expuesta | CWE-693, CWE-200 / A05 | ZAP 10038, 10020, 10021, 10063, 90004 y 10036 | CSP restrictiva, `X-Frame-Options: DENY`, `nosniff`, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, `Cache-Control: no-store` y `Server: SecureDev` | `test_cabeceras_de_seguridad`; ZAP sin alertas Medias ni Bajas |
| V6 | Contenedor ejecutándose como root | CWE-250 / A05 | SonarQube (Dockerfile) | Usuario `appuser` (UID 10001). En producción: `--read-only`, `--cap-drop ALL` y `no-new-privileges` | SonarQube con 0 issues; `docker inspect` |
| V7 | Dependencias con CVE conocidos (Flask y Werkzeug 2.2.2) | CWE-1104 / A06 Vulnerable and Outdated Components | pip-audit, Dependency-Check, Dependabot | Flask 3.1.3 y Werkzeug 3.1.9 fijados con hash (ver [gestión de dependencias](03-gestion-dependencias.md)) | pip-audit y Dependency-Check en 0; Dependabot 12/12 *fixed* |

## Medida adicional: registro de eventos de seguridad

La aplicación corregida registra cada intento de XSS, cada entrada inválida y cada
ruta inexistente. Los registra como log (`event=... ip=... path=... detail=...`) y
como métrica de Prometheus (`app_security_events_total{type}`). El detalle se
registra con `repr()` para evitar la inyección de saltos de línea en los logs
(CWE-117). Esto permite la monitorización descrita en
[04-monitorizacion-incidentes.md](04-monitorizacion-incidentes.md).

## Código corregido (fragmento)

```python
@app.get("/hello")
def hello():
    name = request.args.get("name", DEFAULT_NAME).strip() or DEFAULT_NAME

    if not NAME_PATTERN.fullmatch(name):
        event_type = "xss_attempt" if XSS_PATTERN.search(name) else "invalid_input"
        register_security_event(event_type, name)
        return "Invalid name", 400, {"Content-Type": "text/plain; charset=utf-8"}

    # Defensa en profundidad: aunque la entrada ya fue validada, se escapa.
    return f"Hello, {escape(name)}!"
```
