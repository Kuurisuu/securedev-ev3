"""SecureDev - aplicación corregida (Evaluación Parcial 3).

Correcciones aplicadas sobre el código vulnerable original:
  V1 XSS reflejado (CWE-79): validación por lista blanca + escapado de salida.
  V2 Modo debug en producción (CWE-489): debug desactivado por defecto y
     ejecución con gunicorn en lugar del servidor de desarrollo.
  V3 Protección CSRF ausente (CWE-352): CSRFProtect de Flask-WTF.
  V4 Entrada no validada / "Hello, None!" (CWE-20): valor por defecto y
     rechazo de entradas fuera de la lista blanca (HTTP 400).
  V5 Cabeceras de seguridad ausentes (CWE-693): CSP, anti-clickjacking, etc.
Además se exponen métricas para la monitorización con Prometheus y Grafana.
"""
import logging
import os
import re
import secrets
import time

from flask import Flask, g, request
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape
from prometheus_client import Counter, Histogram, start_http_server

app = Flask(__name__)
# Clave para firmar los tokens CSRF: se toma del entorno o se genera al azar.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
csrf = CSRFProtect(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
security_log = logging.getLogger("security")

# Lista blanca: letras (incluye tildes y ñ), espacios, apóstrofo y guion.
NAME_PATTERN = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ' -]{1,50}$")
XSS_PATTERN = re.compile(r"<|>|javascript:|on\w+\s*=", re.IGNORECASE)
DEFAULT_NAME = "guest"

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

# Métricas para Prometheus (consumidas por Grafana).
HTTP_REQUESTS = Counter(
    "app_http_requests_total", "Peticiones HTTP atendidas",
    ["method", "endpoint", "status"],
)
HTTP_LATENCY = Histogram(
    "app_http_request_duration_seconds", "Latencia de las peticiones HTTP",
    ["endpoint"],
)
SECURITY_EVENTS = Counter(
    "app_security_events_total", "Eventos de seguridad detectados por la aplicación",
    ["type"],
)


def register_security_event(event_type, detail):
    SECURITY_EVENTS.labels(event_type).inc()
    # repr() evita inyección de saltos de línea en los logs (CWE-117).
    security_log.warning(
        "event=%s ip=%s path=%s detail=%r",
        event_type, request.remote_addr, request.path, detail[:100],
    )


@app.before_request
def start_timer():
    g.start_time = time.perf_counter()


@app.after_request
def add_security_headers_and_metrics(response):
    response.headers.update(SECURITY_HEADERS)
    response.headers["Server"] = "SecureDev"

    # Se usa la ruta declarada (no la URL recibida) para no crear una serie
    # de métricas por cada URL que pruebe un escáner o atacante.
    endpoint = request.url_rule.rule if request.url_rule else "no_route"
    if response.status_code == 404:
        register_security_event("resource_probe", request.path)
    HTTP_REQUESTS.labels(request.method, endpoint, str(response.status_code)).inc()
    HTTP_LATENCY.labels(endpoint).observe(
        time.perf_counter() - g.get("start_time", time.perf_counter())
    )
    return response


@app.errorhandler(500)
def internal_error(_error):
    # Respuesta genérica: no se exponen trazas ni detalles internos.
    return "Internal server error", 500, {"Content-Type": "text/plain; charset=utf-8"}


@app.get("/hello")
def hello():
    name = request.args.get("name", DEFAULT_NAME).strip() or DEFAULT_NAME

    if not NAME_PATTERN.fullmatch(name):
        event_type = "xss_attempt" if XSS_PATTERN.search(name) else "invalid_input"
        register_security_event(event_type, name)
        return "Invalid name", 400, {"Content-Type": "text/plain; charset=utf-8"}

    # Defensa en profundidad: aunque la entrada ya fue validada, se escapa.
    return f"Hello, {escape(name)}!"


metrics_port = os.environ.get("METRICS_PORT")
if metrics_port:
    # Puerto interno de métricas: no se publica fuera de la red de Docker.
    start_http_server(int(metrics_port))


if __name__ == "__main__":
    # Solo para desarrollo local; en producción se usa gunicorn.
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
