# Imagen corregida de SecureDev.
FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    METRICS_PORT=9100

WORKDIR /app

# V6: usuario sin privilegios para ejecutar la aplicación (no root).
RUN useradd --system --uid 10001 --no-create-home appuser

# Dependencias fijadas con hash: pip rechaza cualquier paquete alterado.
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app.py test_app.py ./

USER appuser

EXPOSE 5000 9100

# V2: servidor de producción (gunicorn) en lugar del servidor de desarrollo.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", \
     "--no-control-socket", "--access-logfile", "-", "app:app"]
