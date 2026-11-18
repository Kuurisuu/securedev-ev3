# Versión inicial del proyecto, construida tal como se recibió.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py test_app.py ./

EXPOSE 5000

# El código original usa app.run(debug=True), que dentro de un contenedor solo
# escucha en 127.0.0.1. Se usa la CLI de Flask con --debug para reproducir el
# mismo modo de depuración, pero accesible desde la red de Docker.
CMD ["flask", "--app", "app", "--debug", "run", "--host", "0.0.0.0", "--port", "5000"]
