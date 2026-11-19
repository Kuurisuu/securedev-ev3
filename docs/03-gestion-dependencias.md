# Gestión de dependencias

## Problema inicial

La versión 1 usaba `Flask==2.2.2` y `Werkzeug==2.2.2`, sin hashes y sin revisión
automática. Esas dos dependencias sumaban:

- 13 vulnerabilidades según pip-audit.
- 11 CVE según Dependency-Check, 4 de ellos con CVSS ≥ 7.0.
- 12 alertas de Dependabot.

## Estrategia aplicada

| Control | Implementación | Riesgo que mitiga |
|---------|----------------|-------------------|
| Dependencias directas declaradas con rangos | `requirements.in`: `Flask>=3.1.3,<4`, `Flask-WTF>=1.3,<2`, `gunicorn>=27,<28`, `prometheus-client>=0.26,<1` | Versiones vulnerables antiguas; saltos de versión mayor no revisados |
| Bloqueo de versiones con hash | `pip-compile --generate-hashes requirements.in` (pip-tools 7.7.0) genera `requirements.txt` con las 11 dependencias, incluidas las transitivas, fijadas a una versión exacta y un hash SHA-256 | Paquetes alterados o suplantados en PyPI (cadena de suministro); builds no reproducibles |
| Instalación verificada | `pip install --require-hashes -r requirements.txt` en el Dockerfile | pip rechaza cualquier paquete cuyo hash no coincida |
| Análisis SCA en cada build | pip-audit (base PyPI/OSV) sobre `requirements.txt` | Vulnerabilidades conocidas en las versiones declaradas |
| Análisis SCA en cada build | OWASP Dependency-Check con API key de la NVD sobre los paquetes **realmente instalados en la imagen** (`scripts/export_dependencies.py`) | Diferencias entre lo declarado y lo instalado |
| Política de bloqueo | Security Gate: cualquier vulnerabilidad de pip-audit o CVSS ≥ 7.0 en Dependency-Check → BLOQUEADO | Que una dependencia vulnerable llegue a producción |
| Actualización continua | Dependabot (`.github/dependabot.yml`) para `pip` y `docker`, semanal, con alertas y *security updates* activados | Nuevos CVE publicados después del despliegue |

## Versiones resultantes (`requirements.txt`)

| Paquete | Versión | Tipo |
|---------|---------|------|
| flask | 3.1.3 | Directa |
| flask-wtf | 1.3.0 | Directa |
| gunicorn | 27.0.1 | Directa |
| prometheus-client | 0.26.0 | Directa |
| werkzeug | 3.1.9 | Transitiva (flask) |
| jinja2 | 3.1.6 | Transitiva (flask) |
| markupsafe | 3.0.4 | Transitiva (jinja2, werkzeug) |
| itsdangerous | 2.2.0 | Transitiva (flask) |
| click | 8.5.1 | Transitiva (flask) |
| blinker | 1.9.0 | Transitiva (flask) |
| wtforms | 3.3.2 | Transitiva (flask-wtf) |

## Resultado

| Herramienta | v1 (build #1) | v2 (build #3 / #4) |
|-------------|---------------|--------------------|
| pip-audit | 13 vulnerabilidades | 0 |
| Dependency-Check | 11 CVE (4 con CVSS ≥ 7.0) | 0 de 204 dependencias analizadas |
| Dependabot | 12 alertas abiertas (3 altas) | 12/12 cerradas automáticamente como *fixed* |

## Procedimiento para actualizar una dependencia

1. Dependabot abre un pull request, o se edita `requirements.in`.
2. Se regenera el lock con `pip-compile --generate-hashes requirements.in`.
3. Jenkins ejecuta el pipeline completo: pruebas, SAST, SCA, DAST y gate.
4. Solo si el gate aprueba se integra a `main` y se despliega a producción.
