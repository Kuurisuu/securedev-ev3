# Monitorización de producción e incidentes

## Arquitectura

```
securedev-prod (:5000 app, :9100 métricas)  --scrape 5s-->  Prometheus (:9090)  -->  Grafana (:3000)
        |                                                    reglas de alerta
        +-- logs "security event=..." (docker logs)
```

Todo está definido como código en [`monitoring/`](../monitoring):

- `docker-compose.yml`: levanta Prometheus v3.16.0 y Grafana 13.2.6 en la red `devsecops-lab`.
  Grafana tiene el registro de usuarios y el acceso anónimo desactivados.
- `prometheus/prometheus.yml`: recolecta `securedev-prod:9100` cada 5 s (`environment=production`).
- `prometheus/alerts.yml`: reglas de alerta, validadas con `promtool check rules` (4 reglas, SUCCESS).
- `grafana/provisioning/`: datasource Prometheus y carpeta de dashboards, aprovisionados automáticamente.
- `grafana/dashboards/securedev-produccion.json`: dashboard *SecureDev - Producción*.

El puerto de métricas 9100 no se publica fuera de la red de Docker.

## Métricas expuestas por la aplicación

| Métrica | Etiquetas | Uso |
|---------|-----------|-----|
| `app_http_requests_total` | method, endpoint, status | Tráfico y tasa de errores |
| `app_http_request_duration_seconds` | endpoint | Latencia p95 |
| `app_security_events_total` | type = `xss_attempt`, `invalid_input`, `resource_probe` | Detección de ataques |
| `up` (Prometheus) | job | Disponibilidad |

`endpoint` usa la ruta declarada, o `no_route` si la ruta no existe, y no la URL
recibida. Así un escáner no puede crear miles de series de métricas.

## Dashboard *SecureDev - Producción* (se actualiza cada 5 s)

1. Estado de la aplicación: EN LÍNEA o CAÍDA.
2. Intentos de XSS bloqueados.
3. Rutas inexistentes sondeadas.
4. Porcentaje de respuestas 4xx.
5. Peticiones por segundo según código HTTP.
6. Eventos de seguridad por tipo.
7. Latencia p95 por endpoint.
8. Tabla de alertas de seguridad activas.

## Reglas de alerta

| Alerta | Condición | Severidad | Qué indica |
|--------|-----------|-----------|------------|
| `IntentoXSSDetectado` | `increase(app_security_events_total{type="xss_attempt"}[1m]) > 0` | critical | Alguien intenta inyectar scripts |
| `ReconocimientoDeRutas` | más de 5 rutas inexistentes en 1 minuto | warning | Escaneo o enumeración de la aplicación |
| `TasaAltaDeErroresCliente` | más del 30 % de respuestas 4xx durante 30 s | warning | Tráfico anómalo o ataque automatizado |
| `AplicacionCaida` | `up == 0` durante 15 s | critical | Producción no disponible |

La etapa **Monitor** del pipeline consulta la API de Prometheus después de cada
despliegue. En el build #4 registró `up{job=securedev-prod} = 1`.

---

## Informe de incidente INC-001: reconocimiento e intentos de XSS en producción

| Campo | Detalle |
|-------|---------|
| Fecha | 18-11-2026 |
| Entorno | Producción (`securedev-prod`, imagen `securedev-ev3:3`, commit `1805740`) |
| Tipo | Simulación controlada de ataque (`scripts/simular_incidente.ps1`) |
| Severidad | Crítica (por la alerta), **sin impacto**: todos los ataques fueron bloqueados |
| Origen | `172.19.0.1`, puerta de enlace de Docker; corresponde al equipo local del laboratorio |

### Cronología (hora local, UTC-3)

| Hora | Evento |
|------|--------|
| 20:40 – 20:41 | Pruebas manuales de verificación: `/hello?name=<script>alert(1)</script>` → 400 y `/console` → 404. Quedaron registradas como `xss_attempt` y `resource_probe`. |
| 21:22 | **Ejecución 1 de la simulación.** Fase 1: 30 peticiones legítimas → 200. Fase 2: 8 rutas sensibles (`/admin`, `/.env`, `/wp-login.php`, `/phpmyadmin`, `/console`, `/config.json`, `/backup.zip`, `/.git/config`) → 404. Fase 3: 6 payloads XSS (`<script>`, `<img onerror>`, `<svg onload>`, `javascript:`, robo de cookie con `fetch`, `<body onload>`) → 400. |
| 21:22:16 | **FIRING:** `IntentoXSSDetectado` (critical) y `ReconocimientoDeRutas` (warning). |
| 21:22:46 | **FIRING:** `TasaAltaDeErroresCliente` (warning), tras 30 s con más del 30 % de 4xx. |
| 21:23:06 | Las alertas se resuelven: ya no hay eventos nuevos en la ventana de 1 minuto. |
| 21:28:26 – 21:29:16 | **Ejecución 2 de la simulación**: mismas alertas, mismo comportamiento (detección reproducible). |
| 21:44 | Build #4 (`ac05990`) vuelve a desplegar producción. Etapa Monitor: `up = 1`. |

En total Prometheus registró **13 intentos de XSS** y **17 rutas sondeadas**. Todos
recibieron 400 o 404, y la aplicación siguió **EN LÍNEA** durante todo el incidente.

### Detección

- Grafana: los paneles de XSS y de rutas sondeadas pasaron a rojo y naranja, hubo un
  pico en *Eventos de seguridad por tipo* y las alertas aparecieron en la tabla de
  alertas activas.
- Prometheus `/alerts`: las tres reglas indicadas en la cronología, en estado FIRING.
- Logs de la aplicación, con detalle forense de cada evento:
  ```
  WARNING security event=xss_attempt ip=172.19.0.1 path=/hello detail='<script>alert(1)</script>'
  WARNING security event=resource_probe ip=172.19.0.1 path=/console detail='/console'
  ```

### Análisis

- **Patrón:** reconocimiento de rutas seguido de inyección. Es la secuencia típica de
  un escáner automatizado: primero busca archivos de configuración y paneles, y
  luego prueba XSS.
- **Impacto:** ninguno. El log de acceso no muestra ninguna petición maliciosa con
  respuesta 200. La validación por lista blanca (V1) rechazó todos los payloads, y
  el debugger (`/console`, V2) ya no existe.
- **Causa:** la actividad es externa y no hay una vulnerabilidad nueva. Los controles
  funcionaron como se diseñaron.

### Acciones de respuesta

| # | Acción | Estado |
|---|--------|--------|
| 1 | Revisar las alertas en Grafana y Prometheus y confirmar que la aplicación sigue disponible (`up = 1`) | Realizada |
| 2 | Extraer de los logs la IP de origen, la hora, la ruta y el payload de cada evento (`docker logs securedev-prod \| Select-String "security event"`) | Realizada |
| 3 | Verificar que ninguna petición maliciosa recibió 200 (búsqueda de `" 400 "` y `" 404 "` en el log de acceso) | Realizada |
| 4 | Confirmar que los controles de V1 (XSS) y V2 (debug) siguen vigentes en la imagen desplegada (`docker inspect`: commit `1805740`) | Realizada |
| 5 | Redesplegar con el pipeline completo (build #4) y verificar el monitoreo desde la etapa Monitor | Realizada |
| 6 | En un entorno real: bloquear la IP de origen en el proxy inverso o WAF y aplicar *rate limiting* a `/hello` | Recomendada |
| 7 | Integrar Alertmanager para notificar las alertas críticas por correo o chat | Recomendada |

### Lecciones aprendidas

- Instrumentar la aplicación con eventos de seguridad permitió detectar el ataque
  en segundos, sin depender de herramientas externas.
- Una ventana de 1 minuto hace que las alertas se resuelvan rápido. Es útil para
  detectar ataques en curso, pero la investigación debe apoyarse en el histórico
  de Prometheus y en los logs.
