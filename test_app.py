import unittest

from prometheus_client import REGISTRY

from app import app


class FunctionalTest(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_hello_responde_saludo(self):
        response = self.client.get("/hello?name=Ana")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "Hello, Ana!")

    def test_hello_acepta_tildes_y_espacios(self):
        response = self.client.get("/hello?name=José Peña")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "Hello, José Peña!")

    def test_hello_sin_parametro_usa_valor_por_defecto(self):
        # V4: el código original respondía "Hello, None!".
        response = self.client.get("/hello")
        self.assertEqual(response.get_data(as_text=True), "Hello, guest!")


class SecurityTest(unittest.TestCase):
    """Pruebas de regresión de las vulnerabilidades corregidas."""

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_xss_reflejado_es_rechazado(self):
        # V1: el payload no debe volver a la página.
        response = self.client.get("/hello?name=<script>alert(1)</script>")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("<script>", response.get_data(as_text=True))

    def test_xss_con_atributo_de_evento_es_rechazado(self):
        response = self.client.get('/hello?name="><img src=x onerror=alert(1)>')
        self.assertEqual(response.status_code, 400)

    def test_intento_xss_queda_registrado_como_evento(self):
        before = REGISTRY.get_sample_value(
            "app_security_events_total", {"type": "xss_attempt"}
        ) or 0
        self.client.get("/hello?name=<svg onload=alert(1)>")
        after = REGISTRY.get_sample_value(
            "app_security_events_total", {"type": "xss_attempt"}
        )
        self.assertEqual(after, before + 1)

    def test_modo_debug_desactivado(self):
        # V2: el debugger de Werkzeug no debe estar activo.
        self.assertFalse(app.debug)
        self.assertEqual(self.client.get("/console").status_code, 404)

    def test_proteccion_csrf_activa(self):
        # V3: CSRFProtect queda registrado en la aplicación.
        self.assertIn("csrf", app.extensions)

    def test_cabeceras_de_seguridad(self):
        # V5: cabeceras que ZAP reportó como ausentes.
        headers = self.client.get("/hello?name=Ana").headers
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Server"], "SecureDev")


if __name__ == "__main__":
    unittest.main()
