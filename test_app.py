import unittest

from app import app


class AppTest(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_hello_responde_saludo(self):
        response = self.client.get("/hello?name=Ana")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), "Hello, Ana!")


if __name__ == "__main__":
    unittest.main()
