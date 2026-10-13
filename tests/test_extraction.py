import unittest

from src.extraction import (masquer_secrets, normaliser_docker,
                            normaliser_trivy)

LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"


class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("login ok password=abc123 user=bob"),
                         "login ok password=[SECRET] user=bob")

    def test_masquer_secrets_variantes(self):
        self.assertEqual(masquer_secrets("token: xyz TOKEN=abc SECRET foo=1"),
                         "token: [SECRET] TOKEN=[SECRET] SECRET foo=1")
        self.assertEqual(masquer_secrets("api_key=123 passwd:abc"),
                         "api_key=[SECRET] passwd:[SECRET]")
        # insensible à la casse
        self.assertEqual(masquer_secrets("PASSWORD=abc"),
                         "PASSWORD=[SECRET]")

    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE, 125)
        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.source, "DOCKER")
        self.assertEqual(evt.component, "backend")
        self.assertEqual(evt.event_type, "CONTAINER_RESTART")
        self.assertEqual(evt.severity, "HIGH")

    def test_normaliser_docker_warn_masque(self):
        ligne = ("2026-10-05 10:05:40 WARN frontend slow response "
                 "password=abc123 time=2300ms")
        evt = normaliser_docker(ligne, 3)
        self.assertEqual(evt.severity, "MEDIUM")
        self.assertEqual(evt.event_type, "LOG")
        self.assertIn("password=[SECRET]", evt.message)
        self.assertNotIn("abc123", evt.message)

    def test_normaliser_docker_invalide(self):
        with self.assertRaises(ValueError):
            normaliser_docker("2026-10-05 ERROR", 1)

    def test_normaliser_trivy(self):
        rapport = {"Target": "backend", "VulnerabilityID": "CVE-2026-1234",
                   "PkgName": "lib", "InstalledVersion": "1.2.3",
                   "Severity": "CRITICAL",
                   "Timestamp": "2026-10-05T10:07:00Z"}
        evt = normaliser_trivy(rapport, 5)
        self.assertEqual(evt.id, "EVT-00005")
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")
        self.assertIn("CVE-2026-1234", evt.message)

    def test_normaliser_trivy_cle_manquante(self):
        with self.assertRaises(ValueError):
            normaliser_trivy({"Target": "backend"}, 1)


if __name__ == "__main__":
    unittest.main()
