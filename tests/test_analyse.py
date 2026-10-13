import unittest
from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement

def evt(event_type="LOG", severity="LOW", message="ok", component="backend", source="DOCKER", id="EVT-00001"):
    return Evenement(id, "2026-10-05T10:00:00Z", source, component,
                     "production", event_type, severity, message)

class TestAnalyse(unittest.TestCase):
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))

    def test_rechercher_runbook(self):
        e1 = evt(message="Erreur OOMKilled détectée")
        self.assertIsNotNone(rechercher_runbook(e1, RUNBOOKS))
        e2 = evt(message="Aucun problème ici")
        self.assertIsNone(rechercher_runbook(e2, RUNBOOKS))

    def test_classer_redemarrages(self):
        e_crit = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e_crit), "CRITICAL")
        e_med = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=4")
        self.assertEqual(classer(e_med), "MEDIUM")

    def test_classer_vulnerabilite_et_defaut(self):
        e_vuln = evt("VULNERABILITY", "CRITICAL", "CVE detectee")
        self.assertEqual(classer(e_vuln), "HIGH")
        e_info = evt("LOG", "LOW", "simple log")
        self.assertEqual(classer(e_info), "LOW")

    def test_analyser(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14", component="api")
        analyse = analyser(e, RUNBOOKS)
        self.assertEqual(analyse.criticite, "CRITICAL")
        self.assertEqual(analyse.action_recommandee, "Redémarrer api")
        self.assertTrue(analyse.sensible)
        self.assertEqual(e.status, "ANALYSED")
        self.assertEqual(analyse.sources, ["DOCKER"])

if __name__ == "__main__":
    unittest.main()