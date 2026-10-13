import unittest
from src.contrat import Analyse, Evenement
from src.notification import (
    choisir_canal,
    demander_validation,
    notifier,
    rediger,
)


def exemple(sensible=True, criticite="CRITICAL"):
  e = Evenement(
      "EVT-00125",
      "2026-10-05T10:02:11Z",
      "DOCKER",
      "backend",
      "production",
      "CONTAINER_RESTART",
      "HIGH",
      "OOMKilled restarts=14",
  )
  a = Analyse(
      "EVT-00125",
      criticite,
      "Limite mémoire",
      "Redémarrer backend",
      sensible,
      ["DOCKER"],
  )
  return e, a


class TestNotification(unittest.TestCase):

  def test_canaux(self):
    self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
    self.assertEqual(choisir_canal("LOW"), "DASHBOARD")

  def test_validation(self):
    _, a = exemple()
    self.assertTrue(demander_validation(a, " OUI "))
    self.assertFalse(demander_validation(a, "n"))