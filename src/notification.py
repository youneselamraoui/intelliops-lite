from src.contrat import Analyse, Evenement, Notification


def choisir_canal(criticite: str) -> str:
  """Choisit le canal de notification en fonction de la criticité."""
  if criticite in ("CRITICAL", "HIGH"):
    return "TEAMS"
  elif criticite == "MEDIUM":
    return "EMAIL"
  elif criticite == "LOW":
    return "DASHBOARD"
  else:
    raise ValueError(f"Criticité inconnue : {criticite}")


def rediger(evt: Evenement, analyse: Analyse) -> str:
  """Rédige le message de notification formaté sur 5 lignes exactement."""
  sources_str = ", ".join(analyse.sources)
  return (
      f"[{analyse.criticite}] Service : {evt.component}\n"
      f"Incident {evt.message}\n"
      f"Cause probable: {analyse.cause_probable}\n"
      f"Action {analyse.action_recommandee}\n"
      f"Sources {sources_str}"
  )


def notifier(
    evt: Evenement, analyse: Analyse, journal: list
) -> Notification:
  """Crée la notification, l'ajoute au journal, met à jour l'événement et la renvoie."""
  canal = choisir_canal(analyse.criticite)
  message = rediger(evt, analyse)
  
  notif = Notification(
      event_id=evt.id,
      canal=canal,
      destinataire="equipe-ops",
      message=message,
  )
  
  journal.append(notif)
  evt.status = "NOTIFIED"
  return notif


def demander_validation(analyse: Analyse, reponse: str) -> bool:
  """Gère la validation humaine si l'action est sensible."""
  if not analyse.sensible:
    return True
  
  reponse_clean = reponse.strip().lower()
  return reponse_clean in ("o", "oui", "y", "yes")