import re
from src.contrat import Analyse, Evenement

def est_doublon(evt: Evenement, deja_vus: set) -> bool:
    cle = (evt.source, evt.component, evt.event_type, evt.message)
    if cle in deja_vus:
        return True
    deja_vus.add(cle)
    return False

def rechercher_runbook(evt: Evenement, base: dict):
    message_lower = evt.message.lower()
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in message_lower:
            return procedure
    return None

def classer(evt: Evenement) -> str:
    if evt.event_type == "CONTAINER_RESTART":
        match = re.search(r"restarts\s*=\s*(\d+)", evt.message)
        restarts = int(match.group(1)) if match else 0
        return "CRITICAL" if restarts > 100 else "MEDIUM"
    
    if evt.event_type == "VULNERABILITY" and evt.severity.upper() == "CRITICAL":
        return "HIGH"
        
    return evt.severity

def analyser(evt: Evenement, base: dict) -> Analyse:
    criticite = classer(evt)
    procedure = rechercher_runbook(evt, base)
    
    cause_probable = procedure if procedure is not None else "Cause inconnue : analyse manuelle requise"
    
    if evt.event_type == "CONTAINER_RESTART":
        action = f"Redémarrer {evt.component}"
    elif evt.event_type == "VULNERABILITY":
        action = "Mettre à jour la dépendance"
    else:
        action = "Consulter les logs"
        
    sensible = criticite in ("HIGH", "CRITICAL")
    evt.status = "ANALYSED"
    
    return Analyse(
        event_id=evt.id,
        criticite=criticite,
        cause_probable=cause_probable,
        action_recommandee=action,
        sensible=sensible,
        sources=[evt.source]
    )