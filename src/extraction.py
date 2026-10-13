import re

from src.contrat import Evenement, SEVERITES

# password, passwd, token, secret, api_key suivis de = ou : -> [SECRET], insensible à la casse
_SECRETS_RE = re.compile(
    r"(?i)(password|passwd|token|secret|api_key)(\s*[=:]\s*)\S+"
)


def masquer_secrets(texte: str) -> str:
    return _SECRETS_RE.sub(r"\1\2[SECRET]", texte)


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    parties = ligne.split(None, 4)
    if len(parties) < 5:
        raise ValueError("Ligne Docker invalide : moins de 5 champs")
    date, heure, niveau, composant, message = parties
    ident = f"EVT-{numero:05d}"
    timestamp = f"{date}T{heure}Z"
    niveau_up = niveau.upper()
    if niveau_up == "ERROR":
        severity = "HIGH"
    elif niveau_up == "WARN":
        severity = "MEDIUM"
    elif niveau_up == "INFO":
        severity = "LOW"
    else:
        severity = "LOW"
    message = masquer_secrets(message)
    if "restarts=" in message:
        event_type = "CONTAINER_RESTART"
    else:
        event_type = "LOG"
    return Evenement(
        id=ident,
        timestamp=timestamp,
        source="DOCKER",
        component=composant,
        environment=environment,
        event_type=event_type,
        severity=severity,
        message=message,
    )


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    cles = ["Target", "VulnerabilityID", "PkgName",
            "InstalledVersion", "Severity", "Timestamp"]
    for cle in cles:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport Trivy : {cle}")
    severity = str(rapport["Severity"]).upper()
    if severity not in SEVERITES:
        severity = "LOW"
    message = (f"Vulnérabilité {rapport['VulnerabilityID']} détectée "
               f"dans {rapport['PkgName']} {rapport['InstalledVersion']}.")
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=str(rapport["Timestamp"]),
        source="TRIVY",
        component=str(rapport["Target"]),
        environment=environment,
        event_type="VULNERABILITY",
        severity=severity,
        message=message,
    )
