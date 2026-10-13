from src.contrat import Evenement, SEVERITES


def masquer_secrets(texte: str) -> str:
    raise NotImplementedError


def normaliser_docker(ligne: str, numero: int,
                      environment: str = "production") -> Evenement:
    raise NotImplementedError


def normaliser_trivy(rapport: dict, numero: int,
                     environment: str = "production") -> Evenement:
    raise NotImplementedError
