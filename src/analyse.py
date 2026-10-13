from src.contrat import Analyse, Evenement


def est_doublon(evt: Evenement, deja_vus: set) -> bool:
    raise NotImplementedError


def rechercher_runbook(evt: Evenement, base: dict):
    raise NotImplementedError


def classer(evt: Evenement) -> str:
    raise NotImplementedError


def analyser(evt: Evenement, base: dict) -> Analyse:
    raise NotImplementedError
