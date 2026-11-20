# -*- coding: utf-8 -*-
"""
features_flux.py — Définitions PARTAGÉES entre l'entraînement (notebook) et
l'étape 7 (trafic réel capturé par Zeek).

POURQUOI un fichier séparé ?
Le modèle n'est valable sur mon trafic que si les caractéristiques (features)
sont calculées EXACTEMENT de la même façon à l'entraînement (CICIDS2017) et en
production (conn.log de Zeek). En centralisant ici le regroupement des labels
et le calcul des features, on évite toute divergence entre les deux étapes.
"""

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# 1) REGROUPEMENT DES LABELS CICIDS2017 -> 5 CLASSES DU PROJET
# ---------------------------------------------------------------------------
# Les 5 classes correspondent aux scénarios que je rejouerai depuis Kali :
#   PortScan   <- nmap
#   BruteForce <- hydra (SSH) ; CICIDS2017 contient aussi FTP-Patator (même logique :
#                 essais répétés de mots de passe sur un service d'authentification)
#   DoS        <- DoS Hulk / GoldenEye = inondation de requêtes HTTP (HTTP Flood),
#                 slowloris / Slowhttptest = DoS "lent" par épuisement de connexions
#   WebAttack  <- attaques applicatives HTTP (brute force de formulaire, XSS, SQLi)
#   Normal     <- BENIGN
# "Heartbleed" (11 flux seulement) est une exploitation de vulnérabilité OpenSSL :
# elle n'appartient à aucun de mes scénarios et 11 exemples ne permettent pas
# d'apprendre une classe -> elle est EXCLUE (valeur None).
CLASSES = ["Normal", "PortScan", "BruteForce", "DoS", "WebAttack"]

MAPPING_LABELS = {
    "BENIGN": "Normal",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": None,
}


def regrouper_label(label):
    """Convertit un label d'origine CICIDS2017 en l'une des 5 classes du projet.

    Les labels "Web Attack" contiennent un caractère mal encodé dans les CSV
    (tiret long) : on les reconnaît donc par leur préfixe plutôt que par égalité.
    """
    label = str(label).strip()
    if label.startswith("Web Attack"):
        return "WebAttack"
    return MAPPING_LABELS.get(label)


# ---------------------------------------------------------------------------
# 2) VARIABLE CATÉGORIELLE "service" DÉRIVÉE DU PORT DE DESTINATION
# ---------------------------------------------------------------------------
# Un numéro de port est un IDENTIFIANT, pas une grandeur : 443 n'est pas "plus
# grand" que 80 au sens métier. On le transforme donc en catégorie de service.
# Avantage : un scan nmap touche des milliers de ports différents -> ils tombent
# tous dans "autre_*", ce qui généralise mieux que d'apprendre des numéros.
def categoriser_service(port):
    port = int(port)
    if port == 22:
        return "ssh"
    if port == 21:
        return "ftp"
    if port in (80, 8080):
        return "http"
    if port == 443:
        return "https"
    if port == 53:
        return "dns"
    if port < 1024:
        return "autre_systeme"      # autres ports "bien connus" (<1024)
    return "autre_haut"             # ports hauts / éphémères


# ---------------------------------------------------------------------------
# 3) FORMAT "DE BASE" COMMUN : 6 grandeurs que CICIDS2017 ET Zeek fournissent
# ---------------------------------------------------------------------------
COLONNES_BASE = ["duree_s", "paquets_aller", "paquets_retour",
                 "octets_aller", "octets_retour", "port_dest"]

# Correspondance colonne CICIDS2017 (CICFlowMeter) -> nom de base
CICIDS_VERS_BASE = {
    "Flow Duration": "duree_s",                       # en microsecondes dans CICIDS
    "Total Fwd Packets": "paquets_aller",
    "Total Backward Packets": "paquets_retour",
    "Total Length of Fwd Packets": "octets_aller",
    "Total Length of Bwd Packets": "octets_retour",
    "Destination Port": "port_dest",
}

# Correspondance champ Zeek conn.log -> nom de base
ZEEK_VERS_BASE = {
    "duration": "duree_s",                            # déjà en secondes dans Zeek
    "orig_pkts": "paquets_aller",
    "resp_pkts": "paquets_retour",
    "orig_bytes": "octets_aller",                     # octets de charge utile
    "resp_bytes": "octets_retour",
    "id.resp_p": "port_dest",
}


def base_depuis_cicids(df):
    """Extrait les 6 grandeurs de base d'un DataFrame CICIDS2017 (colonnes nettoyées)."""
    base = df[list(CICIDS_VERS_BASE)].rename(columns=CICIDS_VERS_BASE).copy()
    base["duree_s"] = base["duree_s"] / 1e6           # microsecondes -> secondes
    return base


def base_depuis_zeek(df):
    """Extrait les 6 grandeurs de base d'un DataFrame issu d'un conn.log Zeek.

    Zeek écrit "-" quand une valeur est inconnue (ex. durée d'un flux d'un seul
    paquet) : on la remplace par 0, ce qui est cohérent avec CICFlowMeter.
    """
    base = df[list(ZEEK_VERS_BASE)].rename(columns=ZEEK_VERS_BASE).copy()
    for col in COLONNES_BASE:
        base[col] = pd.to_numeric(base[col], errors="coerce").fillna(0)
    return base


# ---------------------------------------------------------------------------
# 4) CALCUL DES FEATURES DU MODÈLE "COMPATIBLE ZEEK"
# ---------------------------------------------------------------------------
FEATURES_NUM_ZEEK = [
    "duree_s", "paquets_aller", "paquets_retour", "octets_aller", "octets_retour",
    "paquets_total", "octets_total", "octets_par_s", "paquets_par_s",
    "taille_moy_aller", "taille_moy_retour", "ratio_paquets_retour_aller",
]
FEATURES_CAT_ZEEK = ["service"]
FEATURES_ZEEK = FEATURES_NUM_ZEEK + FEATURES_CAT_ZEEK


def _division_sure(numerateur, denominateur):
    """Division qui renvoie 0 quand le dénominateur vaut 0.

    C'est précisément la division par une durée nulle qui crée les valeurs
    "Infinity" de CICIDS2017 : ici on les évite par construction.
    """
    numerateur = np.asarray(numerateur, dtype="float64")
    denominateur = np.asarray(denominateur, dtype="float64")
    resultat = np.zeros_like(numerateur)
    np.divide(numerateur, denominateur, out=resultat, where=denominateur > 0)
    return resultat


def _sans_bourrage(octets, paquets):
    """Met à 0 les octets d'un sens quand ils ne sont que du bourrage Ethernet.

    Une trame Ethernet fait au minimum 60 octets : un paquet TCP SANS données
    (SYN, RST, ACK pur = 54 à 58 octets) est complété par 2 à 6 octets de
    bourrage. CICFlowMeter compte ce bourrage comme de la charge utile, Zeek non.
    Dans CICIDS2017, 99 % des PortScan valent ainsi "0 ou 2 octets aller, 6 octets
    retour" : sans correction, le modèle apprendrait la règle "6 octets = scan",
    qui n'existe pas dans un conn.log (Zeek y écrit 0).
    Règle : si un sens transporte au plus 6 octets par paquet en moyenne, on
    considère qu'il n'a transporté aucune donnée réelle.
    """
    return octets.where(octets > 6 * paquets, 0)


def construire_features(base):
    """À partir des 6 grandeurs de base, calcule les 13 features du modèle.

    La même fonction est appelée sur CICIDS2017 (entraînement) et sur Zeek
    (étape 7) : les définitions sont donc garanties identiques.
    """
    f = pd.DataFrame(index=base.index)
    f["duree_s"] = base["duree_s"].clip(lower=0)
    f["paquets_aller"] = base["paquets_aller"]
    f["paquets_retour"] = base["paquets_retour"]
    # Neutralisation du BOURRAGE ETHERNET (voir _sans_bourrage ci-dessus)
    f["octets_aller"] = _sans_bourrage(base["octets_aller"], base["paquets_aller"])
    f["octets_retour"] = _sans_bourrage(base["octets_retour"], base["paquets_retour"])
    # Volumes totaux du flux
    f["paquets_total"] = f["paquets_aller"] + f["paquets_retour"]
    f["octets_total"] = f["octets_aller"] + f["octets_retour"]
    # Débits : un DoS/flood se voit au débit, un scan à sa brièveté
    f["octets_par_s"] = _division_sure(f["octets_total"], f["duree_s"])
    f["paquets_par_s"] = _division_sure(f["paquets_total"], f["duree_s"])
    # Taille moyenne des paquets : un scan = paquets vides, un brute force = petits paquets
    f["taille_moy_aller"] = _division_sure(f["octets_aller"], f["paquets_aller"])
    f["taille_moy_retour"] = _division_sure(f["octets_retour"], f["paquets_retour"])
    # Asymétrie : le serveur répond-il ? (port fermé / serveur saturé -> peu de retour)
    f["ratio_paquets_retour_aller"] = _division_sure(f["paquets_retour"], f["paquets_aller"])
    # Variable catégorielle
    f["service"] = base["port_dest"].map(categoriser_service)
    return f[FEATURES_ZEEK]
