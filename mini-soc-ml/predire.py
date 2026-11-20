# -*- coding: utf-8 -*-
"""
predire.py — Fonction predict(flux) utilisable à l'étape 7 (test sur MON trafic).

Utilisation minimale :
    from predire import predict
    flux = {"duree_s": 0.00005, "paquets_aller": 1, "paquets_retour": 1,
            "octets_aller": 0, "octets_retour": 0, "port_dest": 3389}
    print(predict(flux))            # -> "PortScan"

Le modèle chargé est le Random Forest "compatible Zeek" : il n'a besoin que de
6 grandeurs par flux (celles que fournit conn.log), les 13 features étant
recalculées par features_flux.construire_features().
"""

from pathlib import Path

import joblib
import pandas as pd

from features_flux import COLONNES_BASE, construire_features

CHEMIN_MODELE = Path(__file__).parent / "sorties" / "modeles" / "modele_rf_zeek.joblib"
_modele = None  # chargé une seule fois, au premier appel (le fichier fait plusieurs Mo)


def charger_modele(chemin=CHEMIN_MODELE):
    """Charge le pipeline (prétraitement + Random Forest) sauvegardé par le notebook."""
    global _modele
    if _modele is None:
        if not Path(chemin).exists():
            raise FileNotFoundError(
                f"Modèle introuvable : {chemin}\n"
                "-> Exécuter d'abord le notebook module_ml_mini_soc.ipynb pour l'entraîner."
            )
        _modele = joblib.load(chemin)
    return _modele


def _vers_dataframe(flux):
    """Accepte un dict (un flux), une liste de dicts ou un DataFrame (plusieurs flux)."""
    if isinstance(flux, dict):
        flux = [flux]
    df = pd.DataFrame(flux)
    manquantes = [c for c in COLONNES_BASE if c not in df.columns]
    if manquantes:
        raise ValueError(f"Caractéristiques manquantes : {manquantes}. Attendu : {COLONNES_BASE}")
    return df


def predict(flux):
    """Renvoie la classe prédite : Normal, PortScan, BruteForce, DoS ou WebAttack.

    - flux = dict  -> renvoie une chaîne (la classe)
    - flux = liste de dicts / DataFrame -> renvoie la liste des classes
    """
    df = _vers_dataframe(flux)
    classes = charger_modele().predict(construire_features(df))
    return classes[0] if isinstance(flux, dict) else list(classes)


def predict_detail(flux):
    """Comme predict(), mais renvoie un DataFrame avec la probabilité de chaque classe.

    La "confiance" est la proportion d'arbres de la forêt qui votent pour la
    classe retenue : utile pour ne remonter dans Wazuh que les alertes sûres.
    """
    df = _vers_dataframe(flux)
    modele = charger_modele()
    probas = pd.DataFrame(modele.predict_proba(construire_features(df)),
                          columns=[f"p_{c}" for c in modele.classes_], index=df.index)
    resultat = pd.DataFrame({"classe_predite": modele.classes_[probas.values.argmax(axis=1)],
                             "confiance": probas.max(axis=1).round(3)}, index=df.index)
    return pd.concat([resultat, probas.round(3)], axis=1)


if __name__ == "__main__":
    # Petit test manuel : python predire.py
    exemples = {
        "sonde nmap sur un port fermé": dict(duree_s=0.00005, paquets_aller=1, paquets_retour=1,
                                             octets_aller=0, octets_retour=0, port_dest=3389),
        "navigation HTTPS ordinaire": dict(duree_s=1.8, paquets_aller=12, paquets_retour=14,
                                           octets_aller=900, octets_retour=6500, port_dest=443),
    }
    for nom, flux in exemples.items():
        print(f"{nom:35s} -> {predict(flux)}")
