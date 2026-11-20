# -*- coding: utf-8 -*-
"""
creer_echantillon.py — Fabrique data/echantillon_cicids2017.csv, un petit extrait
RÉEL et BRUT (non nettoyé) de CICIDS2017, pour que le notebook puisse tourner
sur une machine où le dataset complet (~650 Mo) n'est pas téléchargé.

À lancer une seule fois, sur une machine qui possède les 5 CSV complets :
    python creer_echantillon.py
"""

from pathlib import Path

import pandas as pd

DOSSIER = Path(__file__).parent / "data"
LIGNES_MAX_PAR_LABEL = 1500     # par fichier et par label d'origine

morceaux = []
for fichier in sorted((DOSSIER / "CICIDS2017").glob("*.csv")):
    df = pd.read_csv(fichier, encoding="latin-1", low_memory=False)
    label = df.columns[-1]                                      # ' Label' (avec espace)
    # Tirage aléatoire de 1500 lignes au plus pour chaque label du fichier
    extrait = pd.concat(g.sample(min(len(g), LIGNES_MAX_PAR_LABEL), random_state=42)
                        for _, g in df.groupby(label))
    morceaux.append(extrait)
    print(f"{fichier.name:60s} {len(extrait):6d} lignes")

echantillon = pd.concat(morceaux, ignore_index=True)
echantillon.to_csv(DOSSIER / "echantillon_cicids2017.csv", index=False, encoding="latin-1")
print(f"\nÉchantillon écrit : {len(echantillon)} lignes")
