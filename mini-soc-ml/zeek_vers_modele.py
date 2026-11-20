# -*- coding: utf-8 -*-
"""
zeek_vers_modele.py — ÉTAPE 7 : classer les flux de MON réseau capturés par Zeek.

Utilisation :
    python zeek_vers_modele.py chemin/vers/conn.log
    python zeek_vers_modele.py chemin/vers/conn.log --sortie predictions.csv

Le script lit un conn.log (format TSV par défaut de Zeek, ou JSON si Zeek est
configuré avec LogAscii::use_json=T), le convertit au format attendu par le
modèle, puis affiche la classe prédite pour chaque connexion.
"""

import argparse
import json

import pandas as pd

from features_flux import base_depuis_zeek
from predire import predict_detail


def lire_conn_log(chemin):
    """Lit un conn.log Zeek et renvoie un DataFrame (une ligne = une connexion).

    Format TSV de Zeek : des lignes d'en-tête commençant par '#'. La ligne
    '#fields' donne le nom des colonnes ; les valeurs absentes sont notées '-'.
    """
    with open(chemin, encoding="utf-8") as f:
        premiere = f.readline()
    if premiere.lstrip().startswith("{"):                       # --- format JSON (1 objet / ligne)
        with open(chemin, encoding="utf-8") as f:
            return pd.DataFrame([json.loads(ligne) for ligne in f if ligne.strip()])

    colonnes = None                                             # --- format TSV (par défaut)
    with open(chemin, encoding="utf-8") as f:
        for ligne in f:
            if ligne.startswith("#fields"):
                colonnes = ligne.rstrip("\n").split("\t")[1:]
                break
    if colonnes is None:
        raise ValueError("Ligne '#fields' introuvable : ce fichier n'est pas un conn.log Zeek.")
    return pd.read_csv(chemin, sep="\t", comment="#", names=colonnes,
                       na_values=["-", "(empty)"], low_memory=False)


def classer_conn_log(chemin):
    """conn.log -> DataFrame avec le contexte (IP, ports, état) + la prédiction du modèle."""
    conn = lire_conn_log(chemin)
    # On ne garde que TCP/UDP : CICIDS2017 (donc le modèle) ne connaît pas ICMP/ARP.
    conn = conn[conn["proto"].isin(["tcp", "udp"])].reset_index(drop=True)
    base = base_depuis_zeek(conn)                   # 6 grandeurs de base, '-' -> 0
    predictions = predict_detail(base)              # features + Random Forest
    contexte = [c for c in ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto",
                            "service", "conn_state"] if c in conn.columns]
    return pd.concat([conn[contexte], base.drop(columns="port_dest"), predictions], axis=1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classe les connexions d'un conn.log Zeek.")
    parser.add_argument("conn_log", help="chemin du fichier conn.log")
    parser.add_argument("--sortie", help="fichier CSV où enregistrer les prédictions")
    args = parser.parse_args()

    resultat = classer_conn_log(args.conn_log)
    print(resultat.to_string(max_rows=40))
    print("\nRépartition des classes prédites :")
    print(resultat["classe_predite"].value_counts().to_string())
    if args.sortie:
        resultat.to_csv(args.sortie, index=False)
        print(f"\nPrédictions enregistrées dans {args.sortie}")
