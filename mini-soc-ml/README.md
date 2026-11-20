# Mini-SOC — Module Machine Learning (étape 6)

Classification de flux réseau en 5 classes : `Normal`, `PortScan`, `BruteForce`, `DoS`, `WebAttack`.
Dataset : CICIDS2017 (5 fichiers). Modèle : Random Forest (scikit-learn).

## Contenu

| Fichier | Rôle |
|---|---|
| `module_ml_mini_soc.ipynb` | **Le notebook** : données → nettoyage → prétraitement → modèle → évaluation → sorties → synthèse |
| `features_flux.py` | Définitions partagées : regroupement des labels, catégorie `service`, calcul des 13 features (utilisé à l'entraînement ET à l'étape 7) |
| `predire.py` | `predict(flux)` et `predict_detail(flux)` — charge `sorties/modeles/modele_rf_zeek.joblib` |
| `zeek_vers_modele.py` | Étape 7 : lit un `conn.log` Zeek (TSV ou JSON) et classe chaque connexion |
| `creer_echantillon.py` | Régénère `data/echantillon_cicids2017.csv` (extrait réel de secours) |
| `data/CICIDS2017/` | Les 5 CSV complets (~650 Mo) |
| `data/exemple_conn.log` | Petit conn.log **fabriqué** pour tester la chaîne de lecture Zeek |
| `sorties/figures/*.png` | Graphiques pour le rapport Word |
| `sorties/modeles/*.joblib` | Modèles entraînés (A complet, B compatible Zeek) |
| `sorties/tableau_metriques.csv` | Tableau récapitulatif (séparateur `;`, virgule décimale) |
| `sorties/synthese_rapport.txt` | Paragraphe de synthèse généré avec les métriques réelles |

## Installation et exécution

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
jupyter notebook module_ml_mini_soc.ipynb
```

Exécution complète : environ 10 minutes (8 cœurs, 16 Go de RAM), dont l'essentiel pour la validation croisée.

## Dataset

Télécharger `MachineLearningCSV.zip` depuis <https://www.unb.ca/cic/datasets/ids-2017.html> et copier dans
`data/CICIDS2017/` les fichiers Monday, Tuesday, Wednesday, Thursday-Morning-WebAttacks et Friday-Afternoon-PortScan.
Sans ces fichiers, le notebook tourne sur `data/echantillon_cicids2017.csv` (test du code uniquement).

## Étape 7 — tester sur mon trafic

```bash
python zeek_vers_modele.py chemin/vers/conn.log --sortie predictions.csv
```
