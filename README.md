# Log Analyzer — Détection de comportements suspects

Outil Python d'analyse de logs d'authentification pour détecter des comportements suspects :
brute force, connexions hors heures ouvrées, utilisateurs les plus ciblés.


---

## Fonctionnalités

- Détection de brute force (seuil paramétrable d'échecs par IP)
- Identification des connexions réussies hors heures ouvrées
- Classement des utilisateurs les plus ciblés
- Génération automatique d'un rapport texte

---

## Structure

```
log-analyzer/
├── log_analyzer.py       # Script principal
├── auth.log              # Exemple de fichier de logs
├── rapport_securite.txt  # Rapport généré (exemple)
└── README.md
```

---

## Format des logs attendu

```
2024-01-15 08:22:47 FAILED login for user admin from 45.33.32.156
2024-01-15 08:14:02 SUCCESS login for user alice from 192.168.1.10
```

---

## Installation et utilisation

```bash
# Aucune dépendance externe — Python 3.10+ suffit
python log_analyzer.py
```

Le rapport est affiché dans le terminal et sauvegardé dans `rapport_securite.txt`.

---

## Configuration

Dans `log_analyzer.py`, modifier les constantes en haut du fichier :

```python
SEUIL_BRUTE_FORCE = 5    # Nombre d'échecs avant alerte
HEURE_DEBUT = 8          # Début heures ouvrées
HEURE_FIN   = 19         # Fin heures ouvrées
FICHIER_LOGS = "auth.log"
```

---

## Exemple de rapport généré

```
============================================================
       RAPPORT D'ANALYSE DE LOGS DE SÉCURITÉ
       Généré le : 2024-01-16 09:00:00
============================================================

[RÉSUMÉ GÉNÉRAL]
  Total d'événements analysés : 24
  Connexions réussies          : 8
  Tentatives échouées          : 16

[ALERTES BRUTE FORCE] (seuil : 5 échecs)
  ⚠  IP 45.33.32.156 — 8 tentatives échouées
  ⚠  IP 198.51.100.42 — 5 tentatives échouées

[CONNEXIONS HORS HEURES OUVRÉES] (8h–19h)
  ⚠  2024-01-15 02:17 — utilisateur 'dave' depuis 10.0.0.99
  ⚠  2024-01-15 03:22 — utilisateur 'admin' depuis 45.33.32.156

[UTILISATEURS LES PLUS CIBLÉS]
  admin — 9 tentative(s) échouée(s)
  root  — 7 tentative(s) échouée(s)
```

---

