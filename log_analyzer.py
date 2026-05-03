import re
import os
from collections import defaultdict
from datetime import datetime


# ── Configuration ──────────────────────────────────────────────────────────
SEUIL_BRUTE_FORCE = 5
HEURE_DEBUT = 8
HEURE_FIN = 19
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FICHIER_LOGS = os.path.join(BASE_DIR, "auth.log")
FICHIER_RAPPORT = os.path.join(BASE_DIR, "rapport_securite.txt")


# ── Regex pour parser les lignes de log ───────────────────────────────────
# Exemple du format attendu : 2024-01-15 03:22:14 FAILED login for user admin from 192.168.1.1
PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(FAILED|SUCCESS)\s+login for user\s+(\w+)\s+from\s+([\d.]+)"
)


def charger_logs(fichier: str) -> list[dict]:
    """Lit et parse le fichier de logs. Retourne une liste d'événements."""
    evenements = []
    try:
        with open(fichier, "r", encoding="utf-8") as f:
            for numero, ligne in enumerate(f, 1):
                match = PATTERN.search(ligne)
                if match:
                    horodatage_str, statut, utilisateur, ip = match.groups()
                    horodatage = datetime.strptime(horodatage_str, "%Y-%m-%d %H:%M:%S")
                    evenements.append({
                        "horodatage": horodatage,
                        "statut": statut,
                        "utilisateur": utilisateur,
                        "ip": ip,
                        "ligne": numero
                    })
    except FileNotFoundError:
        print(f"[ERREUR] Fichier '{fichier}' introuvable.")
    return evenements


def detecter_brute_force(evenements: list[dict]) -> dict:
    """
    Détecte les IP ayant dépassé le seuil d'échecs de connexion.
    Retourne un dict {ip: nombre_echecs}.
    """
    echecs_par_ip = defaultdict(int)
    for evt in evenements:
        if evt["statut"] == "FAILED":
            echecs_par_ip[evt["ip"]] += 1

    suspects = {ip: nb for ip, nb in echecs_par_ip.items() if nb >= SEUIL_BRUTE_FORCE}
    return dict(sorted(suspects.items(), key=lambda x: x[1], reverse=True))


def detecter_acces_hors_heures(evenements: list[dict]) -> list[dict]:
    """Retourne les connexions réussies en dehors des heures ouvrées."""
    hors_heures = []
    for evt in evenements:
        heure = evt["horodatage"].hour
        if evt["statut"] == "SUCCESS" and not (HEURE_DEBUT <= heure < HEURE_FIN):
            hors_heures.append(evt)
    return hors_heures


def compter_tentatives_par_utilisateur(evenements: list[dict]) -> dict:
    """Compte les échecs par nom d'utilisateur ciblé."""
    echecs = defaultdict(int)
    for evt in evenements:
        if evt["statut"] == "FAILED":
            echecs[evt["utilisateur"]] += 1
    return dict(sorted(echecs.items(), key=lambda x: x[1], reverse=True))


def generer_rapport(evenements, suspects_bf, acces_hors_heures, cibles) -> str:
    """Construit le rapport texte complet."""
    lignes = []
    sep = "=" * 60

    lignes.append(sep)
    lignes.append("       RAPPORT D'ANALYSE DE LOGS DE SÉCURITÉ")
    lignes.append(f"       Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lignes.append(sep)

    # Résumé général
    total = len(evenements)
    echecs = sum(1 for e in evenements if e["statut"] == "FAILED")
    succes = total - echecs
    lignes.append(f"\n[RÉSUMÉ GÉNÉRAL]")
    lignes.append(f"  Total d'événements analysés : {total}")
    lignes.append(f"  Connexions réussies          : {succes}")
    lignes.append(f"  Tentatives échouées          : {echecs}")

    # Brute force
    lignes.append(f"\n[ALERTES BRUTE FORCE] (seuil : {SEUIL_BRUTE_FORCE} échecs)")
    if suspects_bf:
        for ip, nb in suspects_bf.items():
            lignes.append(f"  ⚠  IP {ip} — {nb} tentatives échouées")
    else:
        lignes.append("  Aucune IP suspecte détectée.")

    # Accès hors heures
    lignes.append(f"\n[CONNEXIONS HORS HEURES OUVRÉES] ({HEURE_DEBUT}h–{HEURE_FIN}h)")
    if acces_hors_heures:
        for evt in acces_hors_heures:
            lignes.append(
                f"  ⚠  {evt['horodatage'].strftime('%Y-%m-%d %H:%M')} "
                f"— utilisateur '{evt['utilisateur']}' depuis {evt['ip']}"
            )
    else:
        lignes.append("  Aucune connexion suspecte hors heures ouvrées.")

    # Utilisateurs les plus ciblés
    lignes.append(f"\n[UTILISATEURS LES PLUS CIBLÉS]")
    if cibles:
        for user, nb in list(cibles.items())[:5]:
            lignes.append(f"  {user} — {nb} tentative(s) échouée(s)")
    else:
        lignes.append("  Aucune donnée.")

    lignes.append(f"\n{sep}")
    lignes.append("Fin du rapport.")
    lignes.append(sep)

    return "\n".join(lignes)


def main():
    print(f"[*] Chargement des logs depuis '{FICHIER_LOGS}'...")
    evenements = charger_logs(FICHIER_LOGS)

    if not evenements:
        print("[!] Aucun événement parsé. Vérifiez le fichier de logs.")
        return

    print(f"[*] {len(evenements)} événements chargés.")
    print("[*] Analyse en cours...\n")

    suspects_bf = detecter_brute_force(evenements)
    acces_hors_heures = detecter_acces_hors_heures(evenements)
    cibles = compter_tentatives_par_utilisateur(evenements)

    rapport = generer_rapport(evenements, suspects_bf, acces_hors_heures, cibles)

    print(rapport)

    with open(FICHIER_RAPPORT, "w", encoding="utf-8") as f:
        f.write(rapport)
    print(f"\n[✓] Rapport sauvegardé dans '{FICHIER_RAPPORT}'.")


if __name__ == "__main__":
    main()
