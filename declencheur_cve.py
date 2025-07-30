# -*- coding: utf-8 -*-
# Auteur: ozGod

import argparse
import requests
import sys
import json

def display_banner():
    """Affiche une bannière stylisée pour l'outil."""
    VERSION = "1.0.0"
    AUTHOR = "ozGod"
    banner = f"""
╔══════════════════════════════════════════════════════════╗
║                                                              ║
║  🚨 Déclencheur-CVE v{VERSION}                               ║
║                                                              ║
║  Récupère les détails d'une CVE depuis une API publique.    ║
║  Créé par {AUTHOR}                                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)

def fetch_cve_details(cve_id):
    """Récupère les informations d'une CVE depuis l'API de cve.circl.lu."""
    api_url = f"https://cve.circl.lu/api/cve/{cve_id}"
    print(f"[*] Recherche des informations pour : {cve_id}")
    
    try:
        response = requests.get(api_url, timeout=15)
        
        if response.status_code == 404:
            print(f"[!] Erreur: La CVE '{cve_id}' n'a pas été trouvée.", file=sys.stderr)
            return None
        
        response.raise_for_status() # Lève une exception pour les autres codes d'erreur HTTP
        return response.json()
        
    except requests.RequestException as e:
        print(f"[!] Erreur de connexion à l'API : {e}", file=sys.stderr)
        return None

def display_cve_summary(cve_data):
    """Affiche un résumé formaté des informations de la CVE."""
    if not cve_data:
        return

    print("\n--- Résumé de la Vulnérabilité ---")
    print(f"ID: {cve_data.get('id', 'N/A')}")
    print(f"Publiée le: {cve_data.get('Published', 'N/A')}")
    print(f"Modifiée le: {cve_data.get('last-modified', 'N/A')}")
    
    # Affiche le score CVSS s'il est disponible
    cvss_score = cve_data.get('cvss')
    if cvss_score:
        print(f"Score CVSS v2: {cvss_score}")

    # Affiche le résumé
    summary = cve_data.get('summary', 'Aucun résumé disponible.')
    print("\nRésumé:")
    print(summary)

    # Affiche les références
    references = cve_data.get('references')
    if references:
        print("\nRéférences:")
        for ref in references[:5]: # Limite à 5 pour la lisibilité
            print(f"  - {ref}")

def main():
    display_banner()
    parser = argparse.ArgumentParser(
        description="Récupère les détails d'une CVE en utilisant l'API de cve.circl.lu.",
        epilog=f"Créé par ozGod."
    )
    parser.add_argument("cve_id", help="L'identifiant de la CVE à rechercher (ex: CVE-2021-44228).")
    args = parser.parse_args()

    cve_data = fetch_cve_details(args.cve_id)
    if cve_data:
        display_cve_summary(cve_data)

if __name__ == "__main__":
    main()
