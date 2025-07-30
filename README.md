# 🚨 Déclencheur-CVE - Récupérateur d'Informations CVE

**Créé par ozGod-sh**

## Description

Déclencheur-CVE est un outil de recherche et d'analyse des vulnérabilités CVE (Common Vulnerabilities and Exposures). Il récupère automatiquement les détails des vulnérabilités depuis l'API publique de cve.circl.lu et présente les informations de manière structurée pour l'analyse de sécurité.

## Fonctionnalités

### 🔍 Recherche CVE complète
- **API cve.circl.lu** : Source fiable et mise à jour
- **Informations détaillées** : Description, score CVSS, références
- **Dates de publication** : Chronologie des vulnérabilités
- **Références externes** : Liens vers les sources et correctifs

### 📊 Analyse de vulnérabilités
- **Score CVSS v2** : Évaluation de la criticité
- **Résumé technique** : Description de la vulnérabilité
- **Références multiples** : Sources d'information additionnelles
- **Formatage lisible** : Présentation claire des données

## Installation

### Prérequis
- Python 3.6+
- Connexion Internet pour accéder à l'API

### Installation des dépendances
```bash
cd Declencheur-CVE
pip install -r requirements.txt
```

### Dépendances
- `requests` : Bibliothèque HTTP pour les appels API

## Utilisation

### Syntaxe de base
```bash
python declencheur_cve.py <CVE_ID>
```

### Exemples d'utilisation

#### 1. Recherche Log4Shell
```bash
python declencheur_cve.py CVE-2021-44228
```

#### 2. Recherche Heartbleed
```bash
python declencheur_cve.py CVE-2014-0160
```

#### 3. Recherche Spectre
```bash
python declencheur_cve.py CVE-2017-5753
```

## Structure des fichiers

```
Declencheur-CVE/
├── declencheur_cve.py    # Script principal
├── requirements.txt      # Dépendances Python
└── README.md            # Cette documentation
```

## Logique de fonctionnement

### 1. Appel API
```python
api_url = f"https://cve.circl.lu/api/cve/{cve_id}"
response = requests.get(api_url, timeout=15)
```

### 2. Gestion des erreurs
```python
if response.status_code == 404:
    print(f"CVE '{cve_id}' n'a pas été trouvée.")
    return None
response.raise_for_status()
```

### 3. Formatage des données
```python
def display_cve_summary(cve_data):
    print(f"ID: {cve_data.get('id', 'N/A')}")
    print(f"Score CVSS v2: {cve_data.get('cvss')}")
    print(f"Résumé: {cve_data.get('summary')}")
```

## Cas d'usage

### Analyse de vulnérabilités
- **Recherche rapide** : Obtenir des détails sur une CVE spécifique
- **Évaluation de risque** : Comprendre l'impact d'une vulnérabilité
- **Veille sécurité** : Suivre les nouvelles vulnérabilités
- **Documentation** : Créer des rapports de sécurité

### Gestion des incidents
- **Réponse d'urgence** : Informations rapides sur les vulnérabilités critiques
- **Priorisation** : Utiliser le score CVSS pour prioriser les correctifs
- **Communication** : Partager des informations précises avec les équipes
- **Suivi** : Documenter les vulnérabilités traitées

## Exemple de sortie

### Pour CVE-2021-44228 (Log4Shell)
```
╔══════════════════════════════════════════════════════════╗
║                                                              ║
║  🚨 Déclencheur-CVE v1.0.0                               ║
║                                                              ║
║  Récupère les détails d'une CVE depuis une API publique.    ║
║  Créé par ozGod                                           ║
║                                                              ║
╚══════════════════════════════════════════════════════════╝

[*] Recherche des informations pour : CVE-2021-44228

--- Résumé de la Vulnérabilité ---
ID: CVE-2021-44228
Publiée le: 2021-12-10T10:15Z
Modifiée le: 2021-12-29T00:15Z
Score CVSS v2: 9.3

Résumé:
Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

Références:
  - https://logging.apache.org/log4j/2.x/security.html
  - https://www.lunasec.io/docs/blog/log4j-zero-day/
  - https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  - https://www.cve.org/CVERecord?id=CVE-2021-44228
```

## API cve.circl.lu

### Endpoints disponibles
- `/api/cve/{cve_id}` : Détails d'une CVE spécifique
- `/api/last` : Dernières CVE publiées
- `/api/search/{vendor}/{product}` : Recherche par produit

### Format de réponse
```json
{
  "id": "CVE-2021-44228",
  "Published": "2021-12-10T10:15Z",
  "last-modified": "2021-12-29T00:15Z",
  "cvss": 9.3,
  "summary": "Description de la vulnérabilité...",
  "references": [
    "https://example.com/advisory",
    "https://vendor.com/patch"
  ]
}
```

## Intégration avec d'autres outils

### Scripts d'automatisation
```bash
#!/bin/bash
# Analyser plusieurs CVE
cves=("CVE-2021-44228" "CVE-2021-45046" "CVE-2021-45105")
for cve in "${cves[@]}"; do
    echo "=== $cve ==="
    python declencheur_cve.py "$cve"
    echo ""
done
```

### Avec des outils de monitoring
```python
import subprocess
import json

def get_cve_info(cve_id):
    result = subprocess.run(['python', 'declencheur_cve.py', cve_id], 
                          capture_output=True, text=True)
    return result.stdout
```

### Pipeline de veille sécurité
```bash
# Surveiller les CVE critiques
python declencheur_cve.py CVE-2021-44228 | grep "Score CVSS" | awk '{if($4 > 7.0) print "CRITIQUE: " $0}'
```

## Gestion des erreurs

### Erreurs courantes
- **404 Not Found** : CVE inexistante ou mal formatée
- **Timeout** : Problème de connectivité réseau
- **500 Server Error** : Problème temporaire de l'API
- **Rate Limiting** : Trop de requêtes simultanées

### Solutions
```bash
# Vérifier la connectivité
ping cve.circl.lu

# Tester l'API manuellement
curl "https://cve.circl.lu/api/cve/CVE-2021-44228"

# Vérifier le format CVE
echo "CVE-YYYY-NNNN" # Format correct
```

## Limitations

### API externe
- **Dépendance réseau** : Nécessite une connexion Internet
- **Disponibilité** : Dépend de la disponibilité de l'API
- **Rate limiting** : Limites de requêtes possibles
- **Données** : Limitées aux informations de l'API

### Fonctionnalités
- **Recherche simple** : Uniquement par ID CVE
- **Pas de cache** : Pas de stockage local des données
- **Format fixe** : Sortie uniquement en texte
- **Pas de filtrage** : Affiche toutes les informations disponibles

## Améliorations futures

### Fonctionnalités avancées
- Cache local des CVE consultées
- Recherche par mots-clés ou produits
- Export en JSON/XML/CSV
- Intégration avec d'autres bases CVE (NVD, MITRE)

### Interface
- Interface graphique
- Mode interactif
- Recherche batch de plusieurs CVE
- Notifications pour nouvelles CVE

### Intégrations
- Plugin pour IDEs
- API REST pour intégration
- Webhooks pour alertes
- Base de données locale

## Alternatives et sources

### Autres APIs CVE
- **NVD (NIST)** : https://nvd.nist.gov/developers
- **MITRE** : https://cve.mitre.org/
- **CVE Details** : https://www.cvedetails.com/
- **Vulners** : https://vulners.com/api

### Outils similaires
- **cve-search** : Outil plus complet avec base locale
- **vulndb** : Base de données de vulnérabilités
- **OpenVAS** : Scanner de vulnérabilités complet
- **Nessus** : Solution commerciale

## Bonnes pratiques

### Utilisation responsable
- **Rate limiting** : Ne pas surcharger l'API
- **Cache** : Éviter les requêtes répétées
- **Attribution** : Créditer la source des données
- **Mise à jour** : Vérifier régulièrement les informations

### Sécurité
- **Validation** : Valider les IDs CVE avant requête
- **Timeout** : Configurer des timeouts appropriés
- **Logs** : Enregistrer les requêtes pour audit
- **Erreurs** : Gérer gracieusement les erreurs

## Sécurité et éthique

⚠️ **Utilisation responsable**
- Respecter les limites de l'API
- Ne pas utiliser pour des activités malveillantes
- Créditer les sources d'information
- Utiliser les informations pour améliorer la sécurité

## Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

---

**Déclencheur-CVE v1.0.0** | Créé par ozGod-sh