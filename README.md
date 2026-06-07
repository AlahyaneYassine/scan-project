#PROJET_REALISER_PAR:
YASSINE ALAHYANE & MOHAMED KAOUTHAR & ABDELMOUNIM KHODJI 4CIR-G2

# API de Scan Reseau (Django + DRF)

Backend de scan reseau pour projet cybersecurite, avec architecture propre (MVC + couche service).

## Structure du projet

scanner/
- views.py
- serializers.py
- urls.py
- models.py
- services/
  - nmap_service.py

## Architecture (simple)

- Vue (controller): recoit la requete HTTP et retourne la reponse JSON.
- Serializer: valide et nettoie l'entree utilisateur (IPv4 uniquement).
- Service: contient la logique metier Nmap (execution, timeout, erreurs).
- Modele: persiste chaque scan (ip, resultat, date).

Cette separation rend le code plus maintenable, testable et evolutif.

## Fonctionnalites

- Route POST /api/scan/
- Validation IPv4 stricte
- Execution du scan Nmap via subprocess.run (sans os.system)
- Timeout et gestion des erreurs metier
- Sauvegarde automatique en base dans ScanResult
- Reponse JSON exploitable par un frontend

## Securite

- Validation stricte IPv4 dans le serializer (pas d'entrees shell)
- subprocess.run utilise une liste d'arguments avec shell=False
- Verification de la presence de nmap dans le PATH
- Erreurs controlees (timeout, nmap absent, echec execution)

## Prerequis (Linux Kali / Parrot)

- Python 3.10+
- Nmap

Installation systeme (Debian/Ubuntu/Kali/Parrot):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap
```

## Installation projet

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## API

### Requete

POST /api/scan/

```json
{
  "ip": "192.168.1.1"
}
```

### Reponse succes

```json
{
  "ip": "192.168.1.1",
  "command": "nmap -sV 192.168.1.1",
  "output": "Starting Nmap ...",
  "date": "2026-04-14T12:00:00+00:00"
}
```

### Test rapide avec curl

```bash
curl -X POST http://127.0.0.1:8000/api/scan/ \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.1"}'
  


#Description

Titre :
Mise en Place de PenTests au Moyen d’Outils Open Source (Nmap, Metasploit, Kali/Parrot OS) et Intégration d’un LLM pour Renforcer la Sécurité d’un Réseau Informatique

⸻

🎯 Objectif du projet

L’objectif principal est de développer une plateforme web intelligente de cybersécurité permettant d’identifier les vulnérabilités d’un réseau informatique, d’évaluer leur impact et de proposer automatiquement des solutions de sécurité grâce à l’intelligence artificielle.

⸻

🛠️ Technologies utilisées

Cybersécurité

* Nmap : scan des ports, détection des services et des vulnérabilités.
* Metasploit Framework : validation et exploitation contrôlée des vulnérabilités détectées.
* Kali Linux ou Parrot OS : environnement de test.

Développement Web

* Django (Python)
* HTML, CSS, JavaScript
* Bootstrap

Base de données

* SQLite ou MySQL

Intelligence Artificielle

* API DeepSeek (préférée) ou API OpenAI

⸻

⚙️ Fonctionnement du système

1. L’administrateur accède au dashboard web.
2. Il saisit l’adresse IP à analyser.
3. Le système exécute automatiquement un script de sécurité.
4. Le script lance :
    * un scan Nmap ;
    * une analyse Metasploit.
5. Les résultats sont enregistrés dans des fichiers et dans la base de données.
6. L’IA analyse automatiquement les résultats.
7. Le dashboard affiche :
    * les ports ouverts ;
    * les services détectés ;
    * les vulnérabilités identifiées ;
    * les recommandations de sécurité.
8. Un chatbot IA permet à l’utilisateur de poser des questions et d’obtenir des explications ou des conseils sans quitter l’application.

⸻

🤖 Valeur ajoutée du projet

Contrairement aux outils classiques qui affichent uniquement les résultats techniques, cette plateforme intègre un assistant intelligent capable :

* d’expliquer les vulnérabilités détectées ;
* d’indiquer leur niveau de risque ;
* de proposer des solutions adaptées ;
* de répondre aux questions de l’administrateur en langage naturel.

Exemple :

Utilisateur :

Que signifie le port 22 ouvert ?

Chatbot :

Le port 22 correspond au service SSH utilisé pour l’administration à distance. Il est recommandé d’utiliser une authentification par clé SSH et de désactiver la connexion root pour renforcer la sécurité.

⸻

📊 Résultats attendus

* Détection automatique des ports ouverts.
* Identification des services actifs.
* Recherche des vulnérabilités connues (CVE).
* Validation de certaines vulnérabilités via Metasploit.
* Analyse intelligente par IA.
* Génération de rapports PDF/HTML.
* Tableau de bord centralisé.
* Assistance interactive via chatbot IA.

⸻

🎓 Conclusion

Ce projet combine cybersécurité, développement web et intelligence artificielle afin de créer une plateforme capable d’automatiser les tests d’intrusion, d’analyser les résultats et d’aider les administrateurs à sécuriser leurs infrastructures informatiques grâce à des recommandations intelligentes et interactives. Il s’agit d’une solution moderne qui facilite la détection proactive des failles avant qu’elles ne soient exploitées par des attaquants.
```
