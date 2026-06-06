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
```
