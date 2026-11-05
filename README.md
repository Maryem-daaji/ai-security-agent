# Agent IA de détection d'attaques pour sites e-commerce

Projet réalisé lors d'un stage de développeuse d'agents IA chez GED PLUS (juillet 2026).

## Description

Un agent qui analyse les logs d'un serveur web, détecte les comportements suspects
(brute force, injections SQL/XSS, scan de fichiers sensibles), explique chaque alerte
en langage simple et recommande des actions. Les résultats sont exposés par une API
et affichés dans un dashboard.

**Note** : les logs sont simulés (générateur dans `src/generate_logs.py`).

## Architecture

logs -> parsing (Pandas) -> règles (regex) + ML (Isolation Forest)
-> agent (explication + actions) -> API FastAPI -> dashboard React / alertes Telegram

## Technologies

Python, Pandas, Scikit-learn, FastAPI, React (Vite, Recharts), Docker, Pytest.

## Installation

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src\generate_logs.py
```

## Lancement

API (depuis le dossier `src`) :

```powershell
cd src
uvicorn api:app --reload
```

Dashboard (dans un autre terminal) :

```powershell
cd dashboard
npm install
npm run dev
```

Dashboard : http://localhost:5173 - Documentation API : http://127.0.0.1:8000/docs

## Mode LLM (optionnel)

Sans clé, l'agent utilise un playbook de réponses prédéfinies. Avec la variable
d'environnement `ANTHROPIC_API_KEY`, un LLM rédige les explications.
Pour Telegram, renseigner `TELEGRAM_BOT_TOKEN` et `TELEGRAM_CHAT_ID` dans un fichier `.env`.

## Tests

```powershell
python -m pytest tests -v
```

## Résultats

| Méthode | Attaquants détectés | Alertes | Précision | Rappel |
|---|---|---|---|---|
| Règles | 3 / 3 | 3 | 100 % | 100 % |
| ML (contamination 0.02) | 3 / 3 | 8 | 37,5 % | 100 % |

Effet du seuil de score du modèle ML :

| Seuil | Alertes | Précision | Rappel |
|---|---|---|---|
| -0.01 | 7 | 43 % | 100 % |
| -0.05 | 4 | 75 % | 100 % |
| -0.10 | 3 | 100 % | 100 % |

## Limites

- Données simulées : les attaques sont très évidentes, sur de vrais logs les résultats seraient moins nets.
- Le ML a besoin d'une population normale suffisante (premier essai raté avec 1 requête par IP).
- Pas de blocage automatique des IP, seulement des recommandations.

## Perspectives

Tests sur de vrais logs, apprentissage supervisé, blocage automatique, intégration directe à PrestaShop/WordPress.