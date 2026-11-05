import os
import json
from parse_logs import parse_log
from rules import run_all_rules
from ml_detect import build_features, detect_anomalies

PLAYBOOK = {
    "brute_force": {
        "explication": "L'IP {ip} a tenté {count} connexions échouées sur /login. "
                       "Un attaquant essaie probablement de deviner des mots de passe.",
        "actions": ["Bloquer l'IP {ip} au niveau du pare-feu",
                    "Activer une limite de tentatives (rate limiting) sur /login",
                    "Imposer des mots de passe forts et l'authentification à deux facteurs"],
    },
    "injection_sqli_xss": {
        "explication": "L'IP {ip} a envoyé {count} requêtes contenant du code malveillant "
                       "(injection SQL ou XSS) pour tenter de voler ou modifier des données.",
        "actions": ["Bloquer l'IP {ip} immédiatement",
                    "Vérifier que les modules/plugins sont à jour",
                    "Activer un pare-feu applicatif (WAF)"],
    },
    "scan_fichiers_sensibles": {
        "explication": "L'IP {ip} a cherché {count} fichiers sensibles (.env, .git, phpmyadmin). "
                       "C'est une phase de reconnaissance avant une attaque.",
        "actions": ["Bloquer l'IP {ip}",
                    "Vérifier qu'aucun fichier sensible n'est accessible publiquement",
                    "Restreindre l'accès à /phpmyadmin et /wp-admin"],
    },
    "anomalie_ml": {
        "explication": "L'IP {ip} a un comportement inhabituel détecté par le modèle "
                       "(score {score}). Aucune règle connue ne correspond.",
        "actions": ["Surveiller cette IP",
                    "Examiner manuellement ses requêtes avant de bloquer"],
    },
}

def explain_simulated(alert):
    p = PLAYBOOK[alert["type"]]
    return {
        "explication": p["explication"].format(**alert),
        "actions": [a.format(**alert) for a in p["actions"]],
    }

def explain_llm(alert):
    """Mode LLM : nécessite ANTHROPIC_API_KEY dans les variables d'environnement."""
    import anthropic
    client = anthropic.Anthropic()
    prompt = (
        "Tu es un analyste de sécurité pour un site e-commerce. "
        "Explique cette alerte en 2 phrases simples pour un administrateur non expert, "
        "puis propose 3 actions concrètes. Réponds uniquement en JSON avec les clés "
        '"explication" (texte) et "actions" (liste de textes).\n\n'
        f"Alerte : {json.dumps(alert, ensure_ascii=False)}"
    )
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text.strip().removeprefix("```json").removesuffix("```").strip()
    return json.loads(text)

def explain(alert):
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            return explain_llm(alert)
        except Exception as e:
            print(f"[LLM indisponible, mode simulé] {e}")
    return explain_simulated(alert)

def collect_alerts(df, seuil_ml=-0.10):
    alerts = run_all_rules(df)
    ips_regles = {a["ip"] for a in alerts}

    feats = build_features(df)
    feats = feats[feats["nb_requetes"] >= 5]
    res = detect_anomalies(feats, contamination=0.02)
    for ip, row in res[res["score"] < seuil_ml].iterrows():
        if ip not in ips_regles:
            alerts.append({"type": "anomalie_ml", "ip": ip,
                           "count": int(row["nb_requetes"]),
                           "score": round(float(row["score"]), 2),
                           "severity": "medium"})
    return alerts

if __name__ == "__main__":
    df = parse_log()
    alerts = collect_alerts(df)
    mode = "LLM" if os.getenv("ANTHROPIC_API_KEY") else "simulé"
    print(f"Mode : {mode} | {len(alerts)} alertes\n")
    for a in alerts:
        r = explain(a)
        print(f"[{a['severity'].upper()}] {a['type']} - {a['ip']}")
        print(f"  {r['explication']}")
        for act in r["actions"]:
            print(f"   - {act}")
        print()