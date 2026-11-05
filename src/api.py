from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from parse_logs import parse_log
from agent import collect_alerts, explain
from notify import notify

app = FastAPI(title="AI Security Agent")

# Autorise le dashboard React (localhost:5173) à appeler l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_alerts_with_explanations():
    df = parse_log()
    result = []
    for a in collect_alerts(df):
        result.append({**a, **explain(a)})
    return result

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/alerts")
def alerts():
    return get_alerts_with_explanations()

@app.get("/stats")
def stats():
    df = parse_log()
    return {
        "total_requetes": len(df),
        "ip_uniques": int(df["ip"].nunique()),
        "taux_erreur": round(float((df["status"] >= 400).mean()), 3),
        "codes_http": {str(k): int(v) for k, v in df["status"].value_counts().items()},
    }

@app.post("/notify")
def send_alerts():
    sent = 0
    for a in collect_alerts(parse_log()):
        if a["severity"] in ("high", "critical"):
            notify(a, explain(a))
            sent += 1
    return {"alertes_envoyees": sent}