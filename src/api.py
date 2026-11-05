from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from parse_logs import parse_log, parse_lines
from agent import collect_alerts, explain
import os

app = FastAPI(title="AI Security Agent")

ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)
def analyze(df):
    alerts = [{**a, **explain(a)} for a in collect_alerts(df)]
    flagged = {a["ip"] for a in alerts}

    df = df.copy()
    df["is_error"] = df["status"] >= 400

    g = df.groupby("ip")
    top = (
        g.agg(requetes=("ip", "size"), taux_erreur=("is_error", "mean"))
        .sort_values("requetes", ascending=False)
        .head(10)
    )
    top_ips = [
        {"ip": ip, "requetes": int(r.requetes),
         "taux_erreur": round(float(r.taux_erreur), 3),
         "suspect": ip in flagged}
        for ip, r in top.iterrows()
    ]

    par_heure = df.set_index("time").resample("1h").size()
    timeline = [{"heure": t.strftime("%d/%m %Hh"), "n": int(n)}
                for t, n in par_heure.items()]

    return {
        "stats": {
            "total_requetes": len(df),
            "ip_uniques": int(df["ip"].nunique()),
            "taux_erreur": round(float(df["is_error"].mean()), 3),
            "codes_http": {str(k): int(v) for k, v in df["status"].value_counts().items()},
        },
        "alerts": alerts,
        "top_ips": top_ips,
        "timeline": timeline,
    }

@app.get("/")
def root():
    return {"status": "ok"}

@app.get("/analyze/demo")
def analyze_demo():
    return analyze(parse_log())

MAX_BYTES = 5 * 1024 * 1024  # 5 Mo

@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (5 Mo maximum).")
    content = raw.decode("utf-8", errors="ignore")
    try:
        df = parse_lines(content.splitlines())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return analyze(df)

@app.get("/alerts")
def alerts():
    return analyze(parse_log())["alerts"]

@app.get("/stats")
def stats():
    return analyze(parse_log())["stats"]

