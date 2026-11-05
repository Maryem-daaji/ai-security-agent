import pandas as pd
from sklearn.ensemble import IsolationForest
from parse_logs import parse_log
from rules import run_all_rules

def build_features(df):
    df = df.copy()
    df["is_error"] = df["status"] >= 400
    df["is_post"] = df["method"] == "POST"
    df["minute"] = df["time"].dt.floor("min")

    g = df.groupby("ip")
    feats = pd.DataFrame({
        "nb_requetes": g.size(),
        "taux_erreur": g["is_error"].mean(),
        "nb_urls_distinctes": g["path"].nunique(),
        "nb_post": g["is_post"].sum(),
        "taille_moyenne": g["size"].mean(),
    })
    per_minute = df.groupby(["ip", "minute"]).size()
    feats["req_par_minute_max"] = per_minute.groupby("ip").max()
    return feats

def detect_anomalies(feats, contamination=0.001):
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(feats)
    feats = feats.copy()
    feats["score"] = model.decision_function(feats)  # plus bas = plus anormal
    feats["anomalie"] = model.predict(feats.drop(columns="score")) == -1
    return feats

if __name__ == "__main__":
    df = parse_log()
    feats = build_features(df)
    print(f"{len(feats)} IP au total")

    feats = feats[feats["nb_requetes"] >= 5]
    print(f"{len(feats)} IP analysées (au moins 5 requêtes)\n")

    res = detect_anomalies(feats, contamination=0.02)
    suspects = res[res["anomalie"]].sort_values("score")
    print("=== IP signalées par le ML ===")
    print(suspects.round(2), "\n")

    ips_regles = {a["ip"] for a in run_all_rules(df)}
    ips_ml = set(suspects.index)
    print("IP détectées par les règles :", len(ips_regles))
    print("IP détectées par le ML      :", len(ips_ml))
    print("Détectées par les deux      :", len(ips_regles & ips_ml))
    print("Seulement par le ML         :", ips_ml - ips_regles)
    print("Ratées par le ML            :", ips_regles - ips_ml)
    print("\n=== Effet du seuil de score ===")
    for seuil in [-0.01, -0.05, -0.10, -0.20]:
        flagged = set(res[res["score"] < seuil].index)
        tp = len(flagged & ips_regles)
        precision = tp / len(flagged) if flagged else 0
        rappel = tp / len(ips_regles)
        print(f"seuil {seuil:>6} : {len(flagged)} alertes, "
              f"précision {precision:.0%}, rappel {rappel:.0%}")