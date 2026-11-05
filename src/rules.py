import re
import pandas as pd
from parse_logs import parse_log

SQLI_XSS = re.compile(
    r"(union\s+select|'\s*or\s*'|drop\s+table|<script|--|;\s*drop)",
    re.IGNORECASE,
)
SENSITIVE = re.compile(
    r"(\.env|\.git|phpmyadmin|backup\.sql|wp-admin/install)",
    re.IGNORECASE,
)

def detect_bruteforce(df, threshold=10):
    fails = df[(df["path"] == "/login") & (df["status"] == 401)]
    counts = fails.groupby("ip").size()
    return [
        {"type": "brute_force", "ip": ip, "count": int(n), "severity": "high"}
        for ip, n in counts.items() if n >= threshold
    ]

def detect_injection(df):
    mask = df["path"].apply(lambda p: bool(SQLI_XSS.search(p)))
    counts = df[mask].groupby("ip").size()
    return [
        {"type": "injection_sqli_xss", "ip": ip, "count": int(n), "severity": "critical"}
        for ip, n in counts.items()
    ]

def detect_scan(df, threshold=5):
    mask = df["path"].apply(lambda p: bool(SENSITIVE.search(p)))
    counts = df[mask].groupby("ip").size()
    return [
        {"type": "scan_fichiers_sensibles", "ip": ip, "count": int(n), "severity": "medium"}
        for ip, n in counts.items() if n >= threshold
    ]

def run_all_rules(df):
    return detect_bruteforce(df) + detect_injection(df) + detect_scan(df)

if __name__ == "__main__":
    df = parse_log()
    alerts = run_all_rules(df)
    print(f"{len(alerts)} alertes détectées\n")
    for a in alerts:
        print(a)