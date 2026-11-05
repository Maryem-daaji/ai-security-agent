import re
import pandas as pd

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.+?) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

def parse_log(path="data/access.log"):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if m:
                rows.append(m.groupdict())
    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["time"], format="%d/%b/%Y:%H:%M:%S %z")
    df["status"] = df["status"].astype(int)
    df["size"] = df["size"].astype(int)
    return df

if __name__ == "__main__":
    df = parse_log()
    print(f"{len(df)} lignes parsées\n")
    print(df.head(), "\n")

    print("=== Codes HTTP ===")
    print(df["status"].value_counts(), "\n")

    print("=== Top 5 IP par nombre de requêtes ===")
    print(df["ip"].value_counts().head(5), "\n")

    print("=== Top 5 user-agents ===")
    print(df["ua"].value_counts().head(5), "\n")

    print("=== Top 5 URL les plus demandées ===")
    print(df["path"].value_counts().head(5))