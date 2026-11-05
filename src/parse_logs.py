import re
from pathlib import Path
import pandas as pd

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "data" / "access.log"

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>.+?) HTTP/[\d.]+" '
    r'(?P<status>\d{3}) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

def parse_lines(lines):
    rows = []
    for line in lines:
        m = LOG_PATTERN.match(line.strip())
        if m:
            rows.append(m.groupdict())
    if not rows:
        raise ValueError("Aucune ligne valide (format attendu : Nginx/Apache combined).")
    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["time"], format="%d/%b/%Y:%H:%M:%S %z")
    df["status"] = df["status"].astype(int)
    df["size"] = df["size"].astype(int)
    return df

def parse_log(path=DEFAULT_LOG):
    with open(path, encoding="utf-8") as f:
        return parse_lines(f)

if __name__ == "__main__":
    df = parse_log()
    print(f"{len(df)} lignes parsées")
    print(df["ip"].value_counts().head(5))