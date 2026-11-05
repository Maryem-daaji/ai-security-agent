import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from parse_logs import parse_log
from rules import run_all_rules

def test_parsing_complet():
    df = parse_log()
    assert len(df) == 5310

def test_trois_attaques_detectees():
    alerts = run_all_rules(parse_log())
    types = {a["type"] for a in alerts}
    assert types == {"brute_force", "injection_sqli_xss", "scan_fichiers_sensibles"}

def test_comptes_exacts():
    alerts = {a["type"]: a["count"] for a in run_all_rules(parse_log())}
    assert alerts["brute_force"] == 200
    assert alerts["injection_sqli_xss"] == 30
    assert alerts["scan_fichiers_sensibles"] == 80