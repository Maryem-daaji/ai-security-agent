import random
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()
random.seed(42)

NORMAL_PATHS = ["/", "/produits", "/panier", "/categorie/chaussures",
                "/produit/123", "/contact", "/login", "/mon-compte"]
SQLI = ["/produits?id=1' OR '1'='1", "/produits?id=1 UNION SELECT user,pass FROM users--",
        "/search?q=<script>alert(1)</script>", "/produit?id=1; DROP TABLE users"]
SCAN = ["/wp-admin/install.php", "/.env", "/phpmyadmin/", "/backup.sql", "/.git/config"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)",
       "Mozilla/5.0 (X11; Linux x86_64)"]

def line(ip, ts, method, path, status, size, ua):
    return (f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"')

def generate(n_normal=5000, out="data/access.log"):
    start = datetime(2026, 7, 1)
    rows = []
    # Trafic normal
        # Trafic normal : 400 visiteurs avec plusieurs requêtes chacun
    visiteurs = [(fake.ipv4(), random.choice(UAS)) for _ in range(400)]
    for _ in range(n_normal):
        ip, ua = random.choice(visiteurs)
        ts = start + timedelta(seconds=random.randint(0, 7*86400))
        rows.append((ts, line(ip, ts, "GET", random.choice(NORMAL_PATHS),
                     random.choice([200]*9 + [404]), random.randint(500, 20000), ua)))
    # Attaque 1 : brute force sur /login
    ip = fake.ipv4(); t0 = start + timedelta(days=2, hours=3)
    for i in range(200):
        ts = t0 + timedelta(seconds=i*2)
        rows.append((ts, line(ip, ts, "POST", "/login", 401, 300, "python-requests/2.31")))
    # Attaque 2 : injections SQL / XSS
    ip = fake.ipv4(); t0 = start + timedelta(days=4, hours=14)
    for i in range(30):
        ts = t0 + timedelta(seconds=i*5)
        rows.append((ts, line(ip, ts, "GET", random.choice(SQLI), 500, 200, "sqlmap/1.7")))
    # Attaque 3 : scan de fichiers sensibles
    ip = fake.ipv4(); t0 = start + timedelta(days=5, hours=2)
    for i in range(80):
        ts = t0 + timedelta(seconds=i)
        rows.append((ts, line(ip, ts, "GET", random.choice(SCAN), 404, 150, "Nikto/2.5")))
    rows.sort(key=lambda r: r[0])
    with open(out, "w") as f:
        f.write("\n".join(r[1] for r in rows))
    print(f"{len(rows)} lignes générées dans {out}")

if __name__ == "__main__":
    generate()