import { useEffect, useRef, useState } from "react";
import {
  AreaChart, Area, BarChart, Bar, Cell, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from "recharts";

const API = "http://127.0.0.1:8000";
const SEV = { critical: "Critique", high: "Élevée", medium: "Moyenne" };
const TYPES = {
  brute_force: "Brute force",
  injection_sqli_xss: "Injection SQL / XSS",
  scan_fichiers_sensibles: "Scan de fichiers sensibles",
  anomalie_ml: "Anomalie (ML)",
};
const COULEUR_CODE = { 200: "#16a34a", 404: "#ca8a04", 401: "#ea580c", 500: "#b91c1c" };
const tooltipStyle = {
  background: "var(--card)", border: "1px solid var(--border)", color: "var(--text)",
};

export default function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [erreur, setErreur] = useState("");
  const [source, setSource] = useState("");
  const [filtre, setFiltre] = useState("all");
  const [drag, setDrag] = useState(false);
  const [theme, setTheme] = useState(() =>
    window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
  );
  const inputRef = useRef(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  async function charger(url, options, nom) {
    setLoading(true);
    setErreur("");
    try {
      const res = await fetch(url, options);
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || "Erreur pendant l'analyse");
      setData(json);
      setSource(nom);
      setFiltre("all");
    } catch (e) {
      setErreur(
        e.message === "Failed to fetch"
          ? "Impossible de joindre l'API. Est-elle lancée ?"
          : e.message
      );
    } finally {
      setLoading(false);
    }
  }

  const demo = () => charger(`${API}/analyze/demo`, undefined, "Données de démonstration");

  function envoyer(file) {
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    charger(`${API}/analyze`, { method: "POST", body: fd }, file.name);
  }

  useEffect(() => {
    demo();
  }, []);

  function exporter() {
    const blob = new Blob([JSON.stringify(data.alerts, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "alertes.json";
    a.click();
    URL.revokeObjectURL(a.href);
  }

  const alertes = data ? data.alerts.filter((a) => filtre === "all" || a.severity === filtre) : [];
  const nb = (s) => (data ? data.alerts.filter((a) => a.severity === s).length : 0);
  const codes = data
    ? Object.entries(data.stats.codes_http).map(([code, n]) => ({ code, n }))
    : [];

  return (
    <div className="wrap">
      <header>
        <div>
          <h1>Agent IA de sécurité</h1>
          <div className="sub">Détection d'attaques dans les logs d'un site e-commerce</div>
        </div>
        <button className="btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? "Thème clair" : "Thème sombre"}
        </button>
      </header>

      <div
        className={`drop ${drag ? "drag" : ""}`}
        onClick={() => inputRef.current.click()}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); envoyer(e.dataTransfer.files[0]); }}
      >
        <strong>Dépose un fichier de logs ici</strong> ou clique pour le choisir
        <br />
        <small>Format Nginx / Apache (access.log)</small>
        <input
          ref={inputRef}
          type="file"
          accept=".log,.txt"
          hidden
          onChange={(e) => { envoyer(e.target.files[0]); e.target.value = ""; }}
        />
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <button className="btn" onClick={demo}>Utiliser les données de démo</button>
        {source && <span className="sub">Source : {source}</span>}
        {loading && <span className="sub">Analyse en cours...</span>}
      </div>

      {erreur && <div className="error">{erreur}</div>}

      {data && (
        <>
          <div className="cards">
            <Carte t="Requêtes" v={data.stats.total_requetes} />
            <Carte t="IP uniques" v={data.stats.ip_uniques} />
            <Carte t="Taux d'erreur" v={`${(data.stats.taux_erreur * 100).toFixed(1)} %`} />
            <Carte t="Alertes" v={data.alerts.length} />
          </div>

          <h2>Trafic et codes HTTP</h2>
          <div className="grid2">
            <div className="card">
              <div className="t">Requêtes par heure</div>
              <div className="chart">
                <ResponsiveContainer>
                  <AreaChart data={data.timeline}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                    <XAxis dataKey="heure" minTickGap={50} stroke="var(--muted)" fontSize={12} />
                    <YAxis stroke="var(--muted)" fontSize={12} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Area dataKey="n" name="Requêtes" stroke="#4f46e5" fill="#4f46e5" fillOpacity={0.25} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="card">
              <div className="t">Codes HTTP</div>
              <div className="chart">
                <ResponsiveContainer>
                  <BarChart data={codes}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                    <XAxis dataKey="code" stroke="var(--muted)" fontSize={12} />
                    <YAxis stroke="var(--muted)" fontSize={12} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="n" name="Requêtes">
                      {codes.map((c) => (
                        <Cell key={c.code} fill={COULEUR_CODE[c.code] || "#4f46e5"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          <h2>Top 10 des IP les plus actives</h2>
          <div className="card" style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr><th>IP</th><th>Requêtes</th><th>Taux d'erreur</th><th>Statut</th></tr>
              </thead>
              <tbody>
                {data.top_ips.map((r) => (
                  <tr key={r.ip}>
                    <td>{r.ip}</td>
                    <td>{r.requetes}</td>
                    <td>{(r.taux_erreur * 100).toFixed(0)} %</td>
                    <td>
                      <span className={`badge ${r.suspect ? "sus" : "ok"}`}>
                        {r.suspect ? "Suspecte" : "Normale"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="row" style={{ justifyContent: "space-between", marginTop: 8 }}>
            <h2>Alertes ({alertes.length})</h2>
            <div className="row filters">
              {[["all", `Toutes (${data.alerts.length})`],
                ["critical", `Critiques (${nb("critical")})`],
                ["high", `Élevées (${nb("high")})`],
                ["medium", `Moyennes (${nb("medium")})`]].map(([k, label]) => (
                <button key={k} className={`btn ${filtre === k ? "active" : ""}`} onClick={() => setFiltre(k)}>
                  {label}
                </button>
              ))}
              <button className="btn primary" onClick={exporter}>Exporter JSON</button>
            </div>
          </div>

          {alertes.length === 0 && <div className="empty">Aucune alerte pour ce filtre.</div>}
          {alertes.map((a, i) => (
            <div key={i} className="alert" style={{ borderLeftColor: `var(--${a.severity})` }}>
              <h3>
                {TYPES[a.type] || a.type}{" "}
                <span className="badge" style={{ color: `var(--${a.severity})` }}>
                  {SEV[a.severity]}
                </span>
              </h3>
              <div className="sub">IP {a.ip} - {a.count} requêtes</div>
              <p>{a.explication}</p>
              <strong>Actions recommandées</strong>
              <ul>{a.actions.map((x, j) => <li key={j}>{x}</li>)}</ul>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function Carte({ t, v }) {
  return (
    <div className="card">
      <div className="t">{t}</div>
      <div className="v">{v}</div>
    </div>
  );
}