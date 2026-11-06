import { useEffect, useRef, useState } from "react";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, ReferenceDot,
} from "recharts";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const SEV = { critical: "critique", high: "élevée", medium: "moyenne" };
const ORDRE = ["critical", "high", "medium"];
const TYPES = {
  brute_force: "Brute force sur la page de connexion",
  injection_sqli_xss: "Injection SQL / XSS",
  scan_fichiers_sensibles: "Scan de fichiers sensibles",
  anomalie_ml: "Comportement anormal (ML)",
};
const COURT = {
  brute_force: "Brute force",
  injection_sqli_xss: "Injection",
  scan_fichiers_sensibles: "Scan",
  anomalie_ml: "Anomalie",
};
const CODES = { 200: "Succès", 401: "Non autorisé", 404: "Introuvable", 500: "Erreur serveur" };
const COULEUR_CODE = {
  200: "var(--ok)", 401: "var(--high)", 404: "var(--medium)", 500: "var(--critical)",
};
const nf = new Intl.NumberFormat("fr-FR");
const pluriel = (n, mot) => `${n} ${mot}${n > 1 ? "s" : ""}`;
const tooltipStyle = {
  background: "var(--panel)", border: "1px solid var(--line)",
  color: "var(--ink)", borderRadius: 8, fontSize: 13,
};

export default function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [erreur, setErreur] = useState("");
  const [source, setSource] = useState("");
  const [estDemo, setEstDemo] = useState(true);
  const [filtre, setFiltre] = useState("all");
  const [drag, setDrag] = useState(false);
  const [copie, setCopie] = useState("");
  const [theme, setTheme] = useState(() =>
    window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"
  );
  const inputRef = useRef(null);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  async function charger(url, options, nom, demo) {
    setLoading(true);
    setErreur("");
    try {
      const res = await fetch(url, options);
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || "Erreur pendant l'analyse");
      setData(json);
      setSource(nom);
      setEstDemo(demo);
      setFiltre("all");
    } catch (e) {
      setErreur(
        e.message === "Failed to fetch"
          ? "Impossible de joindre l'API. Vérifie qu'elle est lancée sur le port 8000."
          : e.message
      );
    } finally {
      setLoading(false);
    }
  }

  const demo = () => charger(`${API}/analyze/demo`, undefined, "Données de démonstration", true);

  function envoyer(file) {
    if (!file) return;
    const fd = new FormData();
    fd.append("file", file);
    charger(`${API}/analyze`, { method: "POST", body: fd }, file.name, false);
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

  async function copier(ip) {
    try {
      await navigator.clipboard.writeText(ip);
      setCopie(ip);
      setTimeout(() => setCopie(""), 1500);
    } catch {
      setErreur("Impossible de copier l'adresse IP.");
    }
  }

  const nb = (s) => (data ? data.alerts.filter((a) => a.severity === s).length : 0);
  const alertes = data ? data.alerts.filter((a) => filtre === "all" || a.severity === filtre) : [];
  const total = data ? data.alerts.length : 0;
  const codes = data
    ? Object.entries(data.stats.codes_http)
        .map(([c, n]) => ({ c: Number(c), n }))
        .sort((a, b) => a.c - b.c)
    : [];
  const pic = data ? Math.max(...data.timeline.map((t) => t.n)) : 0;
  const maxReq = data ? Math.max(...data.top_ips.map((r) => r.requetes)) : 1;
  const pointDe = (a) => data.timeline.find((t) => t.heure === a.pic);

  return (
    <div
      className="app"
      onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
      onDragLeave={(e) => { if (!e.relatedTarget) setDrag(false); }}
      onDrop={(e) => { e.preventDefault(); setDrag(false); envoyer(e.dataTransfer.files[0]); }}
    >
      {drag && <div className="overlay">Dépose ton fichier de logs pour l'analyser</div>}

      <aside className="side">
        <div className="brand">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
               strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" aria-hidden="true">
            <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          <span>Agent IA<br />de sécurité</span>
        </div>
        <nav aria-label="Sections">
          <a href="#vue">Vue d'ensemble</a>
          <a href="#trafic">Trafic</a>
          <a href="#ip">Adresses IP</a>
          <a href="#alertes">Alertes</a>
        </nav>
        <div className="src">
          <small>Source analysée</small>
          <div className="name">{source || "Aucune"}</div>
          <div className="stack">
            <button className="btn solid" onClick={() => inputRef.current.click()}>
              Charger un fichier de logs
            </button>
            <button className="btn" onClick={demo}>Utiliser les données de démo</button>
            <button className="btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
              {theme === "dark" ? "Passer au thème clair" : "Passer au thème sombre"}
            </button>
          </div>
          <input
            ref={inputRef}
            type="file"
            accept=".log,.txt"
            hidden
            onChange={(e) => { envoyer(e.target.files[0]); e.target.value = ""; }}
          />
        </div>
      </aside>

      <main className="main">
        <div className="top">
          <h1>Analyse de sécurité des logs d'un site e-commerce</h1>
          {loading && <span className="status" role="status">Analyse en cours...</span>}
        </div>

        {erreur && (
          <div className="error" role="alert">
            <strong>Analyse impossible.</strong> {erreur}
            <div className="muted">Format attendu : fichier access.log Nginx ou Apache (.log ou .txt, 5 Mo maximum).</div>
          </div>
        )}

        {data && (
          <>
            <section className="hero" id="vue">
              <h2>
                {total === 0
                  ? "Aucune alerte, le trafic semble sain"
                  : `${pluriel(total, "alerte")} à traiter`}
              </h2>
              <p className="lead">
                L'agent a analysé {nf.format(data.stats.total_requetes)} requêtes
                provenant de {nf.format(data.stats.ip_uniques)} adresses IP.
              </p>
              {total > 0 && (
                <>
                  <div className="seg" aria-hidden="true">
                    {ORDRE.map((s) => nb(s) > 0 && (
                      <span key={s} style={{ flex: nb(s), background: `var(--${s})` }} />
                    ))}
                  </div>
                  <div className="legend">
                    {ORDRE.map((s) => nb(s) > 0 && (
                      <span key={s}>
                        <i className="dot" style={{ background: `var(--${s})` }} />
                        {nb(s)} {SEV[s]}{nb(s) > 1 ? "s" : ""}
                      </span>
                    ))}
                  </div>
                </>
              )}
            </section>

            <div className="panel kpis">
              <div className="kpi"><div className="t">Requêtes</div><div className="v num">{nf.format(data.stats.total_requetes)}</div></div>
              <div className="kpi"><div className="t">Adresses IP</div><div className="v num">{nf.format(data.stats.ip_uniques)}</div></div>
              <div className="kpi"><div className="t">Taux d'erreur</div><div className="v num">{(data.stats.taux_erreur * 100).toFixed(1).replace(".", ",")} %</div></div>
              <div className="kpi"><div className="t">Pic de trafic</div><div className="v num">{nf.format(pic)} / h</div></div>
            </div>

            <h2 className="sec" id="trafic">Trafic heure par heure</h2>
            <p className="sec-sub">Chaque point marque le moment où une alerte a atteint son maximum.</p>
            <div className="panel chart">
              <ResponsiveContainer>
                <AreaChart data={data.timeline} margin={{ top: 28, right: 24, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
                  <XAxis dataKey="heure" minTickGap={60} stroke="var(--muted)" fontSize={12} />
                  <YAxis stroke="var(--muted)" fontSize={12} domain={[0, (m) => Math.ceil(m * 1.12)]} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Area dataKey="n" name="Requêtes" stroke="var(--accent)" strokeWidth={2}
                        fill="var(--accent)" fillOpacity={0.14} />
                  {data.alerts.map((a, i) => {
                    const p = pointDe(a);
                    return p && (
                      <ReferenceDot
                        key={i} x={p.heure} y={p.n} r={6}
                        fill={`var(--${a.severity})`} stroke="var(--panel)" strokeWidth={2}
                        label={{ value: COURT[a.type] || a.type, position: "top", fill: "var(--ink)", fontSize: 12 }}
                      />
                    );
                  })}
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <h2 className="sec" id="ip">Origine du trafic</h2>
            <p className="sec-sub">Les codes de réponse du serveur et les adresses les plus actives.</p>
            <div className="cols">
              <div className="panel pad">
                {codes.map(({ c, n }) => (
                  <div className="crow" key={c}>
                    <span><span className="mono">{c}</span> {CODES[c] || ""}</span>
                    <div className="track">
                      <div className="fill" style={{
                        width: `${(n / data.stats.total_requetes) * 100}%`,
                        background: COULEUR_CODE[c] || "var(--accent)",
                      }} />
                    </div>
                    <span className="right num">
                      {nf.format(n)} <span className="muted">({((n / data.stats.total_requetes) * 100).toFixed(1).replace(".", ",")} %)</span>
                    </span>
                  </div>
                ))}
              </div>

              <div className="panel pad" style={{ overflowX: "auto" }}>
                <table>
                  <thead>
                    <tr><th>Adresse IP</th><th>Requêtes</th><th>Erreurs</th><th>Statut</th></tr>
                  </thead>
                  <tbody>
                    {data.top_ips.map((r) => (
                      <tr key={r.ip}>
                        <td className="mono">{r.ip}</td>
                        <td>
                          <div className="barcell">
                            <div className="bar" style={{ width: `${(r.requetes / maxReq) * 90}px` }} />
                            <span className="num">{nf.format(r.requetes)}</span>
                          </div>
                        </td>
                        <td className="num">{(r.taux_erreur * 100).toFixed(0)} %</td>
                        <td>
                          {r.suspect
                            ? <span className="badge" style={{ color: "var(--critical)" }}>Suspecte</span>
                            : <span className="badge ok">Normale</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="alerts-head">
              <h2 className="sec" id="alertes">Alertes</h2>
              <div className="tools">
                <div className="tabs" role="group" aria-label="Filtrer par gravité">
                  {[["all", `Toutes (${total})`],
                    ["critical", `Critiques (${nb("critical")})`],
                    ["high", `Élevées (${nb("high")})`],
                    ["medium", `Moyennes (${nb("medium")})`]].map(([k, label]) => (
                    <button key={k} aria-pressed={filtre === k} onClick={() => setFiltre(k)}>{label}</button>
                  ))}
                </div>
                <button className="btn" onClick={exporter}>Exporter en JSON</button>
              </div>
            </div>

            {alertes.length === 0 && <div className="empty">Aucune alerte pour ce filtre.</div>}
            {alertes.map((a, i) => (
              <details className="alert" key={`${a.ip}-${a.type}`} open={i === 0}
                       style={{ "--sev": `var(--${a.severity})` }}>
                <summary>
                  <div className="a-title">
                    <strong>{TYPES[a.type] || a.type}</strong>
                    <span className="mono">{a.ip}</span>
                  </div>
                  <div className="a-meta">
                    {nf.format(a.count)} requêtes<br />pic le {a.pic}
                  </div>
                  <span className="badge" style={{ color: `var(--${a.severity})` }}>
                    {SEV[a.severity][0].toUpperCase() + SEV[a.severity].slice(1)}
                  </span>
                  <span className="chev" aria-hidden="true" />
                </summary>
                <div className="a-body">
                  <h4>Ce qui s'est passé</h4>
                  <p>{a.explication}</p>
                  <h4>Actions recommandées</h4>
                  <ul>{a.actions.map((x, j) => <li key={j}>{x}</li>)}</ul>
                  <button className="btn" onClick={() => copier(a.ip)}>
                    {copie === a.ip ? "Adresse copiée" : "Copier l'adresse IP"}
                  </button>
                </div>
              </details>
            ))}

            {estDemo && (
              <p className="note">
                Les données de démonstration sont des logs simulés, générés pour tester l'agent.
              </p>
            )}
          </>
        )}
      </main>
    </div>
  );
}