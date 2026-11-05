import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

const API = "http://127.0.0.1:8000";
const COULEURS = { critical: "#b91c1c", high: "#ea580c", medium: "#ca8a04" };

export default function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [erreur, setErreur] = useState("");

  useEffect(() => {
    Promise.all([
      fetch(`${API}/stats`).then((r) => r.json()),
      fetch(`${API}/alerts`).then((r) => r.json()),
    ])
      .then(([s, a]) => {
        setStats(s);
        setAlerts(a);
      })
      .catch(() => setErreur("Impossible de joindre l'API. Est-elle lancée ?"));
  }, []);

  if (erreur) return <p style={{ padding: 24, color: "#b91c1c" }}>{erreur}</p>;
  if (!stats) return <p style={{ padding: 24 }}>Chargement...</p>;

  const codes = Object.entries(stats.codes_http).map(([code, n]) => ({ code, n }));

  return (
    <div style={{ maxWidth: 900, margin: "0 auto", padding: 24, fontFamily: "sans-serif" }}>
      <h1>Agent IA de sécurité</h1>

      <div style={{ display: "flex", gap: 16, marginBottom: 24 }}>
        <Carte titre="Requêtes" valeur={stats.total_requetes} />
        <Carte titre="IP uniques" valeur={stats.ip_uniques} />
        <Carte titre="Taux d'erreur" valeur={`${(stats.taux_erreur * 100).toFixed(1)} %`} />
        <Carte titre="Alertes" valeur={alerts.length} />
      </div>

      <h2>Codes HTTP</h2>
      <div style={{ height: 220 }}>
        <ResponsiveContainer>
          <BarChart data={codes}>
            <XAxis dataKey="code" />
            <YAxis />
            <Tooltip />
            <Bar dataKey="n" fill="#4f46e5" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <h2>Alertes</h2>
      {alerts.map((a, i) => (
        <div key={i} style={{ border: "1px solid #ddd", borderLeft: `6px solid ${COULEURS[a.severity]}`,
                              borderRadius: 6, padding: 12, marginBottom: 12 }}>
          <strong>{a.type}</strong> ({a.severity}) - IP {a.ip}
          <p>{a.explication}</p>
          <ul>
            {a.actions.map((act, j) => <li key={j}>{act}</li>)}
          </ul>
        </div>
      ))}
    </div>
  );
}

function Carte({ titre, valeur }) {
  return (
    <div style={{ flex: 1, background: "#f3f4f6", borderRadius: 8, padding: 16 }}>
      <div style={{ fontSize: 13, color: "#555" }}>{titre}</div>
      <div style={{ fontSize: 24, fontWeight: "bold" }}>{valeur}</div>
    </div>
  );
}