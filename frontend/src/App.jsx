
import { useState, useEffect } from "react";
import {
  Activity, Shield, ShieldAlert, Network,
  RefreshCw, Search, Radar, Database,
  AlertTriangle, Download, Trash2, Terminal, GitBranch, Clock3, Cpu
} from "lucide-react";
import {
  ResponsiveContainer, PieChart, Pie,
  Cell, Tooltip, BarChart, Bar, XAxis, YAxis
} from "recharts";
import "./App.css";
import "./cyber-enhancements.css";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [routes, setRoutes] = useState({});
  const [connected, setConnected] = useState(false);
  const [prefix, setPrefix] = useState("203.0.113.0/24");
  const [asn, setAsn] = useState("64500");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const [selected, setSelected] = useState(null);

  async function refresh() {
    try {
      const [a, r] = await Promise.all([
        fetch(`${API}/alerts`),
        fetch(`${API}/routes`)
      ]);

      if (!a.ok || !r.ok) throw Error("API unavailable");

      setAlerts(await a.json());
      setRoutes(await r.json());
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  }, []);

  async function analyze(e) {
    e.preventDefault();
    setLoading(true);
    setMessage("");

    try {
      const res = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prefix,
          origin_asn: Number(asn)
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw Error(JSON.stringify(data.detail));
      }

      setMessage(
        data.anomaly_detected
          ? `${data.anomalies.length} anomaly alert(s) detected`
          : `Route accepted — RPKI: ${data.rpki?.status || "Unknown"}`
      );

      await refresh();
    } catch (err) {
      setMessage(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  async function reset() {
    if (!window.confirm("Clear all stored demo data?")) return;

    try {
      const res = await fetch(`${API}/reset`, {
        method: "POST"
      });
      if (!res.ok) throw Error("Reset failed");

      setSelected(null);
      setMessage("Demo data cleared");
      await refresh();
    } catch (err) {
      setMessage(err.message);
    }
  }

  function exportCSV() {
    const columns = [
      "timestamp", "type", "severity", "prefix",
      "previous_origin", "new_origin",
      "rpki_status", "explanation"
    ];

    const escapeCSV = value =>
      `"${String(value ?? "").replace(/"/g, '""')}"`;

    const csv = [
      columns.join(","),
      ...alerts.map(a =>
        columns.map(c => escapeCSV(a[c])).join(",")
      )
    ].join("\r\n");

    const blob = new Blob([csv], {
      type: "text/csv;charset=utf-8;"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "pairadox-security-alerts.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  const critical = alerts.filter(
    a => a.severity === "CRITICAL"
  ).length;

  const originChanges = alerts.filter(
    a => a.type === "ORIGIN_CHANGE"
  ).length;

  const subprefix = alerts.filter(
    a => a.type === "SUBPREFIX_ANOMALY"
  ).length;

  const rpkiInvalid = alerts.filter(
    a => a.type === "RPKI_INVALID"
  ).length;

  const pieData = [
    { name: "Origin Change", value: originChanges },
    { name: "Subprefix", value: subprefix },
    { name: "RPKI Invalid", value: rpkiInvalid }
  ].filter(x => x.value > 0);

  const barData = [
    { name: "Origin", count: originChanges },
    { name: "Subprefix", count: subprefix },
    { name: "RPKI", count: rpkiInvalid }
  ];

  const recentEvents = [...alerts].reverse().slice(0, 6);
  const maxRisk = alerts.reduce((max, a) => Math.max(max, Number(a.risk_score) || 0), 0);
  const filteredAlerts = [...alerts]
    .filter(a => filter === "ALL" || a.type === filter)
    .reverse();

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <Radar size={32} />
          <div>
            <strong>PAIRADOX</strong>
            <small>BGP SENTINEL</small>
          </div>
        </div>

        <div className="nav active">
          <Activity size={18} /> Security Overview
        </div>
        <div className="nav">
          <ShieldAlert size={18} /> Threat Intelligence
        </div>
        <div className="nav">
          <Network size={18} /> Routing Monitor
        </div>

        <div className="sidebar-footer">
          <Shield size={20} />
          <span>AIORI HACKATHON 3.0</span>
          <small>PS-005 · TEAM PAIRADOX</small>
        </div>
      </aside>

      <main className="main">
        <header>
          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS / BGP INTELLIGENCE
            </div>
            <h1>Network Threat Overview</h1>
            <p>
              Explainable BGP origin and subprefix anomaly monitoring
            </p>
          </div>

          <div className="connection">
            <span className={connected ? "dot" : "dot offline"} />
            {connected ? "System Operational" : "Backend Offline"}
          </div>
        </header>

        <div className="demo-banner">
          <AlertTriangle size={17} />
          DEMONSTRATION ENVIRONMENT — Simulated BGP
          announcements and local demo ROA records.
        </div>

        <section className="stats">
          <Stat icon={<Network />} title="Observed Prefixes"
            value={Object.keys(routes).length}
            note="Tracked routing entries" />

          <Stat icon={<ShieldAlert />} title="Total Alerts"
            value={alerts.length}
            note="Anomaly events detected" />

          <Stat icon={<AlertTriangle />} title="Critical Alerts"
            value={critical}
            note="High-priority investigation" />

          <Stat icon={<Database />} title="RPKI Invalid"
            value={rpkiInvalid}
            note="Demo ROA conflicts" />
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Announcement Analyzer</h3>
              <p>Inspect a network prefix and its origin ASN</p>
            </div>
            <Search size={20} />
          </div>

          <form className="analyzer" onSubmit={analyze}>
            <label>
              NETWORK PREFIX
              <input
                value={prefix}
                onChange={e => setPrefix(e.target.value)}
                required
              />
            </label>

            <label>
              ORIGIN ASN
              <input
                type="number"
                min="0"
                max="4294967295"
                value={asn}
                onChange={e => setAsn(e.target.value)}
                required
              />
            </label>

            <button disabled={loading || !connected}>
              {loading ? "Analyzing..." : "Analyze Route"}
            </button>
          </form>

          {message && <div className="result">{message}</div>}

          <div className="test-scenarios">
            <span>QUICK TEST SCENARIOS</span>
            <button type="button" onClick={() => {
              setPrefix("203.0.113.0/24");
              setAsn("64500");
            }}>Valid Origin</button>
            <button type="button" onClick={() => {
              setPrefix("203.0.113.0/24");
              setAsn("64599");
            }}>Origin Change</button>
            <button type="button" onClick={() => {
              setPrefix("203.0.113.0/25");
              setAsn("64598");
            }}>Subprefix</button>
          </div>
        </section>

        <section className="cyber-grid">
          <div className="panel topology-panel">
            <div className="panel-header"><div><h3><GitBranch size={18} /> Routing Topology</h3><p>Illustrative connections derived from submitted routes</p></div><span className="cyber-tag">SIMULATED VIEW</span></div>
            <Topology routes={routes} alerts={alerts} />
          </div>
          <div className="panel timeline-panel">
            <div className="panel-header"><div><h3><Clock3 size={18} /> Threat Activity</h3><p>Most recent detection events</p></div><span className="cyber-tag">{alerts.length} EVENTS</span></div>
            <div className="event-timeline">
              {recentEvents.length ? recentEvents.map((a, i) => <button key={i} className="event-item" onClick={() => { setSelected(a); document.getElementById("alert-feed")?.scrollIntoView({behavior:"smooth"}); }}>
                <span className={`event-dot ${String(a.severity).toLowerCase()}`} />
                <span><strong>{a.type.replaceAll("_", " ")}</strong><small>{a.prefix} · AS{a.new_origin}</small><small>{a.timestamp ? new Date(a.timestamp).toLocaleString() : "—"}</small></span>
                <span className="event-risk">{a.risk_score ?? "—"}<small>/100</small></span>
              </button>) : <div className="chart-empty">No detected anomalies yet</div>}
            </div>
          </div>
        </section>

        <section className="cyber-grid">
          <div className="panel risk-panel">
            <div className="panel-header"><div><h3><ShieldAlert size={18} /> Threat Priority Index</h3><p>Highest observed heuristic risk score</p></div><span className="cyber-tag">NOT A PROBABILITY</span></div>
            <div className="risk-readout"><strong>{maxRisk}</strong><span>/ 100</span></div>
            <div className="risk-track"><div style={{width:`${maxRisk}%`}} /></div>
            <p className="risk-disclaimer">Scores prioritize investigation based on anomaly indicators and demo RPKI conflicts.</p>
          </div>
          <div className="panel terminal-panel">
            <div className="panel-header"><div><h3><Terminal size={18} /> Detection Console</h3><p>Latest stored alert records · refreshed every 5 seconds</p></div><span className="terminal-live"><span className={connected ? "dot" : "dot offline"} />{connected ? "CONNECTED" : "OFFLINE"}</span></div>
            <div className="terminal-body">
              <div className="terminal-line"><span>SYS</span> Pairadox BGP Sentinel initialized</div>
              <div className="terminal-line"><span>INFO</span> {Object.keys(routes).length} observed prefix(es)</div>
              {recentEvents.slice(0, 4).map((a, i) => <div className="terminal-line" key={i}><span className="terminal-warning">ALERT</span> {a.type} · {a.prefix} · risk {a.risk_score ?? "N/A"}</div>)}
              <div className="terminal-line terminal-cursor">&gt; awaiting next announcement <b>_</b></div>
            </div>
          </div>
        </section>

        <section className="charts">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Threat Distribution</h3>
                <p>Anomalies by detection category</p>
              </div>
            </div>

            <div className="chart-area">
              {pieData.length ? (
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={65}
                      outerRadius={95}
                      paddingAngle={5}
                    >
                      {pieData.map((item, i) => (
                        <Cell
                          key={item.name}
                          fill={["#38bdf8", "#a78bfa", "#fb7185"][
                            ["Origin Change", "Subprefix", "RPKI Invalid"]
                              .indexOf(item.name)
                          ]}
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="chart-empty">No anomalies yet</div>
              )}
            </div>

            <div className="legend">
              <span>🔵 Origin Change</span>
              <span>🟣 Subprefix</span>
              <span>🔴 RPKI Invalid</span>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <div>
                <h3>Detection Analytics</h3>
                <p>Alert counts by category</p>
              </div>
            </div>

            <div className="chart-area">
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={barData}>
                  <XAxis dataKey="name" stroke="#8494ad" />
                  <YAxis stroke="#8494ad" allowDecimals={false} />
                  <Tooltip />
                  <Bar
                    dataKey="count"
                    fill="#3b82f6"
                    radius={[5, 5, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        <section className="panel" id="alert-feed">
          <div className="panel-header">
            <div>
              <h3>Security Alert Feed</h3>
              <p>
                Select an alert to inspect its supporting evidence
              </p>
            </div>
            <div className="actions">
              <select value={filter}
                onChange={e => setFilter(e.target.value)}>
                <option value="ALL">All Alerts</option>
                <option value="ORIGIN_CHANGE">Origin Change</option>
                <option value="SUBPREFIX_ANOMALY">Subprefix</option>
                <option value="RPKI_INVALID">RPKI Invalid</option>
              </select>
              <button className="secondary" onClick={exportCSV}>
                <Download size={15} /> Export CSV
              </button>
              <button className="secondary" onClick={refresh}>
                <RefreshCw size={15} />
              </button>
            </div>
          </div>

          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Risk</th>
                  <th>Severity</th>
                  <th>Detection Type</th>
                  <th>Prefix</th>
                  <th>Origin ASN</th>
                  <th>RPKI</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((a, i) => (
                  <tr key={i} onClick={() => setSelected(a)}>
                    <td className="mono">{a.risk_score ?? "—"}/100</td>
                    <td>
                      <span className={
                        "severity " + a.severity.toLowerCase()
                      }>
                        {a.severity}
                      </span>
                    </td>
                    <td>{a.type.replaceAll("_", " ")}</td>
                    <td className="mono">{a.prefix}</td>
                    <td className="mono">AS{a.new_origin}</td>
                    <td>{a.rpki_status || "Unknown"}</td>
                    <td>
                      {a.timestamp
                        ? new Date(a.timestamp).toLocaleString()
                        : "-"}
                    </td>
                  </tr>
                ))}

                {!filteredAlerts.length && (
                  <tr>
                    <td colSpan="7" className="empty">
                      No matching alerts found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        {selected && (
          <section className="panel investigation">
            <div className="panel-header">
              <div>
                <h3>Investigation Details</h3>
                <p>Explainable routing anomaly evidence</p>
              </div>
              <button className="secondary"
                onClick={() => setSelected(null)}>
                Close
              </button>
            </div>

            <div className="evidence-grid">
              <div><span>DETECTION</span><strong>{selected.type}</strong></div>
              <div><span>SEVERITY</span><strong>{selected.severity}</strong></div>
              <div><span>HEURISTIC RISK</span><strong>{selected.risk_score ?? "N/A"}/100</strong></div>
              <div><span>PREFIX</span><strong>{selected.prefix}</strong></div>
              <div><span>RPKI STATUS</span><strong>{selected.rpki_status}</strong></div>
              <div><span>PREVIOUS ASN</span><strong>{selected.previous_origin == null ? "N/A" : `AS${selected.previous_origin}`}</strong></div>
              <div><span>NEW ASN</span><strong>AS{selected.new_origin}</strong></div>
            </div>

            <div className="explanation">
              <h4>Why was this flagged?</h4>
              <p>{selected.explanation}</p>
              <h4>Recommended Investigation</h4>
              <p>
                Verify the origin ASN with the network operator,
                examine route history, and check authoritative
                RPKI records before concluding that a hijack occurred.
              </p>
            </div>
          </section>
        )}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>Observed Routing Table</h3>
              <p>Latest origin ASN for each observed prefix</p>
            </div>
            <button className="secondary" onClick={reset}>
              <Trash2 size={15} /> Reset Demo
            </button>
          </div>

          <div className="routes">
            {Object.entries(routes).map(([p, a]) => (
              <div className="route" key={p}>
                <span>{p}</span>
                <strong>AS{a}</strong>
              </div>
            ))}

            {!Object.keys(routes).length && (
              <p className="empty">No announcements submitted.</p>
            )}
          </div>
        </section>

        <footer>
          PAIRADOX BGP SENTINEL · AIORI HACKATHON 3.0 · PS-005
        </footer>
      </main>
    </div>
  );
}

function Stat({ icon, title, value, note }) {
  return (
    <div className="stat">
      <div className="stat-top">
        {icon}
        <span>{title}</span>
      </div>
      <h2>{value}</h2>
      <p>{note}</p>
    </div>
  );
}


function Topology({ routes, alerts }) {
  const entries = Object.entries(routes).slice(0, 6);
  const nodes = entries.map(([prefix, asn], i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(entries.length, 1);
    return { prefix, asn, x: 250 + Math.cos(angle) * 168, y: 160 + Math.sin(angle) * 112,
      flagged: alerts.some(a => a.prefix === prefix) };
  });
  return <div className="topology-wrap">
    <svg viewBox="0 0 500 320" role="img" aria-label="Illustrative routing topology for observed prefixes">
      <defs><filter id="node-glow"><feGaussianBlur stdDeviation="4" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
      <circle cx="250" cy="160" r="95" className="topo-ring" />
      <circle cx="250" cy="160" r="145" className="topo-ring topo-ring-outer" />
      {nodes.map((n, i) => <g key={i}>
        <line x1="250" y1="160" x2={n.x} y2={n.y} className={n.flagged ? "topo-link flagged" : "topo-link"} />
        <circle cx={n.x} cy={n.y} r="19" className={n.flagged ? "topo-node flagged" : "topo-node"} />
        <text x={n.x} y={n.y + 4} textAnchor="middle" className="topo-as">AS</text>
        <text x={n.x} y={n.y + (n.y < 160 ? -29 : 35)} textAnchor="middle" className="topo-label">{n.prefix}</text>
      </g>)}
      <circle cx="250" cy="160" r="32" className="topo-core" />
      <text x="250" y="156" textAnchor="middle" className="topo-core-text">BGP</text>
      <text x="250" y="172" textAnchor="middle" className="topo-core-sub">MONITOR</text>
      {!nodes.length && <text x="250" y="260" textAnchor="middle" className="topo-empty">Submit a route to populate the topology</text>}
    </svg>
    <div className="topology-legend"><span><i className="legend-dot safe"/> Observed prefix</span><span><i className="legend-dot danger"/> Has alert history</span></div>
  </div>;
}
