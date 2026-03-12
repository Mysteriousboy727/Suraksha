import { useState, useEffect } from "react";

const S = {
  bg: "#0b0b14",
  sidebar: "#0e0e1c",
  card: "#13131f",
  cardHover: "#17172a",
  border: "#1c1c30",
  borderBright: "#2a2a45",
  accent: "#7c3aed",
  accentDim: "rgba(124,58,237,0.2)",
  accentGlow: "rgba(124,58,237,0.08)",
  purple: "#8b5cf6",
  purpleDim: "rgba(139,92,246,0.15)",
  critical: "#ef4444",
  criticalDim: "rgba(239,68,68,0.12)",
  high: "#f97316",
  highDim: "rgba(249,115,22,0.12)",
  medium: "#eab308",
  mediumDim: "rgba(234,179,8,0.10)",
  low: "#22c55e",
  lowDim: "rgba(34,197,94,0.10)",
  text: "#e2e8f0",
  textSub: "#94a3b8",
  textDim: "#475569",
  green: "#10b981",
  cyan: "#06b6d4",
};

const NAV = [
  { icon: "⊞", label: "Dashboard" },
  { icon: "◎", label: "Discovery" },
  { icon: "⬡", label: "OT-IDS Monitor" },
  { icon: "△", label: "Alert Feed" },
  { icon: "◈", label: "Protocol Analysis" },
  { icon: "⬡", label: "Device Registry" },
  { icon: "⊛", label: "Incident Response" },
  { icon: "◉", label: "ML Anomaly Engine" },
  { icon: "⬢", label: "Workflow & Architecture", special: true },
];

const ALERTS = [
  { id: 1, sev: "CRITICAL", title: "Force Coil on Safety Relay — PLC-03", src: "192.168.10.88", dst: "192.168.10.33", cmd: "FC-05", mitre: "T0836", time: "14:31:58", risk: "Emergency shutoff valve state may change — physical damage possible.", fix: "1) Verify physical valve state. 2) Isolate switch port for .10.88. 3) Review access logs." },
  { id: 2, sev: "CRITICAL", title: "Mass Register Write — SCADA-01", src: "192.168.10.88", dst: "192.168.10.12", cmd: "FC-16", mitre: "T0831", time: "14:31:51", risk: "18 holding registers overwritten — setpoint tampering detected.", fix: "1) Compare registers to backup. 2) Roll back changed values. 3) Isolate rogue device." },
  { id: 3, sev: "HIGH", title: "Modbus Reconnaissance Sweep", src: "192.168.10.88", dst: "10.0/24", cmd: "FC-01", mitre: "T0846", time: "14:28:45", risk: "Unknown device polling all coil addresses — mapping plant topology.", fix: "1) Identify device at .10.88. 2) Check MAC vendor. 3) Verify asset registry." },
  { id: 4, sev: "HIGH", title: "Cross-Zone OPC-UA Browse", src: "192.168.10.88", dst: "HMI-01", cmd: "OPC-UA", mitre: "T0830", time: "14:29:12", risk: "Level 3 device browsing Level 1 HMI — Purdue model violation.", fix: "1) Enforce DMZ firewall rules. 2) Review HMI access control list." },
  { id: 5, sev: "MEDIUM", title: "DNP3 Unsolicited Response Flood", src: "RTU-07", dst: "SCADA-01", cmd: "DNP3", mitre: "T0814", time: "14:22:03", risk: "RTU sending 300% above baseline unsolicited responses — possible DoS.", fix: "1) Check RTU-07 health. 2) Reduce unsolicited reporting rate in device config." },
  { id: 6, sev: "LOW", title: "New Unwhitelisted Device Appeared", src: "192.168.10.88", dst: "—", cmd: "ARP", mitre: "T0845", time: "14:28:01", risk: "Unwhitelisted MAC detected. Vendor: Unknown.", fix: "1) Identify device physically. 2) Add to registry or isolate the port." },
];

const DEVICES = [
  { name: "UNKNOWN-88", ip: "192.168.10.88", proto: "Modbus TCP", role: "Unknown", anomaly: 99, status: "rogue", wl: false, last: "14:32:07" },
  { name: "PLC-03", ip: "192.168.10.33", proto: "Modbus TCP", role: "PLC", anomaly: 94, status: "critical", wl: true, last: "14:32:07" },
  { name: "SCADA-01", ip: "192.168.10.12", proto: "Modbus/OPC-UA", role: "SCADA", anomaly: 72, status: "warning", wl: true, last: "14:32:01" },
  { name: "HMI-01", ip: "192.168.10.20", proto: "OPC-UA", role: "HMI", anomaly: 61, status: "warning", wl: true, last: "14:31:55" },
  { name: "RTU-07", ip: "192.168.10.45", proto: "DNP3", role: "RTU", anomaly: 38, status: "warning", wl: true, last: "14:31:40" },
  { name: "PLC-01", ip: "192.168.10.31", proto: "Modbus TCP", role: "PLC", anomaly: 12, status: "normal", wl: true, last: "14:32:00" },
  { name: "Sensor-12", ip: "192.168.10.60", proto: "Modbus RTU", role: "Sensor", anomaly: 5, status: "normal", wl: true, last: "14:31:58" },
  { name: "FW-DMZ", ip: "192.168.10.1", proto: "Multi", role: "Firewall", anomaly: 3, status: "normal", wl: true, last: "14:32:07" },
];

const FC_MATRIX = [
  { fc: "FC-01", name: "Read Coil Status", count: "14,200", src: 3, risk: "LOW", ok: true },
  { fc: "FC-02", name: "Read Discrete Inputs", count: "5,430", src: 4, risk: "LOW", ok: true },
  { fc: "FC-03", name: "Read Holding Registers", count: "8,900", src: 2, risk: "LOW", ok: true },
  { fc: "FC-04", name: "Read Input Registers", count: "3,210", src: 2, risk: "LOW", ok: true },
  { fc: "FC-05", name: "Force Single Coil", count: "3", src: 1, risk: "CRITICAL", ok: false },
  { fc: "FC-16", name: "Write Multiple Registers", count: "18", src: 1, risk: "CRITICAL", ok: false },
];

const SEV = {
  CRITICAL: { color: S.critical, bg: S.criticalDim, border: "rgba(239,68,68,0.3)" },
  HIGH: { color: S.high, bg: S.highDim, border: "rgba(249,115,22,0.3)" },
  MEDIUM: { color: S.medium, bg: S.mediumDim, border: "rgba(234,179,8,0.3)" },
  LOW: { color: S.low, bg: S.lowDim, border: "rgba(34,197,94,0.3)" },
};

// ─── tiny helpers ──────────────────────────────────────────────────────────────
function Dot({ status }) {
  const c = { rogue: S.critical, critical: S.critical, warning: S.medium, normal: S.green }[status] || S.textDim;
  const pulse = status === "rogue" || status === "critical";
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: c, boxShadow: pulse ? `0 0 6px ${c}` : "none", animation: pulse ? "pulse 1.4s infinite" : "none", flexShrink: 0 }} />;
}

function Bar({ score }) {
  const c = score > 80 ? S.critical : score > 50 ? S.medium : S.green;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
      <div style={{ width: 44, height: 4, background: S.border, borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: c, borderRadius: 2 }} />
      </div>
      <span style={{ color: c, fontSize: 10, fontWeight: 700 }}>{score}</span>
    </div>
  );
}

// ─── Traffic Timeline Tab ──────────────────────────────────────────────────────
function TrafficTimeline() {
  const [pts, setPts] = useState(() => Array.from({ length: 60 }, (_, i) => ({ n: Math.random() * 35 + 55, a: i > 45 ? Math.random() * 70 + 15 : 0 })));
  useEffect(() => {
    const t = setInterval(() => setPts(p => [...p.slice(1), { n: Math.random() * 35 + 55, a: Math.random() > 0.55 ? Math.random() * 55 + 10 : 0 }]), 800);
    return () => clearInterval(t);
  }, []);
  const W = 520, H = 120, mx = 150;
  const nPath = pts.map((d, i) => `${i === 0 ? "M" : "L"}${(i / 59) * W},${H - (d.n / mx) * H}`).join(" ");
  const aPath = pts.map((d, i) => `${i === 0 ? "M" : "L"}${(i / 59) * W},${H - (d.a / mx) * H}`).join(" ");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14, padding: "16px 20px", overflowY: "auto", flex: 1 }}>
      <div style={{ background: S.card, border: `1px solid ${S.border}`, borderRadius: 12, padding: 16 }}>
        <div style={{ fontSize: 11, color: S.textDim, letterSpacing: 1, marginBottom: 12 }}>TRAFFIC ANOMALY — 60s ROLLING WINDOW</div>
        <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
          <defs>
            <linearGradient id="ng" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={S.purple} stopOpacity="0.3" /><stop offset="100%" stopColor={S.purple} stopOpacity="0" /></linearGradient>
            <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={S.critical} stopOpacity="0.45" /><stop offset="100%" stopColor={S.critical} stopOpacity="0" /></linearGradient>
          </defs>
          <path d={`${nPath} L${W},${H} L0,${H} Z`} fill="url(#ng)" />
          <path d={nPath} fill="none" stroke={S.purple} strokeWidth={1.5} />
          <path d={`${aPath} L${W},${H} L0,${H} Z`} fill="url(#ag)" />
          <path d={aPath} fill="none" stroke={S.critical} strokeWidth={2} />
          <line x1={W * 0.76} y1={0} x2={W * 0.76} y2={H} stroke={S.critical} strokeWidth={1} strokeDasharray="4,3" />
          <text x={W * 0.76 + 4} y={13} fill={S.critical} fontSize={9} fontFamily="monospace">FC-05 14:31:44</text>
        </svg>
        <div style={{ display: "flex", gap: 16, marginTop: 8 }}>
          {[[S.purple, "Normal baseline"], [S.critical, "ML-flagged anomaly"]].map(([c, l]) => (
            <div key={l} style={{ display: "flex", alignItems: "center", gap: 6 }}><div style={{ width: 18, height: 3, background: c, borderRadius: 1 }} /><span style={{ color: S.textDim, fontSize: 10 }}>{l}</span></div>
          ))}
        </div>
      </div>
      <div style={{ background: S.card, border: `1px solid ${S.border}`, borderRadius: 12, padding: 14 }}>
        <div style={{ fontSize: 10, color: S.textDim, letterSpacing: 1, marginBottom: 8 }}>LAST 10 MINUTES — EVENT STRIP</div>
        <div style={{ display: "flex", gap: 2, height: 18 }}>
          {Array.from({ length: 60 }, (_, i) => <div key={i} style={{ flex: 1, borderRadius: 2, background: i > 50 ? S.critical : i > 43 ? S.medium : S.green, opacity: i > 43 ? 1 : 0.35 }} />)}
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
          <span style={{ color: S.textDim, fontSize: 9 }}>-10 min</span>
          <span style={{ color: S.textDim, fontSize: 9 }}>now</span>
        </div>
      </div>
      <div style={{ background: S.card, border: `1px solid ${S.border}`, borderRadius: 12, padding: 14 }}>
        <div style={{ fontSize: 10, color: S.textDim, letterSpacing: 1, marginBottom: 10 }}>PROTOCOL BREAKDOWN</div>
        {[["Modbus TCP", "56%", S.purple], ["OPC-UA", "23%", S.cyan], ["DNP3", "15%", S.green], ["Unknown", "6%", S.critical]].map(([n, p, c]) => (
          <div key={n} style={{ marginBottom: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}><span style={{ color: S.textSub, fontSize: 11 }}>{n}</span><span style={{ color: c, fontSize: 11, fontWeight: 700 }}>{p}</span></div>
            <div style={{ height: 4, background: S.border, borderRadius: 3, overflow: "hidden" }}><div style={{ width: p, height: "100%", background: c, borderRadius: 3 }} /></div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Workflow Architecture Section ────────────────────────────────────────────
function WorkflowView() {
  const boxStyle = (color, glow) => ({
    border: `1px solid ${color}50`,
    borderRadius: 12,
    padding: "14px 16px",
    background: `rgba(${glow},0.07)`,
    position: "relative",
  });

  const Tag = ({ color, children }) => (
    <span style={{ background: `${color}20`, color, border: `1px solid ${color}40`, borderRadius: 5, fontSize: 9, fontWeight: 700, padding: "2px 7px", letterSpacing: 1 }}>{children}</span>
  );

  const Arrow = ({ label }) => (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, margin: "6px 0" }}>
      <div style={{ width: 1, height: 18, background: S.borderBright || "#2a2a45" }} />
      <div style={{ color: S.textDim, fontSize: 9, letterSpacing: 1 }}>{label}</div>
      <div style={{ width: 1, height: 10, background: S.borderBright || "#2a2a45" }} />
      <div style={{ width: 0, height: 0, borderLeft: "5px solid transparent", borderRight: "5px solid transparent", borderTop: `7px solid ${S.textDim}` }} />
    </div>
  );

  const HArrow = () => (
    <div style={{ display: "flex", alignItems: "center", padding: "0 4px" }}>
      <div style={{ height: 1, width: 20, background: "#2a2a45" }} />
      <div style={{ width: 0, height: 0, borderTop: "4px solid transparent", borderBottom: "4px solid transparent", borderLeft: `6px solid ${S.textDim}` }} />
    </div>
  );

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: "20px 24px", background: S.bg }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 8 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: `linear-gradient(135deg, ${S.accent}, ${S.purple})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>⬢</div>
          <div>
            <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: 1 }}>Workflow & Architecture</div>
            <div style={{ color: S.textDim, fontSize: 11 }}>System design · Data flow · Technology stack</div>
          </div>
        </div>
        <div style={{ padding: "12px 16px", background: S.accentGlow, border: `1px solid ${S.accentDim}`, borderRadius: 10 }}>
          <span style={{ color: S.purple, fontWeight: 700, fontSize: 12 }}>What is this system? </span>
          <span style={{ color: S.textSub, fontSize: 12 }}>SENTINEL OT-IDS is a real-time Industrial Control System intrusion detection platform. It passively captures OT network packets, runs ML anomaly detection, correlates incidents, and presents actionable alerts to plant operators — all without touching live control systems.</span>
        </div>
      </div>

      {/* Main flow diagram */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, color: S.textDim, letterSpacing: 2, marginBottom: 14 }}>▶ END-TO-END DATA FLOW</div>

        {/* Row 1: OT Network sources */}
        <div style={{ display: "flex", gap: 10, marginBottom: 4, justifyContent: "center" }}>
          {[["PLC / RTU", S.critical, "Field Controllers\nModbus TCP/RTU"], ["SCADA / HMI", S.medium, "Control Systems\nOPC-UA"], ["Sensors", S.green, "Field Devices\nDNP3 / Modbus"], ["Firewall / DMZ", S.cyan, "Network Boundary\nMulti-protocol"]].map(([n, c, d]) => (
            <div key={n} style={{ flex: 1, border: `1px solid ${c}40`, borderRadius: 10, padding: "10px 12px", background: `${c}08`, textAlign: "center" }}>
              <div style={{ color: c, fontWeight: 700, fontSize: 11 }}>{n}</div>
              <div style={{ color: S.textDim, fontSize: 9, marginTop: 4, whiteSpace: "pre-line", lineHeight: 1.6 }}>{d}</div>
            </div>
          ))}
        </div>

        <Arrow label="SPAN port / passive tap — READ ONLY, zero impact on live network" />

        {/* Capture layer */}
        <div style={{ ...boxStyle(S.cyan, "6,182,212"), marginBottom: 4 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <Tag color={S.cyan}>CAPTURE LAYER</Tag>
                <Tag color={S.textDim}>BACKEND</Tag>
              </div>
              <div style={{ color: S.text, fontWeight: 600, fontSize: 13 }}>Packet Capture Engine</div>
              <div style={{ color: S.textDim, fontSize: 11, marginTop: 4 }}>Passively mirrors all OT network traffic. Decodes Modbus, DNP3, OPC-UA frames. Extracts function codes, register addresses, source/destination IPs.</div>
            </div>
            <div style={{ textAlign: "right", flexShrink: 0, marginLeft: 16 }}>
              <div style={{ color: S.cyan, fontSize: 11, fontWeight: 700 }}>Tools Used</div>
              <div style={{ color: S.textSub, fontSize: 10, marginTop: 4, lineHeight: 1.8 }}>libpcap / Scapy<br />PyModbus<br />OpenDNP3<br />asyncio pipeline</div>
            </div>
          </div>
        </div>

        <Arrow label="parsed packet objects → processing queue" />

        {/* Processing row */}
        <div style={{ display: "flex", gap: 10, marginBottom: 4 }}>
          {/* Protocol Analyzer */}
          <div style={{ flex: 1, ...boxStyle(S.purple, "139,92,246") }}>
            <Tag color={S.purple}>PROTOCOL ENGINE</Tag>
            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, margin: "6px 0 4px" }}>Protocol Analyzer</div>
            <div style={{ color: S.textDim, fontSize: 10, lineHeight: 1.6 }}>Validates function codes against whitelist. Detects illegal FC usage (FC-05, FC-16 from unknown sources). Flags cross-zone Purdue violations. Builds FC matrix.</div>
            <div style={{ marginTop: 8, color: S.purple, fontSize: 10, fontWeight: 700 }}>Stack: Python · FastAPI · Pydantic</div>
          </div>

          {/* ML Engine */}
          <div style={{ flex: 1, ...boxStyle(S.medium, "234,179,8") }}>
            <Tag color={S.medium}>ML ENGINE</Tag>
            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, margin: "6px 0 4px" }}>Anomaly Detection</div>
            <div style={{ color: S.textDim, fontSize: 10, lineHeight: 1.6 }}>Isolation Forest on 30-day behavioral baseline per device. Scores each event 0–1. Extracts explainability features (write rate, time of day, register range). Triggers at threshold 0.65.</div>
            <div style={{ marginTop: 8, color: S.medium, fontSize: 10, fontWeight: 700 }}>Stack: scikit-learn · NumPy · Pandas</div>
          </div>

          {/* Correlation */}
          <div style={{ flex: 1, ...boxStyle(S.high, "249,115,22") }}>
            <Tag color={S.high}>CORRELATION</Tag>
            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, margin: "6px 0 4px" }}>Incident Correlator</div>
            <div style={{ color: S.textDim, fontSize: 10, lineHeight: 1.6 }}>Groups related alerts into incidents. Maps to MITRE ATT&CK for ICS kill chain stages. Generates physical risk narrative. Produces recommended response steps.</div>
            <div style={{ marginTop: 8, color: S.high, fontSize: 10, fontWeight: 700 }}>Stack: Python · NetworkX · Redis</div>
          </div>
        </div>

        <Arrow label="processed events → storage + real-time stream" />

        {/* Database row */}
        <div style={{ display: "flex", gap: 10, marginBottom: 4 }}>
          <div style={{ flex: 1, ...boxStyle(S.green, "16,185,129") }}>
            <Tag color={S.green}>DATABASE</Tag>
            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, margin: "6px 0 4px" }}>Time-Series Store</div>
            <div style={{ color: S.textDim, fontSize: 10, lineHeight: 1.6 }}>Stores all packets, events, anomaly scores with nanosecond timestamps. Supports 30-day historical queries for baseline learning and forensic replay.</div>
            <div style={{ marginTop: 8, color: S.green, fontSize: 10, fontWeight: 700 }}>InfluxDB · TimescaleDB</div>
          </div>
          <div style={{ flex: 1, ...boxStyle(S.cyan, "6,182,212") }}>
            <Tag color={S.cyan}>DATABASE</Tag>
            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, margin: "6px 0 4px" }}>Asset Registry</div>
            <div style={{ color: S.textDim, fontSize: 10, lineHeight: 1.6 }}>Stores device inventory, whitelist rules, Purdue level tags, vendor info (from MAC OUI lookup), behavioral fingerprints per device.</div>
            <div style={{ marginTop: 8, color: S.cyan, fontSize: 10, fontWeight: 700 }}>PostgreSQL · SQLAlchemy</div>
          </div>
          <div style={{ flex: 1, ...boxStyle(S.medium, "234,179,8") }}>
            <Tag color={S.medium}>CACHE / STREAM</Tag>
            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, margin: "6px 0 4px" }}>Real-Time Bus</div>
            <div style={{ color: S.textDim, fontSize: 10, lineHeight: 1.6 }}>Pub/sub for live alert streaming to dashboard. Holds rolling 60s traffic window for chart updates. Session state for active incidents.</div>
            <div style={{ marginTop: 8, color: S.medium, fontSize: 10, fontWeight: 700 }}>Redis · WebSocket (FastAPI)</div>
          </div>
        </div>

        <Arrow label="REST API + WebSocket → browser" />

        {/* Frontend */}
        <div style={{ ...boxStyle(S.purple, "139,92,246") }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <Tag color={S.purple}>FRONTEND</Tag>
                <Tag color={S.textDim}>REACT + VITE</Tag>
              </div>
              <div style={{ color: S.text, fontWeight: 600, fontSize: 13 }}>SENTINEL Dashboard (this UI)</div>
              <div style={{ color: S.textDim, fontSize: 11, marginTop: 4, lineHeight: 1.7 }}>
                Single-page React app served by Vite. Polls REST API every second for KPIs. WebSocket for live alert push. SVG charts rendered in-browser. No external charting library needed.
              </div>
            </div>
            <div style={{ flexShrink: 0, marginLeft: 20 }}>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
                {[["React 18", S.cyan], ["Vite", S.purple], ["WebSocket", S.medium], ["SVG Charts", S.green], ["IBM Plex Mono", S.textSub]].map(([t, c]) => (
                  <Tag key={t} color={c}>{t}</Tag>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Tech Stack Summary ── */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, color: S.textDim, letterSpacing: 2, marginBottom: 14 }}>▶ TECHNOLOGY STACK AT A GLANCE</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          {[
            { layer: "Frontend", color: S.purple, items: ["React 18 — component UI", "Vite — dev server & bundler", "IBM Plex Mono — typography", "Native SVG — live charts", "WebSocket client — push alerts"] },
            { layer: "Backend API", color: S.cyan, items: ["Python 3.11 — core runtime", "FastAPI — REST + WebSocket", "Pydantic — data validation", "asyncio — concurrent capture", "JWT — operator auth"] },
            { layer: "ML & Analytics", color: S.medium, items: ["scikit-learn — Isolation Forest", "Pandas + NumPy — feature engineering", "NetworkX — attack graph correlation", "MITRE ATT&CK ICS — taxonomy", "Custom explainability layer"] },
            { layer: "Database & Infra", color: S.green, items: ["InfluxDB — time-series packets", "PostgreSQL — asset registry", "Redis — event stream + cache", "Docker Compose — deployment", "Nginx — reverse proxy + TLS"] },
          ].map(({ layer, color, items }) => (
            <div key={layer} style={{ background: S.card, border: `1px solid ${color}30`, borderRadius: 12, padding: "14px 16px", borderTop: `2px solid ${color}` }}>
              <div style={{ color, fontWeight: 700, fontSize: 12, letterSpacing: 1, marginBottom: 10 }}>{layer}</div>
              {items.map(i => (
                <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 6 }}>
                  <span style={{ color, fontSize: 10, marginTop: 1, flexShrink: 0 }}>▸</span>
                  <span style={{ color: S.textSub, fontSize: 11 }}>{i}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* ── Plain English Summary ── */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 11, color: S.textDim, letterSpacing: 2, marginBottom: 14 }}>▶ PLAIN ENGLISH — HOW IT WORKS</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {[
            ["1", S.cyan, "Network tap listens", "A passive sensor mirrors all OT network traffic — like a wiretap that never touches the live wires. PLCs, SCADA, HMIs don't know it's there."],
            ["2", S.purple, "Packets get decoded", "Every Modbus command, DNP3 message, and OPC-UA request is unpacked. We know who sent what command to which device, at exactly what time."],
            ["3", S.medium, "ML spots the weird stuff", "The AI has learned what 'normal' looks like for each device over 30 days. Anything that deviates — unusual command, wrong time, unknown source — gets a high anomaly score."],
            ["4", S.high, "Alerts get grouped into incidents", "Instead of 47 separate alerts, the system finds the pattern: 'reconnaissance → mapping → write commands = Triton-style attack' and tells you in plain English."],
            ["5", S.green, "Operators see exactly what to do", "The dashboard shows the physical risk ('this could open the wrong valve'), a numbered fix list, and a PCAP file to hand to forensics. No cybersecurity degree needed."],
            ["6", S.critical, "Nothing touches the live network", "The entire system is read-only. It cannot send commands to PLCs. If SENTINEL fails, the plant keeps running. Safe by design."],
          ].map(([num, color, title, desc]) => (
            <div key={num} style={{ display: "flex", gap: 14, padding: "14px 16px", background: S.card, border: `1px solid ${S.border}`, borderRadius: 12, alignItems: "flex-start" }}>
              <div style={{ width: 28, height: 28, borderRadius: "50%", background: `${color}20`, border: `1px solid ${color}50`, display: "flex", alignItems: "center", justifyContent: "center", color, fontWeight: 800, fontSize: 13, flexShrink: 0 }}>{num}</div>
              <div>
                <div style={{ color, fontWeight: 700, fontSize: 12, marginBottom: 4 }}>{title}</div>
                <div style={{ color: S.textSub, fontSize: 12, lineHeight: 1.7 }}>{desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Deployment Architecture ── */}
      <div>
        <div style={{ fontSize: 11, color: S.textDim, letterSpacing: 2, marginBottom: 14 }}>▶ DEPLOYMENT ARCHITECTURE</div>
        <div style={{ background: S.card, border: `1px solid ${S.border}`, borderRadius: 12, padding: "16px 20px" }}>
          <div style={{ display: "flex", gap: 8, alignItems: "stretch", overflowX: "auto" }}>
            {[
              { label: "OT Network", sub: "Air-gapped / VLAN", color: S.critical, items: ["PLC-01..03", "SCADA-01", "HMI-01", "RTU-07", "Sensors"] },
              { label: "→ SPAN Port", sub: "Passive mirror", color: S.textDim, items: ["Read-only copy", "No packets sent back", "Zero plant impact"] },
              { label: "Capture VM", sub: "Linux / Docker", color: S.cyan, items: ["libpcap daemon", "Protocol decoders", "FastAPI server", "Redis + Postgres"] },
              { label: "→ HTTPS/WSS", sub: "TLS 1.3 + JWT", color: S.textDim, items: ["REST API :8000", "WebSocket :8001", "Nginx proxy"] },
              { label: "Operator Browser", sub: "React + Vite", color: S.purple, items: ["Dashboard UI", "No install needed", "Works on any PC"] },
            ].map((node, i) => (
              <div key={i} style={node.label.startsWith("→") ? { display: "flex", alignItems: "center", padding: "0 4px", color: S.textDim, fontSize: 18 } : { flex: 1, border: `1px solid ${node.color}30`, borderRadius: 10, padding: "12px 12px", borderTop: `2px solid ${node.color}`, minWidth: 100 }}>
                {node.label.startsWith("→") ? (
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}>
                    <div style={{ color: S.textDim, fontSize: 9, letterSpacing: 1, whiteSpace: "nowrap" }}>{node.sub}</div>
                    <div style={{ fontSize: 20, color: S.textDim }}>→</div>
                    {node.items.map(x => <div key={x} style={{ color: S.textDim, fontSize: 9 }}>{x}</div>)}
                  </div>
                ) : (
                  <>
                    <div style={{ color: node.color, fontWeight: 700, fontSize: 11, marginBottom: 2 }}>{node.label}</div>
                    <div style={{ color: S.textDim, fontSize: 9, marginBottom: 8 }}>{node.sub}</div>
                    {node.items.map(x => (
                      <div key={x} style={{ display: "flex", gap: 5, marginBottom: 3 }}>
                        <span style={{ color: node.color, fontSize: 9 }}>◾</span>
                        <span style={{ color: S.textSub, fontSize: 10 }}>{x}</span>
                      </div>
                    ))}
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeNav, setActiveNav] = useState(2);
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [activeTab, setActiveTab] = useState("alerts");
  const [pkts, setPkts] = useState(2847293);
  const [clock, setClock] = useState(new Date());

  useEffect(() => {
    const t1 = setInterval(() => setPkts(p => p + Math.floor(Math.random() * 80 + 40)), 200);
    const t2 = setInterval(() => setClock(new Date()), 1000);
    return () => { clearInterval(t1); clearInterval(t2); };
  }, []);

  const utc = clock.toUTCString().slice(17, 25);
  const local = clock.toLocaleTimeString();
  const isWorkflow = activeNav === 8;

  return (
    <div style={{ display: "flex", width: "100vw", height: "100vh", background: S.bg, fontFamily: "'IBM Plex Mono','Courier New',monospace", color: S.text, overflow: "hidden", boxSizing: "border-box" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600;700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:#2a2a45;border-radius:2px}
        @keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:0.45;transform:scale(1.4)}}
        @keyframes slidein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
        .nav-item:hover{background:rgba(124,58,237,0.1)!important;cursor:pointer}
        .alert-card:hover{background:#17172a!important}
        .dev-row:hover{background:#17172a!important;cursor:pointer}
        .tab-btn:hover{color:#e2e8f0!important}
      `}</style>

      {/* ── SIDEBAR ── */}
      <div style={{ width: 220, minWidth: 220, background: S.sidebar, borderRight: `1px solid ${S.border}`, display: "flex", flexDirection: "column" }}>
        {/* Logo */}
        <div style={{ padding: "18px 16px 14px", borderBottom: `1px solid ${S.border}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
            <div style={{ width: 34, height: 34, borderRadius: 10, background: `linear-gradient(135deg,${S.accent},${S.purple})`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15, boxShadow: `0 0 18px ${S.accentDim}` }}>⬡</div>
            <div><div style={{ fontWeight: 700, fontSize: 13, letterSpacing: 1 }}>SENTINEL</div><div style={{ color: S.textDim, fontSize: 9, letterSpacing: 2 }}>OT-IDS v2.4</div></div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", background: S.accentGlow, borderRadius: 8, border: `1px solid ${S.accentDim}` }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", background: `linear-gradient(135deg,${S.accent}60,${S.purple}60)`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11 }}>OA</div>
            <div><div style={{ fontSize: 11, fontWeight: 600 }}>Operator A</div><div style={{ color: S.textDim, fontSize: 9 }}>Plant Security</div></div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: "10px 8px", overflowY: "auto" }}>
          {NAV.map((n, i) => (
            <div key={i} className="nav-item" onClick={() => setActiveNav(i)} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 10px", borderRadius: 8, marginBottom: 2, background: activeNav === i ? S.accentDim : "transparent", borderLeft: activeNav === i ? `2px solid ${S.accent}` : `2px solid transparent`, transition: "all 0.15s" }}>
              <span style={{ color: activeNav === i ? S.purple : S.textDim, fontSize: 13 }}>{n.icon}</span>
              <span style={{ color: activeNav === i ? S.text : S.textSub, fontSize: 11, fontWeight: activeNav === i ? 600 : 400 }}>{n.label}</span>
              {n.label === "Alert Feed" && <span style={{ marginLeft: "auto", background: S.critical, color: "#fff", fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 10 }}>6</span>}
              {n.special && <span style={{ marginLeft: "auto", background: S.accentDim, color: S.purple, fontSize: 8, padding: "1px 5px", borderRadius: 4 }}>NEW</span>}
            </div>
          ))}
        </nav>

        {/* Sys health */}
        <div style={{ padding: "12px 14px", borderTop: `1px solid ${S.border}` }}>
          <div style={{ fontSize: 9, color: S.textDim, letterSpacing: 2, marginBottom: 7 }}>SYSTEM HEALTH</div>
          {[["CAPTURE", true], ["ML ENGINE", true], ["DATABASE", true]].map(([l, ok]) => (
            <div key={l} style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ color: S.textDim, fontSize: 10 }}>{l}</span>
              <span style={{ color: ok ? S.green : S.critical, fontSize: 10, fontWeight: 700 }}>● {ok ? "ON" : "OFF"}</span>
            </div>
          ))}
          <div style={{ marginTop: 8, padding: "6px 8px", background: S.accentGlow, borderRadius: 6, border: `1px solid ${S.accentDim}` }}>
            <div style={{ color: S.textDim, fontSize: 9, letterSpacing: 1 }}>PACKETS CAPTURED</div>
            <div style={{ color: S.purple, fontSize: 12, fontWeight: 700 }}>{pkts.toLocaleString()}</div>
          </div>
          <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 10, color: S.textDim }}>UTC {utc}</div>
            <div style={{ fontSize: 10, color: S.textSub }}>{local} local</div>
          </div>
        </div>
      </div>

      {/* ── MAIN ── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>

        {/* Header */}
        <div style={{ padding: "13px 22px", borderBottom: `1px solid ${S.border}`, display: "flex", alignItems: "center", justifyContent: "space-between", background: S.sidebar, flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: 1 }}>{isWorkflow ? "Workflow & Architecture" : "OT-IDS Monitor"}</div>
            <div style={{ color: S.textDim, fontSize: 11 }}>{isWorkflow ? "System design · Data flow · Technology stack" : "Industrial Control System Intrusion Detection"}</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 14px", borderRadius: 8, background: S.criticalDim, border: `1px solid rgba(239,68,68,0.4)` }}>
              <div style={{ width: 9, height: 9, borderRadius: "50%", background: S.critical, animation: "pulse 1.2s infinite", boxShadow: `0 0 8px ${S.critical}` }} />
              <span style={{ color: S.critical, fontWeight: 700, fontSize: 12, letterSpacing: 2 }}>RED ALERT</span>
            </div>
            <div style={{ color: S.textDim, fontSize: 11, textAlign: "right" }}>
              <div>🔔 <span style={{ color: S.critical, fontWeight: 700 }}>6</span> alerts</div>
              <div style={{ fontSize: 9 }}>UTC {utc}</div>
            </div>
          </div>
        </div>

        {/* Workflow view fills everything below header */}
        {isWorkflow ? (
          <WorkflowView />
        ) : (
          <>
            {/* KPI Strip */}
            <div style={{ display: "flex", gap: 12, padding: "12px 22px", borderBottom: `1px solid ${S.border}`, flexShrink: 0 }}>
              {[
                { label: "ACTIVE THREATS", value: "3 CRITICAL", sub: "+2 this hour", color: S.critical },
                { label: "DEVICES ONLINE", value: "24 / 26", sub: "2 offline — check PLC-02", color: S.medium },
                { label: "PACKETS / SEC", value: "4,280 p/s", sub: "Baseline: 3,800", color: S.purple },
                { label: "ANOMALY SCORE", value: "87 / 100", sub: "ML confidence 96%", color: S.critical },
                { label: "PROTOCOL VIOLATIONS", value: "14 today", sub: "FC-05, FC-16 misuse", color: S.high },
                { label: "MEAN TIME DETECT", value: "4.2 sec", sub: "↓ improving", color: S.green },
              ].map((k, i) => (
                <div key={i} style={{ flex: 1, background: S.card, border: `1px solid ${S.border}`, borderRadius: 10, padding: "12px 14px", position: "relative", overflow: "hidden", borderTop: `2px solid ${k.color}` }}>
                  <div style={{ position: "absolute", top: -14, right: -14, width: 50, height: 50, borderRadius: "50%", background: `${k.color}18`, filter: "blur(14px)" }} />
                  <div style={{ color: S.textDim, fontSize: 8, letterSpacing: 1.5, marginBottom: 5 }}>{k.label}</div>
                  <div style={{ color: k.color, fontSize: 15, fontWeight: 700, marginBottom: 3 }}>{k.value}</div>
                  <div style={{ color: S.textDim, fontSize: 9 }}>{k.sub}</div>
                </div>
              ))}
            </div>

            {/* Body: 3 columns */}
            <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>

              {/* LEFT: Device Registry */}
              <div style={{ width: 230, borderRight: `1px solid ${S.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                <div style={{ padding: "12px 14px", borderBottom: `1px solid ${S.border}`, display: "flex", justifyContent: "space-between", alignItems: "center", flexShrink: 0 }}>
                  <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 1 }}>DEVICE REGISTRY</span>
                  <span style={{ background: S.accentDim, color: S.purple, fontSize: 10, padding: "2px 7px", borderRadius: 5 }}>8</span>
                </div>
                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${S.border}`, flexShrink: 0 }}>
                  <input placeholder="Search devices..." style={{ width: "100%", background: S.card, border: `1px solid ${S.border}`, borderRadius: 7, padding: "6px 10px", color: S.text, fontSize: 10, outline: "none" }} />
                </div>
                <div style={{ flex: 1, overflowY: "auto", padding: 8 }}>
                  {DEVICES.map((d, i) => (
                    <div key={i} className="dev-row" style={{ padding: "9px 10px", borderRadius: 8, marginBottom: 4, background: d.status === "rogue" ? "rgba(239,68,68,0.05)" : "transparent", border: d.status === "rogue" ? "1px solid rgba(239,68,68,0.22)" : "1px solid transparent", transition: "all 0.15s" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                        <Dot status={d.status} />
                        <span style={{ fontWeight: 600, fontSize: 11, color: d.status === "rogue" ? S.critical : S.text }}>{d.name}</span>
                        {!d.wl && <span style={{ marginLeft: "auto", color: S.critical, fontSize: 8, border: `1px solid ${S.critical}40`, padding: "1px 5px", borderRadius: 3 }}>ROGUE</span>}
                      </div>
                      <div style={{ color: S.textDim, fontSize: 9, marginBottom: 4 }}>{d.ip} · {d.proto}</div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ color: S.textDim, fontSize: 8, background: S.border, padding: "1px 6px", borderRadius: 3 }}>{d.role}</span>
                        <Bar score={d.anomaly} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* CENTER */}
              <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>
                {/* Tabs */}
                <div style={{ display: "flex", borderBottom: `1px solid ${S.border}`, padding: "0 18px", flexShrink: 0 }}>
                  {[["alerts", "⚡ Alert Feed"], ["protocol", "⬡ Protocol Matrix"], ["timeline", "◎ Traffic Timeline"]].map(([k, l]) => (
                    <button key={k} className="tab-btn" onClick={() => setActiveTab(k)} style={{ padding: "11px 16px", background: "none", border: "none", borderBottom: activeTab === k ? `2px solid ${S.accent}` : "2px solid transparent", color: activeTab === k ? S.text : S.textDim, fontSize: 11, fontWeight: activeTab === k ? 600 : 400, cursor: "pointer", fontFamily: "inherit", transition: "all 0.15s" }}>{l}</button>
                  ))}
                </div>

                {/* Alert Feed */}
                {activeTab === "alerts" && (
                  <div style={{ flex: 1, overflowY: "auto", padding: "14px 18px" }}>
                    {ALERTS.map(a => {
                      const cfg = SEV[a.sev];
                      const open = expandedAlert === a.id;
                      return (
                        <div key={a.id} className="alert-card" style={{ background: S.card, border: `1px solid ${open ? cfg.border : S.border}`, borderRadius: 11, marginBottom: 9, overflow: "hidden", transition: "all 0.2s", animation: "slidein 0.25s ease" }}>
                          <div style={{ padding: "12px 14px", cursor: "pointer" }} onClick={() => setExpandedAlert(open ? null : a.id)}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 7 }}>
                              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                                <span style={{ background: cfg.bg, color: cfg.color, fontSize: 9, fontWeight: 800, letterSpacing: 1.5, padding: "2px 8px", borderRadius: 5, border: `1px solid ${cfg.border}` }}>{a.sev}</span>
                                <span style={{ color: S.textDim, fontSize: 10 }}>{a.time}</span>
                              </div>
                              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                                <span style={{ color: S.purple, fontSize: 9, background: S.accentGlow, padding: "2px 7px", borderRadius: 5, border: `1px solid ${S.accentDim}` }}>⬡ {a.mitre}</span>
                                <span style={{ color: S.textDim, fontSize: 11 }}>{open ? "▲" : "▼"}</span>
                              </div>
                            </div>
                            <div style={{ color: S.text, fontWeight: 600, fontSize: 12, marginBottom: 5 }}>{a.title}</div>
                            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                              <span style={{ color: cfg.color, fontSize: 10 }}>{a.src}</span>
                              <span style={{ color: S.textDim, fontSize: 10 }}>→</span>
                              <span style={{ color: S.purple, fontSize: 10 }}>{a.dst}</span>
                              <span style={{ background: "rgba(255,255,255,0.05)", color: S.textSub, fontSize: 9, padding: "1px 7px", borderRadius: 4 }}>[{a.cmd}]</span>
                            </div>
                          </div>
                          {open && (
                            <div style={{ padding: "12px 14px", borderTop: `1px solid ${S.border}`, background: cfg.bg }}>
                              <div style={{ marginBottom: 9 }}>
                                <div style={{ color: S.textDim, fontSize: 8, letterSpacing: 1.5, marginBottom: 3 }}>⚠ PHYSICAL RISK</div>
                                <div style={{ color: cfg.color, fontSize: 11, lineHeight: 1.6 }}>{a.risk}</div>
                              </div>
                              <div style={{ marginBottom: 9 }}>
                                <div style={{ color: S.textDim, fontSize: 8, letterSpacing: 1.5, marginBottom: 3 }}>▶ FIX STEPS</div>
                                <div style={{ color: S.textSub, fontSize: 11, lineHeight: 1.8 }}>{a.fix}</div>
                              </div>
                              <div style={{ display: "flex", gap: 7 }}>
                                <button style={{ background: S.accentDim, border: `1px solid ${S.accent}`, color: S.purple, fontSize: 10, padding: "5px 11px", borderRadius: 7, cursor: "pointer", fontFamily: "inherit" }}>↓ Download PCAP</button>
                                <button style={{ background: "transparent", border: `1px solid ${S.border}`, color: S.textDim, fontSize: 10, padding: "5px 11px", borderRadius: 7, cursor: "pointer", fontFamily: "inherit" }}>Suppress</button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* Protocol Matrix */}
                {activeTab === "protocol" && (
                  <div style={{ flex: 1, overflowY: "auto", padding: "14px 18px" }}>
                    <div style={{ fontSize: 10, color: S.textDim, letterSpacing: 1, marginBottom: 10 }}>MODBUS FUNCTION CODE MATRIX — LAST 24H</div>
                    <div style={{ background: S.card, border: `1px solid ${S.border}`, borderRadius: 11, overflow: "hidden", marginBottom: 14 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "80px 1fr 80px 50px 80px 80px", padding: "9px 14px", borderBottom: `1px solid ${S.border}`, background: S.sidebar }}>
                        {["FC", "Name", "Count", "Src", "Risk", "Status"].map(h => <div key={h} style={{ color: S.textDim, fontSize: 9, letterSpacing: 1 }}>{h}</div>)}
                      </div>
                      {FC_MATRIX.map((r, i) => (
                        <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 80px 50px 80px 80px", padding: "11px 14px", borderBottom: `1px solid ${S.border}`, background: !r.ok ? "rgba(239,68,68,0.04)" : "transparent" }}>
                          <div style={{ color: S.purple, fontSize: 11, fontWeight: 700 }}>{r.fc}</div>
                          <div style={{ color: S.text, fontSize: 10 }}>{r.name}</div>
                          <div style={{ color: S.textSub, fontSize: 10 }}>{r.count}</div>
                          <div style={{ color: S.textSub, fontSize: 10 }}>{r.src}</div>
                          <div style={{ color: r.ok ? S.green : S.critical, fontSize: 9, fontWeight: 700 }}>{r.risk}</div>
                          <div style={{ color: r.ok ? S.green : S.critical, fontSize: 10 }}>{r.ok ? "✓ Normal" : "✗ ALERT"}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ background: S.card, border: `1px solid ${S.border}`, borderRadius: 11, padding: "14px" }}>
                      <div style={{ fontSize: 10, color: S.textDim, letterSpacing: 1, marginBottom: 10 }}>COMMAND SEQUENCE — ACTIVE ATTACK PATTERN</div>
                      {[
                        ["14:28:01", ".10.88 → Network", "ARP broadcast — device discovery", S.medium],
                        ["14:28:45", ".10.88 → PLC-03", "FC-01 poll coils 0x0000–0x00FF", S.medium],
                        ["14:29:12", ".10.88 → HMI-01", "OPC-UA browse all node IDs", S.high],
                        ["14:31:44", ".10.88 → PLC-03", "FC-05 coil:0x0048 — Force Single Coil", S.critical],
                        ["14:31:51", ".10.88 → PLC-03", "FC-16 regs:0x0010–0x001E (18 regs)", S.critical],
                        ["14:31:58", ".10.88 → PLC-03", "FC-05 repeat — write-verify pattern", S.critical],
                      ].map(([t, src, cmd, c], i) => (
                        <div key={i} style={{ display: "flex", gap: 10, padding: "7px 0", borderBottom: `1px solid ${S.border}`, alignItems: "flex-start" }}>
                          <span style={{ color: S.textDim, fontSize: 9, minWidth: 52, flexShrink: 0, marginTop: 1 }}>{t}</span>
                          <div style={{ width: 2, background: c, borderRadius: 1, alignSelf: "stretch", flexShrink: 0 }} />
                          <div><div style={{ color: c, fontSize: 10, fontWeight: 600, marginBottom: 1 }}>{src}</div><div style={{ color: S.textSub, fontSize: 10 }}>{cmd}</div></div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Traffic Timeline */}
                {activeTab === "timeline" && <TrafficTimeline />}
              </div>

              {/* RIGHT: ML + Incident */}
              <div style={{ width: 280, borderLeft: `1px solid ${S.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
                {/* ML Explainer */}
                <div style={{ padding: "12px 14px", borderBottom: `1px solid ${S.border}`, flexShrink: 0 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1, marginBottom: 10, color: S.purple }}>◉ ML ANOMALY EXPLAINER</div>
                  <div style={{ background: S.criticalDim, border: "1px solid rgba(239,68,68,0.3)", borderRadius: 9, padding: 12 }}>
                    <div style={{ color: S.critical, fontSize: 9, fontWeight: 700, letterSpacing: 1, marginBottom: 8 }}>ISOLATION FOREST — PLC-03</div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}><span style={{ color: S.textDim, fontSize: 10 }}>Score</span><span style={{ color: S.critical, fontWeight: 700, fontSize: 12 }}>0.94 / 1.0</span></div>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}><span style={{ color: S.textDim, fontSize: 10 }}>Confidence</span><span style={{ color: S.critical, fontWeight: 700, fontSize: 12 }}>96%</span></div>
                    <div style={{ height: 1, background: S.border, marginBottom: 8 }} />
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 40px 36px 54px", gap: 3, marginBottom: 6 }}>
                      <span style={{ color: S.textDim, fontSize: 8, letterSpacing: 0.5 }}>FEATURE</span>
                      <span style={{ color: S.textDim, fontSize: 8, textAlign: "right" }}>NOW</span>
                      <span style={{ color: S.textDim, fontSize: 8, textAlign: "right" }}>BASE</span>
                      <span style={{ color: S.textDim, fontSize: 8, textAlign: "right" }}>DELTA</span>
                    </div>
                    {[["Write cmds/min", "800", "12", "+6567%"], ["FC-16 usage", "18", "0", "∞"], ["Source IPs", "2", "1", "+100%"], ["Time of day", "02:17", "09–17", "Off-hrs"], ["Register range", "0x10–1E", "0x00–08", "Unusual"]].map(([f, c, b, d]) => (
                      <div key={f} style={{ display: "grid", gridTemplateColumns: "1fr 40px 36px 54px", gap: 3, marginBottom: 5 }}>
                        <span style={{ color: S.textSub, fontSize: 9 }}>{f}</span>
                        <span style={{ color: S.text, fontSize: 9, textAlign: "right" }}>{c}</span>
                        <span style={{ color: S.textDim, fontSize: 9, textAlign: "right" }}>{b}</span>
                        <span style={{ color: S.critical, fontSize: 9, textAlign: "right", fontWeight: 700 }}>{d}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Incident */}
                <div style={{ flex: 1, overflowY: "auto", padding: "12px 14px" }}>
                  <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: 1, marginBottom: 10, color: S.purple }}>⊛ INCIDENT #047</div>
                  <div style={{ background: S.criticalDim, border: "1px solid rgba(239,68,68,0.3)", borderRadius: 9, padding: 12, marginBottom: 12 }}>
                    <div style={{ color: S.critical, fontSize: 11, fontWeight: 700, marginBottom: 4 }}>Triton-Pattern Attack</div>
                    <div style={{ color: S.textDim, fontSize: 9, marginBottom: 8 }}>Duration: 4m 23s · Devices: 2</div>
                    <div style={{ color: S.textDim, fontSize: 8, letterSpacing: 1, marginBottom: 6 }}>KILL CHAIN STAGE</div>
                    <div style={{ display: "flex", gap: 3, marginBottom: 6 }}>
                      {["Recon", "Dev", "Del", "Inst", "C2", "Exec", "Impact"].map((s, i) => (
                        <div key={i} style={{ flex: 1, height: 5, borderRadius: 2, background: S.critical, opacity: 0.3 + i * 0.1 }} title={s} />
                      ))}
                    </div>
                    <div style={{ color: S.critical, fontSize: 10, fontWeight: 700 }}>Stage 7/7 — IMPACT</div>
                  </div>

                  <div style={{ fontSize: 9, color: S.textDim, letterSpacing: 1, marginBottom: 8 }}>ATTACK TIMELINE</div>
                  {[["14:28:01", "New device .10.88 appears", S.medium, false], ["14:28:45", "Modbus recon FC-01 sweep", S.medium, false], ["14:29:12", "OPC-UA browse HMI-01", S.high, false], ["14:31:44", "FC-05 Force Coil — safety relay", S.critical, true], ["14:31:51", "FC-16 Mass write — 18 regs", S.critical, true], ["14:32:07", "FC-05 repeat — SAFETY TARGETED", S.critical, true]].map(([t, e, c, crit], i, arr) => (
                    <div key={i} style={{ display: "flex", gap: 8, marginBottom: 7, alignItems: "flex-start" }}>
                      <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                        <div style={{ width: 7, height: 7, borderRadius: "50%", background: c, boxShadow: crit ? `0 0 5px ${c}` : "none", flexShrink: 0, marginTop: 2 }} />
                        {i < arr.length - 1 && <div style={{ width: 1, height: 14, background: S.border, marginTop: 2 }} />}
                      </div>
                      <div><div style={{ color: S.textDim, fontSize: 8 }}>{t}</div><div style={{ color: crit ? c : S.textSub, fontSize: 10 }}>{e}</div></div>
                    </div>
                  ))}

                  <div style={{ marginTop: 10, padding: 12, background: S.accentGlow, border: `1px solid ${S.accentDim}`, borderRadius: 9 }}>
                    <div style={{ fontSize: 8, color: S.textDim, letterSpacing: 1, marginBottom: 8 }}>RECOMMENDED RESPONSE</div>
                    {["Verify physical state of all valves NOW", "Isolate switch port for 192.168.10.88", "Download PCAP bundle — all 6 events", "Notify Plant manager + CISA ICS-CERT"].map((s, i) => (
                      <div key={i} style={{ display: "flex", gap: 6, marginBottom: 5 }}>
                        <span style={{ color: S.accent, fontWeight: 700, fontSize: 10, flexShrink: 0 }}>{i + 1}.</span>
                        <span style={{ color: S.textSub, fontSize: 10 }}>{s}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}